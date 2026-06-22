import json
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models import LogEvent, Severity, AlertStatus
from shared.db_models import AssetORM, AlertORM, TicketORM, UserORM
from shared.db import get_session, AsyncSessionLocal, wait_for_postgres, run_startup_migrations
from shared.utils import (
    generate_alert_id,
    generate_ticket_id,
    generate_asset_id,
    timestamp_now,
)
from shared.config import settings
from shared.integrations import ElasticsearchIndexer
from shared.auth import (
    CurrentUser,
    ROLES,
    create_access_token,
    get_current_user,
    hash_password,
    internal_headers,
    require_caller_roles,
    require_roles,
    verify_password,
)
from shared.audit import record_audit
from shared.bootstrap import bootstrap_admin_user
from shared.repository import UserRepository

app = FastAPI(title="SIEM Engine", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logs_buffer: List[LogEvent] = []
detection_rules: List[Dict[str, Any]] = []
indexer = ElasticsearchIndexer(settings)

DETECTION_RULES = [
    {"id": "RULE-001", "name": "Brute Force Attack", "description": "10 failed logins in 2 minutes", "event_type": "failed_login", "threshold": 10, "time_window": 120, "severity": Severity.HIGH},
    {"id": "RULE-002", "name": "Impossible Travel", "description": "Login from different countries within short time", "event_type": "login", "severity": Severity.HIGH},
    {"id": "RULE-003", "name": "Privilege Escalation", "description": "Unauthorized privilege elevation detected", "event_type": "privilege_escalation", "severity": Severity.CRITICAL},
    {"id": "RULE-004", "name": "Malware Hash Detection", "description": "Known malicious hash detected", "event_type": "file_hash_match", "severity": Severity.CRITICAL},
    {"id": "RULE-005", "name": "Beaconing Traffic", "description": "Periodic outbound connections detected", "event_type": "outbound_connection", "threshold": 5, "time_window": 300, "severity": Severity.HIGH},
    {"id": "RULE-006", "name": "Suspicious Outbound Traffic", "description": "Large volume of outbound data", "event_type": "outbound_traffic", "severity": Severity.MEDIUM},
]


class LogIngestRequest(BaseModel):
    logs: List[Dict[str, Any]]


class AlertResponse(BaseModel):
    alert_id: str
    severity: str
    status: str
    rule_triggered: str
    asset: str
    timestamp: str
    description: str


class DashboardStats(BaseModel):
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    open_tickets: int
    recent_alerts: List[AlertResponse]


class AssetUpsertRequest(BaseModel):
    hostname: str
    asset_name: Optional[str] = None
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    criticality: str = "medium"
    environment: str = "production"
    location: Optional[str] = None
    platform: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class RoleUpdateRequest(BaseModel):
    role: str


@app.on_event("startup")
async def startup():
    detection_rules.extend(DETECTION_RULES)
    if settings.RUN_MIGRATIONS_ON_STARTUP:
        await wait_for_postgres()
        await run_startup_migrations()
    async with AsyncSessionLocal() as bootstrap_session:
        await bootstrap_admin_user(bootstrap_session)
    print(f"[ES] URL={settings.ELASTICSEARCH_URL}")
    await indexer.ensure_indices()
    print("SIEM Engine started with", len(detection_rules), "detection rules")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "siem-engine"}


@app.post("/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest, session: AsyncSession = Depends(get_session)):
    repo = UserRepository(session)
    user = await repo.get_by_username(request.username)
    if not user or not user.is_active or not verify_password(request.password, user.hashed_password):
        await record_audit(
            session, actor=request.username, action="auth.login_failed",
            resource_type="user", success=False, service="siem-engine",
        )
        await session.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user.last_login_at = datetime.now(timezone.utc)
    token = create_access_token(user.username, user.role)
    await record_audit(
        session, actor=user.username, actor_role=user.role, action="auth.login",
        resource_type="user", resource_id=user.user_id, service="siem-engine",
    )
    await session.commit()
    return TokenResponse(access_token=token, username=user.username, role=user.role)


@app.get("/auth/me")
async def get_me(current_user: CurrentUser = Depends(get_current_user)):
    return {"username": current_user.username, "role": current_user.role}


@app.post("/auth/users", status_code=201)
async def create_user(
    request: UserCreateRequest,
    current_user: CurrentUser = Depends(require_roles("admin")),
    session: AsyncSession = Depends(get_session),
):
    if request.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {ROLES}")
    repo = UserRepository(session)
    if await repo.get_by_username(request.username):
        raise HTTPException(status_code=409, detail="Username already exists")

    user = UserORM(username=request.username, hashed_password=hash_password(request.password), role=request.role)
    session.add(user)
    await record_audit(
        session, actor=current_user.username, actor_role=current_user.role, action="user.create",
        resource_type="user", resource_id=request.username, details={"role": request.role}, service="siem-engine",
    )
    await session.commit()
    return {"username": user.username, "role": user.role}


@app.get("/auth/users")
async def list_users(
    current_user: CurrentUser = Depends(require_roles("admin")),
    session: AsyncSession = Depends(get_session),
):
    repo = UserRepository(session)
    users = await repo.list_all()
    return [
        {
            "username": u.username,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        }
        for u in users
    ]


@app.patch("/auth/users/{username}/role")
async def update_user_role(
    username: str,
    request: RoleUpdateRequest,
    current_user: CurrentUser = Depends(require_roles("admin")),
    session: AsyncSession = Depends(get_session),
):
    if request.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {ROLES}")
    repo = UserRepository(session)
    user = await repo.get_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = user.role
    user.role = request.role
    await record_audit(
        session, actor=current_user.username, actor_role=current_user.role, action="user.role_update",
        resource_type="user", resource_id=username, details={"old_role": old_role, "new_role": request.role},
        service="siem-engine",
    )
    await session.commit()
    return {"username": user.username, "role": user.role}


@app.delete("/auth/users/{username}")
async def deactivate_user(
    username: str,
    current_user: CurrentUser = Depends(require_roles("admin")),
    session: AsyncSession = Depends(get_session),
):
    if username == current_user.username:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    repo = UserRepository(session)
    user = await repo.get_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    await record_audit(
        session, actor=current_user.username, actor_role=current_user.role, action="user.deactivate",
        resource_type="user", resource_id=username, service="siem-engine",
    )
    await session.commit()
    return {"username": user.username, "is_active": False}


def _asset_to_dict(asset: AssetORM) -> Dict[str, Any]:
    return {
        "asset_id": asset.asset_id,
        "hostname": asset.hostname,
        "asset_name": asset.asset_name,
        "owner": asset.owner,
        "business_unit": asset.business_unit,
        "criticality": asset.criticality,
        "environment": asset.environment,
        "location": asset.location,
        "platform": asset.platform,
        "tags": asset.tags or [],
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
        "metadata": asset.asset_metadata or {},
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "updated_at": asset.updated_at.isoformat() if asset.updated_at else None,
    }


def _alert_to_response(alert: AlertORM) -> AlertResponse:
    return AlertResponse(
        alert_id=alert.alert_id,
        severity=alert.severity,
        status=alert.status,
        rule_triggered=alert.rule_triggered,
        asset=alert.asset,
        timestamp=alert.timestamp.isoformat(),
        description=alert.description,
    )


async def _get_asset_by_hostname(session: AsyncSession, hostname: str) -> Optional[AssetORM]:
    result = await session.execute(select(AssetORM).where(AssetORM.hostname == hostname))
    return result.scalar_one_or_none()


async def _upsert_asset(
    session: AsyncSession,
    hostname: str,
    metadata: Dict[str, Any],
    asset_name: Optional[str] = None,
) -> AssetORM:
    existing = await _get_asset_by_hostname(session, hostname)
    criticality = str(metadata.get("criticality", "medium")).lower()
    criticality = criticality if criticality in {"low", "medium", "high", "critical"} else "medium"

    if existing:
        existing.asset_name = asset_name or str(metadata.get("asset_name") or hostname)
        existing.owner = metadata.get("owner")
        existing.business_unit = metadata.get("business_unit")
        existing.criticality = criticality
        existing.environment = str(metadata.get("environment", "production"))
        existing.location = metadata.get("location")
        existing.platform = metadata.get("platform")
        existing.tags = metadata.get("tags", existing.tags or [])
        existing.last_seen = datetime.now(timezone.utc)
        existing.asset_metadata = metadata
        await session.flush()
        return existing

    asset = AssetORM(
        asset_id=str(metadata.get("asset_id") or generate_asset_id()),
        hostname=str(hostname),
        asset_name=str(asset_name or metadata.get("asset_name") or hostname),
        owner=metadata.get("owner"),
        business_unit=metadata.get("business_unit"),
        criticality=criticality,
        environment=str(metadata.get("environment", "production")),
        location=metadata.get("location"),
        platform=metadata.get("platform"),
        tags=metadata.get("tags", []),
        last_seen=datetime.now(timezone.utc),
        asset_metadata=metadata,
    )
    session.add(asset)
    await session.flush()
    return asset


@app.post("/assets")
async def upsert_asset(
    request: AssetUpsertRequest,
    current_user: CurrentUser = Depends(require_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    asset = await _upsert_asset(
        session,
        hostname=request.hostname,
        metadata={
            "owner": request.owner,
            "business_unit": request.business_unit,
            "criticality": request.criticality,
            "environment": request.environment,
            "location": request.location,
            "platform": request.platform,
            "tags": request.tags,
        },
        asset_name=request.asset_name or request.hostname,
    )
    await record_audit(
        session, actor=current_user.username, actor_role=current_user.role, action="asset.upsert",
        resource_type="asset", resource_id=asset.asset_id, service="siem-engine",
    )
    await session.commit()
    await indexer.index_asset(_asset_to_dict(asset))
    return {"status": "success", "asset": _asset_to_dict(asset)}


@app.get("/assets")
async def list_assets(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(AssetORM).order_by(AssetORM.created_at.desc()))
    return [_asset_to_dict(asset) for asset in result.scalars().all()]


@app.get("/assets/{asset_id}")
async def get_asset(
    asset_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    asset = await session.get(AssetORM, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_to_dict(asset)


@app.post("/ingest", response_model=Dict[str, Any])
async def ingest_logs(
    request: LogIngestRequest,
    current_user: CurrentUser = Depends(require_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    parsed_logs = []
    for log in request.logs:
        parsed = parse_log(log)
        parsed_logs.append(parsed)
        logs_buffer.append(parsed)

        asset_name = parsed.metadata.get("asset") or parsed.destination_ip or parsed.source_ip or "unknown"
        if asset_name != "unknown":
            asset = await _upsert_asset(session, asset_name, parsed.metadata)
            await indexer.index_asset(_asset_to_dict(asset))

    await run_correlation(parsed_logs, session)
    await session.commit()
    return {"status": "success", "logs_ingested": len(parsed_logs), "timestamp": timestamp_now()}


def parse_log(raw_log: Dict[str, Any]) -> LogEvent:
    metadata = dict(raw_log.get("metadata", {}))
    if "asset" in raw_log and "asset" not in metadata:
        metadata["asset"] = raw_log["asset"]

    return LogEvent(
        timestamp=datetime.fromisoformat(raw_log.get("timestamp", timestamp_now()).replace("Z", "+00:00")),
        source_ip=raw_log.get("source_ip"),
        destination_ip=raw_log.get("destination_ip"),
        event_type=raw_log.get("event_type", "unknown"),
        severity=Severity(raw_log.get("severity", "low")),
        raw_log=json.dumps(raw_log),
        metadata=metadata,
    )


async def run_correlation(logs: List[LogEvent], session: AsyncSession):
    for rule in detection_rules:
        matched = apply_rule(rule, logs)
        if matched:
            await create_alert(rule, matched, session)


def apply_rule(rule: Dict[str, Any], logs: List[LogEvent]) -> Optional[List[LogEvent]]:
    event_type = rule["event_type"]
    matched_logs = [log for log in logs if log.event_type == event_type]

    if "threshold" in rule:
        time_window = rule.get("time_window", 300)
        now = datetime.utcnow()
        recent_logs = [
            log for log in matched_logs
            if (now - log.timestamp.replace(tzinfo=None)).total_seconds() <= time_window
        ]
        if len(recent_logs) >= rule["threshold"]:
            return recent_logs
    elif len(matched_logs) > 0:
        return matched_logs

    return None


async def create_alert(rule: Dict[str, Any], matched_logs: List[LogEvent], session: AsyncSession):
    alert_id = generate_alert_id()
    asset_name = matched_logs[0].metadata.get("asset", "Unknown")
    asset = await _get_asset_by_hostname(session, asset_name)

    alert = AlertORM(
        alert_id=alert_id,
        severity=rule["severity"].value if hasattr(rule["severity"], "value") else str(rule["severity"]),
        rule_triggered=rule["name"],
        asset=asset_name,
        timestamp=datetime.now(timezone.utc),
        status=AlertStatus.NEW.value,
        description=rule["description"],
        evidence=[{"log": log.raw_log, "timestamp": log.timestamp.isoformat()} for log in matched_logs[:5]],
        iocs=[],
        mitre_techniques=[],
        ai_analysis=None,
    )
    session.add(alert)

    ticket = TicketORM(
        ticket_id=generate_ticket_id(),
        alert_id=alert_id,
        severity=rule["severity"].value if hasattr(rule["severity"], "value") else str(rule["severity"]),
        status="new",
        recommended_actions=get_recommended_actions(rule["name"]),
        evidence=alert.evidence,
    )
    session.add(ticket)
    await record_audit(
        session, actor="system", action="alert.created", resource_type="alert", resource_id=alert_id,
        details={"rule_triggered": rule["name"], "severity": alert.severity, "asset": asset_name},
        service="siem-engine",
    )
    await session.flush()
    await session.commit()

    background_payload = {
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "rule_triggered": alert.rule_triggered,
        "asset": alert.asset,
        "evidence": alert.evidence,
        "description": alert.description,
        "asset_context": _asset_to_dict(asset) if asset else None,
    }
    await send_to_ai_orchestrator(background_payload)
    await indexer.index_alert(background_payload)
    print(f"Alert created: {alert_id} - {rule['name']}")


def get_recommended_actions(rule_name: str) -> List[str]:
    actions_map = {
        "Brute Force Attack": ["Block source IP", "Disable targeted account", "Review access logs"],
        "Impossible Travel": ["Verify user identity", "Check for compromised credentials", "Enable MFA"],
        "Privilege Escalation": ["Revoke elevated privileges", "Isolate affected system", "Audit privilege changes"],
        "Malware Hash Detection": ["Quarantine file", "Isolate endpoint", "Run full system scan"],
        "Beaconing Traffic": ["Block C2 domain/IP", "Isolate infected host", "Analyze network traffic"],
        "Suspicious Outbound Traffic": ["Block outbound connection", "Review data access", "Check for data exfiltration"],
    }
    return actions_map.get(rule_name, ["Investigate further", "Collect evidence"])


async def send_to_ai_orchestrator(alert_payload: Dict[str, Any]):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.AI_ORCHESTRATOR_URL}/analyze-alert",
                json=alert_payload,
                headers=internal_headers(),
                timeout=30.0,
            )
            print(f"[DEBUG] AI Orchestrator response: {response.status_code}")
    except Exception as e:
        print(f"Failed to send to AI Orchestrator: {e}")


@app.get("/alerts")
async def get_alerts(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(AlertORM).order_by(AlertORM.timestamp.desc()))
    return [_alert_to_response(a).model_dump() for a in result.scalars().all()]


@app.get("/alerts/{alert_id}")
async def get_alert(
    alert_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    alert = await session.get(AlertORM, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "status": alert.status,
        "rule_triggered": alert.rule_triggered,
        "asset": alert.asset,
        "timestamp": alert.timestamp.isoformat(),
        "description": alert.description,
        "evidence": alert.evidence,
        "iocs": alert.iocs,
        "mitre_techniques": alert.mitre_techniques,
        "ai_analysis": alert.ai_analysis,
    }


@app.put("/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    status: AlertStatus,
    current_user: CurrentUser = Depends(require_caller_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    alert = await session.get(AlertORM, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    old_status = alert.status
    alert.status = status.value
    await record_audit(
        session, actor=current_user.username, actor_role=current_user.role, action="alert.status_update",
        resource_type="alert", resource_id=alert_id, details={"old_status": old_status, "new_status": status.value},
        service="siem-engine",
    )
    await session.commit()
    return {"status": "updated", "alert_id": alert_id, "new_status": status.value}


@app.get("/tickets")
async def get_tickets(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(TicketORM).order_by(TicketORM.created_at.desc()))
    tickets = []
    for ticket in result.scalars().all():
        tickets.append(
            {
                "ticket_id": ticket.ticket_id,
                "alert_id": ticket.alert_id,
                "severity": ticket.severity,
                "status": ticket.status,
                "assigned_analyst": ticket.assigned_analyst,
                "recommended_actions": ticket.recommended_actions,
                "evidence": ticket.evidence,
                "created_at": ticket.created_at.isoformat() if ticket.created_at else None,
                "resolved_at": ticket.resolved_at.isoformat() if ticket.resolved_at else None,
            }
        )
    return tickets


@app.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(AlertORM).order_by(AlertORM.timestamp.desc()))
    all_alerts = list(result.scalars().all())
    critical = sum(1 for a in all_alerts if a.severity == Severity.CRITICAL.value)
    high = sum(1 for a in all_alerts if a.severity == Severity.HIGH.value)

    ticket_result = await session.execute(select(TicketORM))
    open_tickets = sum(1 for t in ticket_result.scalars().all() if t.status != AlertStatus.RESOLVED.value)

    recent = all_alerts[:5]
    return DashboardStats(
        total_alerts=len(all_alerts),
        critical_alerts=critical,
        high_alerts=high,
        open_tickets=open_tickets,
        recent_alerts=[_alert_to_response(a) for a in recent],
    )


@app.get("/search/alerts")
async def search_alerts(
    q: str = Query(..., min_length=1),
    current_user: CurrentUser = Depends(get_current_user),
):
    query = {
        "query": {
            "multi_match": {
                "query": q,
                "fields": ["rule_triggered^2", "description", "asset", "severity", "status"],
            }
        }
    }
    return await indexer.search(settings.ELASTICSEARCH_ALERT_INDEX, query)


@app.post("/simulate")
async def simulate_attack(
    attack_type: str = "brute_force",
    current_user: CurrentUser = Depends(require_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    simulations = {
        "brute_force": [
            {
                "timestamp": (datetime.utcnow() - timedelta(seconds=i * 10)).isoformat() + "Z",
                "source_ip": "45.33.22.11",
                "destination_ip": "10.0.0.5",
                "event_type": "failed_login",
                "severity": "medium",
                "metadata": {"asset": "Server-22", "username": "admin", "port": 22, "criticality": "critical"},
            }
            for i in range(12)
        ],
        "beaconing": [
            {
                "timestamp": (datetime.utcnow() - timedelta(seconds=i * 60)).isoformat() + "Z",
                "source_ip": "10.0.0.15",
                "destination_ip": "185.220.101.4",
                "event_type": "outbound_connection",
                "severity": "medium",
                "metadata": {"asset": "Workstation-15", "port": 443, "bytes": 1024, "criticality": "high"},
            }
            for i in range(6)
        ],
        "privilege_escalation": [
            {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "source_ip": "10.0.0.8",
                "event_type": "privilege_escalation",
                "severity": "critical",
                "metadata": {"asset": "Server-08", "user": "service_account", "escalated_to": "SYSTEM", "criticality": "critical"},
            }
        ],
    }
    logs = simulations.get(attack_type, simulations["brute_force"])
    return await ingest_logs(LogIngestRequest(logs=logs), current_user=current_user, session=session)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)