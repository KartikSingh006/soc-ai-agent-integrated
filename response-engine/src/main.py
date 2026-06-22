"""
Response Engine - Automated threat containment and response actions.
Integrates with SOAR playbooks, EDR, firewall APIs, and CrowdStrike Falcon.

Every executed action is persisted to Postgres (response_actions table)
here too — previously only the AI Orchestrator's own background-task path
wrote to that table, so actions triggered directly against this service
(manual dashboard action, a playbook run) left no audit trail at all.
"""
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models import ResponseAction
from shared.db_models import ResponseActionORM
from shared.db import get_session, wait_for_postgres, run_startup_migrations
from shared.utils import timestamp_now
from shared.config import settings
from shared.integrations import CrowdStrikeConnector
from shared.auth import CurrentUser, get_caller, require_caller_roles
from shared.audit import record_audit

app = FastAPI(title="Response Engine", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory "current containment state" used only for quick status lookups
# and /revert — the source of truth for what was *requested and when* is
# the response_actions table, written on every /execute call below.
action_log: List[Dict[str, Any]] = []
blocked_ips: set = set()
isolated_hosts: set = set()
disabled_accounts: set = set()
quarantined_files: set = set()

crowdstrike = CrowdStrikeConnector(settings)


class ExecuteRequest(BaseModel):
    action: str
    target: str
    parameters: Optional[Dict[str, Any]] = None


class ExecuteResponse(BaseModel):
    success: bool
    message: str
    action_id: Optional[str] = None
    executed_at: str


class PlaybookRequest(BaseModel):
    playbook_name: str
    alert_id: str
    parameters: Dict[str, Any]


async def block_ip(ip_address: str, duration: int = 3600) -> Dict[str, Any]:
    blocked_ips.add(ip_address)
    return {"success": True, "message": f"IP {ip_address} blocked on firewall for {duration}s", "details": {"action": "block_ip", "target": ip_address, "duration": duration, "provider": "simulated"}}


async def unblock_ip(ip_address: str) -> Dict[str, Any]:
    blocked_ips.discard(ip_address)
    return {"success": True, "message": f"IP {ip_address} unblocked", "details": {"action": "unblock_ip", "target": ip_address, "provider": "simulated"}}


async def isolate_host(hostname: str) -> Dict[str, Any]:
    isolated_hosts.add(hostname)
    # Falcon containment operates on the device's agent ID, not the
    # hostname, so we resolve hostname -> AID before calling out.
    cs_result = await crowdstrike.contain_host_by_hostname(hostname)
    return {"success": cs_result.get("success", True), "message": cs_result.get("message", f"Host {hostname} isolated from network"), "details": {"action": "isolate_host", "target": hostname, "provider": cs_result.get("provider", "simulated"), "raw": cs_result.get("raw")}}


async def restore_host(hostname: str) -> Dict[str, Any]:
    isolated_hosts.discard(hostname)
    cs_result = await crowdstrike.lift_containment_by_hostname(hostname)
    return {"success": cs_result.get("success", True), "message": cs_result.get("message", f"Host {hostname} network access restored"), "details": {"action": "restore_host", "target": hostname, "provider": cs_result.get("provider", "simulated"), "raw": cs_result.get("raw")}}


async def disable_account(username: str) -> Dict[str, Any]:
    disabled_accounts.add(username)
    return {"success": True, "message": f"Account {username} disabled", "details": {"action": "disable_account", "target": username, "provider": "simulated"}}


async def enable_account(username: str) -> Dict[str, Any]:
    disabled_accounts.discard(username)
    return {"success": True, "message": f"Account {username} enabled", "details": {"action": "enable_account", "target": username, "provider": "simulated"}}


async def quarantine_file(file_path: str) -> Dict[str, Any]:
    quarantined_files.add(file_path)
    return {"success": True, "message": f"File {file_path} quarantined", "details": {"action": "quarantine_file", "target": file_path, "provider": "simulated"}}


async def block_domain(domain: str) -> Dict[str, Any]:
    return {"success": True, "message": f"Domain {domain} blocked on DNS/proxy", "details": {"action": "block_domain", "target": domain, "provider": "simulated"}}


async def kill_process(pid: str, hostname: str) -> Dict[str, Any]:
    return {"success": True, "message": f"Process {pid} killed on {hostname}", "details": {"action": "kill_process", "target": pid, "host": hostname, "provider": "simulated"}}


async def capture_traffic(interface: str = "eth0", duration: int = 300) -> Dict[str, Any]:
    return {"success": True, "message": f"Traffic capture started on {interface} for {duration}s", "details": {"action": "capture_traffic", "interface": interface, "duration": duration, "provider": "simulated"}}


async def run_scan(hostname: str, scan_type: str = "full") -> Dict[str, Any]:
    return {"success": True, "message": f"{scan_type} scan initiated on {hostname}", "details": {"action": "run_scan", "target": hostname, "scan_type": scan_type, "provider": "simulated"}}


async def revoke_privileges(username: str) -> Dict[str, Any]:
    return {"success": True, "message": f"Privileges revoked for {username}", "details": {"action": "revoke_privileges", "target": username, "provider": "simulated"}}


async def audit_changes(system: str) -> Dict[str, Any]:
    return {"success": True, "message": f"Audit initiated on {system}", "details": {"action": "audit_changes", "target": system, "provider": "simulated"}}


ACTION_HANDLERS = {
    "block_ip": block_ip,
    "unblock_ip": unblock_ip,
    "isolate_host": isolate_host,
    "restore_host": restore_host,
    "disable_account": disable_account,
    "enable_account": enable_account,
    "quarantine_file": quarantine_file,
    "block_domain": block_domain,
    "kill_process": kill_process,
    "capture_traffic": capture_traffic,
    "run_scan": run_scan,
    "revoke_privileges": revoke_privileges,
    "audit_changes": audit_changes,
}

PLAYBOOKS = {
    "brute_force_response": {"name": "Brute Force Response", "description": "Automated response to brute force attacks", "steps": [{"action": "block_ip", "params": {"duration": 86400}}, {"action": "disable_account", "params": {}}, {"action": "capture_traffic", "params": {"duration": 600}}]},
    "malware_containment": {"name": "Malware Containment", "description": "Isolate and contain malware infections", "steps": [{"action": "isolate_host", "params": {}}, {"action": "quarantine_file", "params": {}}, {"action": "run_scan", "params": {"scan_type": "full"}}]},
    "c2_beaconing_response": {"name": "C2 Beaconing Response", "description": "Respond to C2 beaconing detection", "steps": [{"action": "block_domain", "params": {}}, {"action": "isolate_host", "params": {}}, {"action": "capture_traffic", "params": {"duration": 1800}}]},
    "privilege_escalation_response": {"name": "Privilege Escalation Response", "description": "Respond to unauthorized privilege escalation", "steps": [{"action": "revoke_privileges", "params": {}}, {"action": "audit_changes", "params": {}}, {"action": "disable_account", "params": {}}]},
}


@app.on_event("startup")
async def startup():
    if settings.RUN_MIGRATIONS_ON_STARTUP:
        await wait_for_postgres()
        await run_startup_migrations()
    print("Response Engine started with", len(ACTION_HANDLERS), "action handlers and", len(PLAYBOOKS), "playbooks")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "response-engine"}


@app.get("/status")
async def get_status(current_user: CurrentUser = Depends(get_caller)):
    return {
        "status": "operational",
        "handlers": len(ACTION_HANDLERS),
        "playbooks": len(PLAYBOOKS),
        "crowdstrike_configured": bool(settings.CROWDSTRIKE_CLIENT_ID and settings.CROWDSTRIKE_CLIENT_SECRET),
        "timestamp": timestamp_now(),
    }


@app.get("/falcon/status")
async def falcon_status(current_user: CurrentUser = Depends(get_caller)):
    return {
        "configured": bool(settings.CROWDSTRIKE_CLIENT_ID and settings.CROWDSTRIKE_CLIENT_SECRET),
        "base_url": settings.CROWDSTRIKE_BASE_URL,
    }


async def _dispatch_action(action: str, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if action == "block_ip":
        return await block_ip(target, params.get("duration", 3600))
    elif action == "isolate_host":
        return await isolate_host(target)
    elif action == "disable_account":
        return await disable_account(target)
    elif action == "quarantine_file":
        return await quarantine_file(target)
    elif action == "block_domain":
        return await block_domain(target)
    elif action == "kill_process":
        return await kill_process(target, params.get("hostname", "unknown"))
    elif action == "capture_traffic":
        return await capture_traffic(params.get("interface", "eth0"), params.get("duration", 300))
    elif action == "run_scan":
        return await run_scan(target, params.get("scan_type", "full"))
    elif action == "revoke_privileges":
        return await revoke_privileges(target)
    elif action == "audit_changes":
        return await audit_changes(target)
    elif action == "restore_host":
        return await restore_host(target)
    elif action == "unblock_ip":
        return await unblock_ip(target)
    elif action == "enable_account":
        return await enable_account(target)
    raise KeyError(action)


@app.post("/execute", response_model=ExecuteResponse)
async def execute_action(
    request: ExecuteRequest,
    current_user: CurrentUser = Depends(get_caller),
    session: AsyncSession = Depends(get_session),
):
    action = request.action
    target = request.target
    params = request.parameters or {}

    if action not in ACTION_HANDLERS:
        return ExecuteResponse(success=False, message=f"Unknown action: {action}", executed_at=timestamp_now())

    action_id = f"ACT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    try:
        result = await _dispatch_action(action, target, params)
        action_log.append({"action": action, "target": target, "result": result, "timestamp": datetime.utcnow().isoformat()})

        session.add(
            ResponseActionORM(
                action_id=action_id,
                action_type=action,
                target=target,
                status="completed" if result["success"] else "failed",
                result=result.get("message", ""),
                executed_at=datetime.now(timezone.utc),
                provider=(result.get("details") or {}).get("provider"),
                raw_response=result,
                requested_by=current_user.username,
                approved_by=current_user.username if not current_user.is_internal else None,
            )
        )
        await record_audit(
            session, actor=current_user.username, actor_role=current_user.role, action="response_action.execute",
            resource_type="response_action", resource_id=action_id,
            details={"action_type": action, "target": target, "success": result["success"]}, service="response-engine",
        )
        await session.commit()

        return ExecuteResponse(success=result["success"], message=result["message"], action_id=action_id, executed_at=timestamp_now())
    except Exception as e:
        await session.rollback()
        return ExecuteResponse(success=False, message=f"Action execution failed: {str(e)}", executed_at=timestamp_now())


@app.post("/playbook/execute")
async def execute_playbook(
    request: PlaybookRequest,
    current_user: CurrentUser = Depends(require_caller_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    playbook_name = request.playbook_name
    if playbook_name not in PLAYBOOKS:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_name} not found")
    playbook = PLAYBOOKS[playbook_name]
    results = []
    for step in playbook["steps"]:
        action = step["action"]
        params = {**step["params"], **request.parameters}
        result = await execute_action(
            ExecuteRequest(action=action, target=request.parameters.get("target", "unknown"), parameters=params),
            current_user=current_user,
            session=session,
        )
        results.append(result.model_dump())
    return {"playbook": playbook_name, "alert_id": request.alert_id, "steps_executed": len(results), "results": results, "status": "completed"}


@app.get("/playbooks")
async def get_playbooks(current_user: CurrentUser = Depends(get_caller)):
    return [{"name": name, "description": pb["description"], "steps": len(pb["steps"])} for name, pb in PLAYBOOKS.items()]


@app.get("/playbooks/{playbook_name}")
async def get_playbook(playbook_name: str, current_user: CurrentUser = Depends(get_caller)):
    if playbook_name not in PLAYBOOKS:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return PLAYBOOKS[playbook_name]


@app.get("/actions")
async def get_actions(current_user: CurrentUser = Depends(get_caller)):
    return list(ACTION_HANDLERS.keys())


@app.post("/revert")
async def revert_action(
    payload: Dict[str, Any],
    current_user: CurrentUser = Depends(require_caller_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    action = payload.get("action")
    target = payload.get("target")
    revert_map = {"block_ip": "unblock_ip", "isolate_host": "restore_host", "disable_account": "enable_account"}
    revert_action_type = revert_map.get(action)
    if not revert_action_type:
        return {"success": False, "message": "No revert handler for action"}
    result = await execute_action(
        ExecuteRequest(action=revert_action_type, target=target), current_user=current_user, session=session,
    )
    return result.model_dump()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)
