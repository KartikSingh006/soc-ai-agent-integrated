import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import httpx
from fastapi import FastAPI, BackgroundTasks, HTTPException, Query, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models import (
    AlertStatus,
    Severity,
    Incident,
    IncidentType,
    AIAnalysisResult,
    EnrichmentResult,
    ResponseAction,
)
from shared.db_models import IncidentORM, AIAnalysisORM, ReportORM, ResponseActionORM
from shared.db import get_session, AsyncSessionLocal, wait_for_postgres, run_startup_migrations
from shared.utils import generate_incident_id, generate_report_id, timestamp_now, calculate_risk_score
from shared.config import settings
from shared.integrations import ElasticsearchIndexer, DjangoTicketClient
from shared.auth import (
    CurrentUser,
    get_current_user,
    get_caller,
    internal_headers,
    require_caller_roles,
    require_roles,
)
from shared.audit import record_audit
from shared.repository import ResponseActionRepository, IncidentRepository, AuditLogRepository

app = FastAPI(title="AI Orchestrator", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

agent_memory: Dict[str, Any] = {}
indexer = ElasticsearchIndexer(settings)
django_client = DjangoTicketClient(settings)

MITRE_MAPPING = {
    "Brute Force Attack": ["T1110", "T1078", "T1133"],
    "Impossible Travel": ["T1078", "T1535", "T1550"],
    "Privilege Escalation": ["T1068", "T1078", "T1548", "T1134"],
    "Malware Hash Detection": ["T1204", "T1059", "T1105", "T1027"],
    "Beaconing Traffic": ["T1071", "T1572", "T1001", "T1105"],
    "Suspicious Outbound Traffic": ["T1041", "T1048", "T1567", "T1020"],
}

ATTACK_TYPE_MAPPING = {
    "Brute Force Attack": IncidentType.BRUTE_FORCE,
    "Impossible Travel": IncidentType.CREDENTIAL_THEFT,
    "Privilege Escalation": IncidentType.INSIDER_THREAT,
    "Malware Hash Detection": IncidentType.MALWARE,
    "Beaconing Traffic": IncidentType.MALWARE,
    "Suspicious Outbound Traffic": IncidentType.DATA_EXFILTRATION,
}


class AnalyzeAlertRequest(BaseModel):
    alert_id: str
    severity: str
    rule_triggered: str
    asset: str
    evidence: List[Dict[str, Any]]
    description: str
    asset_context: Optional[Dict[str, Any]] = None


class DecisionRequest(BaseModel):
    alert_id: str
    analysis_result: AIAnalysisResult
    enrichment_result: EnrichmentResult


class OrchestratorResponse(BaseModel):
    alert_id: str
    incident_id: Optional[str]
    decision: str
    confidence: float
    actions: List[str]
    requires_approval: bool


class IntakeAgent:
    async def process(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        iocs = self._extract_iocs(alert_data.get("evidence", []))
        return {
            "alert_id": alert_data["alert_id"],
            "iocs": iocs,
            "severity": alert_data["severity"],
            "rule_triggered": alert_data["rule_triggered"],
            "asset": alert_data["asset"],
            "asset_context": alert_data.get("asset_context"),
            "prepared": True,
        }

    def _extract_iocs(self, evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        iocs = []
        for item in evidence:
            raw = item.get("log", "{}")
            try:
                log_data = json.loads(raw) if isinstance(raw, str) else raw
                if "source_ip" in log_data:
                    iocs.append({"type": "ip", "value": log_data["source_ip"]})
                if "destination_ip" in log_data:
                    iocs.append({"type": "ip", "value": log_data["destination_ip"]})
                if "hash" in log_data:
                    iocs.append({"type": "hash", "value": log_data["hash"]})
                if "domain" in log_data:
                    iocs.append({"type": "domain", "value": log_data["domain"]})
            except Exception:
                pass
        return iocs


class ThreatIntelAgent:
    async def enrich(self, alert_data: Dict[str, Any]) -> EnrichmentResult:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{settings.TIP_PLATFORM_URL}/enrich",
                    json={"alert_id": alert_data["alert_id"], "iocs": alert_data.get("iocs", [])},
                    headers=internal_headers(),
                    timeout=30.0,
                )
                return EnrichmentResult(**response.json())
        except Exception as e:
            print(f"[ThreatIntelAgent] TIP enrichment failed: {e}")
            return EnrichmentResult(alert_id=alert_data["alert_id"])


class CorrelationAgent:
    def __init__(self):
        self.alert_history: List[Dict[str, Any]] = []

    async def correlate(self, alert_data: Dict[str, Any], enrichment: EnrichmentResult) -> Dict[str, Any]:
        self.alert_history.append(alert_data)
        related = [a for a in self.alert_history if a["asset"] == alert_data["asset"] and a["alert_id"] != alert_data["alert_id"]]
        campaign_indicators = [f"Linked to {enrichment.threat_actor}"] if enrichment.threat_actor else []
        attack_chain = self._detect_attack_chain(related, alert_data)
        return {
            "related_alerts": len(related),
            "campaign_indicators": campaign_indicators,
            "attack_chain_detected": attack_chain is not None,
            "attack_chain": attack_chain,
            "escalation_recommended": len(related) >= 2 or enrichment.risk_score > 70,
        }

    def _detect_attack_chain(self, related: List[Dict], current: Dict) -> Optional[str]:
        if len(related) >= 2:
            return f"Multi-stage attack detected on {current['asset']}: {len(related)} related alerts"
        return None


class DecisionAgent:
    async def decide(self, alert_data: Dict[str, Any], analysis: AIAnalysisResult, enrichment: EnrichmentResult, correlation: Dict[str, Any]) -> Dict[str, Any]:
        asset_criticality = (alert_data.get("asset_context") or {}).get("criticality", "medium")
        risk_score = calculate_risk_score(analysis.severity.value, analysis.confidence, len(enrichment.iocs_enriched), asset_criticality)

        if analysis.is_threat and analysis.confidence > 0.8 and risk_score > 70:
            decision = "auto_contain"
            requires_approval = False
        elif analysis.is_threat and analysis.confidence > 0.6:
            decision = "contain_with_approval"
            requires_approval = True
        elif analysis.confidence < 0.4:
            decision = "false_positive"
            requires_approval = False
        else:
            decision = "analyst_review"
            requires_approval = True

        actions = self._generate_actions(decision, alert_data, enrichment)
        return {
            "decision": decision,
            "risk_score": risk_score,
            "requires_approval": requires_approval,
            "actions": actions,
            "priority": self._calculate_priority(risk_score),
        }

    def _generate_actions(self, decision: str, alert_data: Dict, enrichment: EnrichmentResult) -> List[str]:
        actions = []
        if decision in ["auto_contain", "contain_with_approval"]:
            rule = alert_data["rule_triggered"]
            if "Brute Force" in rule:
                actions.extend(["block_ip", "disable_account", "isolate_host"])
            elif "Beaconing" in rule or "Outbound" in rule:
                actions.extend(["block_domain", "isolate_host", "capture_traffic"])
            elif "Malware" in rule:
                actions.extend(["quarantine_file", "isolate_host", "run_scan"])
            elif "Privilege" in rule:
                actions.extend(["revoke_privileges", "audit_changes", "isolate_host"])
            else:
                actions.extend(["investigate", "collect_evidence"])
        if enrichment.threat_actor:
            actions.append(f"hunt_for_{enrichment.threat_actor.lower().replace(' ', '_')}_ttps")
        return actions

    def _calculate_priority(self, risk_score: int) -> str:
        if risk_score >= 80:
            return "P1-Critical"
        elif risk_score >= 60:
            return "P2-High"
        elif risk_score >= 40:
            return "P3-Medium"
        return "P4-Low"


class ResponseAgent:
    async def execute(self, actions: List[str], alert_id: str, asset: str) -> List[ResponseAction]:
        executed = []
        for action in actions:
            result = await self._execute_action(action, asset)
            executed.append(
                ResponseAction(
                    action_id=f"ACT-{alert_id[:4]}-{uuid.uuid4().hex[:8]}",
                    action_type=action,
                    target=asset,
                    status="completed" if result["success"] else "failed",
                    result=result.get("message", ""),
                    executed_at=datetime.utcnow(),
                    provider=result.get("provider"),
                    raw_response=result,
                )
            )
        return executed

    async def _execute_action(self, action: str, target: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{settings.RESPONSE_ENGINE_URL}/execute",
                    json={"action": action, "target": target},
                    headers=internal_headers(),
                    timeout=30.0,
                )
                return response.json()
        except Exception as e:
            return {"success": False, "message": str(e), "provider": "orchestrator-fallback"}


class InvestigationAgent:
    async def investigate(self, alert_data: Dict, enrichment: EnrichmentResult) -> Dict[str, Any]:
        timeline = self._generate_timeline(alert_data)
        root_cause = self._analyze_root_cause(alert_data, enrichment)
        impact = self._assess_impact(alert_data, enrichment)
        return {
            "timeline": timeline,
            "root_cause": root_cause,
            "impact_assessment": impact,
            "lateral_movement_detected": "lateral" in alert_data.get("rule_triggered", "").lower(),
            "persistence_detected": "persistence" in alert_data.get("rule_triggered", "").lower(),
        }

    def _generate_timeline(self, alert_data: Dict) -> List[Dict[str, Any]]:
        timeline = []
        for i, evidence in enumerate(alert_data.get("evidence", [])[:10]):
            timeline.append(
                {
                    "time": evidence.get("timestamp", timestamp_now()),
                    "event": f"Event {i + 1}: {alert_data['rule_triggered']}",
                    "source": evidence.get("log", "")[:100],
                }
            )
        return timeline

    def _analyze_root_cause(self, alert_data: Dict, enrichment: EnrichmentResult) -> str:
        causes = {
            "Brute Force Attack": "Weak or compromised credentials allowing repeated authentication attempts",
            "Impossible Travel": "Compromised account credentials used from multiple geographic locations",
            "Privilege Escalation": "Vulnerability or misconfiguration allowing unauthorized privilege elevation",
            "Malware Hash Detection": "Malicious file executed on endpoint, likely via phishing or drive-by download",
            "Beaconing Traffic": "Compromised endpoint communicating with C2 server",
            "Suspicious Outbound Traffic": "Potential data exfiltration or unauthorized communication channel",
        }
        cause = causes.get(alert_data["rule_triggered"], "Unknown - requires manual investigation")
        if enrichment.threat_actor:
            cause += f". Activity consistent with {enrichment.threat_actor} TTPs."
        return cause

    def _assess_impact(self, alert_data: Dict, enrichment: EnrichmentResult) -> Dict[str, Any]:
        severity = alert_data.get("severity", "low")
        impact_levels = {
            "critical": {"business": "Severe", "data": "High risk of data breach", "availability": "Service disruption likely"},
            "high": {"business": "Significant", "data": "Sensitive data at risk", "availability": "Degraded performance possible"},
            "medium": {"business": "Moderate", "data": "Limited data exposure", "availability": "Minimal impact"},
            "low": {"business": "Minor", "data": "No sensitive data at risk", "availability": "No impact"},
        }
        return impact_levels.get(severity, impact_levels["low"])


class ReportingAgent:
    async def generate_report(self, incident_id: str, analysis: AIAnalysisResult, enrichment: EnrichmentResult, investigation: Dict[str, Any], session: AsyncSession) -> Dict[str, Any]:
        report_id = generate_report_id()
        executive_summary = self._generate_executive_summary(analysis, enrichment, investigation)
        technical_details = self._generate_technical_details(analysis, enrichment, investigation)
        recommendations = self._generate_recommendations(analysis, enrichment)
        indicators = []
        for item in enrichment.iocs_enriched:
            ioc_obj = getattr(item, "ioc", None)
            indicators.append(getattr(ioc_obj, "value", str(ioc_obj)))

        report_data = {
            "report_id": report_id,
            "incident_id": incident_id,
            "report_type": "full",
            "generated_at": timestamp_now(),
            "executive_summary": executive_summary,
            "technical_details": technical_details,
            "timeline": investigation.get("timeline", []),
            "indicators": indicators,
            "recommendations": recommendations,
            "mitre_techniques": analysis.mitre_mapping,
        }

        report_orm = ReportORM(
            report_id=report_id,
            incident_id=incident_id,
            report_type="full",
            content=f"{executive_summary}\n\n{technical_details}",
            report_metadata={
                "executive_summary": executive_summary,
                "technical_details": technical_details,
                "timeline": investigation.get("timeline", []),
                "indicators": indicators,
                "recommendations": recommendations,
                "mitre_techniques": analysis.mitre_mapping,
            },
        )
        session.add(report_orm)
        await session.commit()
        await indexer.index_report(report_data)
        return report_data

    def _generate_executive_summary(self, analysis: AIAnalysisResult, enrichment: EnrichmentResult, investigation: Dict) -> str:
        parts = [
            f"A {analysis.severity.value} severity security incident was detected.",
            f"AI analysis indicates a {analysis.confidence:.0%} confidence that this is a real threat.",
        ]
        if enrichment.threat_actor:
            parts.append(f"The activity has been linked to {enrichment.threat_actor}.")
        parts.append(f"Root cause: {investigation.get('root_cause', 'Under investigation')}")
        return " ".join(parts)

    def _generate_technical_details(self, analysis: AIAnalysisResult, enrichment: EnrichmentResult, investigation: Dict) -> str:
        parts = [
            f"Attack Type: {analysis.attack_type or 'Unknown'}",
            f"MITRE ATT&CK: {', '.join(analysis.mitre_mapping)}",
            f"Threat Actor: {enrichment.threat_actor or 'Unknown'}",
            f"Risk Score: {enrichment.risk_score}/100",
        ]
        return "\n".join(parts)

    def _generate_recommendations(self, analysis: AIAnalysisResult, enrichment: EnrichmentResult) -> List[str]:
        recs = analysis.recommended_actions.copy()
        if enrichment.threat_actor:
            recs.append(f"Conduct threat hunting for {enrichment.threat_actor} indicators")
        recs.extend([
            "Review and update detection rules",
            "Conduct security awareness training",
            "Perform vulnerability assessment on affected systems",
        ])
        return recs


intake_agent = IntakeAgent()
threat_intel_agent = ThreatIntelAgent()
correlation_agent = CorrelationAgent()
decision_agent = DecisionAgent()
response_agent = ResponseAgent()
investigation_agent = InvestigationAgent()
reporting_agent = ReportingAgent()


@app.on_event("startup")
async def startup():
    if settings.RUN_MIGRATIONS_ON_STARTUP:
        await wait_for_postgres()
        await run_startup_migrations()
    print(f"[ES] URL={settings.ELASTICSEARCH_URL}")
    await indexer.ensure_indices()
    print("AI Orchestrator started")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "ai-orchestrator"}


async def _persist_analysis(session: AsyncSession, analysis: AIAnalysisResult):
    row = AIAnalysisORM(
        alert_id=analysis.alert_id,
        is_threat=analysis.is_threat,
        confidence=analysis.confidence,
        severity=analysis.severity.value if hasattr(analysis.severity, "value") else str(analysis.severity),
        attack_type=analysis.attack_type,
        mitre_mapping=analysis.mitre_mapping,
        explanation=analysis.explanation,
        recommended_actions=analysis.recommended_actions,
        false_positive_reason=analysis.false_positive_reason,
        provider=getattr(analysis, "provider", None),
        model_name=getattr(analysis, "model_name", None),
        prompt_version=getattr(analysis, "prompt_version", None),
        latency_ms=getattr(analysis, "latency_ms", None),
        token_usage=getattr(analysis, "token_usage", None),
        cost_usd=getattr(analysis, "cost_usd", None),
        raw_response=getattr(analysis, "raw_response", None),
    )
    session.add(row)
    await session.commit()
    return row


def _analysis_orm_to_dict(row: AIAnalysisORM) -> Dict[str, Any]:
    return {
        "id": row.id,
        "alert_id": row.alert_id,
        "is_threat": row.is_threat,
        "confidence": row.confidence,
        "severity": row.severity,
        "attack_type": row.attack_type,
        "mitre_mapping": row.mitre_mapping or [],
        "explanation": row.explanation,
        "recommended_actions": row.recommended_actions or [],
        "false_positive_reason": row.false_positive_reason,
        "provider": row.provider,
        "model_name": row.model_name,
        "prompt_version": row.prompt_version,
        "latency_ms": row.latency_ms,
        "token_usage": row.token_usage,
        "cost_usd": row.cost_usd,
        "raw_response": row.raw_response,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def _incident_orm_to_dict(row: IncidentORM) -> Dict[str, Any]:
    return {
        "incident_id": row.incident_id,
        "alert_ids": row.alert_ids or [],
        "incident_type": row.incident_type,
        "severity": row.severity,
        "status": row.status,
        "description": row.description,
        "affected_assets": row.affected_assets or [],
        "iocs": row.iocs or [],
        "timeline": row.timeline or [],
        "containment_actions": row.containment_actions or [],
        "investigation_notes": row.investigation_notes,
        "root_cause": row.root_cause,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "django_ticket_id": row.django_ticket_id,
        "django_ticket_status": row.django_ticket_status,
        "asset_context": row.asset_context,
    }


def _report_orm_to_dict(row: ReportORM) -> Dict[str, Any]:
    meta = row.report_metadata or {}
    return {
        "report_id": row.report_id,
        "incident_id": row.incident_id,
        "report_type": row.report_type,
        "generated_at": row.generated_at.isoformat() if row.generated_at else None,
        "executive_summary": meta.get("executive_summary"),
        "technical_details": meta.get("technical_details"),
        "timeline": meta.get("timeline", []),
        "indicators": meta.get("indicators", []),
        "recommendations": meta.get("recommendations", []),
        "mitre_techniques": meta.get("mitre_techniques", []),
        "content": row.content,
        "metadata": meta,
    }


def _response_action_orm_to_dict(row: ResponseActionORM) -> Dict[str, Any]:
    return {
        "action_id": row.action_id,
        "action_type": row.action_type,
        "target": row.target,
        "status": row.status,
        "result": row.result,
        "requested_at": row.requested_at.isoformat() if row.requested_at else None,
        "executed_at": row.executed_at.isoformat() if row.executed_at else None,
        "approved_by": row.approved_by,
        "requested_by": row.requested_by,
        "provider": row.provider,
        "incident_id": row.incident_id,
        "alert_id": row.alert_id,
    }


@app.post("/analyze-alert")
async def analyze_alert(
    request: AnalyzeAlertRequest,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(get_caller),
    session: AsyncSession = Depends(get_session),
):
    alert_data = request.model_dump()
    processed = await intake_agent.process(alert_data)
    enrichment = await threat_intel_agent.enrich(processed)
    analysis = await perform_ai_analysis(alert_data, enrichment)

    await _persist_analysis(session, analysis)

    correlation = await correlation_agent.correlate(processed, enrichment)
    decision = await decision_agent.decide(alert_data, analysis, enrichment, correlation)

    incident_id = None
    if analysis.is_threat and analysis.confidence > 0.5:
        incident = await create_incident(alert_data, analysis, enrichment, decision, session)
        incident_id = incident["incident_id"]
        if decision["decision"] == "auto_contain":
            background_tasks.add_task(
                execute_response_actions,
                decision["actions"],
                alert_data["alert_id"],
                alert_data["asset"],
                incident_id,
            )
        elif decision["decision"] == "contain_with_approval" and decision["actions"]:
            # Human-approval gate: persist the recommended actions as
            # pending_approval rows instead of executing them. An analyst
            # or admin must call POST /response-actions/{id}/approve (or
            # /reject) before anything actually touches the endpoint.
            await create_pending_response_actions(
                decision["actions"], alert_data["alert_id"], alert_data["asset"], incident_id, session,
            )
        investigation = await investigation_agent.investigate(alert_data, enrichment)
        await reporting_agent.generate_report(incident_id, analysis, enrichment, investigation, session)

    await update_siem_alert(alert_data["alert_id"], analysis, decision)

    return OrchestratorResponse(
        alert_id=alert_data["alert_id"],
        incident_id=incident_id,
        decision=decision["decision"],
        confidence=analysis.confidence,
        actions=decision["actions"],
        requires_approval=decision["requires_approval"],
    )


def _parse_llm_json(content: str) -> Dict[str, Any]:
    """
    LLMs frequently wrap JSON in ```json ... ``` fences even when told not
    to. Strip those before parsing instead of letting json.loads blow up
    and silently falling back to the heuristic analyzer every time.
    """
    text = content.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1] if text.count("```") >= 2 else text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    return json.loads(text)


async def perform_ai_analysis(alert_data: Dict, enrichment: EnrichmentResult) -> AIAnalysisResult:
    model_name = settings.LLM_MODEL
    provider = "heuristic"
    start = datetime.utcnow()

    asset_context = alert_data.get("asset_context") or {}
    asset_criticality = asset_context.get("criticality", "medium")
    rule = alert_data["rule_triggered"]

    analysis_payload = {
        "alert": alert_data,
        "enrichment": enrichment.model_dump(),
        "instructions": "You are a senior SOC analyst. Return JSON with is_threat, confidence, severity, attack_type, mitre_mapping, explanation, recommended_actions, false_positive_reason.",
    }

    llm_result: Optional[Dict[str, Any]] = None
    if settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY:
        try:
            if settings.ANTHROPIC_API_KEY:
                provider = "anthropic"
                async with httpx.AsyncClient(timeout=45.0) as client:
                    res = await client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": settings.ANTHROPIC_API_KEY,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        json={
                            "model": model_name if "claude" in model_name.lower() else "claude-sonnet-4-6",
                            "max_tokens": 1200,
                            "messages": [{"role": "user", "content": json.dumps(analysis_payload)}],
                        },
                    )
                    if res.status_code < 400:
                        content = res.json()["content"][0]["text"]
                        llm_result = _parse_llm_json(content)
            elif settings.OPENAI_API_KEY:
                provider = "openai"
                async with httpx.AsyncClient(timeout=45.0) as client:
                    res = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}", "content-type": "application/json"},
                        json={
                            "model": model_name,
                            "messages": [
                                {"role": "system", "content": "You are a senior SOC analyst. Return JSON only."},
                                {"role": "user", "content": json.dumps(analysis_payload)},
                            ],
                            "temperature": 0.1,
                        },
                    )
                    if res.status_code < 400:
                        content = res.json()["choices"][0]["message"]["content"]
                        llm_result = _parse_llm_json(content)
        except Exception:
            llm_result = None

    if llm_result:
        severity = Severity(llm_result.get("severity", alert_data["severity"]))
        confidence = float(llm_result.get("confidence", 0.8))
        return AIAnalysisResult(
            alert_id=alert_data["alert_id"],
            is_threat=bool(llm_result.get("is_threat", True)),
            confidence=max(0.0, min(0.99, confidence)),
            severity=severity,
            attack_type=llm_result.get("attack_type", rule),
            mitre_mapping=llm_result.get("mitre_mapping", MITRE_MAPPING.get(rule, ["T1001"])),
            explanation=llm_result.get("explanation", ""),
            recommended_actions=llm_result.get("recommended_actions", generate_recommended_actions(rule, enrichment)),
            false_positive_reason=llm_result.get("false_positive_reason"),
            provider=provider,
            model_name=model_name,
            prompt_version="v1",
            latency_ms=int((datetime.utcnow() - start).total_seconds() * 1000),
            raw_response=llm_result,
        )

    base_confidence = 0.7
    if enrichment.risk_score > 70:
        base_confidence += 0.2
    elif enrichment.risk_score > 50:
        base_confidence += 0.1
    malicious_iocs = sum(1 for i in enrichment.iocs_enriched if i.ioc.reputation == "malicious")
    if malicious_iocs > 0:
        base_confidence += 0.15
    if asset_criticality in {"high", "critical"}:
        base_confidence += 0.05

    confidence = min(base_confidence, 0.98)
    is_threat = confidence > 0.5
    severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
    severity = severity_map.get(alert_data["severity"], Severity.MEDIUM)
    mitre = MITRE_MAPPING.get(rule, ["T1001"])
    explanation = generate_ai_explanation(rule, enrichment, confidence, asset_context)
    recommended_actions = generate_recommended_actions(rule, enrichment)

    return AIAnalysisResult(
        alert_id=alert_data["alert_id"],
        is_threat=is_threat,
        confidence=confidence,
        severity=severity,
        attack_type=rule,
        mitre_mapping=mitre,
        explanation=explanation,
        recommended_actions=recommended_actions,
        provider=provider,
        model_name=model_name,
        prompt_version="heuristic-v1",
        latency_ms=int((datetime.utcnow() - start).total_seconds() * 1000),
    )


def generate_ai_explanation(rule: str, enrichment: EnrichmentResult, confidence: float, asset_context: Optional[Dict[str, Any]] = None) -> str:
    parts = [f"AI analysis detected a {rule} pattern with {confidence:.0%} confidence."]
    if enrichment.threat_actor:
        parts.append(f"Threat intelligence links this activity to {enrichment.threat_actor}.")
    if enrichment.iocs_enriched:
        malicious = sum(1 for i in enrichment.iocs_enriched if i.ioc.reputation == "malicious")
        if malicious > 0:
            parts.append(f"{malicious} malicious IOCs identified.")
    if asset_context and asset_context.get("criticality"):
        parts.append(f"Asset criticality is {asset_context.get('criticality')}, increasing business impact.")
    parts.append("Behavioral analysis indicates coordinated attack patterns consistent with known TTPs.")
    return " ".join(parts)


def generate_recommended_actions(rule: str, enrichment: EnrichmentResult) -> List[str]:
    if "Brute Force" in rule:
        actions = ["Block attacking IP", "Disable targeted account", "Force password reset"]
    elif "Beaconing" in rule:
        actions = ["Block C2 communication", "Isolate infected endpoint", "Capture memory dump"]
    elif "Malware" in rule:
        actions = ["Quarantine malicious files", "Isolate affected systems", "Run EDR scan"]
    elif "Privilege" in rule:
        actions = ["Revoke unauthorized privileges", "Audit privilege changes", "Review admin accounts"]
    else:
        actions = ["Investigate further", "Collect forensic evidence", "Monitor for escalation"]
    if enrichment.threat_actor:
        actions.append(f"Hunt for additional {enrichment.threat_actor} indicators")
    return actions


async def create_incident(alert_data: Dict, analysis: AIAnalysisResult, enrichment: EnrichmentResult, decision: Dict, session: AsyncSession) -> Dict[str, Any]:
    incident_id = generate_incident_id()
    incident = Incident(
        incident_id=incident_id,
        alert_ids=[alert_data["alert_id"]],
        incident_type=ATTACK_TYPE_MAPPING.get(alert_data["rule_triggered"], IncidentType.MALWARE),
        severity=analysis.severity,
        status=AlertStatus.CONFIRMED,
        description=analysis.explanation,
        affected_assets=[alert_data["asset"]],
        iocs=[ioc.ioc for ioc in enrichment.iocs_enriched],
        timeline=[{"time": timestamp_now(), "event": f"Alert {alert_data['alert_id']} triggered: {alert_data['rule_triggered']}"}],
        asset_context=alert_data.get("asset_context"),
    )
    incident_dict = incident.model_dump(mode="json")

    incident_orm = IncidentORM(
        incident_id=incident_dict["incident_id"],
        alert_ids=incident_dict["alert_ids"],
        incident_type=incident_dict["incident_type"],
        severity=incident_dict["severity"],
        status=incident_dict["status"],
        description=incident_dict["description"],
        affected_assets=incident_dict["affected_assets"],
        iocs=incident_dict["iocs"],
        timeline=incident_dict["timeline"],
        containment_actions=incident_dict.get("containment_actions", []),
        investigation_notes=incident_dict.get("investigation_notes", ""),
        root_cause=incident_dict.get("root_cause"),
        django_ticket_id=incident_dict.get("django_ticket_id"),
        django_ticket_status=incident_dict.get("django_ticket_status"),
        asset_context=incident_dict.get("asset_context"),
    )
    session.add(incident_orm)
    await record_audit(
        session, actor="ai-orchestrator", action="incident.created", resource_type="incident",
        resource_id=incident_id, details={"severity": incident_dict["severity"], "incident_type": incident_dict["incident_type"]},
        service="ai-orchestrator",
    )
    await session.commit()

    # Django Ticket Management System sync — optional, no-ops safely when
    # DJANGO_BASE_URL isn't configured (same fallback pattern as VT/CrowdStrike).
    ticket = await django_client.create_ticket(incident_dict)
    if ticket:
        incident_orm.django_ticket_id = ticket["id"]
        incident_orm.django_ticket_status = ticket["status"]
        incident_dict["django_ticket_id"] = ticket["id"]
        incident_dict["django_ticket_status"] = ticket["status"]
        await record_audit(
            session, actor="ai-orchestrator", action="incident.ticket_synced", resource_type="incident",
            resource_id=incident_id, details={"django_ticket_id": ticket["id"]}, service="ai-orchestrator",
        )
        await session.commit()

    await indexer.index_incident(incident_dict)
    return incident_dict


async def create_pending_response_actions(
    actions: List[str], alert_id: str, asset: str, incident_id: str, session: AsyncSession,
) -> List[ResponseActionORM]:
    """
    Persist recommended containment actions as pending_approval rows
    instead of executing them. This is the human-approval gate: nothing
    here touches response-engine until an analyst/admin calls
    POST /response-actions/{id}/approve.
    """
    rows = []
    for action in actions:
        row = ResponseActionORM(
            action_id=f"ACT-{alert_id[:4]}-{uuid.uuid4().hex[:8]}",
            action_type=action,
            target=asset,
            status="pending_approval",
            incident_id=incident_id,
            alert_id=alert_id,
            requested_by="ai-orchestrator",
        )
        session.add(row)
        rows.append(row)
    await record_audit(
        session, actor="ai-orchestrator", action="response_action.pending_created", resource_type="incident",
        resource_id=incident_id, details={"actions": actions, "alert_id": alert_id}, service="ai-orchestrator",
    )
    await session.commit()
    return rows


async def execute_response_actions(actions: List[str], alert_id: str, asset: str, incident_id: str):
    results = await response_agent.execute(actions, alert_id, asset)

    async with AsyncSessionLocal() as session:
        stmt = select(IncidentORM).where(IncidentORM.incident_id == incident_id)
        incident = (await session.execute(stmt)).scalar_one_or_none()
        if incident:
            incident.containment_actions = [
                {"action": r.action_type, "status": r.status, "result": r.result, "provider": r.provider}
                for r in results
            ]
            incident.status = AlertStatus.CONTAINED.value

        for r in results:
            session.add(
                ResponseActionORM(
                    action_id=r.action_id,
                    action_type=r.action_type,
                    target=r.target,
                    status=r.status,
                    result=r.result,
                    executed_at=r.executed_at,
                    provider=r.provider,
                    raw_response=r.raw_response,
                    incident_id=incident_id,
                    alert_id=alert_id,
                    requested_by=None,
                    approved_by=None,
                )
            )
        await session.commit()

        if incident:
            await indexer.index_incident(_incident_orm_to_dict(incident))


async def update_siem_alert(alert_id: str, analysis: AIAnalysisResult, decision: Dict):
    try:
        status = AlertStatus.CONFIRMED if analysis.is_threat else AlertStatus.FALSE_POSITIVE
        async with httpx.AsyncClient() as client:
            await client.put(
                f"{settings.SIEM_ENGINE_URL}/alerts/{alert_id}/status",
                params={"status": status.value},
                headers=internal_headers(),
                timeout=10.0,
            )
    except Exception as e:
        print(f"Failed to update SIEM alert: {e}")


@app.get("/incidents")
async def get_incidents(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(IncidentORM).order_by(IncidentORM.created_at.desc()))
    return [_incident_orm_to_dict(i) for i in result.scalars().all()]


@app.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    incident = await session.get(IncidentORM, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _incident_orm_to_dict(incident)


@app.post("/incidents/{incident_id}/sync-ticket")
async def sync_incident_ticket(
    incident_id: str,
    current_user: CurrentUser = Depends(require_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    """Manual retry for Django ticket sync (e.g. Django was down when the incident was first created)."""
    incident = await session.get(IncidentORM, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if not django_client.configured:
        raise HTTPException(status_code=400, detail="DJANGO_BASE_URL is not configured on this deployment")

    incident_dict = _incident_orm_to_dict(incident)
    if incident.django_ticket_id:
        result = await django_client.update_ticket_status(incident.django_ticket_id, incident.status)
    else:
        result = await django_client.create_ticket(incident_dict)

    if not result:
        raise HTTPException(status_code=502, detail="Django ticket sync failed — check DJANGO_BASE_URL/DJANGO_API_TOKEN and service logs")

    incident.django_ticket_id = result["id"]
    incident.django_ticket_status = result["status"]
    await record_audit(
        session, actor=current_user.username, actor_role=current_user.role, action="incident.ticket_synced",
        resource_type="incident", resource_id=incident_id, details={"django_ticket_id": result["id"]},
        service="ai-orchestrator",
    )
    await session.commit()
    return {"incident_id": incident_id, "django_ticket_id": result["id"], "django_ticket_status": result["status"]}


@app.post("/webhooks/django-ticket-update")
async def django_ticket_webhook(
    payload: Dict[str, Any],
    x_webhook_secret: Optional[str] = Header(default=None),
    session: AsyncSession = Depends(get_session),
):
    """
    Receives status-change notifications from the Django Ticket Management
    System (ticket closed/resolved/reopened, etc) and reflects them back
    onto the matching incident. Expects {"ticket_id": ..., "status": ...}.
    """
    if x_webhook_secret != settings.DJANGO_WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="Invalid webhook secret")

    ticket_id = str(payload.get("ticket_id", ""))
    new_status = payload.get("status")
    if not ticket_id or not new_status:
        raise HTTPException(status_code=400, detail="ticket_id and status are required")

    incident_repo = IncidentRepository(session)
    incident = await incident_repo.get_by_django_ticket(ticket_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"No incident found for django_ticket_id={ticket_id}")

    incident.django_ticket_status = new_status
    if new_status in {"closed", "resolved"}:
        incident.status = AlertStatus.RESOLVED.value
        incident.resolved_at = datetime.now(timezone.utc)

    await record_audit(
        session, actor="django-webhook", action="incident.ticket_webhook_update", resource_type="incident",
        resource_id=incident.incident_id, details={"django_ticket_id": ticket_id, "new_status": new_status},
        service="ai-orchestrator",
    )
    await session.commit()
    return {"incident_id": incident.incident_id, "status": incident.status, "django_ticket_status": new_status}


@app.get("/response-actions/pending")
async def list_pending_response_actions(
    current_user: CurrentUser = Depends(require_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    repo = ResponseActionRepository(session)
    pending = await repo.list_pending()
    return [_response_action_orm_to_dict(r) for r in pending]


@app.get("/response-actions")
async def list_response_actions(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    repo = ResponseActionRepository(session)
    rows = await repo.list_recent()
    return [_response_action_orm_to_dict(r) for r in rows]


@app.post("/response-actions/{action_id}/approve")
async def approve_response_action(
    action_id: str,
    current_user: CurrentUser = Depends(require_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    action = await session.get(ResponseActionORM, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Response action not found")
    if action.status != "pending_approval":
        raise HTTPException(status_code=409, detail=f"Action is '{action.status}', not pending approval")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.RESPONSE_ENGINE_URL}/execute",
                json={"action": action.action_type, "target": action.target},
                headers=internal_headers(),
                timeout=30.0,
            )
            result = response.json()
    except Exception as e:
        result = {"success": False, "message": str(e), "provider": "orchestrator-fallback"}

    action.status = "completed" if result.get("success") else "failed"
    action.result = result.get("message", "")
    action.provider = (result.get("details") or {}).get("provider")
    action.raw_response = result
    action.approved_by = current_user.username
    action.executed_at = datetime.now(timezone.utc)

    if action.incident_id:
        incident = await session.get(IncidentORM, action.incident_id)
        if incident:
            incident.containment_actions = (incident.containment_actions or []) + [
                {"action": action.action_type, "status": action.status, "result": action.result, "provider": action.provider}
            ]
            if action.status == "completed":
                incident.status = AlertStatus.CONTAINED.value

    await record_audit(
        session, actor=current_user.username, actor_role=current_user.role, action="response_action.approve",
        resource_type="response_action", resource_id=action_id,
        details={"action_type": action.action_type, "target": action.target, "result": action.status},
        service="ai-orchestrator",
    )
    await session.commit()
    return _response_action_orm_to_dict(action)


@app.post("/response-actions/{action_id}/reject")
async def reject_response_action(
    action_id: str,
    current_user: CurrentUser = Depends(require_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    action = await session.get(ResponseActionORM, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Response action not found")
    if action.status != "pending_approval":
        raise HTTPException(status_code=409, detail=f"Action is '{action.status}', not pending approval")

    action.status = "rejected"
    action.approved_by = current_user.username
    action.result = "Rejected by analyst"
    action.executed_at = datetime.now(timezone.utc)

    await record_audit(
        session, actor=current_user.username, actor_role=current_user.role, action="response_action.reject",
        resource_type="response_action", resource_id=action_id,
        details={"action_type": action.action_type, "target": action.target}, service="ai-orchestrator",
    )
    await session.commit()
    return _response_action_orm_to_dict(action)


@app.get("/audit-log")
async def get_audit_log(
    resource_type: Optional[str] = None,
    limit: int = Query(default=200, le=1000),
    current_user: CurrentUser = Depends(require_roles("admin")),
    session: AsyncSession = Depends(get_session),
):
    repo = AuditLogRepository(session)
    rows = await repo.recent(limit=limit, resource_type=resource_type)
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "actor": r.actor,
            "actor_role": r.actor_role,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "success": r.success,
            "details": r.details,
            "service": r.service,
        }
        for r in rows
    ]


@app.get("/analysis/{alert_id}")
async def get_analysis(
    alert_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(AIAnalysisORM).where(AIAnalysisORM.alert_id == alert_id).order_by(AIAnalysisORM.created_at.desc())
    result = await session.execute(stmt)
    analysis = result.scalars().first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return _analysis_orm_to_dict(analysis)


@app.get("/reports")
async def get_reports(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(ReportORM).order_by(ReportORM.generated_at.desc()))
    return [_report_orm_to_dict(r) for r in result.scalars().all()]


@app.get("/reports/{report_id}")
async def get_report(
    report_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    report = await session.get(ReportORM, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return _report_orm_to_dict(report)


@app.get("/search/incidents")
async def search_incidents(q: str = Query(..., min_length=1), current_user: CurrentUser = Depends(get_current_user)):
    query = {"query": {"multi_match": {"query": q, "fields": ["description^2", "severity", "status", "affected_assets", "root_cause"]}}}
    return await indexer.search(settings.ELASTICSEARCH_INCIDENT_INDEX, query)


@app.get("/search/reports")
async def search_reports(q: str = Query(..., min_length=1), current_user: CurrentUser = Depends(get_current_user)):
    query = {"query": {"multi_match": {"query": q, "fields": ["executive_summary^2", "technical_details", "recommendations", "incident_id"]}}}
    return await indexer.search(settings.ELASTICSEARCH_REPORT_INDEX, query)


@app.get("/orchestrator/status")
async def get_orchestrator_status(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    alerts_processed = await session.scalar(select(func.count()).select_from(AIAnalysisORM))
    incidents_created = await session.scalar(select(func.count()).select_from(IncidentORM))
    reports_generated = await session.scalar(select(func.count()).select_from(ReportORM))
    return {
        "status": "operational",
        "agents": {
            "intake": "active",
            "threat_intel": "active",
            "correlation": "active",
            "decision": "active",
            "response": "active",
            "investigation": "active",
            "reporting": "active",
        },
        "metrics": {
            "alerts_processed": int(alerts_processed or 0),
            "incidents_created": int(incidents_created or 0),
            "reports_generated": int(reports_generated or 0),
        },
        "timestamp": timestamp_now(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)