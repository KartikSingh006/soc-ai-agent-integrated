"""
External integrations: Elasticsearch, VirusTotal, CrowdStrike Falcon.
All integrations are optional and fall back safely when credentials are missing.
"""
from __future__ import annotations

import base64
from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from .config import Settings
from .models import Alert, AssetRecord, AIAnalysisResult, IOC, IOCType, Incident, Report, Severity, ThreatIntel
from .utils import hash_ioc, timestamp_now


def _encode_scalar(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    try:
        return value.value  # pydantic/enums/customs
    except Exception:
        return value


def _safe_json(value: Any) -> Any:
    if value is None:
        return {}
    if hasattr(value, "model_dump"):
        value = value.model_dump()
    elif hasattr(value, "dict"):
        value = value.dict()

    if isinstance(value, dict):
        return {str(k): _safe_json(v) if isinstance(v, (dict, list, tuple, set)) else _encode_scalar(v)
                for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [(_safe_json(v) if isinstance(v, (dict, list, tuple, set)) else _encode_scalar(v)) for v in value]
    return _encode_scalar(value)


class ElasticsearchIndexer:
    """Tiny async Elasticsearch helper used by SIEM and the orchestrator."""

    def __init__(self, settings: Settings):
        self.settings = settings

    async def ensure_indices(self) -> None:
        mappings: Dict[str, Dict[str, Any]] = {
            self.settings.ELASTICSEARCH_ALERT_INDEX: {
                "mappings": {"properties": {
                    "alert_id": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "rule_triggered": {"type": "text"},
                    "asset": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "description": {"type": "text"},
                    "evidence": {"type": "object", "enabled": False},
                    "iocs": {"type": "object", "enabled": False},
                    "mitre_techniques": {"type": "keyword"},
                    "ai_analysis": {"type": "object", "enabled": False},
                }}
            },
            self.settings.ELASTICSEARCH_INCIDENT_INDEX: {
                "mappings": {"properties": {
                    "incident_id": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "incident_type": {"type": "keyword"},
                    "description": {"type": "text"},
                    "affected_assets": {"type": "keyword"},
                    "alert_ids": {"type": "keyword"},
                    "root_cause": {"type": "text"},
                    "created_at": {"type": "date"},
                    "django_ticket_id": {"type": "keyword"},
                    "django_ticket_status": {"type": "keyword"},
                }}
            },
            self.settings.ELASTICSEARCH_REPORT_INDEX: {
                "mappings": {"properties": {
                    "report_id": {"type": "keyword"},
                    "incident_id": {"type": "keyword"},
                    "report_type": {"type": "keyword"},
                    "executive_summary": {"type": "text"},
                    "technical_details": {"type": "text"},
                    "generated_at": {"type": "date"},
                }}
            },
            self.settings.ELASTICSEARCH_ASSET_INDEX: {
                "mappings": {"properties": {
                    "asset_id": {"type": "keyword"},
                    "hostname": {"type": "keyword"},
                    "asset_name": {"type": "text"},
                    "owner": {"type": "keyword"},
                    "business_unit": {"type": "keyword"},
                    "criticality": {"type": "keyword"},
                    "environment": {"type": "keyword"},
                    "location": {"type": "keyword"},
                    "platform": {"type": "keyword"},
                    "last_seen": {"type": "date"},
                }}
            },
            self.settings.ELASTICSEARCH_IOC_INDEX: {
                "mappings": {"properties": {
                    "ioc_hash": {"type": "keyword"},
                    "ioc_type": {"type": "keyword"},
                    "value": {"type": "keyword"},
                    "reputation": {"type": "keyword"},
                    "actor": {"type": "keyword"},
                    "country": {"type": "keyword"},
                    "malware_family": {"type": "keyword"},
                    "confidence": {"type": "integer"},
                    "threat_level": {"type": "keyword"},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                }}
            },
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            for index_name, body in mappings.items():
                try:
                    exists = await client.get(f"{self.settings.ELASTICSEARCH_URL}/{index_name}")
                    print(f"[ES INIT] index={index_name} exists_status={exists.status_code}")

                    if exists.status_code == 404:
                        res = await client.put(f"{self.settings.ELASTICSEARCH_URL}/{index_name}", json=body)
                        print(f"[ES CREATE] index={index_name} status={res.status_code}")
                        if res.status_code >= 400:
                            print(f"[ES CREATE FAILED] index={index_name} body={res.text[:500]}")
                except Exception as e:
                    print(f"[ES INIT ERROR] index={index_name} error={e}")

    async def index_document(self, index_name: str, doc_id: str, document: Dict[str, Any]) -> None:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.put(
                    f"{self.settings.ELASTICSEARCH_URL}/{index_name}/_doc/{doc_id}",
                    json=document,
                )
                print(f"[ES INDEX] index={index_name} doc={doc_id} status={res.status_code}")
                if res.status_code >= 400:
                    print(f"[ES INDEX FAILED] index={index_name} doc={doc_id} body={res.text[:500]}")
        except Exception as e:
            print(f"[ES INDEX ERROR] index={index_name} doc={doc_id} error={e}")

    async def search(self, index_name: str, query: Dict[str, Any]) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(f"{self.settings.ELASTICSEARCH_URL}/{index_name}/_search", json=query)
                return res.json()
        except Exception as exc:
            return {"hits": {"hits": []}, "error": str(exc)}

    async def index_alert(self, alert: Alert, analysis: Optional[AIAnalysisResult] = None) -> None:
        doc = _safe_json(alert)
        if analysis is not None:
            doc["ai_analysis"] = _safe_json(analysis)
        await self.index_document(self.settings.ELASTICSEARCH_ALERT_INDEX, alert.alert_id, doc)

    async def index_incident(self, incident: Incident) -> None:
        await self.index_document(self.settings.ELASTICSEARCH_INCIDENT_INDEX, incident.incident_id, _safe_json(incident))

    async def index_report(self, report: Report | Dict[str, Any]) -> None:
        doc = _safe_json(report)
        report_id = doc.get("report_id") or doc.get("id") or "unknown"
        await self.index_document(self.settings.ELASTICSEARCH_REPORT_INDEX, report_id, doc)

    async def index_asset(self, asset: AssetRecord) -> None:
        await self.index_document(self.settings.ELASTICSEARCH_ASSET_INDEX, asset.asset_id, _safe_json(asset))

    async def index_ioc(self, ioc: Dict[str, Any]) -> None:
        ioc_hash = ioc.get("ioc_hash") or hash_ioc(str(ioc.get("value", "")))
        await self.index_document(self.settings.ELASTICSEARCH_IOC_INDEX, ioc_hash, ioc)


class VirusTotalClient:
    """VirusTotal v3 IOC enrichment."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def _url_id(self, url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async def enrich_ioc(self, ioc: IOC) -> ThreatIntel:
        if not self.settings.VIRUSTOTAL_API_KEY:
            return ThreatIntel(ioc=ioc, confidence=0, threat_level=Severity.LOW, source="fallback")

        value = ioc.value.strip()
        if ioc.ioc_type == IOCType.IP:
            endpoint = f"/ip_addresses/{quote(value)}"
        elif ioc.ioc_type == IOCType.DOMAIN:
            endpoint = f"/domains/{quote(value)}"
        elif ioc.ioc_type == IOCType.HASH:
            endpoint = f"/files/{quote(value)}"
        elif ioc.ioc_type == IOCType.URL:
            endpoint = f"/urls/{quote(self._url_id(value))}"
        else:
            return ThreatIntel(ioc=ioc, confidence=0, threat_level=Severity.LOW, source="fallback")

        headers = {"x-apikey": self.settings.VIRUSTOTAL_API_KEY, "accept": "application/json"}
        async with httpx.AsyncClient(timeout=20.0) as client:
            try:
                res = await client.get(f"{self.settings.VIRUSTOTAL_BASE_URL}{endpoint}", headers=headers)
                if res.status_code != 200:
                    return ThreatIntel(ioc=ioc, confidence=0, threat_level=Severity.LOW, source="virustotal")
                payload = res.json().get("data", {}).get("attributes", {})
            except Exception:
                return ThreatIntel(ioc=ioc, confidence=0, threat_level=Severity.LOW, source="virustotal")

        stats = payload.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))

        if malicious == 0 and suspicious == 0:
            confidence = 90
        else:
            confidence = min(100, malicious * 15 + suspicious * 8 + 20)

        if malicious >= 3:
            threat_level = Severity.CRITICAL
            reputation = "malicious"
        elif malicious > 0 or suspicious > 0:
            threat_level = Severity.HIGH if malicious > 1 else Severity.MEDIUM
            reputation = "suspicious"
        else:
            threat_level = Severity.LOW
            reputation = "clean"

        print(f"[VT] IOC={ioc.value} malicious={malicious} suspicious={suspicious} harmless={harmless} confidence={confidence}")

        actor = None
        malware_family = None
        if isinstance(payload.get("popular_threat_classification"), dict):
            ptc = payload["popular_threat_classification"]
            actor = ptc.get("suggested_threat_label") or ptc.get("popular_threat_name")
            malware_family = ptc.get("suggested_threat_label")

        return ThreatIntel(
            ioc=IOC(
                ioc_type=ioc.ioc_type,
                value=ioc.value,
                reputation=reputation,
                confidence=confidence,
                source="virustotal",
            ),
            country=payload.get("country"),
            actor=actor,
            campaign=payload.get("crowdsourced_yara_results", [{}])[0].get("source") if payload.get("crowdsourced_yara_results") else None,
            malware_family=malware_family,
            confidence=confidence,
            threat_level=threat_level,
            ttps=[],
            source="virustotal",
        )


class CrowdStrikeConnector:
    """
    CrowdStrike Falcon connector. If credentials are not configured,
    the connector falls back to a safe simulated response.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self._token: Optional[str] = None

    async def _get_token(self) -> Optional[str]:
        if not (self.settings.CROWDSTRIKE_CLIENT_ID and self.settings.CROWDSTRIKE_CLIENT_SECRET):
            return None
        if self._token:
            return self._token

        async with httpx.AsyncClient(timeout=20.0) as client:
            res = await client.post(
                f"{self.settings.CROWDSTRIKE_BASE_URL}/oauth2/token",
                data={
                    "client_id": self.settings.CROWDSTRIKE_CLIENT_ID,
                    "client_secret": self.settings.CROWDSTRIKE_CLIENT_SECRET,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            res.raise_for_status()
            token = res.json().get("access_token")
            self._token = token
            return token

    async def _headers(self) -> Dict[str, str]:
        token = await self._get_token()
        if not token:
            return {}
        return {"Authorization": f"Bearer {token}", "accept": "application/json"}

    async def contain_host(self, host_aid: str, audit_message: str = "SOC containment") -> Dict[str, Any]:
        if not (self.settings.CROWDSTRIKE_CLIENT_ID and self.settings.CROWDSTRIKE_CLIENT_SECRET):
            return {"success": True, "provider": "simulated", "message": f"Contained host {host_aid} (simulated)"}

        headers = await self._headers()
        async with httpx.AsyncClient(timeout=20.0) as client:
            res = await client.post(
                f"{self.settings.CROWDSTRIKE_BASE_URL}/devices/entities/devices-actions/v2",
                params={"action_name": "contain"},
                json={"ids": [host_aid]},
                headers=headers,
            )
            if res.status_code >= 400:
                return {"success": False, "provider": "crowdstrike", "message": res.text}
            return {"success": True, "provider": "crowdstrike", "message": f"Containment requested for {host_aid}", "raw": res.json()}

    async def lift_containment(self, host_aid: str) -> Dict[str, Any]:
        if not (self.settings.CROWDSTRIKE_CLIENT_ID and self.settings.CROWDSTRIKE_CLIENT_SECRET):
            return {"success": True, "provider": "simulated", "message": f"Released host {host_aid} (simulated)"}

        headers = await self._headers()
        async with httpx.AsyncClient(timeout=20.0) as client:
            res = await client.post(
                f"{self.settings.CROWDSTRIKE_BASE_URL}/devices/entities/devices-actions/v2",
                params={"action_name": "lift_containment"},
                json={"ids": [host_aid]},
                headers=headers,
            )
            if res.status_code >= 400:
                return {"success": False, "provider": "crowdstrike", "message": res.text}
            return {"success": True, "provider": "crowdstrike", "message": f"Lift containment requested for {host_aid}", "raw": res.json()}

    async def get_host_details(self, host_aid: str) -> Dict[str, Any]:
        headers = await self._headers()
        if not headers:
            return {"success": False, "provider": "simulated", "message": "CrowdStrike credentials not configured"}
        async with httpx.AsyncClient(timeout=20.0) as client:
            res = await client.get(
                f"{self.settings.CROWDSTRIKE_BASE_URL}/devices/entities/devices/v1",
                params={"ids": host_aid},
                headers=headers,
            )
            if res.status_code >= 400:
                return {"success": False, "provider": "crowdstrike", "message": res.text}
            return {"success": True, "provider": "crowdstrike", "data": res.json()}

    async def resolve_aid_by_hostname(self, hostname: str) -> Optional[str]:
        """
        Falcon containment actions operate on the device's agent ID (AID),
        not its hostname. Returns None (rather than raising) when
        credentials aren't configured or no matching device is found, so
        callers can fall back to simulated mode the same way the rest of
        this connector does.
        """
        if not (self.settings.CROWDSTRIKE_CLIENT_ID and self.settings.CROWDSTRIKE_CLIENT_SECRET):
            return None
        headers = await self._headers()
        async with httpx.AsyncClient(timeout=20.0) as client:
            res = await client.get(
                f"{self.settings.CROWDSTRIKE_BASE_URL}/devices/queries/devices/v1",
                params={"filter": f"hostname:'{hostname}'"},
                headers=headers,
            )
            if res.status_code >= 400:
                return None
            resource_ids = res.json().get("resources", [])
            return resource_ids[0] if resource_ids else None

    async def contain_host_by_hostname(self, hostname: str, audit_message: str = "SOC containment") -> Dict[str, Any]:
        """Resolve hostname -> AID, then contain. Falls back to simulated if unresolved/unconfigured."""
        if not (self.settings.CROWDSTRIKE_CLIENT_ID and self.settings.CROWDSTRIKE_CLIENT_SECRET):
            return {"success": True, "provider": "simulated", "message": f"Contained host {hostname} (simulated)"}
        aid = await self.resolve_aid_by_hostname(hostname)
        if not aid:
            return {
                "success": False,
                "provider": "crowdstrike",
                "message": f"No CrowdStrike-managed device found for hostname '{hostname}'",
            }
        return await self.contain_host(aid, audit_message)

    async def lift_containment_by_hostname(self, hostname: str) -> Dict[str, Any]:
        if not (self.settings.CROWDSTRIKE_CLIENT_ID and self.settings.CROWDSTRIKE_CLIENT_SECRET):
            return {"success": True, "provider": "simulated", "message": f"Released host {hostname} (simulated)"}
        aid = await self.resolve_aid_by_hostname(hostname)
        if not aid:
            return {
                "success": False,
                "provider": "crowdstrike",
                "message": f"No CrowdStrike-managed device found for hostname '{hostname}'",
            }
        return await self.lift_containment(aid)


class DjangoTicketClient:
    """
    Syncs incidents into an external Django Ticket Management System.
    Optional — when DJANGO_BASE_URL is unset, every method returns None
    (or a no-op acknowledgement) so callers can proceed without it, the
    same fallback pattern used by VirusTotalClient/CrowdStrikeConnector.

    Expected (configurable) Django-side contract — adjust DJANGO_TICKET_ENDPOINT
    if your ticket app uses different field names:
        POST {DJANGO_BASE_URL}{DJANGO_TICKET_ENDPOINT}
            {"title", "description", "severity", "source", "source_id", "metadata"}
            -> {"id": "...", "status": "..."}
        PATCH {DJANGO_BASE_URL}{DJANGO_TICKET_ENDPOINT}{ticket_id}/
            {"status": "..."} -> {"id": "...", "status": "..."}
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def configured(self) -> bool:
        return bool(self.settings.DJANGO_BASE_URL)

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.settings.DJANGO_API_TOKEN:
            headers["Authorization"] = f"Token {self.settings.DJANGO_API_TOKEN}"
        return headers

    async def create_ticket(self, incident: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.configured:
            return None
        payload = {
            "title": f"[{incident.get('severity', 'medium').upper()}] {incident.get('incident_type', 'incident')} - {incident.get('incident_id')}",
            "description": incident.get("description", ""),
            "severity": incident.get("severity"),
            "source": "soc-ai-agent",
            "source_id": incident.get("incident_id"),
            "metadata": {
                "affected_assets": incident.get("affected_assets", []),
                "alert_ids": incident.get("alert_ids", []),
                "mitre_techniques": incident.get("iocs", []),
            },
        }
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                res = await client.post(
                    f"{self.settings.DJANGO_BASE_URL}{self.settings.DJANGO_TICKET_ENDPOINT}",
                    json=payload,
                    headers=self._headers(),
                )
                if res.status_code >= 400:
                    print(f"[DJANGO] create_ticket failed status={res.status_code} body={res.text[:300]}")
                    return None
                data = res.json()
                return {"id": str(data.get("id")), "status": data.get("status", "open")}
        except Exception as e:
            print(f"[DJANGO] create_ticket error: {e}")
            return None

    async def update_ticket_status(self, ticket_id: str, status: str) -> Optional[Dict[str, Any]]:
        if not self.configured:
            return None
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                res = await client.patch(
                    f"{self.settings.DJANGO_BASE_URL}{self.settings.DJANGO_TICKET_ENDPOINT}{ticket_id}/",
                    json={"status": status},
                    headers=self._headers(),
                )
                if res.status_code >= 400:
                    print(f"[DJANGO] update_ticket_status failed status={res.status_code} body={res.text[:300]}")
                    return None
                data = res.json()
                return {"id": str(data.get("id", ticket_id)), "status": data.get("status", status)}
        except Exception as e:
            print(f"[DJANGO] update_ticket_status error: {e}")
            return None
