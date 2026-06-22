"""
TIP Platform - Threat Intelligence enrichment and IOC analysis.
Integrates with VirusTotal, plus local/heuristic fallback.

IOC intel is persisted in Postgres (ioc_intel table) via IOCRepository —
this used to be an in-memory dict that lost everything on restart.
"""
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models import IOC, IOCType, ThreatIntel, Severity
from shared.utils import timestamp_now
from shared.config import settings
from shared.integrations import VirusTotalClient
from shared.db import get_session, wait_for_postgres, run_startup_migrations
from shared.db_models import IOCIntelORM
from shared.repository import IOCRepository
from shared.auth import CurrentUser, get_current_user, require_caller_roles

app = FastAPI(title="TIP Platform", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

vt_client = VirusTotalClient(settings)

THREAT_ACTORS = {
    "APT29": {"aliases": ["Cozy Bear", "The Dukes"], "origin": "Russia", "motivation": "Espionage", "malware": ["Cobalt Strike", "WellMess", "WellMail"], "ttps": ["T1078", "T1059", "T1021"]},
    "Lazarus Group": {"aliases": ["Hidden Cobra", "ZINC"], "origin": "North Korea", "motivation": "Financial gain, Espionage", "malware": ["WannaCry", "AppleJeus", "DTrack"], "ttps": ["T1071", "T1567", "T1041"]},
    "FIN7": {"aliases": ["Carbanak", "Anunak"], "origin": "Russia", "motivation": "Financial gain", "malware": ["Carbanak", "JSSLoader", "POWERPLANT"], "ttps": ["T1566", "T1053", "T1071"]},
    "APT28": {"aliases": ["Fancy Bear", "Sofacy"], "origin": "Russia", "motivation": "Espionage", "malware": ["X-Agent", "Komplex", "DealersChoice"], "ttps": ["T1059", "T1071", "T1566"]},
}

KNOWN_MALICIOUS_IOCS = {
    "185.220.101.4": {"type": "ip", "reputation": "malicious", "actor": "APT29", "country": "Russia", "confidence": 92, "malware": ["Cobalt Strike"], "threat_level": "critical"},
    "192.168.100.55": {"type": "ip", "reputation": "suspicious", "actor": None, "country": "Unknown", "confidence": 65, "malware": [], "threat_level": "medium"},
    "evil-c2.example.com": {"type": "domain", "reputation": "malicious", "actor": "Lazarus Group", "country": "North Korea", "confidence": 88, "malware": ["AppleJeus"], "threat_level": "high"},
    "a3b8c9d2e1f0": {"type": "hash", "reputation": "malicious", "actor": "FIN7", "country": "Russia", "confidence": 95, "malware": ["Carbanak"], "threat_level": "critical"},
}


class EnrichRequest(BaseModel):
    alert_id: str
    iocs: List[Dict[str, Any]]


class EnrichResponse(BaseModel):
    alert_id: str
    enriched_iocs: List[ThreatIntel]
    threat_actor: Optional[str]
    campaign: Optional[str]
    risk_score: int
    summary: str


class IOCQuery(BaseModel):
    ioc_type: str
    value: str


@app.on_event("startup")
async def startup():
    if settings.RUN_MIGRATIONS_ON_STARTUP:
        await wait_for_postgres()
        await run_startup_migrations()
    print("TIP Platform started with", len(KNOWN_MALICIOUS_IOCS), "known IOCs (seed) + Postgres-backed cache")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "tip-platform"}


def _row_to_threat_intel(row: IOCIntelORM) -> ThreatIntel:
    return ThreatIntel(
        ioc=IOC(
            ioc_type=IOCType(row.ioc_type),
            value=row.value,
            reputation=row.reputation,
            confidence=row.confidence,
            source=row.ioc_source or "cache",
            first_seen=row.first_seen,
            last_seen=row.last_seen,
            related_threats=row.related_threats or [],
        ),
        country=row.country,
        actor=row.actor,
        campaign=row.campaign,
        malware_family=row.malware_family,
        confidence=row.confidence,
        threat_level=Severity(row.threat_level),
        ttps=row.ttps or [],
        related_iocs=row.related_iocs or [],
        source=row.ioc_source or "cache",
    )


@app.post("/enrich", response_model=EnrichResponse)
async def enrich_alert(
    request: EnrichRequest,
    current_user: CurrentUser = Depends(require_caller_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    enriched_iocs = []
    actors = set()
    campaigns = set()
    max_risk = 0

    for ioc_data in request.iocs:
        ioc = IOC(
            ioc_type=IOCType(ioc_data.get("type", "ip")),
            value=ioc_data.get("value", ""),
        )
        intel = await lookup_ioc(ioc, session)
        enriched_iocs.append(intel)

        if intel.actor:
            actors.add(intel.actor)
        if intel.campaign:
            campaigns.add(intel.campaign)

        risk_map = {"low": 25, "medium": 50, "high": 75, "critical": 100}
        max_risk = max(max_risk, risk_map.get(intel.threat_level.value, 0))

    summary = generate_threat_summary(enriched_iocs, actors, campaigns)

    return EnrichResponse(
        alert_id=request.alert_id,
        enriched_iocs=enriched_iocs,
        threat_actor=list(actors)[0] if actors else None,
        campaign=list(campaigns)[0] if campaigns else None,
        risk_score=max_risk,
        summary=summary,
    )


async def lookup_ioc(ioc: IOC, session: AsyncSession) -> ThreatIntel:
    repo = IOCRepository(session)
    cached = await repo.find(ioc.ioc_type.value, ioc.value)
    if cached:
        return _row_to_threat_intel(cached)

    # 1) Try VirusTotal first when configured.
    vt_intel = await vt_client.enrich_ioc(ioc)
    if vt_intel.source == "virustotal":
        await _persist_intel(repo, ioc, vt_intel)
        return vt_intel

    # 2) Local known-intel fallback.
    known = KNOWN_MALICIOUS_IOCS.get(ioc.value)
    if known:
        intel = ThreatIntel(
            ioc=ioc,
            country=known.get("country"),
            actor=known.get("actor"),
            malware_family=known.get("malware", [None])[0] if known.get("malware") else None,
            confidence=known.get("confidence", 0),
            threat_level=Severity(known.get("threat_level", "low")),
            ttps=THREAT_ACTORS.get(known.get("actor"), {}).get("ttps", []),
            source="local",
        )
    else:
        intel = await simulate_external_lookup(ioc)

    await _persist_intel(repo, ioc, intel)
    return intel


async def _persist_intel(repo: IOCRepository, ioc: IOC, intel: ThreatIntel) -> None:
    await repo.upsert(
        ioc.ioc_type.value,
        ioc.value,
        reputation=intel.ioc.reputation if intel.ioc else "unknown",
        confidence=intel.confidence,
        ioc_source=intel.source,
        related_threats=intel.ioc.related_threats if intel.ioc else [],
        country=intel.country,
        actor=intel.actor,
        campaign=intel.campaign,
        malware_family=intel.malware_family,
        threat_level=intel.threat_level.value if hasattr(intel.threat_level, "value") else str(intel.threat_level),
        ttps=intel.ttps,
        related_iocs=intel.related_iocs,
    )
    await repo.session.commit()


async def simulate_external_lookup(ioc: IOC) -> ThreatIntel:
    reputation = "unknown"
    confidence = 0
    country = "Unknown"

    if ioc.ioc_type == IOCType.IP:
        if ioc.value.startswith(("185.", "194.", "91.")):
            reputation = "suspicious"
            confidence = 45
            country = "Unknown"
        else:
            reputation = "clean"
            confidence = 90
            country = "United States"

    return ThreatIntel(
        ioc=IOC(
            ioc_type=ioc.ioc_type,
            value=ioc.value,
            reputation=reputation,
            confidence=confidence,
            source="heuristic",
        ),
        country=country,
        confidence=confidence,
        threat_level=Severity.LOW if reputation == "clean" else Severity.MEDIUM,
        source="heuristic",
    )


def generate_threat_summary(iocs: List[ThreatIntel], actors: set, campaigns: set) -> str:
    malicious_count = sum(1 for i in iocs if i.ioc.reputation in ["malicious", "suspicious"])
    total = len(iocs)

    parts = []
    if malicious_count > 0:
        parts.append(f"Found {malicious_count}/{total} malicious or suspicious IOCs.")
    else:
        parts.append(f"All {total} IOCs appear clean.")

    if actors:
        parts.append(f"Linked to threat actor(s): {', '.join(actors)}.")
    if campaigns:
        parts.append(f"Associated with campaign(s): {', '.join(campaigns)}.")
    return " ".join(parts)


@app.post("/lookup")
async def lookup_single_ioc(
    query: IOCQuery,
    current_user: CurrentUser = Depends(require_caller_roles("analyst", "admin")),
    session: AsyncSession = Depends(get_session),
):
    ioc = IOC(ioc_type=IOCType(query.ioc_type), value=query.value)
    intel = await lookup_ioc(ioc, session)
    return intel


@app.get("/threat-actors")
async def get_threat_actors(current_user: CurrentUser = Depends(get_current_user)):
    return [
        {"name": name, "aliases": data["aliases"], "origin": data["origin"], "motivation": data["motivation"], "malware": data["malware"], "ttps": data["ttps"]}
        for name, data in THREAT_ACTORS.items()
    ]


@app.get("/threat-actors/{actor_name}")
async def get_threat_actor(actor_name: str, current_user: CurrentUser = Depends(get_current_user)):
    if actor_name not in THREAT_ACTORS:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    return THREAT_ACTORS[actor_name]


@app.get("/iocs")
async def get_all_iocs(
    reputation: Optional[str] = None,
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    repo = IOCRepository(session)
    rows = await repo.list(limit=500)
    intel = [_row_to_threat_intel(r) for r in rows]
    if reputation:
        intel = [i for i in intel if i.ioc.reputation == reputation]
    return intel


@app.get("/stats")
async def get_tip_stats(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    repo = IOCRepository(session)
    rows = await repo.list(limit=5000)
    malicious = sum(1 for r in rows if r.reputation == "malicious")
    suspicious = sum(1 for r in rows if r.reputation == "suspicious")
    clean = sum(1 for r in rows if r.reputation == "clean")
    return {
        "total_iocs": len(rows),
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": clean,
        "threat_actors_tracked": len(THREAT_ACTORS),
        "timestamp": timestamp_now(),
    }


@app.post("/feed/import")
async def import_feed(
    payload: Dict[str, Any],
    current_user: CurrentUser = Depends(require_caller_roles("analyst", "admin")),
):
    return {"status": "accepted", "items": len(payload.get("items", [])), "source": payload.get("source", "unknown")}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
