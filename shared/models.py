"""
Shared data models and schemas for the SOC AI Agent system.
"""
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    NEW = "new"
    TRIAGING = "triaging"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    CONTAINED = "contained"
    RESOLVED = "resolved"


class IncidentType(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    INSIDER_THREAT = "insider_threat"
    DDOS = "ddos"
    CREDENTIAL_THEFT = "credential_theft"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    SIGNATURE = "signature"


class LogEvent(BaseModel):
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_type: str
    severity: Severity = Severity.LOW
    raw_log: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AssetRecord(BaseModel):
    asset_id: str
    hostname: str
    asset_name: str
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    criticality: str = "medium"
    environment: str = "production"
    location: Optional[str] = None
    platform: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
    alert_id: str
    severity: Severity
    rule_triggered: str
    asset: str
    timestamp: datetime
    status: AlertStatus = AlertStatus.NEW
    description: str = ""
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    iocs: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    ai_analysis: Optional[Dict[str, Any]] = None


class Ticket(BaseModel):
    ticket_id: str
    alert_id: str
    severity: Severity
    assigned_analyst: Optional[str] = None
    status: AlertStatus = AlertStatus.NEW
    recommended_actions: List[str] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None


class IOC(BaseModel):
    ioc_type: IOCType
    value: str
    reputation: str = "unknown"
    confidence: int = 0
    source: str = ""
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: Optional[datetime] = None
    related_threats: List[str] = Field(default_factory=list)


class ThreatIntel(BaseModel):
    ioc: IOC
    country: Optional[str] = None
    actor: Optional[str] = None
    campaign: Optional[str] = None
    malware_family: Optional[str] = None
    confidence: int = 0
    threat_level: Severity = Severity.LOW
    ttps: List[str] = Field(default_factory=list)
    related_iocs: List[str] = Field(default_factory=list)
    source: str = "internal"


class Incident(BaseModel):
    incident_id: str
    alert_ids: List[str] = Field(default_factory=list)
    incident_type: IncidentType
    severity: Severity
    status: AlertStatus = AlertStatus.NEW
    description: str = ""
    affected_assets: List[str] = Field(default_factory=list)
    iocs: List[IOC] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    containment_actions: List[Dict[str, Any]] = Field(default_factory=list)
    investigation_notes: str = ""
    root_cause: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    django_ticket_id: Optional[str] = None
    django_ticket_status: Optional[str] = None
    asset_context: Optional[Dict[str, Any]] = None


class AIAnalysisResult(BaseModel):
    alert_id: str
    is_threat: bool
    confidence: float
    severity: Severity
    attack_type: Optional[str] = None
    mitre_mapping: List[str] = Field(default_factory=list)
    explanation: str = ""
    recommended_actions: List[str] = Field(default_factory=list)
    false_positive_reason: Optional[str] = None
    provider: Optional[str] = None
    model_name: Optional[str] = None
    prompt_version: Optional[str] = None
    latency_ms: Optional[int] = None
    token_usage: Optional[int] = None
    cost_usd: Optional[float] = None
    raw_response: Optional[Dict[str, Any]] = None


class EnrichmentResult(BaseModel):
    alert_id: str
    iocs_enriched: List[ThreatIntel] = Field(default_factory=list)
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    risk_score: int = 0
    summary: str = ""
    vt_summary: Optional[str] = None


class ResponseAction(BaseModel):
    action_id: str
    action_type: str
    target: str
    status: str = "pending"
    result: Optional[str] = None
    executed_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    provider: Optional[str] = None
    raw_response: Optional[Dict[str, Any]] = None


class Report(BaseModel):
    report_id: str
    incident_id: str
    report_type: str
    content: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
