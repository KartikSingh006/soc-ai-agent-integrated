"""
ORM models — the PostgreSQL-backed counterparts of shared.models's pydantic
schemas. Pydantic models stay the API/validation layer; these are the
persistence layer. JSONB is used for nested/flexible fields since this is
Postgres-only (no more in-memory fallback), which also gives us indexable,
queryable JSON rather than an opaque blob.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shared.db import Base


class AssetORM(Base):
    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    asset_name: Mapped[str] = mapped_column(String(255))
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    business_unit: Mapped[str | None] = mapped_column(String(255), nullable=True)
    criticality: Mapped[str] = mapped_column(String(32), default="medium", index=True)
    environment: Mapped[str] = mapped_column(String(32), default="production")
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    asset_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AlertORM(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    rule_triggered: Mapped[str] = mapped_column(String(255))
    asset: Mapped[str] = mapped_column(String(255), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSONB, default=list)
    iocs: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)
    ai_analysis: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_alerts_status_timestamp", "status", "timestamp"),
    )


class TicketORM(Base):
    __tablename__ = "tickets"

    ticket_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(128), ForeignKey("alerts.alert_id"), index=True)
    severity: Mapped[str] = mapped_column(String(32))
    assigned_analyst: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    recommended_actions: Mapped[list] = mapped_column(JSONB, default=list)
    evidence: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IncidentORM(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    alert_ids: Mapped[list] = mapped_column(JSONB, default=list)
    incident_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    affected_assets: Mapped[list] = mapped_column(JSONB, default=list)
    iocs: Mapped[list] = mapped_column(JSONB, default=list)
    timeline: Mapped[list] = mapped_column(JSONB, default=list)
    containment_actions: Mapped[list] = mapped_column(JSONB, default=list)
    investigation_notes: Mapped[str] = mapped_column(Text, default="")
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Phase 3 (Django ticket sync) hooks — populated once that integration exists.
    django_ticket_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    django_ticket_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    asset_context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


class ReportORM(Base):
    __tablename__ = "reports"

    report_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(128), ForeignKey("incidents.incident_id"), index=True)
    report_type: Mapped[str] = mapped_column(String(64))
    content: Mapped[str] = mapped_column(Text)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    report_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)


class AIAnalysisORM(Base):
    """
    One row per analysis run (an alert can be re-analyzed), unlike the other
    tables this is intentionally append-only history rather than keyed by
    alert_id, so re-runs don't clobber the audit trail of prior verdicts.
    """
    __tablename__ = "ai_analysis_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id: Mapped[str] = mapped_column(String(128), ForeignKey("alerts.alert_id"), index=True)
    is_threat: Mapped[bool] = mapped_column(default=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(32))
    attack_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_mapping: Mapped[list] = mapped_column(JSONB, default=list)
    explanation: Mapped[str] = mapped_column(Text, default="")
    recommended_actions: Mapped[list] = mapped_column(JSONB, default=list)
    false_positive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    token_usage: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_response: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class ResponseActionORM(Base):
    __tablename__ = "response_actions"

    action_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_response: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Traceability back to what triggered this action — additive vs. the
    # original pydantic model, nullable so it's a non-breaking change.
    incident_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    alert_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class UserORM(Base):
    """
    Local user store for RBAC. Deliberately minimal — username + bcrypt hash
    + role. Roles are plain strings rather than a DB enum so adding a role
    later doesn't require a migration.
    """
    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="viewer", index=True)  # admin | analyst | viewer
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLogORM(Base):
    """
    Append-only record of who-did-what. Written for every authenticated
    mutation (alert/incident/response-action changes, user-management,
    approvals) plus automated actions taken by the system itself (actor
    is then "system" / "ai-orchestrator" etc).
    """
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    actor_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    success: Mapped[bool] = mapped_column(default=True)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    service: Mapped[str | None] = mapped_column(String(64), nullable=True)


class IOCIntelORM(Base):
    """Cached/enriched threat-intel record, keyed by (ioc_type, value)."""
    __tablename__ = "ioc_intel"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    reputation: Mapped[str] = mapped_column(String(32), default="unknown")
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    ioc_source: Mapped[str] = mapped_column(String(64), default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    related_threats: Mapped[list] = mapped_column(JSONB, default=list)
    country: Mapped[str | None] = mapped_column(String(128), nullable=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    campaign: Mapped[str | None] = mapped_column(String(255), nullable=True)
    malware_family: Mapped[str | None] = mapped_column(String(255), nullable=True)
    threat_level: Mapped[str] = mapped_column(String(32), default="low")
    ttps: Mapped[list] = mapped_column(JSONB, default=list)
    related_iocs: Mapped[list] = mapped_column(JSONB, default=list)
    vt_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_response: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_ioc_type_value", "ioc_type", "value", unique=True),
    )