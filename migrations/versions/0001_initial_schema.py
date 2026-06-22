"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-18

Creates every table the system uses: assets, alerts, tickets, incidents,
reports, ai_analysis_results, response_actions, ioc_intel, users,
audit_log. This replaces the old `\\dt`-verified-by-hand bootstrap with a
real, repeatable migration (see shared/db.py:run_startup_migrations,
which every service calls on startup under a Postgres advisory lock).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("asset_id", sa.String(128), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("asset_name", sa.String(255), nullable=False),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("business_unit", sa.String(255), nullable=True),
        sa.Column("criticality", sa.String(32), nullable=False, server_default="medium"),
        sa.Column("environment", sa.String(32), nullable=False, server_default="production"),
        sa.Column("location", sa.String(255), nullable=True),
        sa.Column("platform", sa.String(128), nullable=True),
        sa.Column("tags", JSONB, nullable=False, server_default="[]"),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("asset_metadata", JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_assets_hostname", "assets", ["hostname"])
    op.create_index("ix_assets_criticality", "assets", ["criticality"])

    op.create_table(
        "alerts",
        sa.Column("alert_id", sa.String(128), primary_key=True),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("rule_triggered", sa.String(255), nullable=False),
        sa.Column("asset", sa.String(255), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="new"),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence", JSONB, nullable=False, server_default="[]"),
        sa.Column("iocs", JSONB, nullable=False, server_default="[]"),
        sa.Column("mitre_techniques", JSONB, nullable=False, server_default="[]"),
        sa.Column("ai_analysis", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_asset", "alerts", ["asset"])
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_status_timestamp", "alerts", ["status", "timestamp"])

    op.create_table(
        "tickets",
        sa.Column("ticket_id", sa.String(128), primary_key=True),
        sa.Column("alert_id", sa.String(128), sa.ForeignKey("alerts.alert_id"), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("assigned_analyst", sa.String(255), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="new"),
        sa.Column("recommended_actions", JSONB, nullable=False, server_default="[]"),
        sa.Column("evidence", JSONB, nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_tickets_alert_id", "tickets", ["alert_id"])
    op.create_index("ix_tickets_status", "tickets", ["status"])

    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(128), primary_key=True),
        sa.Column("alert_ids", JSONB, nullable=False, server_default="[]"),
        sa.Column("incident_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="new"),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("affected_assets", JSONB, nullable=False, server_default="[]"),
        sa.Column("iocs", JSONB, nullable=False, server_default="[]"),
        sa.Column("timeline", JSONB, nullable=False, server_default="[]"),
        sa.Column("containment_actions", JSONB, nullable=False, server_default="[]"),
        sa.Column("investigation_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("root_cause", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("django_ticket_id", sa.String(128), nullable=True),
        sa.Column("django_ticket_status", sa.String(64), nullable=True),
        sa.Column("asset_context", JSONB, nullable=True),
    )
    op.create_index("ix_incidents_incident_type", "incidents", ["incident_type"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_django_ticket_id", "incidents", ["django_ticket_id"])

    op.create_table(
        "reports",
        sa.Column("report_id", sa.String(128), primary_key=True),
        sa.Column("incident_id", sa.String(128), sa.ForeignKey("incidents.incident_id"), nullable=False),
        sa.Column("report_type", sa.String(64), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("report_metadata", JSONB, nullable=False, server_default="{}"),
    )
    op.create_index("ix_reports_incident_id", "reports", ["incident_id"])

    op.create_table(
        "ai_analysis_results",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("alert_id", sa.String(128), sa.ForeignKey("alerts.alert_id"), nullable=False),
        sa.Column("is_threat", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("attack_type", sa.String(128), nullable=True),
        sa.Column("mitre_mapping", JSONB, nullable=False, server_default="[]"),
        sa.Column("explanation", sa.Text(), nullable=False, server_default=""),
        sa.Column("recommended_actions", JSONB, nullable=False, server_default="[]"),
        sa.Column("false_positive_reason", sa.Text(), nullable=True),
        sa.Column("provider", sa.String(64), nullable=True),
        sa.Column("model_name", sa.String(128), nullable=True),
        sa.Column("prompt_version", sa.String(32), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("token_usage", sa.Integer(), nullable=True),
        sa.Column("cost_usd", sa.Float(), nullable=True),
        sa.Column("raw_response", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_ai_analysis_results_alert_id", "ai_analysis_results", ["alert_id"])
    op.create_index("ix_ai_analysis_results_created_at", "ai_analysis_results", ["created_at"])

    op.create_table(
        "response_actions",
        sa.Column("action_id", sa.String(128), primary_key=True),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("result", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("provider", sa.String(64), nullable=True),
        sa.Column("raw_response", JSONB, nullable=True),
        sa.Column("incident_id", sa.String(128), nullable=True),
        sa.Column("alert_id", sa.String(128), nullable=True),
        sa.Column("requested_by", sa.String(255), nullable=True),
    )
    op.create_index("ix_response_actions_action_type", "response_actions", ["action_type"])
    op.create_index("ix_response_actions_status", "response_actions", ["status"])
    op.create_index("ix_response_actions_incident_id", "response_actions", ["incident_id"])
    op.create_index("ix_response_actions_alert_id", "response_actions", ["alert_id"])

    op.create_table(
        "ioc_intel",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("ioc_type", sa.String(32), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("reputation", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ioc_source", sa.String(64), nullable=False, server_default=""),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("related_threats", JSONB, nullable=False, server_default="[]"),
        sa.Column("country", sa.String(128), nullable=True),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("campaign", sa.String(255), nullable=True),
        sa.Column("malware_family", sa.String(255), nullable=True),
        sa.Column("threat_level", sa.String(32), nullable=False, server_default="low"),
        sa.Column("ttps", JSONB, nullable=False, server_default="[]"),
        sa.Column("related_iocs", JSONB, nullable=False, server_default="[]"),
        sa.Column("vt_summary", sa.Text(), nullable=True),
        sa.Column("raw_response", JSONB, nullable=True),
    )
    op.create_index("ix_ioc_intel_ioc_type", "ioc_intel", ["ioc_type"])
    op.create_index("ix_ioc_intel_value", "ioc_intel", ["value"])
    op.create_index("ix_ioc_type_value", "ioc_intel", ["ioc_type", "value"], unique=True)

    op.create_table(
        "users",
        sa.Column("user_id", sa.String(64), primary_key=True),
        sa.Column("username", sa.String(128), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False, server_default="viewer"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_role", "users", ["role"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("actor_role", sa.String(32), nullable=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=True),
        sa.Column("resource_id", sa.String(128), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("details", JSONB, nullable=False, server_default="{}"),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("service", sa.String(64), nullable=True),
    )
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])
    op.create_index("ix_audit_log_actor", "audit_log", ["actor"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_resource_type", "audit_log", ["resource_type"])
    op.create_index("ix_audit_log_resource_id", "audit_log", ["resource_id"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("users")
    op.drop_table("ioc_intel")
    op.drop_table("response_actions")
    op.drop_table("ai_analysis_results")
    op.drop_table("reports")
    op.drop_table("incidents")
    op.drop_table("tickets")
    op.drop_table("alerts")
    op.drop_table("assets")
