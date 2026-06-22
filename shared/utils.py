"""
Shared utilities for the SOC AI Agent system.
"""
import uuid
import hashlib
from datetime import datetime
from typing import Any, Dict


def generate_id(prefix: str = "ID") -> str:
    """Generate a unique ID with prefix."""
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def generate_alert_id() -> str:
    return generate_id("ALT")


def generate_ticket_id() -> str:
    return generate_id("TKT")


def generate_incident_id() -> str:
    return generate_id("INC")


def generate_report_id() -> str:
    return generate_id("RPT")


def generate_asset_id() -> str:
    return generate_id("AST")


def hash_ioc(value: str) -> str:
    """Hash an IOC value for deduplication."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def timestamp_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def calculate_risk_score(severity: str, confidence: float, ioc_count: int = 0, asset_criticality: str = "medium") -> int:
    """Calculate a risk score from 0-100."""
    severity_weights = {"low": 10, "medium": 30, "high": 60, "critical": 90}
    criticality_bonus = {"low": 0, "medium": 5, "high": 10, "critical": 20}
    base = severity_weights.get(severity, 10)
    score = int(base * confidence + (ioc_count * 5) + criticality_bonus.get(asset_criticality, 5))
    return min(score, 100)
