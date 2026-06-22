"""
Audit logging helper. Every service calls `record_audit` inside the same
DB session/transaction as the mutation it's logging, so the audit row and
the change it describes commit (or roll back) together.
"""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from shared.db_models import AuditLogORM


async def record_audit(
    session: AsyncSession,
    actor: str,
    action: str,
    *,
    actor_role: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    success: bool = True,
    details: Optional[dict[str, Any]] = None,
    source_ip: Optional[str] = None,
    service: Optional[str] = None,
) -> AuditLogORM:
    row = AuditLogORM(
        actor=actor,
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        success=success,
        details=details or {},
        source_ip=source_ip,
        service=service,
    )
    session.add(row)
    await session.flush()
    return row
