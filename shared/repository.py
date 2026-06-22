"""
Repository layer: every route handler talks to these, never to the ORM
or a raw session directly. Keeps SQL/SQLAlchemy specifics out of route
handlers and gives each service one obvious place to add a query.
"""
from datetime import datetime
from typing import Generic, Optional, Sequence, Type, TypeVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.db_models import (
    AIAnalysisORM,
    AlertORM,
    AssetORM,
    AuditLogORM,
    IncidentORM,
    IOCIntelORM,
    ReportORM,
    ResponseActionORM,
    TicketORM,
    UserORM,
)

ModelT = TypeVar("ModelT")


class BaseRepository(Generic[ModelT]):
    model: Type[ModelT]

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get(self, id_: str) -> Optional[ModelT]:
        return await self.session.get(self.model, id_)

    async def list(self, limit: int = 200, offset: int = 0) -> Sequence[ModelT]:
        result = await self.session.execute(select(self.model).limit(limit).offset(offset))
        return result.scalars().all()

    async def create(self, obj: ModelT) -> ModelT:
        self.session.add(obj)
        await self.session.flush()
        return obj

    async def save(self, obj: ModelT) -> ModelT:
        """Insert-or-update by primary key."""
        merged = await self.session.merge(obj)
        await self.session.flush()
        return merged

    async def delete(self, id_: str) -> bool:
        obj = await self.get(id_)
        if obj is None:
            return False
        await self.session.delete(obj)
        await self.session.flush()
        return True

    async def exists(self, id_: str) -> bool:
        return await self.get(id_) is not None

    async def count(self) -> int:
        from sqlalchemy import func as sa_func
        result = await self.session.execute(select(sa_func.count()).select_from(self.model))
        return result.scalar_one()


class AssetRepository(BaseRepository[AssetORM]):
    model = AssetORM

    async def get_by_hostname(self, hostname: str) -> Optional[AssetORM]:
        result = await self.session.execute(select(AssetORM).where(AssetORM.hostname == hostname))
        return result.scalar_one_or_none()


class AlertRepository(BaseRepository[AlertORM]):
    model = AlertORM

    async def list_open(self, limit: int = 200) -> Sequence[AlertORM]:
        stmt = (
            select(AlertORM)
            .where(AlertORM.status.notin_(["resolved", "false_positive"]))
            .order_by(AlertORM.timestamp.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_recent(self, limit: int = 200) -> Sequence[AlertORM]:
        stmt = select(AlertORM).order_by(AlertORM.timestamp.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def update_status(self, alert_id: str, status: str) -> Optional[AlertORM]:
        obj = await self.get(alert_id)
        if obj:
            obj.status = status
            await self.session.flush()
        return obj


class TicketRepository(BaseRepository[TicketORM]):
    model = TicketORM

    async def list_open(self) -> Sequence[TicketORM]:
        stmt = select(TicketORM).where(TicketORM.status != "resolved")
        result = await self.session.execute(stmt)
        return result.scalars().all()


class IncidentRepository(BaseRepository[IncidentORM]):
    model = IncidentORM

    async def list_by_status(self, status: str) -> Sequence[IncidentORM]:
        result = await self.session.execute(select(IncidentORM).where(IncidentORM.status == status))
        return result.scalars().all()

    async def get_by_django_ticket(self, django_ticket_id: str) -> Optional[IncidentORM]:
        result = await self.session.execute(
            select(IncidentORM).where(IncidentORM.django_ticket_id == django_ticket_id)
        )
        return result.scalar_one_or_none()


class ReportRepository(BaseRepository[ReportORM]):
    model = ReportORM

    async def list_for_incident(self, incident_id: str) -> Sequence[ReportORM]:
        result = await self.session.execute(select(ReportORM).where(ReportORM.incident_id == incident_id))
        return result.scalars().all()


class AIAnalysisRepository(BaseRepository[AIAnalysisORM]):
    model = AIAnalysisORM

    async def history_for_alert(self, alert_id: str) -> Sequence[AIAnalysisORM]:
        stmt = (
            select(AIAnalysisORM)
            .where(AIAnalysisORM.alert_id == alert_id)
            .order_by(AIAnalysisORM.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def latest_for_alert(self, alert_id: str) -> Optional[AIAnalysisORM]:
        rows = await self.history_for_alert(alert_id)
        return rows[0] if rows else None


class ResponseActionRepository(BaseRepository[ResponseActionORM]):
    model = ResponseActionORM

    async def list_pending(self) -> Sequence[ResponseActionORM]:
        result = await self.session.execute(
            select(ResponseActionORM).where(ResponseActionORM.status == "pending_approval")
        )
        return result.scalars().all()

    async def list_recent(self, limit: int = 100) -> Sequence[ResponseActionORM]:
        stmt = select(ResponseActionORM).order_by(ResponseActionORM.requested_at.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()


class IOCRepository(BaseRepository[IOCIntelORM]):
    model = IOCIntelORM

    async def find(self, ioc_type: str, value: str) -> Optional[IOCIntelORM]:
        result = await self.session.execute(
            select(IOCIntelORM).where(IOCIntelORM.ioc_type == ioc_type, IOCIntelORM.value == value)
        )
        return result.scalar_one_or_none()

    async def upsert(self, ioc_type: str, value: str, **fields) -> IOCIntelORM:
        existing = await self.find(ioc_type, value)
        if existing:
            for k, v in fields.items():
                setattr(existing, k, v)
            existing.last_seen = datetime.utcnow()
            await self.session.flush()
            return existing
        obj = IOCIntelORM(ioc_type=ioc_type, value=value, **fields)
        self.session.add(obj)
        await self.session.flush()
        return obj


class UserRepository(BaseRepository[UserORM]):
    model = UserORM

    async def get_by_username(self, username: str) -> Optional[UserORM]:
        result = await self.session.execute(select(UserORM).where(UserORM.username == username))
        return result.scalar_one_or_none()

    async def list_all(self) -> Sequence[UserORM]:
        result = await self.session.execute(select(UserORM).order_by(UserORM.created_at.asc()))
        return result.scalars().all()


class AuditLogRepository(BaseRepository[AuditLogORM]):
    model = AuditLogORM

    async def recent(self, limit: int = 200, resource_type: Optional[str] = None) -> Sequence[AuditLogORM]:
        stmt = select(AuditLogORM).order_by(AuditLogORM.timestamp.desc())
        if resource_type:
            stmt = stmt.where(AuditLogORM.resource_type == resource_type)
        stmt = stmt.limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def for_resource(self, resource_type: str, resource_id: str) -> Sequence[AuditLogORM]:
        stmt = (
            select(AuditLogORM)
            .where(AuditLogORM.resource_type == resource_type, AuditLogORM.resource_id == resource_id)
            .order_by(AuditLogORM.timestamp.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()