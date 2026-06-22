"""
Async SQLAlchemy / PostgreSQL engine and session management.

Every service imports `get_session` as a FastAPI dependency to obtain a
transactional session scoped to a single request. Connections are pooled
and pre-pinged so a dead connection (DB restart, network blip) is detected
and replaced rather than surfacing as a 500 on the next request.
"""
from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from shared.config import settings


class Base(DeclarativeBase):
    pass


def to_async_dsn(url: str) -> str:
    """Normalize a postgres URL to the asyncpg dialect SQLAlchemy's async engine expects."""
    if url.startswith("postgresql+asyncpg://"):
        return url
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


engine = create_async_engine(
    to_async_dsn(settings.POSTGRES_URL),
    echo=settings.SQL_ECHO,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=1800,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: one transactional session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def check_db_connection() -> bool:
    """Used by readiness probes to verify the DB is actually reachable, not just configured."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def wait_for_postgres(max_attempts: int = 30, delay_seconds: float = 2.0) -> None:
    """
    `depends_on` in docker-compose only waits for the postgres *container*
    to start, not for Postgres to be ready to accept connections. Every
    service calls this before running migrations so a slow DB start
    doesn't crash the app on its first request.
    """
    import asyncio

    for attempt in range(1, max_attempts + 1):
        if await check_db_connection():
            print(f"[DB] Postgres is ready (attempt {attempt}/{max_attempts})")
            return
        print(f"[DB] Postgres not ready yet (attempt {attempt}/{max_attempts}), retrying in {delay_seconds}s...")
        await asyncio.sleep(delay_seconds)
    raise RuntimeError(f"Postgres did not become ready after {max_attempts} attempts")


def _run_alembic_upgrade_sync() -> None:
    """Blocking; must run in a worker thread (see run_startup_migrations)."""
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    project_root = Path(__file__).resolve().parents[1]
    cfg = Config(str(project_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(project_root / "migrations"))
    command.upgrade(cfg, "head")


_MIGRATION_ADVISORY_LOCK_ID = 727274  # arbitrary, app-specific


async def run_startup_migrations() -> None:
    """
    Run `alembic upgrade head` guarded by a Postgres advisory lock, so that
    when multiple service replicas (or multiple services) start at the same
    time, only one actually runs the DDL — the rest block briefly, then see
    the schema is already current and continue. Safe to call from every
    service's startup handler.
    """
    import asyncio

    async with engine.connect() as conn:
        await conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": _MIGRATION_ADVISORY_LOCK_ID})
        try:
            await asyncio.to_thread(_run_alembic_upgrade_sync)
        finally:
            await conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": _MIGRATION_ADVISORY_LOCK_ID})
async def create_tables() -> None:
    """
    Temporary bootstrap for POC.
    Creates all ORM tables directly from metadata.
    """
    from shared.db_models import (
        AssetORM,
        AlertORM,
        TicketORM,
        IncidentORM,
        ReportORM,
        AIAnalysisORM,
        ResponseActionORM,
        IOCIntelORM,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)