"""
Alembic environment for the SOC AI Agent system.

Runs migrations against the same async engine config the apps use
(shared.config.settings.POSTGRES_URL), via the asyncio-engine recipe.
Imports shared.db_models so every ORM table is registered on
Base.metadata before autogenerate/upgrade runs.
"""
import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

from shared.config import settings
from shared.db import Base, to_async_dsn

# Import every ORM model module so its tables register on Base.metadata.
from shared import db_models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    return to_async_dsn(settings.POSTGRES_URL)


def run_migrations_offline() -> None:
    """Generate SQL without a live DB connection (`alembic upgrade --sql`)."""
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = create_async_engine(get_url(), poolclass=pool.NullPool)
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
