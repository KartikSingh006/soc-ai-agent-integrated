"""
First-run bootstrap: create the initial admin account if the users table
is empty. Idempotent and safe to call on every startup — it's a no-op
once any user exists, so rotating ADMIN_USERNAME/ADMIN_PASSWORD afterward
has no effect (rotate via the /auth/users API or directly in the DB
instead).
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from shared.auth import hash_password
from shared.config import settings
from shared.db_models import UserORM
from shared.repository import UserRepository


async def bootstrap_admin_user(session: AsyncSession) -> None:
    repo = UserRepository(session)
    existing_users = await repo.count()
    if existing_users > 0:
        return

    admin = UserORM(
        username=settings.ADMIN_USERNAME,
        hashed_password=hash_password(settings.ADMIN_PASSWORD),
        role="admin",
        is_active=True,
    )
    session.add(admin)
    await session.commit()
    print(
        f"[BOOTSTRAP] Created initial admin user '{settings.ADMIN_USERNAME}'. "
        "Change this password immediately via POST /auth/users or the dashboard."
    )
