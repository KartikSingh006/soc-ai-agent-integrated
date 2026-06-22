"""
Shared authentication / RBAC for the SOC AI Agent system.

Design notes:
- A single user store (the `users` table) is shared by every service via
  the same Postgres database, but only the SIEM Engine exposes the
  `/auth/*` HTTP routes (login, user management). Every other service
  just *verifies* the JWT — there's no per-service session state, which
  is what makes this safe to do without a dedicated auth server.
- Two kinds of caller are recognized:
    1. A human, carrying a JWT obtained from POST /auth/login.
    2. Another internal service (siem -> orchestrator -> tip/response),
       carrying the shared INTERNAL_SERVICE_TOKEN in `X-Internal-Token`.
  `get_caller` accepts either. `require_roles(...)` accepts a JWT whose
  role is in the allowed set, OR a valid internal-service token (internal
  calls are implicitly trusted — the boundary that matters is the edge
  of the system, not between our own services).
- Passwords are hashed with bcrypt via passlib. JWTs are signed HS256
  with shared.config.settings.SECRET_KEY.
"""
from __future__ import annotations

import time
from typing import Optional, Sequence

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

from shared.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# auto_error=False so we can return our own 401 with a consistent shape,
# and so internal-service calls (no Authorization header at all) aren't
# rejected before we get a chance to check X-Internal-Token instead.
_bearer = HTTPBearer(auto_error=False)

ROLES = ("admin", "analyst", "viewer")


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


def create_access_token(username: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


class CurrentUser:
    """Lightweight identity object attached to a request after auth succeeds."""

    def __init__(self, username: str, role: str, is_internal: bool = False):
        self.username = username
        self.role = role
        self.is_internal = is_internal

    def __repr__(self) -> str:
        return f"CurrentUser(username={self.username!r}, role={self.role!r}, internal={self.is_internal})"


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> CurrentUser:
    """Require a valid human JWT. Use for any endpoint a logged-in user (any role) may call."""
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_access_token(credentials.credentials)
    return CurrentUser(username=payload["sub"], role=payload.get("role", "viewer"))


def require_roles(*allowed_roles: str):
    """
    Dependency factory: require the caller's JWT role to be one of
    `allowed_roles`. Pass no args to just require *any* authenticated role.
    """

    async def _dep(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    ) -> CurrentUser:
        if credentials is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        payload = decode_access_token(credentials.credentials)
        role = payload.get("role", "viewer")
        if allowed_roles and role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' is not permitted to perform this action (requires one of {allowed_roles})",
            )
        return CurrentUser(username=payload["sub"], role=role)

    return _dep


async def get_caller(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    x_internal_token: Optional[str] = Header(default=None),
) -> CurrentUser:
    """
    Accept EITHER a human JWT (any role) OR the internal-service token.
    Used on endpoints that are called both by end users and by other
    services in this system (e.g. response-engine's /execute, which is
    called by analysts via the dashboard AND by the AI orchestrator
    auto-containing a confirmed threat).
    """
    if x_internal_token and x_internal_token == settings.INTERNAL_SERVICE_TOKEN:
        return CurrentUser(username="internal-service", role="admin", is_internal=True)
    if credentials is not None:
        payload = decode_access_token(credentials.credentials)
        return CurrentUser(username=payload["sub"], role=payload.get("role", "viewer"))
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


def require_caller_roles(*allowed_roles: str):
    """Like require_roles, but also accepts the internal-service token regardless of role list."""

    async def _dep(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
        x_internal_token: Optional[str] = Header(default=None),
    ) -> CurrentUser:
        if x_internal_token and x_internal_token == settings.INTERNAL_SERVICE_TOKEN:
            return CurrentUser(username="internal-service", role="admin", is_internal=True)
        if credentials is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        payload = decode_access_token(credentials.credentials)
        role = payload.get("role", "viewer")
        if allowed_roles and role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' is not permitted to perform this action (requires one of {allowed_roles})",
            )
        return CurrentUser(username=payload["sub"], role=role)

    return _dep


def internal_headers() -> dict:
    """Header dict to attach to outbound service-to-service httpx calls."""
    return {"X-Internal-Token": settings.INTERNAL_SERVICE_TOKEN}
