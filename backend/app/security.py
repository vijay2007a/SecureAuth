from __future__ import annotations

import os
from typing import Callable

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .models import AuthenticatedUser, Role

bearer_scheme = HTTPBearer(auto_error=False)


def _dev_user_from_token(token: str) -> AuthenticatedUser | None:
    mapping = {
        os.getenv("DEV_ADMIN_TOKEN", "dev-admin-token"): AuthenticatedUser(
            id="dev-admin",
            email="admin@lab.local",
            name="Dev Admin",
            role=Role.admin,
            token_source="dev",
        ),
        os.getenv("DEV_ANALYST_TOKEN", "dev-analyst-token"): AuthenticatedUser(
            id="dev-analyst",
            email="analyst@lab.local",
            name="Dev Analyst",
            role=Role.analyst,
            token_source="dev",
        ),
        os.getenv("DEV_USER_TOKEN", "dev-user-token"): AuthenticatedUser(
            id="dev-user",
            email="user@lab.local",
            name="Dev User",
            role=Role.user,
            token_source="dev",
        ),
    }
    return mapping.get(token)


def verify_firebase_token(token: str) -> AuthenticatedUser:
    auth_mode = os.getenv("AUTH_MODE", "dev").lower()
    if auth_mode == "dev":
        user = _dev_user_from_token(token)
        if user:
            return user
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid development token")

    try:
        import firebase_admin
        from firebase_admin import auth as firebase_auth
    except Exception as exc:  # pragma: no cover - production dependency issue
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Firebase auth unavailable") from exc

    if not firebase_admin._apps:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Firebase admin is not configured")
    try:
        decoded = firebase_auth.verify_id_token(token)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Firebase token") from exc
    role = Role(decoded.get("role", Role.user.value))
    return AuthenticatedUser(
        id=decoded.get("uid") or decoded.get("user_id"),
        email=decoded.get("email", ""),
        name=decoded.get("name", decoded.get("email", "Firebase User")),
        role=role,
        token_source="firebase",
    )


def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)) -> AuthenticatedUser:
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    return verify_firebase_token(credentials.credentials)


def require_roles(*roles: Role) -> Callable[[AuthenticatedUser], AuthenticatedUser]:
    def _dependency(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if roles and user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return _dependency

