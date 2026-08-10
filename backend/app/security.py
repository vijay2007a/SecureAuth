from __future__ import annotations

import logging
import os
from typing import Callable

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .models import AuthenticatedUser, Role

logger = logging.getLogger(__name__)

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

    # ── Development fallback ──────────────────────────────────────────────────
    if auth_mode == "dev":
        user = _dev_user_from_token(token)
        if user:
            return user
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid development token")

    # ── Firebase path ─────────────────────────────────────────────────────────
    try:
        import firebase_admin
        from firebase_admin import auth as firebase_auth
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Firebase auth package is not installed",
        ) from exc

    # Ensure the SDK is initialised regardless of whether Firestore is in use.
    # This fixes the bug where AUTH_MODE=firebase + USE_FIRESTORE=false left
    # firebase_admin._apps empty, causing every token to be rejected with 503
    # which the WebSocket handler turned into a 403.
    if not firebase_admin._apps:
        try:
            from .firebase_init import init_firebase_app
            init_firebase_app()
        except Exception as exc:
            logger.exception("Firebase Admin initialisation failed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Firebase Admin SDK could not be initialised. "
                       "Check FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, "
                       "and FIREBASE_PRIVATE_KEY on the server.",
            ) from exc

    # Verify the ID token supplied by the client.
    try:
        decoded = firebase_auth.verify_id_token(token)
    except firebase_auth.ExpiredIdTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Firebase ID token has expired — please sign in again.",
        ) from exc
    except firebase_auth.InvalidIdTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Firebase ID token.",
        ) from exc
    except Exception as exc:
        logger.warning("Firebase token verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Firebase token verification failed.",
        ) from exc

    role_value = decoded.get("role", Role.user.value)
    try:
        role = Role(role_value)
    except ValueError:
        role = Role.user

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
