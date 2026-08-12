from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timedelta
from typing import Any

from .models import AuthenticatedUser, NotificationTokenRecord, Severity, utc_now

logger = logging.getLogger(__name__)

NOTIFICATION_COOLDOWN_SECONDS = int(os.getenv("NOTIFICATION_COOLDOWN_SECONDS", "90"))
_last_sent_at: dict[str, datetime] = {}


def _cooldown_key(uid: str, event_type: str, context: str = "") -> str:
    return f"{uid}:{event_type}:{context}"


def _too_soon(key: str) -> bool:
    last = _last_sent_at.get(key)
    if not last:
        return False
    return utc_now() - last < timedelta(seconds=NOTIFICATION_COOLDOWN_SECONDS)


def _mark_sent(key: str) -> None:
    _last_sent_at[key] = utc_now()


def _cleanup_token(store, uid: str, token: str) -> None:
    try:
        store.delete_notification_token(uid, token)
    except Exception:
        logger.exception("Failed to remove stale notification token for uid=%s", uid)


def _token_record_id(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def register_notification_token(
    store,
    user: AuthenticatedUser,
    token: str,
    device_name: str | None = None,
    platform: str = "web",
) -> NotificationTokenRecord:
    normalized = token.strip()
    if not normalized:
        raise ValueError("Token is required")
    record = NotificationTokenRecord(
        id=_token_record_id(normalized),
        uid=user.id,
        email=user.email,
        token=normalized,
        platform=platform or "web",
        device_name=device_name or "Browser",
        last_seen_at=utc_now(),
    )
    return store.upsert_notification_token(record)


def delete_notification_token(store, user: AuthenticatedUser, token: str) -> bool:
    normalized = token.strip()
    if not normalized:
        raise ValueError("Token is required")
    return store.delete_notification_token(user.id, normalized)


def list_notification_tokens(store, user: AuthenticatedUser) -> list[NotificationTokenRecord]:
    return store.list_notification_tokens(user.id)


def _send_to_tokens(tokens: list[str], title: str, body: str, data: dict[str, str]) -> tuple[int, int, list[str]]:
    if not tokens:
        return 0, 0, []

    try:
        import firebase_admin
        from firebase_admin import messaging
    except ImportError as exc:
        raise RuntimeError("firebase-admin messaging is not available") from exc

    if not firebase_admin._apps:
        from .firebase_init import init_firebase_app

        init_firebase_app()

    sent = 0
    failed = 0
    invalid_tokens: list[str] = []
    for token in tokens:
        try:
            message = messaging.Message(
                token=token,
                notification=messaging.Notification(title=title, body=body),
                data=data,
                webpush=messaging.WebpushConfig(
                    notification=messaging.WebpushNotification(title=title, body=body),
                ),
            )
            messaging.send(message)
            sent += 1
        except messaging.UnregisteredError:
            failed += 1
            invalid_tokens.append(token)
        except Exception:
            failed += 1
            logger.exception("FCM send failed")
    return sent, failed, invalid_tokens


def send_password_spray_notification(
    store,
    recipient: AuthenticatedUser,
    target_email: str,
    attempts: int,
    source_ip: str,
    severity: Severity,
    simulation_id: str,
) -> dict[str, Any]:
    key = _cooldown_key(recipient.id, "password_spray", simulation_id)
    if _too_soon(key):
        return {"sent": 0, "failed": 0, "skipped": True, "reason": "cooldown"}

    tokens = [item.token for item in list_notification_tokens(store, recipient)]
    title = "\U0001F6A8 SecureAuth Alert"
    body = f"Password Spray Detected - {attempts} attempts against {target_email}. Risk: {severity.value.upper()}"
    data = {
        "type": "password_spray",
        "target": target_email,
        "attempts": str(attempts),
        "severity": severity.value.upper(),
        "source_ip": source_ip,
        "simulation_id": simulation_id,
        "link": "/alerts",
    }
    sent, failed, invalid_tokens = _send_to_tokens(tokens, title, body, data)
    for token in invalid_tokens:
        _cleanup_token(store, recipient.id, token)
    if sent:
        _mark_sent(key)
    return {"sent": sent, "failed": failed, "tokens": len(tokens)}


def send_test_security_alert(store, recipient: AuthenticatedUser) -> dict[str, Any]:
    key = _cooldown_key(recipient.id, "test_alert")
    if _too_soon(key):
        return {"sent": 0, "failed": 0, "skipped": True, "reason": "cooldown"}

    tokens = [item.token for item in list_notification_tokens(store, recipient)]
    title = "\U0001F6A8 SecureAuth Test Alert"
    body = "Push notifications are working successfully."
    data = {
        "type": "test_alert",
        "target": recipient.email,
        "severity": "INFO",
        "link": "/dashboard",
    }
    sent, failed, invalid_tokens = _send_to_tokens(tokens, title, body, data)
    for token in invalid_tokens:
        _cleanup_token(store, recipient.id, token)
    if sent:
        _mark_sent(key)
    return {"sent": sent, "failed": failed, "tokens": len(tokens)}
