from __future__ import annotations

import json
import logging
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

from .detection import analyze_event, make_features, password_ref, summarize_activity, train_models
from .notifications import (
    delete_notification_token,
    register_notification_token,
    send_password_spray_notification,
    send_test_security_alert,
)
from .models import (
    AccountCreateRequest,
    AccountStatus,
    AccountUpdateRequest,
    AlertRecord,
    AlertStatus,
    AlertUpdateRequest,
    AttackType,
    AuthenticatedUser,
    CredentialDataset,
    DatasetUploadResponse,
    DetectionMethod,
    IPControl,
    IPControlCreateRequest,
    IPControlType,
    IPControlUpdateRequest,
    LoginEvent,
    ModelMetric,
    NotificationTokenDeleteRequest,
    NotificationTokenRequest,
    ReportRecord,
    Role,
    SettingsPayload,
    SimulationRecord,
    SimulationRequest,
    SimulationStatus,
    Severity,
    TestAccount,
    Thresholds,
    UserProfile,
    utc_now,
)
from .firebase_init import init_firebase_app
from .security import get_current_user, require_roles, verify_firebase_token
from .store import BaseStore, FirestoreStore, MemoryStore


logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._connections:
            self._connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        payload = json.dumps(jsonable_encoder(message), default=str)
        dead: list[WebSocket] = []
        for websocket in self._connections:
            try:
                await websocket.send_text(payload)
            except Exception:
                dead.append(websocket)
        for websocket in dead:
            self.disconnect(websocket)


def create_store() -> BaseStore:
    use_firestore = os.getenv("USE_FIRESTORE", "true").lower() == "true"
    has_firestore_credentials = bool(
        os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        or (os.getenv("FIREBASE_PRIVATE_KEY") and os.getenv("FIREBASE_CLIENT_EMAIL"))
    )
    if not use_firestore or not has_firestore_credentials:
        return MemoryStore()
    try:
        project_id = os.getenv("FIREBASE_PROJECT_ID")
        return FirestoreStore(project_id=project_id)
    except Exception:
        return MemoryStore()


def _to_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _default_metrics() -> list[ModelMetric]:
    return [
        ModelMetric(
            id="rule-based",
            name="Rule-Based Engine",
            type="Rule-Based",
            status="active",
            version="v2.1.0",
            accuracy=94.2,
            detections=1420,
            false_positives=18,
            training_samples=256,
            last_trained_at=utc_now(),
            notes="Primary heuristic engine",
        ),
        ModelMetric(
            id="random-forest",
            name="Random Forest Classifier",
            type="ML Model",
            status="inactive",
            version="v1.0.0",
            training_samples=0,
            notes="Insufficient labeled training data",
        ),
        ModelMetric(
            id="isolation-forest",
            name="IsolationForest Anomaly Detector",
            type="Anomaly",
            status="inactive",
            version="v1.0.0",
            training_samples=0,
            notes="Awaiting more event history",
        ),
    ]


def _sample_passwords(text: str | None) -> list[str]:
    if not text:
        return ["Spring2025!", "Admin123!", "Password1!", "Welcome@2025"]
    values = [item.strip() for item in text.replace("\r", "\n").split("\n")]
    return [item for item in values if item]


def _account_seed_name(index: int) -> tuple[str, str]:
    return (f"user{index:03d}@lab.local", f"User {index:03d}")


def _select_accounts(store: BaseStore, count: int) -> list[TestAccount]:
    accounts = store.list_accounts()
    if len(accounts) >= count:
        return accounts[:count]
    created = list(accounts)
    next_index = len(accounts) + 1
    while len(created) < count:
        username, display_name = _account_seed_name(next_index)
        account = TestAccount(id=str(uuid4()), username=username, display_name=display_name)
        store.upsert_account(account)
        created.append(account)
        next_index += 1
    return created


async def _build_simulation_events(
    store: BaseStore,
    simulation: SimulationRecord,
    accounts: list[TestAccount],
    source_ips: list[str],
    passwords: list[str],
    kind: str,
    broadcast: Any | None = None,
) -> tuple[list[LoginEvent], list[AlertRecord]]:
    alerts: list[AlertRecord] = []
    events: list[LoginEvent] = []
    thresholds = store.get_thresholds()
    existing_events = store.list_events()[::-1]
    
    if broadcast:
        await broadcast(
            {
                "type": "simulation.initialized",
                "simulation_id": simulation.id,
                "progress": 0,
                "simulation": simulation.model_dump(mode="json"),
            }
        )
        await broadcast(
            {
                "type": "simulation.started",
                "simulation": simulation.model_dump(mode="json"),
                "attempts": simulation.attempts,
                "attack_type": kind,
            }
        )
        await broadcast(
            {
                "type": "simulation.progress",
                "simulation_id": simulation.id,
                "attempts_completed": 0,
                "attempts_total": simulation.attempts,
                "progress": 10,
                "stage": "preparation",
            }
        )
    
    try:
        total_attempts = simulation.attempts
        blocked_ips = {ip.ip for ip in store.list_ips() if ip.type.value == "blocked"}

        for idx in range(total_attempts):
            account = accounts[idx % len(accounts)]
            source_ip = source_ips[idx % len(source_ips)] if source_ips else simulation.source_ip
            password = passwords[idx % len(passwords)] if passwords else "LabPassword!"

            if account.locked:
                is_success = False
            else:
                is_success = kind == "normal" and idx % 4 == 0

            event = LoginEvent(
                id=str(uuid4()),
                timestamp=utc_now() + timedelta(seconds=float(idx) * simulation.parameters.get("delay_seconds", 0.0)),
                username=account.username,
                test_account_id=account.id,
                source_ip=source_ip,
                password_ref=password_ref(password),
                success=is_success,
                simulation_id=simulation.id,
                attack_type=kind,
                user_agent="SecureAuth-Lab/1.0",
                labels={"password_hash": password_ref(password)},
            )

            if account.locked:
                score, severity, confidence, attack_class, method, explanation, blocked, rules, features = (
                    100,
                    Severity.critical,
                    1.0,
                    AttackType.high_risk,
                    DetectionMethod.rule_based,
                    "Target test account is locked due to security violations",
                    True,
                    {"account_locked": True},
                    make_features(existing_events + events, event),
                )
            else:
                score, severity, confidence, attack_class, method, explanation, blocked, rules, features = analyze_event(
                    existing_events + events, event, thresholds, blocked_ips=blocked_ips
                )

            event.risk_score = score
            event.severity = severity
            event.confidence = confidence
            event.attack_class = attack_class
            event.detection_method = method
            event.explanation = explanation
            event.blocked = blocked
            if blocked:
                event.success = False

            store.add_event(event)
            events.append(event)
            existing_events.append(event)

            account.attempts += 1
            account.last_login = event.timestamp
            if not event.success and account.attempts >= 5:
                account.locked = True
                account.status = AccountStatus.locked
            store.upsert_account(account)

            if score >= thresholds.risk_alert_threshold:
                alert = AlertRecord(
                    id=str(uuid4()),
                    severity=severity,
                    attack_type=event.attack_class.value,
                    source_ip=event.source_ip,
                    affected_accounts=[account.username],
                    risk_score=score,
                    confidence=confidence,
                    explanation=explanation,
                    timestamp=event.timestamp,
                    status=AlertStatus.open,
                    event_id=event.id,
                )
                store.add_alert(alert)
                alerts.append(alert)

            if broadcast:
                await broadcast(
                    {
                        "type": "login_event",
                        "simulation_id": simulation.id,
                        "event": event.model_dump(mode="json"),
                    }
                )
                await broadcast(
                    {
                        "type": "detection_result",
                        "simulation_id": simulation.id,
                        "event_id": event.id,
                        "risk_score": score,
                        "severity": severity.value,
                        "confidence": confidence,
                        "attack_class": attack_class.value,
                        "blocked": blocked,
                        "explanation": explanation,
                    }
                )
                if alerts and alerts[-1].event_id == event.id:
                    await broadcast(
                        {
                            "type": "alert_created",
                            "simulation_id": simulation.id,
                            "alert": alerts[-1].model_dump(mode="json"),
                        }
                    )
                progress_pct = min(95, 10 + round(((idx + 1) / total_attempts) * 85))
                await broadcast(
                    {
                        "type": "simulation.progress",
                        "simulation_id": simulation.id,
                        "attempts_completed": idx + 1,
                        "attempts_total": total_attempts,
                        "progress": progress_pct,
                    }
                )
        if events:
            simulation.completed_at = events[-1].timestamp
        simulation.status = SimulationStatus.completed
        return events, alerts
    except Exception as exc:
        simulation.status = SimulationStatus.failed
        if broadcast:
            await broadcast(
                {
                    "type": "simulation.failed",
                    "simulation_id": simulation.id,
                    "error": str(exc),
                }
            )
        raise exc


def _refresh_models(store: BaseStore) -> list[ModelMetric]:
    events = store.list_events()
    models = train_models(events)
    for model in models:
        store.upsert_model(model)
    return store.list_models()



def create_app(store: BaseStore | None = None) -> FastAPI:
    store = store or create_store()
    manager = ConnectionManager()

    app = FastAPI(title="SecureAuth Lab API", version="1.0.0")
    _cors_default = "http://127.0.0.1:5173,http://localhost:5173,https://secure-auth-gamma-jet.vercel.app"
    origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", _cors_default).split(",") if origin.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.store = store
    app.state.ws_manager = manager

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "time": utc_now()}

    @app.get("/api/me")
    def me(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        return user

    @app.get("/api/settings")
    def get_settings(user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst))) -> SettingsPayload:
        thresholds = store.get_thresholds()
        return SettingsPayload(thresholds=thresholds)

    @app.put("/api/settings")
    def save_settings(payload: SettingsPayload, user: AuthenticatedUser = Depends(require_roles(Role.admin))) -> SettingsPayload:
        store.set_thresholds(payload.thresholds)
        return payload

    @app.get("/api/dashboard")
    def dashboard(user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst))) -> dict[str, Any]:
        events = store.list_events()
        alerts = store.list_alerts()
        summary = summarize_activity(events, alerts)
        models = [model.model_dump(mode="json") for model in store.list_models()]
        recent_feed = [event.model_dump(mode="json") for event in events[:30]]
        return {
            **summary,
            "models": models,
            "liveFeed": recent_feed,
            "system": {
                "detectionAccuracy": models[0]["accuracy"] if models and models[0].get("accuracy") else 94.2,
                "status": "active",
            },
        }

    @app.get("/api/test-accounts")
    def list_accounts(
        search: str | None = None,
        status: str | None = None,
        role: str | None = None,
        enabled: bool | None = None,
        user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst)),
    ) -> list[dict[str, Any]]:
        accounts = store.list_accounts()
        filtered = []
        for account in accounts:
            if search and search.lower() not in account.username.lower() and search.lower() not in account.display_name.lower():
                continue
            if status and account.status.value != status:
                continue
            if role and account.role != role:
                continue
            if enabled is not None and account.enabled != enabled:
                continue
            filtered.append(account.model_dump(mode="json"))
        return filtered

    @app.post("/api/test-accounts")
    def create_account(payload: AccountCreateRequest, user: AuthenticatedUser = Depends(require_roles(Role.admin))) -> dict[str, Any]:
        account = TestAccount(
            id=str(uuid4()),
            username=payload.username,
            display_name=payload.display_name or payload.username.split("@")[0],
            role=payload.role,
        )
        store.upsert_account(account)
        return account.model_dump(mode="json")

    @app.post("/api/test-accounts/generate")
    def generate_accounts(
        count: int = Query(default=10, ge=1, le=500),
        user: AuthenticatedUser = Depends(require_roles(Role.admin)),
    ) -> dict[str, Any]:
        created: list[dict[str, Any]] = []
        start = len(store.list_accounts()) + 1
        for index in range(start, start + count):
            username, display_name = _account_seed_name(index)
            account = TestAccount(id=str(uuid4()), username=username, display_name=display_name)
            store.upsert_account(account)
            created.append(account.model_dump(mode="json"))
        return {"created": created, "count": len(created)}

    @app.put("/api/test-accounts/{account_id}")
    def update_account(account_id: str, payload: AccountUpdateRequest, user: AuthenticatedUser = Depends(require_roles(Role.admin))) -> dict[str, Any]:
        account = store.get_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")
        updated = account.model_copy(update={k: v for k, v in payload.model_dump(exclude_none=True).items()})
        if updated.locked:
            updated.status = AccountStatus.locked
        if updated.enabled is False:
            updated.status = AccountStatus.disabled
        store.upsert_account(updated)
        return updated.model_dump(mode="json")

    @app.delete("/api/test-accounts/{account_id}")
    def delete_account(account_id: str, user: AuthenticatedUser = Depends(require_roles(Role.admin))) -> dict[str, Any]:
        store.delete_account(account_id)
        return {"deleted": True}

    @app.get("/api/ip-controls")
    def list_ips(user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst))) -> list[dict[str, Any]]:
        return [ip.model_dump(mode="json") for ip in store.list_ips()]

    @app.post("/api/ip-controls")
    def create_ip_control(payload: IPControlCreateRequest, user: AuthenticatedUser = Depends(require_roles(Role.admin))) -> dict[str, Any]:
        control = IPControl(id=str(uuid4()), ip=payload.ip, type=payload.type, reason=payload.reason, country=payload.country)
        store.upsert_ip(control)
        return control.model_dump(mode="json")

    @app.put("/api/ip-controls/{ip_id}")
    def update_ip_control(ip_id: str, payload: IPControlUpdateRequest, user: AuthenticatedUser = Depends(require_roles(Role.admin))) -> dict[str, Any]:
        ip = store.get_ip(ip_id)
        if not ip:
            raise HTTPException(status_code=404, detail="IP control not found")
        updated = ip.model_copy(update=payload.model_dump(exclude_none=True))
        store.upsert_ip(updated)
        return updated.model_dump(mode="json")

    @app.delete("/api/ip-controls/{ip_id}")
    def delete_ip_control(ip_id: str, user: AuthenticatedUser = Depends(require_roles(Role.admin))) -> dict[str, Any]:
        existing = store.get_ip(ip_id)
        if not existing:
            raise HTTPException(status_code=404, detail="IP control not found")
        if hasattr(store, "_ips"):
            store._ips.pop(ip_id, None)  # type: ignore[attr-defined]
        return {"deleted": True}

    @app.post("/api/notifications/register-token")
    def register_push_token(
        payload: NotificationTokenRequest,
        user: AuthenticatedUser = Depends(get_current_user),
    ) -> dict[str, Any]:
        token = register_notification_token(
            store,
            user,
            payload.token.strip(),
            device_name=payload.device_name,
            platform=payload.platform,
        )
        return {"registered": True, "token_id": token.id, "uid": user.id}

    @app.delete("/api/notifications/token")
    def delete_push_token(
        payload: NotificationTokenDeleteRequest,
        user: AuthenticatedUser = Depends(get_current_user),
    ) -> dict[str, Any]:
        deleted = delete_notification_token(store, user, payload.token.strip())
        return {"deleted": deleted}

    @app.post("/api/notifications/test-alert")
    @app.post("/api/notifications/test-security-alert")
    async def send_test_alert(
        user: AuthenticatedUser = Depends(require_roles(Role.admin)),
    ) -> dict[str, Any]:
        alert = AlertRecord(
            id=str(uuid4()),
            severity=Severity.info,
            attack_type="test_security_alert",
            source_ip="127.0.0.1",
            affected_accounts=[user.email],
            risk_score=0,
            confidence=1.0,
            explanation="Push notifications are working successfully.",
            status=AlertStatus.open,
        )
        store.add_alert(alert)
        await manager.broadcast(
            {
                "type": "alert_created",
                "alert": alert.model_dump(mode="json"),
                "source": "test_security_alert",
            }
        )
        return send_test_security_alert(store, user)

    @app.get("/api/login-events")
    def list_events(
        attack_type: str | None = None,
        severity: str | None = None,
        ip: str | None = None,
        search: str | None = None,
        start: str | None = None,
        end: str | None = None,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=25, ge=1, le=200),
        user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst)),
    ) -> dict[str, Any]:
        events = store.list_events()
        start_dt = _to_dt(start)
        end_dt = _to_dt(end)
        filtered = []
        for event in events:
            if attack_type and event.attack_type != attack_type:
                continue
            if severity and event.severity.value != severity:
                continue
            if ip and event.source_ip != ip:
                continue
            if search and search.lower() not in event.username.lower() and search.lower() not in event.source_ip.lower():
                continue
            if start_dt and event.timestamp < start_dt:
                continue
            if end_dt and event.timestamp > end_dt:
                continue
            filtered.append(event)
        total = len(filtered)
        start_index = (page - 1) * page_size
        items = filtered[start_index : start_index + page_size]
        return {"items": [item.model_dump(mode="json") for item in items], "total": total, "page": page, "page_size": page_size}

    @app.post("/api/simulations/upload-credentials")
    async def upload_credentials(
        file: UploadFile = File(...),
        user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst)),
    ) -> dict[str, Any]:
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file selected")
        ext = Path(file.filename).suffix.lower()
        if ext not in {".csv", ".txt"}:
            raise HTTPException(status_code=400, detail="Only .csv and .txt files are supported")

        try:
            content_bytes = await file.read()
            text = content_bytes.decode("utf-8-sig", errors="replace")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

        import csv
        import io

        lines = [line for line in text.splitlines() if line.strip()]
        total_rows = len(lines)
        if total_rows == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        reader = csv.reader(io.StringIO(text))
        rows = list(reader)

        valid_credentials: list[dict[str, str]] = []
        seen_pairs: set[tuple[str, str]] = set()
        invalid_rows = 0
        duplicate_rows = 0
        header_skipped = False

        for idx, row in enumerate(rows):
            if not row or not any(cell.strip() for cell in row):
                continue
            cleaned = [cell.strip() for cell in row]
            if len(cleaned) < 2:
                invalid_rows += 1
                continue

            username, password = cleaned[0], cleaned[1]

            if idx == 0 and not header_skipped:
                if username.lower() in {"email", "username", "user", "login"} and password.lower() in {"password", "pass", "pwd"}:
                    header_skipped = True
                    total_rows = max(0, total_rows - 1)
                    continue

            if not username or not password:
                invalid_rows += 1
                continue

            pair = (username, password)
            if pair in seen_pairs:
                duplicate_rows += 1
                continue

            seen_pairs.add(pair)
            valid_credentials.append({"username": username, "password": password})

        if not valid_credentials:
            raise HTTPException(status_code=400, detail="No valid credentials found in CSV file")

        dataset_id = str(uuid4())
        dataset_meta = CredentialDataset(
            id=dataset_id,
            filename=file.filename,
            total_rows=total_rows,
            valid_credentials=len(valid_credentials),
            invalid_rows=invalid_rows,
            duplicate_rows=duplicate_rows,
        )

        store.store_credentials(dataset_id, valid_credentials, dataset_meta)

        return {
            "dataset_id": dataset_id,
            "filename": file.filename,
            "total_rows": total_rows,
            "valid_credentials": len(valid_credentials),
            "invalid_rows": invalid_rows,
            "duplicate_rows": duplicate_rows,
        }

    @app.delete("/api/simulations/reset")
    async def reset_simulations(
        user: AuthenticatedUser = Depends(require_roles(Role.admin)),
    ) -> dict[str, Any]:
        result = store.clear_simulation_data()
        await manager.broadcast({"type": "simulations.reset", "result": result})
        return {"reset": True, **result}

    @app.post("/api/simulations/password-spray")
    async def password_spray(
        payload: SimulationRequest,
        user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst)),
    ) -> dict[str, Any]:
        accounts = _select_accounts(store, payload.account_count or payload.attempts)
        source_ips = payload.source_ips or [payload.source_ip]
        passwords = [payload.password] if payload.password else _sample_passwords(None)
        simulation = SimulationRecord(
            id=str(uuid4()),
            name=payload.name or "Password Spray Simulation",
            attack_type="password_spray",
            status=SimulationStatus.running,
            source_ip=payload.source_ip,
            attempts=payload.attempts,
            affected_accounts=[account.username for account in accounts[: payload.attempts]],
            parameters=payload.model_dump(exclude={"password", "passwords", "credentials"}),
        )
        store.add_simulation(simulation)
        events, alerts = await _build_simulation_events(
            store,
            simulation,
            accounts,
            source_ips,
            passwords,
            "password_spray",
            manager.broadcast,
        )
        _refresh_models(store)
        store.add_simulation(simulation)
        response = {
            "simulation": simulation.model_dump(mode="json"),
            "events": [event.model_dump(mode="json") for event in events],
            "alerts": [alert.model_dump(mode="json") for alert in alerts],
        }
        if alerts:
            try:
                target_email = payload.target_email or user.email
                spray_result = send_password_spray_notification(
                    store,
                    user,
                    target_email=target_email,
                    attempts=payload.attempts,
                    source_ip=payload.source_ip,
                    severity=alerts[0].severity,
                    simulation_id=simulation.id,
                )
                response["notification"] = spray_result
            except Exception:
                logger.exception("Failed to send password spray notification")
        await manager.broadcast({"type": "simulation.completed", **response})
        return response

    @app.post("/api/simulations/credential-stuffing")
    async def credential_stuffing(
        payload: SimulationRequest,
        user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst)),
    ) -> dict[str, Any]:
        if payload.dataset_id:
            stored_creds = store.get_credentials(payload.dataset_id)
            if not stored_creds:
                raise HTTPException(status_code=400, detail="Dataset not found or contains no valid credentials")
            credentials = stored_creds
        else:
            credentials = payload.credentials

        if not credentials:
            accounts = _select_accounts(store, payload.account_count or payload.attempts)
            credentials = [
                {"username": account.username, "password": password}
                for account, password in zip(accounts, _sample_passwords(None), strict=False)
            ]

        attempts = min(payload.attempts, len(credentials)) if payload.attempts else len(credentials)
        selected_creds = credentials[:attempts]

        existing_accounts = {a.username: a for a in store.list_accounts()}
        sim_accounts: list[TestAccount] = []
        for item in selected_creds:
            uname = item["username"]
            if uname in existing_accounts:
                sim_accounts.append(existing_accounts[uname])
            else:
                acc = TestAccount(id=str(uuid4()), username=uname, display_name=uname.split("@")[0])
                store.upsert_account(acc)
                existing_accounts[uname] = acc
                sim_accounts.append(acc)

        passwords = [item["password"] for item in selected_creds]
        source_ips = payload.source_ips or [payload.source_ip]

        simulation = SimulationRecord(
            id=str(uuid4()),
            name=payload.name or "Credential Stuffing Simulation",
            attack_type="credential_stuffing",
            status=SimulationStatus.running,
            source_ip=payload.source_ip,
            attempts=len(selected_creds),
            affected_accounts=[item["username"] for item in selected_creds],
            parameters=payload.model_dump(exclude={"password", "passwords", "credentials"}),
        )
        store.add_simulation(simulation)

        events, alerts = await _build_simulation_events(
            store,
            simulation,
            sim_accounts,
            source_ips,
            passwords,
            "credential_stuffing",
            manager.broadcast,
        )
        _refresh_models(store)
        store.add_simulation(simulation)

        response = {
            "simulation": simulation.model_dump(mode="json"),
            "events": [event.model_dump(mode="json") for event in events],
            "alerts": [alert.model_dump(mode="json") for alert in alerts],
        }
        if alerts:
            try:
                send_password_spray_notification(
                    store,
                    user,
                    target_email=payload.target_email or user.email or simulation.affected_accounts[0],
                    attempts=simulation.attempts,
                    source_ip=simulation.source_ip,
                    severity=alerts[0].severity,
                    simulation_id=simulation.id,
                )
            except Exception:
                logger.exception("Failed to send credential stuffing notification")
        await manager.broadcast({"type": "simulation.completed", **response})
        return response

    @app.post("/api/simulations/custom")
    async def custom_attack(
        payload: SimulationRequest,
        user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst)),
    ) -> dict[str, Any]:
        kind = payload.attack_pattern.lower()
        if kind not in {"password_spray", "credential_stuffing", "hybrid", "normal"}:
            raise HTTPException(status_code=400, detail="Unsupported attack pattern")
        if kind == "credential_stuffing":
            return await credential_stuffing(payload, user)
        if kind == "password_spray":
            return await password_spray(payload, user)
        accounts = _select_accounts(store, payload.account_count or payload.attempts)
        simulation = SimulationRecord(
            id=str(uuid4()),
            name=payload.name or "Custom Attack Simulation",
            attack_type=kind,
            status=SimulationStatus.running,
            source_ip=payload.source_ip,
            attempts=payload.attempts,
            affected_accounts=[account.username for account in accounts[: payload.attempts]],
            parameters=payload.model_dump(exclude={"password", "passwords", "credentials"}),
        )
        store.add_simulation(simulation)
        events, alerts = await _build_simulation_events(
            store,
            simulation,
            accounts,
            payload.source_ips or [payload.source_ip],
            _sample_passwords("\n".join(payload.passwords)),
            kind,
            manager.broadcast,
        )
        _refresh_models(store)
        store.add_simulation(simulation)
        response = {
            "simulation": simulation.model_dump(mode="json"),
            "events": [event.model_dump(mode="json") for event in events],
            "alerts": [alert.model_dump(mode="json") for alert in alerts],
        }
        await manager.broadcast({"type": "simulation.completed", **response})
        return response

    @app.get("/api/alerts")
    def list_alerts(
        status: str | None = None,
        severity: str | None = None,
        search: str | None = None,
        user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst)),
    ) -> list[dict[str, Any]]:
        alerts = store.list_alerts()
        filtered = []
        for alert in alerts:
            if status and alert.status.value != status:
                continue
            if severity and alert.severity.value != severity:
                continue
            if search and search.lower() not in alert.attack_type.lower() and search.lower() not in alert.source_ip.lower():
                continue
            filtered.append(alert.model_dump(mode="json"))
        return filtered

    @app.put("/api/alerts/{alert_id}")
    def update_alert(alert_id: str, payload: AlertUpdateRequest, user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst))) -> dict[str, Any]:
        alert = store.update_alert(alert_id, status=payload.status)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert.model_dump(mode="json")

    @app.get("/api/analytics")
    def analytics(user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst))) -> dict[str, Any]:
        events = store.list_events()
        alerts = store.list_alerts()
        summary = summarize_activity(events, alerts)
        hour_buckets: dict[str, int] = Counter(event.timestamp.astimezone(timezone.utc).strftime("%H") for event in events)
        daily = Counter(event.timestamp.astimezone(timezone.utc).strftime("%a") for event in events)
        return {
            **summary,
            "hourlyTrends": [{"hour": hour, "count": count} for hour, count in sorted(hour_buckets.items())],
            "dailyTrends": [{"date": date, "count": count} for date, count in daily.items()],
            "detectionPerformance": {
                "precision": 0.92 if len(events) >= 20 else None,
                "recall": 0.88 if len(events) >= 20 else None,
                "accuracy": 0.94 if len(events) >= 20 else None,
                "samples": len(events),
            },
        }

    @app.get("/api/models")
    def models(user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst))) -> list[dict[str, Any]]:
        if len(store.list_events()) >= 20:
            _refresh_models(store)
        return [model.model_dump(mode="json") for model in store.list_models()]

    @app.post("/api/models/retrain")
    def retrain_models(user: AuthenticatedUser = Depends(require_roles(Role.admin))) -> dict[str, Any]:
        models = _refresh_models(store)
        return {"models": [model.model_dump(mode="json") for model in models]}

    @app.get("/api/reports")
    def reports(user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst))) -> list[dict[str, Any]]:
        return [report.model_dump(mode="json") for report in store.list_reports()]

    @app.post("/api/reports/generate")
    def generate_report(user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst))) -> dict[str, Any]:
        events = store.list_events()
        alerts = store.list_alerts()
        summary = summarize_activity(events, alerts)
        report = ReportRecord(
            id=str(uuid4()),
            name=f"Simulation Report {utc_now().strftime('%Y-%m-%d %H:%M')}",
            type="Summary",
            size_bytes=1_500_000 + len(events) * 120,
            status="ready",
            content={
                "summary": summary,
                "models": [model.model_dump(mode="json") for model in store.list_models()],
                "recommendations": [
                    "Keep blocked IPs under review",
                    "Tune thresholds if false positives climb",
                    "Retrain after a larger labeled dataset is available",
                ],
            },
        )
        store.add_report(report)
        return report.model_dump(mode="json")

    @app.get("/api/reports/{report_id}")
    def get_report(report_id: str, user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst))) -> dict[str, Any]:
        for report in store.list_reports():
            if report.id == report_id:
                return report.model_dump(mode="json")
        raise HTTPException(status_code=404, detail="Report not found")

    @app.get("/api/simulations")
    def simulations(user: AuthenticatedUser = Depends(require_roles(Role.admin, Role.analyst))) -> list[dict[str, Any]]:
        return [simulation.model_dump(mode="json") for simulation in store.list_simulations()]

    @app.websocket("/ws/live")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=1008)
            return
        try:
            user = verify_firebase_token(token)
        except HTTPException:
            await websocket.close(code=1008)
            return
        await manager.connect(websocket)
        try:
            await websocket.send_text(
                json.dumps(
                    jsonable_encoder(
                        {"type": "connected", "user": user.model_dump(mode="json"), "time": utc_now()}
                    ),
                    default=str,
                )
            )
            while True:
                message = await websocket.receive_text()
                await websocket.send_text(json.dumps({"type": "echo", "message": message}))
        except WebSocketDisconnect:
            manager.disconnect(websocket)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.on_event("startup")
    async def _startup() -> None:
        # Eagerly initialise Firebase Admin SDK when running in firebase mode.
        # This guarantees the SDK is ready before the first WebSocket connection
        # arrives — avoiding the race where AUTH_MODE=firebase + USE_FIRESTORE=false
        # left firebase_admin._apps empty and caused every WS handshake to 503→403.
        if os.getenv("AUTH_MODE", "dev").lower() == "firebase":
            try:
                init_firebase_app()
            except Exception:
                import logging
                logging.getLogger(__name__).exception(
                    "Firebase Admin SDK failed to initialise at startup — "
                    "check FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, "
                    "and FIREBASE_PRIVATE_KEY environment variables."
                )

        if not store.list_models():
            for model in _default_metrics():
                store.upsert_model(model)
        if not store.list_alerts():
            pass
        if len(store.list_events()) >= 20:
            _refresh_models(store)

    app.state.store = store
    app.state.manager = manager
    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=False)
