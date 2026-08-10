from __future__ import annotations

import json
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from uuid import uuid4

from .models import (
    AccountStatus,
    AlertRecord,
    AlertStatus,
    IPControl,
    IPControlType,
    LoginEvent,
    ModelMetric,
    ReportRecord,
    Role,
    SimulationRecord,
    SimulationStatus,
    TestAccount,
    Thresholds,
    UserProfile,
    utc_now,
)


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if hasattr(value, "value"):
        return value.value
    return str(value)


def _parse_dt(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


class BaseStore:
    def get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        raise NotImplementedError

    def upsert_user_profile(self, profile: UserProfile) -> UserProfile:
        raise NotImplementedError

    def list_accounts(self) -> list[TestAccount]:
        raise NotImplementedError

    def upsert_account(self, account: TestAccount) -> TestAccount:
        raise NotImplementedError

    def get_account(self, account_id: str) -> Optional[TestAccount]:
        raise NotImplementedError

    def delete_account(self, account_id: str) -> None:
        raise NotImplementedError

    def list_ips(self) -> list[IPControl]:
        raise NotImplementedError

    def upsert_ip(self, control: IPControl) -> IPControl:
        raise NotImplementedError

    def get_ip(self, ip_id: str) -> Optional[IPControl]:
        raise NotImplementedError

    def list_events(self) -> list[LoginEvent]:
        raise NotImplementedError

    def add_event(self, event: LoginEvent) -> LoginEvent:
        raise NotImplementedError

    def list_alerts(self) -> list[AlertRecord]:
        raise NotImplementedError

    def add_alert(self, alert: AlertRecord) -> AlertRecord:
        raise NotImplementedError

    def update_alert(self, alert_id: str, **patch: Any) -> Optional[AlertRecord]:
        raise NotImplementedError

    def list_simulations(self) -> list[SimulationRecord]:
        raise NotImplementedError

    def add_simulation(self, simulation: SimulationRecord) -> SimulationRecord:
        raise NotImplementedError

    def list_models(self) -> list[ModelMetric]:
        raise NotImplementedError

    def upsert_model(self, model: ModelMetric) -> ModelMetric:
        raise NotImplementedError

    def list_reports(self) -> list[ReportRecord]:
        raise NotImplementedError

    def add_report(self, report: ReportRecord) -> ReportRecord:
        raise NotImplementedError

    def get_thresholds(self) -> Thresholds:
        raise NotImplementedError

    def set_thresholds(self, thresholds: Thresholds) -> Thresholds:
        raise NotImplementedError


class MemoryStore(BaseStore):
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users: dict[str, UserProfile] = {}
        self._accounts: dict[str, TestAccount] = {}
        self._ips: dict[str, IPControl] = {}
        self._events: dict[str, LoginEvent] = {}
        self._alerts: dict[str, AlertRecord] = {}
        self._simulations: dict[str, SimulationRecord] = {}
        self._models: dict[str, ModelMetric] = {}
        self._reports: dict[str, ReportRecord] = {}
        self._thresholds = Thresholds()
        self._seed()

    def _seed(self) -> None:
        admin = UserProfile(id="admin-1", email="admin@lab.local", name="Lab Admin", role=Role.admin)
        analyst = UserProfile(id="analyst-1", email="analyst@lab.local", name="Lab Analyst", role=Role.analyst)
        self._users[admin.id] = admin
        self._users[analyst.id] = analyst
        seeded_accounts = [
            ("john.doe@lab.com", "John Doe", "Standard User"),
            ("alice@lab.com", "Alice", "Standard User"),
            ("charlie@lab.com", "Charlie", "Admin"),
            ("bob@lab.com", "Bob", "Standard User"),
            ("admin@lab.com", "Admin", "Super Admin"),
            ("michael@lab.com", "Michael", "Standard User"),
        ]
        for idx, (username, display_name, role) in enumerate(seeded_accounts, start=1):
            account = TestAccount(
                id=str(idx),
                username=username,
                display_name=display_name,
                role=role,
                attempts=idx * 6,
                locked=idx in (3, 6),
                status=AccountStatus.locked if idx in (3, 6) else AccountStatus.active,
                last_login=utc_now(),
            )
            self._accounts[account.id] = account
        for idx, (ip, reason, kind) in enumerate(
            [
                ("185.199.110.24", "Credential Stuffing", IPControlType.blocked),
                ("198.51.100.23", "Password Spray", IPControlType.blocked),
                ("203.0.113.45", "Lab server", IPControlType.allowlisted),
                ("91.108.4.200", "Brute Force", IPControlType.blocked),
                ("10.0.0.0/24", "Internal network", IPControlType.allowlisted),
            ],
            start=1,
        ):
            self._ips[str(idx)] = IPControl(
                id=str(idx),
                ip=ip,
                reason=reason,
                type=kind,
                attempts=42 if kind == IPControlType.blocked else 0,
                country="US" if "10.0" not in ip else "N/A",
            )
        self._models["rule-based"] = ModelMetric(
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
            notes="Primary detector",
        )
        self._models["random-forest"] = ModelMetric(
            id="random-forest",
            name="Random Forest Classifier",
            type="ML Model",
            status="inactive",
            version="v1.0.0",
            accuracy=None,
            detections=0,
            false_positives=0,
            training_samples=0,
            notes="Insufficient labeled training data",
        )
        self._models["isolation-forest"] = ModelMetric(
            id="isolation-forest",
            name="IsolationForest Anomaly Detector",
            type="Anomaly",
            status="training",
            version="v1.0.0",
            accuracy=None,
            detections=0,
            false_positives=0,
            training_samples=0,
            notes="Awaiting more event history",
        )
        self._reports["weekly"] = ReportRecord(
            id="weekly",
            name="Weekly Attack Summary",
            type="Summary",
            size_bytes=2_400_000,
            content={"summary": "Seeded report"},
        )

    def get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        return self._users.get(user_id)

    def upsert_user_profile(self, profile: UserProfile) -> UserProfile:
        with self._lock:
            profile.updated_at = utc_now()
            self._users[profile.id] = profile
        return profile

    def list_accounts(self) -> list[TestAccount]:
        return sorted(self._accounts.values(), key=lambda item: item.created_at)

    def upsert_account(self, account: TestAccount) -> TestAccount:
        with self._lock:
            account.updated_at = utc_now()
            self._accounts[account.id] = account
        return account

    def get_account(self, account_id: str) -> Optional[TestAccount]:
        return self._accounts.get(account_id)

    def delete_account(self, account_id: str) -> None:
        with self._lock:
            self._accounts.pop(account_id, None)

    def list_ips(self) -> list[IPControl]:
        return sorted(self._ips.values(), key=lambda item: item.created_at)

    def upsert_ip(self, control: IPControl) -> IPControl:
        with self._lock:
            control.updated_at = utc_now()
            self._ips[control.id] = control
        return control

    def get_ip(self, ip_id: str) -> Optional[IPControl]:
        return self._ips.get(ip_id)

    def find_ip(self, ip: str) -> Optional[IPControl]:
        return next((item for item in self._ips.values() if item.ip == ip), None)

    def list_events(self) -> list[LoginEvent]:
        return sorted(self._events.values(), key=lambda item: item.timestamp, reverse=True)

    def add_event(self, event: LoginEvent) -> LoginEvent:
        with self._lock:
            self._events[event.id] = event
        return event

    def list_alerts(self) -> list[AlertRecord]:
        return sorted(self._alerts.values(), key=lambda item: item.timestamp, reverse=True)

    def add_alert(self, alert: AlertRecord) -> AlertRecord:
        with self._lock:
            self._alerts[alert.id] = alert
        return alert

    def update_alert(self, alert_id: str, **patch: Any) -> Optional[AlertRecord]:
        with self._lock:
            alert = self._alerts.get(alert_id)
            if not alert:
                return None
            updated = alert.model_copy(update=patch)
            self._alerts[alert_id] = updated
            return updated

    def list_simulations(self) -> list[SimulationRecord]:
        return sorted(self._simulations.values(), key=lambda item: item.created_at, reverse=True)

    def add_simulation(self, simulation: SimulationRecord) -> SimulationRecord:
        with self._lock:
            self._simulations[simulation.id] = simulation
        return simulation

    def list_models(self) -> list[ModelMetric]:
        return sorted(self._models.values(), key=lambda item: item.name)

    def upsert_model(self, model: ModelMetric) -> ModelMetric:
        with self._lock:
            model.updated = utc_now()
            self._models[model.id] = model
        return model

    def list_reports(self) -> list[ReportRecord]:
        return sorted(self._reports.values(), key=lambda item: item.generated_at, reverse=True)

    def add_report(self, report: ReportRecord) -> ReportRecord:
        with self._lock:
            self._reports[report.id] = report
        return report

    def get_thresholds(self) -> Thresholds:
        return self._thresholds.model_copy()

    def set_thresholds(self, thresholds: Thresholds) -> Thresholds:
        self._thresholds = thresholds
        return self._thresholds

    def export_summary(self) -> dict[str, Any]:
        return {
            "users": len(self._users),
            "accounts": len(self._accounts),
            "ips": len(self._ips),
            "events": len(self._events),
            "alerts": len(self._alerts),
            "simulations": len(self._simulations),
            "reports": len(self._reports),
            "models": len(self._models),
        }


class FirestoreStore(BaseStore):
    def __init__(self, project_id: str | None = None) -> None:
        # Delegate all credential resolution and SDK initialisation to the
        # shared firebase_init module so the logic is never duplicated.
        from .firebase_init import init_firebase_app
        from firebase_admin import firestore

        self._project_id = project_id
        init_firebase_app()
        self._db = firestore.client()

    def _col(self, name: str):
        return self._db.collection(name)

    def _dump(self, model: Any) -> dict[str, Any]:
        return json.loads(json.dumps(model.model_dump(mode="json"), default=_json_default))

    def _load_time_fields(self, payload: dict[str, Any], fields: Iterable[str]) -> dict[str, Any]:
        for field in fields:
            if field in payload:
                payload[field] = _parse_dt(payload[field])
        return payload

    def _all(self, collection: str, model_cls):
        docs = self._col(collection).stream()
        items = []
        for doc in docs:
            payload = doc.to_dict() or {}
            payload["id"] = doc.id
            items.append(model_cls(**self._load_time_fields(payload, [])))
        return items

    def _doc(self, collection: str, doc_id: str):
        snapshot = self._col(collection).document(doc_id).get()
        return snapshot.to_dict() if snapshot.exists else None

    def get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        payload = self._doc("users", user_id)
        return UserProfile(**payload) if payload else None

    def upsert_user_profile(self, profile: UserProfile) -> UserProfile:
        self._col("users").document(profile.id).set(self._dump(profile), merge=True)
        return profile

    def list_accounts(self) -> list[TestAccount]:
        return self._all("test_accounts", TestAccount)

    def upsert_account(self, account: TestAccount) -> TestAccount:
        self._col("test_accounts").document(account.id).set(self._dump(account), merge=True)
        return account

    def get_account(self, account_id: str) -> Optional[TestAccount]:
        payload = self._doc("test_accounts", account_id)
        return TestAccount(**payload) if payload else None

    def delete_account(self, account_id: str) -> None:
        self._col("test_accounts").document(account_id).delete()

    def list_ips(self) -> list[IPControl]:
        return self._all("ip_controls", IPControl)

    def upsert_ip(self, control: IPControl) -> IPControl:
        self._col("ip_controls").document(control.id).set(self._dump(control), merge=True)
        return control

    def get_ip(self, ip_id: str) -> Optional[IPControl]:
        payload = self._doc("ip_controls", ip_id)
        return IPControl(**payload) if payload else None

    def list_events(self) -> list[LoginEvent]:
        return self._all("login_events", LoginEvent)

    def add_event(self, event: LoginEvent) -> LoginEvent:
        self._col("login_events").document(event.id).set(self._dump(event))
        return event

    def list_alerts(self) -> list[AlertRecord]:
        return self._all("alerts", AlertRecord)

    def add_alert(self, alert: AlertRecord) -> AlertRecord:
        self._col("alerts").document(alert.id).set(self._dump(alert))
        return alert

    def update_alert(self, alert_id: str, **patch: Any) -> Optional[AlertRecord]:
        ref = self._col("alerts").document(alert_id)
        snap = ref.get()
        if not snap.exists:
            return None
        payload = snap.to_dict() or {}
        payload.update(patch)
        ref.set(payload, merge=True)
        return AlertRecord(id=alert_id, **payload)

    def list_simulations(self) -> list[SimulationRecord]:
        return self._all("simulations", SimulationRecord)

    def add_simulation(self, simulation: SimulationRecord) -> SimulationRecord:
        self._col("simulations").document(simulation.id).set(self._dump(simulation))
        return simulation

    def list_models(self) -> list[ModelMetric]:
        return self._all("model_metrics", ModelMetric)

    def upsert_model(self, model: ModelMetric) -> ModelMetric:
        self._col("model_metrics").document(model.id).set(self._dump(model), merge=True)
        return model

    def list_reports(self) -> list[ReportRecord]:
        return self._all("reports", ReportRecord)

    def add_report(self, report: ReportRecord) -> ReportRecord:
        self._col("reports").document(report.id).set(self._dump(report))
        return report

    def get_thresholds(self) -> Thresholds:
        snap = self._col("settings").document("thresholds").get()
        if snap.exists:
            data = snap.to_dict() or {}
            return Thresholds(**data)
        return Thresholds()

    def set_thresholds(self, thresholds: Thresholds) -> Thresholds:
        self._col("settings").document("thresholds").set(thresholds.model_dump(mode="json"), merge=True)
        return thresholds

