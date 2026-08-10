from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, Enum):
    admin = "admin"
    analyst = "analyst"
    user = "user"


class AccountStatus(str, Enum):
    active = "active"
    disabled = "disabled"
    locked = "locked"
    suspended = "suspended"


class IPControlType(str, Enum):
    blocked = "blocked"
    allowlisted = "allowlisted"


class AlertStatus(str, Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class AttackType(str, Enum):
    normal = "NORMAL"
    suspicious = "SUSPICIOUS"
    password_spray = "PASSWORD_SPRAY"
    credential_stuffing = "CREDENTIAL_STUFFING"
    high_risk = "HIGH_RISK"


class DetectionMethod(str, Enum):
    rule_based = "rule_based"
    anomaly_detection = "anomaly_detection"
    classification = "classification"
    hybrid = "hybrid"


class UserProfile(BaseModel):
    id: str
    email: str
    name: str
    role: Role
    status: str = "active"
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class TestAccount(BaseModel):
    id: str
    username: str
    display_name: str
    role: str = "Standard User"
    status: AccountStatus = AccountStatus.active
    enabled: bool = True
    locked: bool = False
    attempts: int = 0
    last_login: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class IPControl(BaseModel):
    id: str
    ip: str
    type: IPControlType
    reason: str = "Manual"
    attempts: int = 0
    country: str = "N/A"
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class SimulationStatus(str, Enum):
    running = "running"
    completed = "completed"
    failed = "failed"


class SimulationRecord(BaseModel):
    id: str
    name: str
    attack_type: str
    status: SimulationStatus = SimulationStatus.completed
    source_ip: str
    attempts: int
    affected_accounts: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None


class LoginEvent(BaseModel):
    id: str
    timestamp: datetime = Field(default_factory=utc_now)
    username: str
    test_account_id: str
    source_ip: str
    password_ref: str
    success: bool
    simulation_id: str
    attack_type: str
    user_agent: str = "SecureAuth-Lab/1.0"
    risk_score: int = 0
    severity: Severity = Severity.info
    confidence: float = 0.0
    detection_method: DetectionMethod = DetectionMethod.rule_based
    explanation: str = ""
    blocked: bool = False
    attack_class: AttackType = AttackType.normal
    labels: dict[str, Any] = Field(default_factory=dict)


class AlertRecord(BaseModel):
    id: str
    severity: Severity
    attack_type: str
    source_ip: str
    affected_accounts: list[str] = Field(default_factory=list)
    risk_score: int
    confidence: float
    explanation: str
    timestamp: datetime = Field(default_factory=utc_now)
    status: AlertStatus = AlertStatus.open
    event_id: Optional[str] = None


class ModelMetric(BaseModel):
    id: str
    name: str
    type: str
    status: Literal["active", "inactive", "training", "error"]
    version: str
    updated: datetime = Field(default_factory=utc_now)
    training_samples: int = 0
    anomaly_statistics: dict[str, Any] = Field(default_factory=dict)
    detections: int = 0
    false_positives: int = 0
    accuracy: Optional[float] = None
    last_trained_at: Optional[datetime] = None
    notes: str = ""


class ReportRecord(BaseModel):
    id: str
    name: str
    type: str
    generated_at: datetime = Field(default_factory=utc_now)
    size_bytes: int = 0
    status: Literal["ready", "generating"] = "ready"
    content: dict[str, Any] = Field(default_factory=dict)


class Thresholds(BaseModel):
    password_spray_unique_accounts: int = 8
    password_spray_attempts: int = 12
    credential_stuffing_unique_users: int = 4
    failure_ratio: float = 0.75
    repeated_failures: int = 5
    time_window_attempts: int = 20
    blocked_ip_risk_bonus: int = 25
    risk_alert_threshold: int = 70
    high_risk_threshold: int = 85


class AuthenticatedUser(BaseModel):
    id: str
    email: str
    name: str
    role: Role
    token_source: str = "firebase"


class SimulationRequest(BaseModel):
    name: str | None = None
    source_ip: str
    attempts: int = Field(ge=1, le=5000)
    delay_seconds: float = Field(default=0.0, ge=0.0, le=10.0)
    account_count: int | None = Field(default=None, ge=1, le=5000)
    attack_pattern: str = "password_spray"
    password: str | None = None
    passwords: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    credentials: list[dict[str, str]] = Field(default_factory=list)
    rotate_ips: bool = False


class AccountCreateRequest(BaseModel):
    username: str
    display_name: str | None = None
    role: str = "Standard User"


class AccountUpdateRequest(BaseModel):
    username: str | None = None
    display_name: str | None = None
    role: str | None = None
    enabled: bool | None = None
    locked: bool | None = None
    status: AccountStatus | None = None


class IPControlCreateRequest(BaseModel):
    ip: str
    type: IPControlType = IPControlType.blocked
    reason: str = "Manual"
    country: str = "N/A"


class IPControlUpdateRequest(BaseModel):
    type: IPControlType | None = None
    reason: str | None = None
    country: str | None = None
    attempts: int | None = None


class AlertUpdateRequest(BaseModel):
    status: AlertStatus


class SettingsPayload(BaseModel):
    thresholds: Thresholds = Field(default_factory=Thresholds)
    system_name: str = "SecureAuth Lab"
    timezone: str = "UTC"
    auto_block: bool = True
    realtime_monitoring: bool = True
