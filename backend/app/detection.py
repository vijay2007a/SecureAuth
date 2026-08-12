from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
import hashlib
import math
from uuid import uuid4

from sklearn.ensemble import IsolationForest, RandomForestClassifier

from .models import (
    AlertRecord,
    AttackType,
    DetectionMethod,
    LoginEvent,
    ModelMetric,
    Severity,
    Thresholds,
    utc_now,
)


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def password_ref(password: str | None) -> str:
    if not password:
        return "password:none"
    return f"sha256:{_hash_value(password)}"


def severity_from_score(score: int) -> Severity:
    if score >= 90:
        return Severity.critical
    if score >= 75:
        return Severity.high
    if score >= 50:
        return Severity.medium
    if score >= 25:
        return Severity.low
    return Severity.info


def attack_class_from_score(score: int, rules: dict[str, bool]) -> AttackType:
    if score >= 85:
        return AttackType.high_risk
    if rules.get("credential_stuffing"):
        return AttackType.credential_stuffing
    if rules.get("password_spray"):
        return AttackType.password_spray
    if score >= 50:
        return AttackType.suspicious
    return AttackType.normal


def make_features(events: list[LoginEvent], current: LoginEvent) -> dict[str, float]:
    if not events:
        return {
            "attempt_frequency": 1.0,
            "failure_ratio": 0.0 if current.success else 1.0,
            "unique_accounts": 1.0,
            "unique_passwords": 1.0,
            "unique_ips": 1.0,
            "account_ip_ratio": 1.0,
            "time_window_concentration": 1.0,
            "success_after_failure": 0.0,
        }

    same_ip = [event for event in events if event.source_ip == current.source_ip]
    failures = [event for event in same_ip if not event.success]
    usernames = {event.username for event in same_ip}
    passwords = {event.password_ref for event in same_ip}
    ips = {event.source_ip for event in same_ip}
    window_seconds = max(
        1.0,
        (max(event.timestamp for event in same_ip) - min(event.timestamp for event in same_ip)).total_seconds(),
    ) if same_ip else 1.0
    recent_window = [event for event in same_ip if (current.timestamp - event.timestamp).total_seconds() <= 300]
    success_after_failure = 1.0 if any(event.success for event in same_ip[:-1]) and not current.success else 0.0
    return {
        "attempt_frequency": float(len(recent_window)),
        "failure_ratio": float(len(failures)) / max(1, len(same_ip)),
        "unique_accounts": float(len(usernames)),
        "unique_passwords": float(len(passwords)),
        "unique_ips": float(len(ips)),
        "account_ip_ratio": float(len(usernames)) / max(1, len(ips)),
        "time_window_concentration": float(len(recent_window)) / max(1.0, window_seconds / 60.0),
        "success_after_failure": success_after_failure,
    }


def _score_rules(
    events: list[LoginEvent],
    current: LoginEvent,
    thresholds: Thresholds,
    blocked_ips: set[str] | None = None,
) -> tuple[int, dict[str, bool], str]:
    same_ip = [event for event in events if event.source_ip == current.source_ip]
    same_account = [event for event in events if event.username == current.username]
    failures_same_ip = [event for event in same_ip if not event.success]
    failures_same_account = [event for event in same_account if not event.success]
    unique_accounts = len({event.username for event in same_ip})
    unique_passwords = len({event.password_ref for event in same_ip})
    high_attempt_window = len([event for event in same_ip if (current.timestamp - event.timestamp).total_seconds() <= 300])
    failure_ratio = len(failures_same_ip) / max(1, len(same_ip))
    blocked_ip = current.source_ip in (blocked_ips or set())

    rules = {
        "password_spray": unique_accounts >= thresholds.password_spray_unique_accounts and unique_passwords <= 2,
        "credential_stuffing": unique_passwords >= 2 and unique_accounts >= thresholds.credential_stuffing_unique_users,
        "repeated_failures": len(failures_same_account) >= thresholds.repeated_failures,
        "high_failure_rate": failure_ratio >= thresholds.failure_ratio,
        "time_window": high_attempt_window >= thresholds.time_window_attempts,
        "success_after_failure": any(event.success for event in same_account[:-1]) and not current.success,
        "blocked_ip": blocked_ip,
    }

    score = 10
    explanation_parts: list[str] = []
    if rules["password_spray"]:
        score += 45
        explanation_parts.append("one source IP is targeting many accounts with a limited password set")
    if rules["credential_stuffing"]:
        score += 50
        explanation_parts.append("multiple username/password pairs are being tested against many accounts")
    if rules["repeated_failures"]:
        score += 15
        explanation_parts.append("the same account has repeated failures")
    if rules["high_failure_rate"]:
        score += 10
        explanation_parts.append("the failure rate is unusually high")
    if rules["time_window"]:
        score += 10
        explanation_parts.append("attempts are concentrated in a short time window")
    if rules["success_after_failure"]:
        score += 10
        explanation_parts.append("a success followed repeated failures")
    if blocked_ip:
        score += thresholds.blocked_ip_risk_bonus
        explanation_parts.append("the source IP is blocked by IP Controls")

    score = min(100, score)
    explanation = "; ".join(explanation_parts) if explanation_parts else "activity is within normal bounds"
    return score, rules, explanation


def _ml_confidence(features: dict[str, float], rule_score: int, iso_anomaly: bool, rf_confidence: float | None) -> tuple[float, str]:
    confidence = min(0.99, max(0.25, rule_score / 100.0))
    if iso_anomaly:
        confidence = min(0.99, confidence + 0.12)
    if rf_confidence is not None:
        confidence = min(0.99, (confidence + rf_confidence) / 2.0)
    method = DetectionMethod.rule_based if not iso_anomaly and rf_confidence is None else DetectionMethod.hybrid
    return confidence, method.value


class ModelBundle:
    def __init__(self) -> None:
        self.isolation_forest: IsolationForest | None = None
        self.random_forest: RandomForestClassifier | None = None
        self.feature_names = [
            "attempt_frequency",
            "failure_ratio",
            "unique_accounts",
            "unique_passwords",
            "unique_ips",
            "account_ip_ratio",
            "time_window_concentration",
            "success_after_failure",
        ]

    def vectorize(self, features: dict[str, float]) -> list[float]:
        return [float(features.get(name, 0.0)) for name in self.feature_names]


MODEL_BUNDLE = ModelBundle()


def analyze_event(
    events: list[LoginEvent],
    current: LoginEvent,
    thresholds: Thresholds,
    blocked_ips: set[str] | None = None,
) -> tuple[int, Severity, float, AttackType, DetectionMethod, str, bool, dict[str, bool], dict[str, float]]:
    score, rules, explanation = _score_rules(events, current, thresholds, blocked_ips=blocked_ips)
    attack_class = attack_class_from_score(score, rules)
    severity = severity_from_score(score)
    features = make_features(events, current)
    iso_anomaly = False
    rf_confidence: float | None = None

    if MODEL_BUNDLE.isolation_forest and len(events) >= 20:
        prediction = MODEL_BUNDLE.isolation_forest.predict([MODEL_BUNDLE.vectorize(features)])[0]
        iso_anomaly = bool(prediction == -1)
        if iso_anomaly:
            score = min(100, score + 8)
            severity = severity_from_score(score)
            explanation = f"{explanation}; anomaly detector flagged the event"

    if MODEL_BUNDLE.random_forest and len(events) >= 30:
        rf_prob = MODEL_BUNDLE.random_forest.predict_proba([MODEL_BUNDLE.vectorize(features)])[0]
        rf_confidence = float(max(rf_prob))
        if rf_confidence > 0.75:
            score = min(100, score + 5)
            severity = severity_from_score(score)
            explanation = f"{explanation}; classifier confidence is {rf_confidence:.2f}"

    confidence, method = _ml_confidence(features, score, iso_anomaly, rf_confidence)
    blocked = rules.get("blocked_ip", False) or score >= thresholds.high_risk_threshold
    return score, severity, confidence, attack_class, DetectionMethod(method), explanation, blocked, rules, features


def train_models(events: list[LoginEvent]) -> list[ModelMetric]:
    feature_rows: list[list[float]] = []
    labels: list[int] = []

    detected_count = sum(1 for event in events if event.risk_score >= 70)
    fp_count = sum(1 for event in events if event.risk_score < 25 and event.attack_class != AttackType.normal)

    rule_based = ModelMetric(
        id="rule-based",
        name="Rule-Based Engine",
        type="Rule-Based",
        status="active",
        version="v2.1.0",
        accuracy=None,  # Heuristic engine, no ground-truth evaluation set
        detections=detected_count,
        false_positives=fp_count,
        training_samples=len(events),
        last_trained_at=utc_now(),
        notes="Primary heuristic engine",
    )

    if len(events) >= 20:
        for index, event in enumerate(events):
            feature_rows.append(
                [
                    float(index % 12 + 1),
                    0.0 if event.success else 1.0,
                    float(len(event.username)),
                    float(len(event.password_ref)),
                    1.0,
                    1.0,
                    1.0,
                    1.0 if not event.success else 0.0,
                ]
            )
            labels.append(1 if event.risk_score >= 70 else 0)
        MODEL_BUNDLE.isolation_forest = IsolationForest(contamination="auto", random_state=42)
        MODEL_BUNDLE.isolation_forest.fit(feature_rows)
        isolation_metric = ModelMetric(
            id="isolation-forest",
            name="IsolationForest Anomaly Detector",
            type="Anomaly",
            status="active",
            version="v1.0.0",
            training_samples=len(feature_rows),
            anomaly_statistics={
                "trained": True,
                "samples": len(feature_rows),
                "anomalies": int(sum(1 for label in labels if label == 1)),
            },
            detections=sum(1 for event in events if event.attack_class != AttackType.normal),
            false_positives=sum(1 for event in events if event.attack_class == AttackType.normal and event.risk_score >= 50),
            last_trained_at=utc_now(),
            accuracy=None,  # Unsupervised model, no labeled ground-truth dataset
            notes="Unsupervised anomaly detector trained on live event features",
        )
    else:
        MODEL_BUNDLE.isolation_forest = None
        isolation_metric = ModelMetric(
            id="isolation-forest",
            name="IsolationForest Anomaly Detector",
            type="Anomaly",
            status="inactive",
            version="v1.0.0",
            training_samples=len(feature_rows),
            anomaly_statistics={"trained": False, "reason": "insufficient data", "samples": len(feature_rows)},
            detections=0,
            false_positives=0,
            accuracy=None,
            notes="Requires at least 20 events for training",
        )

    if len(set(labels)) >= 2 and len(events) >= 30:
        MODEL_BUNDLE.random_forest = RandomForestClassifier(n_estimators=100, random_state=42)
        MODEL_BUNDLE.random_forest.fit(feature_rows, labels)
        random_metric = ModelMetric(
            id="random-forest",
            name="Random Forest Classifier",
            type="ML Model",
            status="active",
            version="v1.0.0",
            training_samples=len(feature_rows),
            anomaly_statistics={"trained": True, "labels": Counter(labels)},
            detections=sum(labels),
            false_positives=max(0, len(labels) - sum(labels)),
            last_trained_at=utc_now(),
            accuracy=None,  # Heuristic training labels, no external benchmark dataset
            notes="Supervised classifier trained on heuristic event labels",
        )
    else:
        MODEL_BUNDLE.random_forest = None
        random_metric = ModelMetric(
            id="random-forest",
            name="Random Forest Classifier",
            type="ML Model",
            status="inactive",
            version="v1.0.0",
            training_samples=len(feature_rows),
            anomaly_statistics={
                "trained": False,
                "reason": "insufficient labeled data",
                "labels": dict(Counter(labels)),
            },
            detections=0,
            false_positives=0,
            accuracy=None,
            notes="Requires both normal and attack events (min 30 events)",
        )

    return [rule_based, isolation_metric, random_metric]



def summarize_activity(events: list[LoginEvent], alerts: list[AlertRecord], windows: dict[str, int] | None = None) -> dict[str, Any]:
    windows = windows or {"24h": 24, "7d": 24 * 7, "30d": 24 * 30}
    now = utc_now()
    events_by_window: dict[str, list[LoginEvent]] = {}
    for key, hours in windows.items():
        cutoff = now - timedelta(hours=hours)
        events_by_window[key] = [event for event in events if event.timestamp >= cutoff]

    all_events = events
    unique_ips = len({event.source_ip for event in all_events})
    unique_accounts = len({event.username for event in all_events})
    detections = [event for event in all_events if event.risk_score >= 70]
    blocked = [event for event in all_events if event.blocked]
    attacks = Counter(event.attack_class.value for event in all_events)
    hours = Counter(event.timestamp.astimezone(timezone.utc).strftime("%H:00") for event in all_events)
    hourly = [{"time": f"{hour}", "attacks": count} for hour, count in sorted(hours.items())[-12:]]
    attack_type_distribution = [
        {"name": key.replace("_", " ").title(), "value": count}
        for key, count in attacks.items()
    ]
    risk_buckets = Counter(
        "critical" if event.risk_score >= 90 else
        "high" if event.risk_score >= 75 else
        "medium" if event.risk_score >= 50 else
        "low" if event.risk_score >= 25 else "info"
        for event in all_events
    )
    risk_distribution = [{"name": key, "value": value} for key, value in risk_buckets.items()]
    top_ips = Counter(event.source_ip for event in all_events).most_common(5)
    top_accounts = Counter(event.username for event in all_events).most_common(5)
    success_count = sum(1 for event in all_events if event.success)
    failure_count = len(all_events) - success_count
    alert_distribution = Counter(alert.severity.value for alert in alerts)
    return {
        "totals": {
            "loginAttempts": len(all_events),
            "detectedAttacks": len(detections),
            "uniqueIPs": unique_ips,
            "testAccounts": unique_accounts,
            "blockedAttempts": len(blocked),
            "successCount": success_count,
            "failureCount": failure_count,
        },
        "attackTrends": hourly,
        "attackTypeDistribution": attack_type_distribution,
        "riskDistribution": risk_distribution,
        "topIPs": [{"ip": ip, "count": count} for ip, count in top_ips],
        "topAccounts": [{"username": username, "count": count} for username, count in top_accounts],
        "alertDistribution": [{"severity": key, "count": value} for key, value in alert_distribution.items()],
        "recentAlerts": [alert.model_dump(mode="json") for alert in alerts[:5]],
        "windowCounts": {key: len(value) for key, value in events_by_window.items()},
    }
