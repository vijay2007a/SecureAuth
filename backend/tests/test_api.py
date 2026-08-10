from __future__ import annotations

import os
import unittest

from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.store import MemoryStore


def auth_headers(token: str = "dev-admin-token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class BackendApiTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["AUTH_MODE"] = "dev"
        os.environ["DEV_ADMIN_TOKEN"] = "dev-admin-token"
        os.environ["DEV_ANALYST_TOKEN"] = "dev-analyst-token"
        os.environ["DEV_USER_TOKEN"] = "dev-user-token"
        self.client = TestClient(create_app(MemoryStore()))

    def test_health_endpoint(self) -> None:
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])

    def test_missing_token_rejected(self) -> None:
        response = self.client.get("/api/me")
        self.assertEqual(response.status_code, 401)

    def test_me_endpoint(self) -> None:
        response = self.client.get("/api/me", headers=auth_headers())
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["role"], "admin")
        self.assertEqual(data["token_source"], "dev")

    def test_password_spray_creates_events_and_alerts(self) -> None:
        payload = {
            "source_ip": "198.51.100.23",
            "attempts": 12,
            "account_count": 12,
            "delay_seconds": 0,
            "password": "Spring2025!",
            "attack_pattern": "password_spray",
            "name": "Spray Test",
        }
        response = self.client.post("/api/simulations/password-spray", headers=auth_headers(), json=payload)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body["events"]), 12)
        dashboard = self.client.get("/api/dashboard", headers=auth_headers()).json()
        self.assertGreaterEqual(dashboard["totals"]["loginAttempts"], 12)
        self.assertGreaterEqual(dashboard["totals"]["detectedAttacks"], 1)
        alerts = self.client.get("/api/alerts", headers=auth_headers()).json()
        self.assertGreaterEqual(len(alerts), 1)

    def test_credential_stuffing_creates_high_risk_events(self) -> None:
        payload = {
            "source_ip": "185.199.110.24",
            "attempts": 6,
            "account_count": 6,
            "delay_seconds": 0,
            "attack_pattern": "credential_stuffing",
            "credentials": [
                {"username": "john.doe@lab.com", "password": "Password1!"},
                {"username": "alice@lab.com", "password": "Password2!"},
                {"username": "bob@lab.com", "password": "Password3!"},
                {"username": "charlie@lab.com", "password": "Password4!"},
                {"username": "admin@lab.com", "password": "Password5!"},
                {"username": "michael@lab.com", "password": "Password6!"},
            ],
        }
        response = self.client.post("/api/simulations/credential-stuffing", headers=auth_headers(), json=payload)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertGreaterEqual(len(body["events"]), 6)
        self.assertTrue(any(event["risk_score"] >= 70 for event in body["events"]))

    def test_ip_blocking_and_account_management(self) -> None:
        new_ip = self.client.post(
            "/api/ip-controls",
            headers=auth_headers(),
            json={"ip": "203.0.113.99", "type": "blocked", "reason": "Manual"},
        )
        self.assertEqual(new_ip.status_code, 200)
        listed = self.client.get("/api/ip-controls", headers=auth_headers()).json()
        self.assertTrue(any(item["ip"] == "203.0.113.99" for item in listed))

        new_account = self.client.post(
            "/api/test-accounts",
            headers=auth_headers(),
            json={"username": "test.user@lab.local", "display_name": "Test User", "role": "Standard User"},
        )
        self.assertEqual(new_account.status_code, 200)
        account = new_account.json()
        self.assertEqual(account["username"], "test.user@lab.local")


if __name__ == "__main__":
    unittest.main()

