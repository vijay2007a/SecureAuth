from __future__ import annotations

import os
import unittest
from unittest.mock import patch

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

    def test_notification_registration_and_password_spray_alert(self) -> None:
        token_payload = {"token": "fcm-test-token-1234567890", "device_name": "Test Browser", "platform": "web"}
        registered = self.client.post("/api/notifications/register-token", headers=auth_headers(), json=token_payload)
        self.assertEqual(registered.status_code, 200)
        self.assertTrue(registered.json()["registered"])

        with patch("backend.app.notifications._send_to_tokens", return_value=(1, 0, [])) as mocked_send:
            spray = self.client.post(
                "/api/simulations/password-spray",
                headers=auth_headers(),
                json={
                    "source_ip": "198.51.100.23",
                    "attempts": 12,
                    "account_count": 12,
                    "delay_seconds": 0,
                    "password": "Spring2025!",
                    "attack_pattern": "password_spray",
                    "name": "Notification Test Spray",
                },
            )
            self.assertEqual(spray.status_code, 200)
            body = spray.json()
            self.assertIn("notification", body)
            self.assertEqual(body["notification"]["sent"], 1)
            self.assertTrue(mocked_send.called)

            test_alert = self.client.post("/api/notifications/test-alert", headers=auth_headers())
            self.assertEqual(test_alert.status_code, 200)
            self.assertIn("sent", test_alert.json())
            self.assertGreaterEqual(mocked_send.call_count, 2)

    def test_csv_upload_and_dataset_credential_stuffing(self) -> None:
        csv_content = (
            "email,password\n"
            "user101@lab.test,Secret101!\n"
            "user102@lab.test,Secret102!\n"
            "user101@lab.test,Secret101!\n"  # duplicate row
            "invalid_row_without_password\n"  # invalid row
        )
        files = {"file": ("test_creds.csv", csv_content.encode("utf-8"), "text/csv")}
        res = self.client.post("/api/simulations/upload-credentials", headers=auth_headers(), files=files)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["valid_credentials"], 2)
        self.assertEqual(data["invalid_rows"], 1)
        self.assertEqual(data["duplicate_rows"], 1)
        self.assertIn("dataset_id", data)

        dataset_id = data["dataset_id"]
        stuffing_res = self.client.post(
            "/api/simulations/credential-stuffing",
            headers=auth_headers(),
            json={
                "source_ip": "198.51.100.44",
                "attempts": 2,
                "dataset_id": dataset_id,
            },
        )
        self.assertEqual(stuffing_res.status_code, 200)
        body = stuffing_res.json()
        self.assertEqual(len(body["events"]), 2)
        self.assertEqual(body["events"][0]["username"], "user101@lab.test")

    def test_simulation_reset(self) -> None:
        # Run a spray first
        self.client.post(
            "/api/simulations/password-spray",
            headers=auth_headers(),
            json={
                "source_ip": "198.51.100.23",
                "attempts": 5,
                "password": "Spring2025!",
            },
        )
        reset_res = self.client.delete("/api/simulations/reset", headers=auth_headers())
        self.assertEqual(reset_res.status_code, 200)
        self.assertTrue(reset_res.json()["reset"])

        sims = self.client.get("/api/simulations", headers=auth_headers()).json()
        self.assertEqual(len(sims), 0)


if __name__ == "__main__":
    unittest.main()

