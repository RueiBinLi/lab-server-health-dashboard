from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from lab_dashboard.alerting import (
    AlertingConfigurationError,
    build_alertmanager_config,
    build_prometheus_rules,
    validate_secret_file,
)


class CriticalAlertConfigurationTests(unittest.TestCase):
    def test_routes_group_incidents_and_deliver_each_channel_independently(
        self,
    ) -> None:
        document = build_alertmanager_config(
            smtp_smarthost="smtp.example.test:465",
            smtp_from="alerts@example.test",
            smtp_to="lab-administrators@example.test",
            smtp_username="alerts@example.test",
            smtp_password_file="/run/secrets/smtp-password",
            slack_webhook_file="/run/secrets/slack-webhook",
        )

        route = document["route"]
        self.assertEqual(route["group_by"], ["server_id", "incident_id"])
        self.assertEqual(route["group_wait"], "30s")
        self.assertEqual(route["group_interval"], "5m")
        self.assertEqual(route["repeat_interval"], "4h")
        self.assertEqual(
            [(child["receiver"], child.get("continue")) for child in route["routes"]],
            [("email", True), ("slack", None)],
        )
        receivers = {receiver["name"]: receiver for receiver in document["receivers"]}
        self.assertTrue(receivers["email"]["email_configs"][0]["send_resolved"])
        self.assertTrue(receivers["slack"]["slack_configs"][0]["send_resolved"])
        self.assertEqual(
            receivers["email"]["email_configs"][0]["auth_password_file"],
            "/run/secrets/smtp-password",
        )
        self.assertEqual(
            receivers["slack"]["slack_configs"][0]["api_url_file"],
            "/run/secrets/slack-webhook",
        )
        encoded = json.dumps(document)
        self.assertNotIn("smtp-password", encoded.replace("/run/secrets/smtp-password", ""))
        self.assertNotIn("hooks.slack.com", encoded)

    def test_rules_keep_identity_out_of_causes_and_route_transitions(self) -> None:
        document = build_prometheus_rules()
        rules = document["groups"][0]["rules"]
        by_name = {rule["alert"]: rule for rule in rules}

        incident = by_name["ServerIncident"]
        self.assertEqual(incident["for"], "0s")
        self.assertNotIn("causes", incident["labels"])
        self.assertIn("causes", incident["annotations"])
        self.assertEqual(
            set(incident["labels"]),
            {"severity", "transition", "server_id", "incident_id"},
        )
        self.assertEqual(by_name["ServerIncidentRecovery"]["for"], "0s")
        self.assertEqual(
            by_name["ServerIncidentRecovery"]["labels"]["transition"], "recovery"
        )

    def test_notification_content_is_concise_and_excludes_sensitive_payloads(
        self,
    ) -> None:
        document = build_alertmanager_config(
            smtp_smarthost="smtp.example.test:465",
            smtp_from="alerts@example.test",
            smtp_to="lab-administrators@example.test",
            smtp_username="alerts@example.test",
            smtp_password_file="/run/secrets/smtp-password",
            slack_webhook_file="/run/secrets/slack-webhook",
        )
        encoded = json.dumps(document)
        for field in (
            "server_name",
            "server_id",
            "severity",
            "causes",
            "duration",
            "transition",
            "maintenance",
            "administrator_url",
        ):
            self.assertIn(field, encoded)
        message_text = " ".join(
            (
                document["receivers"][1]["email_configs"][0]["text"],
                document["receivers"][2]["slack_configs"][0]["text"],
            )
        )
        for forbidden in ("raw_log", "secret", "error_payload", "configuration"):
            self.assertNotIn(forbidden, message_text)

    def test_secret_files_must_be_nonempty_regular_and_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            secret = Path(temporary) / "secret"
            secret.write_text("credential\n")
            os.chmod(secret, 0o600)
            validate_secret_file(secret, expected_owner_uid=os.geteuid())

            os.chmod(secret, 0o640)
            with self.assertRaisesRegex(
                AlertingConfigurationError, "owner-readable only"
            ):
                validate_secret_file(secret, expected_owner_uid=os.geteuid())
            os.chmod(secret, 0o200)
            with self.assertRaisesRegex(
                AlertingConfigurationError, "owner-readable"
            ):
                validate_secret_file(secret, expected_owner_uid=os.geteuid())
            secret.unlink()
            with self.assertRaisesRegex(
                AlertingConfigurationError, "required secret file is missing"
            ):
                validate_secret_file(secret, expected_owner_uid=os.geteuid())


if __name__ == "__main__":
    unittest.main()
