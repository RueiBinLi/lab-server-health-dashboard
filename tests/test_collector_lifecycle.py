import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from lab_dashboard.database import initialize_database
from test_http import RunningDashboard, create_csr, identity_headers


ADMINISTRATOR = identity_headers(
    "ada@example.com", "lab-administrator"
)


def seed_active_server(database_path: Path, *, expires_at: datetime) -> None:
    initialize_database(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO servers (
                server_id, display_name, scrape_address,
                profile_id, profile_revision, enrollment_state, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "server-1",
                "Compute 1",
                "https://10.0.0.1:9100/metrics",
                "general-linux",
                1,
                "active",
                "2026-07-01T00:00:00+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO collector_certificates (
                server_id, collector_public_key_fingerprint, expires_at
            ) VALUES (?, ?, ?)
            """,
            ("server-1", "original-fingerprint", expires_at.isoformat()),
        )
        connection.execute(
            """
            INSERT INTO active_scrape_targets (
                server_id, scrape_address, activated_at,
                scrape_client_certificate_path, scrape_client_key_path
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "server-1",
                "https://10.0.0.1:9100/metrics",
                "2026-07-01T00:00:00+00:00",
                "/state/client.crt",
                "/state/client.key",
            ),
        )


class CollectorTrustLifecycleTests(unittest.TestCase):
    def test_current_identity_renews_with_ten_days_remaining(self) -> None:
        now = datetime(2026, 7, 27, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as temporary:
            state_directory = Path(temporary)
            database_path = state_directory / "dashboard.sqlite3"
            seed_active_server(
                database_path, expires_at=now + timedelta(days=10)
            )
            csr = create_csr(state_directory, "server-1")
            with (
                patch("lab_dashboard.database._now", return_value=now),
                RunningDashboard(database_path=database_path) as dashboard,
            ):
                renewed = dashboard.post(
                    "/api/collectors/server-1/certificate-renewals",
                    {"certificateSigningRequest": csr},
                    {
                        "X-Collector-Certificate-Fingerprint": (
                            "original-fingerprint"
                        )
                    },
                )
                audit = dashboard.get("/api/audit-events", ADMINISTRATOR)

        self.assertEqual(renewed[0], 201)
        self.assertEqual(renewed[1]["renewAtDaysRemaining"], 10)
        self.assertEqual(
            renewed[1]["retryBackoffSeconds"], [60, 300, 1800, 7200]
        )
        self.assertEqual(
            audit[1]["events"][-1]["action"],
            "collector-certificate-renewed",
        )

    def test_planned_rotation_overlaps_collector_credentials(self) -> None:
        now = datetime(2026, 7, 27, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as temporary:
            state_directory = Path(temporary)
            database_path = state_directory / "dashboard.sqlite3"
            seed_active_server(
                database_path, expires_at=now + timedelta(days=20)
            )
            csr = create_csr(state_directory, "server-1")
            with (
                patch("lab_dashboard.database._now", return_value=now),
                RunningDashboard(database_path=database_path) as dashboard,
            ):
                rotated = dashboard.post(
                    "/api/servers/server-1/certificate-rotations",
                    {
                        "certificateSigningRequest": csr,
                        "reason": "Scheduled credential rotation",
                    },
                    ADMINISTRATOR,
                )

        self.assertEqual(rotated[0], 201)
        self.assertEqual(
            rotated[1]["previousCredentialAcceptedUntil"],
            (now + timedelta(hours=24)).isoformat(),
        )

    def test_expiry_warnings_are_visible_only_to_lab_administrators(self) -> None:
        now = datetime(2026, 7, 27, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "dashboard.sqlite3"
            seed_active_server(
                database_path, expires_at=now + timedelta(days=7)
            )
            with (
                patch("lab_dashboard.database._now", return_value=now),
                RunningDashboard(database_path=database_path) as dashboard,
            ):
                administrator = dashboard.get("/api/fleet", ADMINISTRATOR)
                lab_user = dashboard.get(
                    "/api/fleet",
                    identity_headers("lin@example.com", "lab-user"),
                )

        self.assertEqual(
            administrator[1]["fleet"][0]["certificateExpiryWarningDays"],
            7,
        )
        self.assertNotIn(
            "certificateExpiryWarningDays", lab_user[1]["fleet"][0]
        )

    def test_forced_revocation_requires_reenrollment_and_is_audited(
        self,
    ) -> None:
        now = datetime(2026, 7, 27, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "dashboard.sqlite3"
            seed_active_server(
                database_path, expires_at=now + timedelta(days=20)
            )
            with (
                patch("lab_dashboard.database._now", return_value=now),
                RunningDashboard(database_path=database_path) as dashboard,
            ):
                revoked = dashboard.post(
                    "/api/servers/server-1/certificate-revocations",
                    {"reason": "Collector key may be compromised"},
                    ADMINISTRATOR,
                )
                fleet = dashboard.get("/api/fleet", ADMINISTRATOR)
                audit = dashboard.get("/api/audit-events", ADMINISTRATOR)

        self.assertEqual(revoked[0], 200)
        self.assertEqual(
            fleet[1]["fleet"][0]["enrollmentState"],
            "re-enrollment-required",
        )
        self.assertEqual(
            audit[1]["events"][-1]["action"],
            "collector-certificate-revoked",
        )
        self.assertNotIn("original-fingerprint", json.dumps(audit))

    def test_retirement_permanently_stops_observation_and_reenrollment(
        self,
    ) -> None:
        now = datetime(2026, 7, 27, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "dashboard.sqlite3"
            seed_active_server(
                database_path, expires_at=now + timedelta(days=20)
            )
            with (
                patch("lab_dashboard.database._now", return_value=now),
                RunningDashboard(database_path=database_path) as dashboard,
            ):
                retired = dashboard.post(
                    "/api/servers/server-1/retirement",
                    {"reason": "Machine decommissioned"},
                    ADMINISTRATOR,
                )
                token = dashboard.post(
                    "/api/servers/server-1/bootstrap-tokens",
                    {"reason": "Try to return retired machine"},
                    ADMINISTRATOR,
                )
                fleet = dashboard.get("/api/fleet", ADMINISTRATOR)

        self.assertEqual(retired[0], 200)
        self.assertEqual(token[0], 409)
        self.assertEqual(
            fleet[1]["fleet"][0]["enrollmentState"], "retired"
        )
        self.assertNotIn("serverHealth", retired[1]["server"])

    def test_scrape_address_switch_requires_matching_fingerprint(
        self,
    ) -> None:
        now = datetime(2026, 7, 27, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "dashboard.sqlite3"
            seed_active_server(
                database_path, expires_at=now + timedelta(days=20)
            )
            with (
                patch("lab_dashboard.database._now", return_value=now),
                RunningDashboard(database_path=database_path) as dashboard,
            ):
                staged = dashboard.post(
                    "/api/servers/server-1/scrape-address-changes",
                    {
                        "scrapeAddress": (
                            "https://10.0.0.2:9100/metrics"
                        ),
                        "collectorFingerprint": "original-fingerprint",
                        "reason": "Server moved to a new rack",
                    },
                    ADMINISTRATOR,
                )
                rejected = dashboard.post(
                    "/api/servers/server-1/scrape-address-activations",
                    {"observedCollectorFingerprint": "different"},
                    ADMINISTRATOR,
                )
                activated = dashboard.post(
                    "/api/servers/server-1/scrape-address-activations",
                    {
                        "observedCollectorFingerprint": (
                            "original-fingerprint"
                        )
                    },
                    ADMINISTRATOR,
                )

        self.assertEqual(staged[0], 202)
        self.assertEqual(rejected[0], 409)
        self.assertEqual(activated[0], 200)
        self.assertEqual(
            activated[1]["server"]["scrapeAddress"],
            "https://10.0.0.2:9100/metrics",
        )

    def test_intermediate_ca_recovery_fails_closed(self) -> None:
        now = datetime(2026, 7, 27, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "dashboard.sqlite3"
            seed_active_server(
                database_path, expires_at=now + timedelta(days=20)
            )
            with (
                patch("lab_dashboard.database._now", return_value=now),
                RunningDashboard(database_path=database_path) as dashboard,
            ):
                recovery = dashboard.post(
                    "/api/trust/intermediate-recovery",
                    {"reason": "Online intermediate key exposed"},
                    ADMINISTRATOR,
                )
                fleet = dashboard.get("/api/fleet", ADMINISTRATOR)

        self.assertEqual(
            recovery,
            (
                200,
                {
                    "trustState": "failed-closed",
                    "affectedServers": 1,
                    "nextAction": (
                        "replace-intermediate-from-offline-root"
                    ),
                },
            ),
        )
        self.assertEqual(
            fleet[1]["fleet"][0]["enrollmentState"],
            "re-enrollment-required",
        )


if __name__ == "__main__":
    unittest.main()
