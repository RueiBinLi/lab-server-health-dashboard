import base64
import hashlib
import json
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from lab_dashboard.app import create_server
from lab_dashboard.config import DashboardConfig


CAPABILITY_NAME = "rueibinli.github.io/cap/lab-server-health"


def identity_headers(login: str, role: str) -> dict[str, str]:
    return {
        "Tailscale-User-Login": login,
        "Tailscale-App-Capabilities": json.dumps(
            {CAPABILITY_NAME: [{"role": role}]}
        ),
    }


def create_csr(directory: Path, common_name: str) -> str:
    key_path = directory / f"{common_name}.key"
    csr_path = directory / f"{common_name}.csr"
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            f"/CN={common_name}",
            "-keyout",
            str(key_path),
            "-out",
            str(csr_path),
        ],
        check=True,
        capture_output=True,
    )
    return csr_path.read_text()


class RunningDashboard:
    def __init__(
        self,
        trusted_proxy_networks: tuple[str, ...] = ("127.0.0.0/8",),
    ) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        directory = Path(self._temporary_directory.name)
        self.server = create_server(
            DashboardConfig(
                database_path=directory / "dashboard.sqlite3",
                trusted_proxy_networks=trusted_proxy_networks,
            ),
            ("127.0.0.1", 0),
        )
        self.thread = threading.Thread(target=self.server.serve_forever)

    def __enter__(self) -> "RunningDashboard":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self._temporary_directory.cleanup()

    @property
    def url(self) -> str:
        host, port = cast(tuple[str, int], self.server.server_address)
        return f"http://{host}:{port}"

    def get(
        self, path: str, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, Any]]:
        request = urllib.request.Request(self.url + path, headers=headers or {})
        try:
            response = urllib.request.urlopen(request, timeout=2)
        except urllib.error.HTTPError as error:
            response = error

        with response:
            return response.status, cast(
                dict[str, Any], json.load(response)
            )

    def get_text(
        self, path: str, headers: dict[str, str] | None = None
    ) -> tuple[int, str]:
        request = urllib.request.Request(self.url + path, headers=headers or {})
        try:
            response = urllib.request.urlopen(request, timeout=2)
        except urllib.error.HTTPError as error:
            response = error

        with response:
            return response.status, response.read().decode()

    def post(
        self,
        path: str,
        body: Mapping[str, object],
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        request_headers = {"Content-Type": "application/json", **(headers or {})}
        request = urllib.request.Request(
            self.url + path,
            data=json.dumps(body).encode(),
            headers=request_headers,
            method="POST",
        )
        try:
            response = urllib.request.urlopen(request, timeout=2)
        except urllib.error.HTTPError as error:
            response = error

        with response:
            return response.status, cast(
                dict[str, Any], json.load(response)
            )


class FleetAuthorizationTests(unittest.TestCase):
    def test_lab_administrator_receives_role_appropriate_empty_fleet(self) -> None:
        with RunningDashboard() as dashboard:
            status, body = dashboard.get(
                "/api/fleet",
                identity_headers("ada@example.com", "lab-administrator"),
            )

        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "viewer": {
                    "login": "ada@example.com",
                    "role": "lab-administrator",
                },
                "fleet": [],
                "emptyMessage": "No servers have been enrolled.",
            },
        )

    def test_lab_user_receives_role_appropriate_empty_fleet(self) -> None:
        with RunningDashboard() as dashboard:
            status, body = dashboard.get(
                "/api/fleet", identity_headers("lin@example.com", "lab-user")
            )

        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "viewer": {"login": "lin@example.com", "role": "lab-user"},
                "fleet": [],
                "emptyMessage": "No servers are available yet.",
            },
        )

    def test_missing_malformed_unknown_and_roleless_identities_are_denied(self) -> None:
        attempts: tuple[dict[str, str], ...] = (
            {},
            identity_headers("not an identity", "lab-user"),
            identity_headers("ada@example..com", "lab-user"),
            identity_headers("ada@example.-com", "lab-user"),
            {"Tailscale-User-Login": "unknown@example.com"},
            {
                "Tailscale-User-Login": "roleless@example.com",
                "Tailscale-App-Capabilities": "{}",
            },
            {
                "Tailscale-User-Login": "lin@example.com",
                "Tailscale-App-Capabilities": "not-json",
            },
            identity_headers("tag:build-server", "lab-user"),
        )

        with RunningDashboard() as dashboard:
            responses = [
                dashboard.get("/api/fleet", headers) for headers in attempts
            ]

        self.assertEqual(
            responses,
            [(403, {"error": "access_denied"})] * len(attempts),
        )

    def test_identity_header_from_unapproved_peer_is_denied(self) -> None:
        with RunningDashboard(
            trusted_proxy_networks=("192.0.2.0/24",),
        ) as dashboard:
            status, body = dashboard.get(
                "/api/fleet",
                identity_headers("ada@example.com", "lab-administrator"),
            )

        self.assertEqual(status, 403)
        self.assertEqual(body, {"error": "access_denied"})

    def test_browser_view_is_empty_and_role_appropriate(self) -> None:
        with RunningDashboard() as dashboard:
            administrator_status, administrator_page = dashboard.get_text(
                "/", identity_headers("ada@example.com", "lab-administrator")
            )
            user_status, user_page = dashboard.get_text(
                "/", identity_headers("lin@example.com", "lab-user")
            )

        self.assertEqual(administrator_status, 200)
        self.assertIn("No servers have been enrolled.", administrator_page)
        self.assertIn("Lab Administrator controls", administrator_page)
        self.assertEqual(user_status, 200)
        self.assertIn("No servers are available yet.", user_page)
        self.assertNotIn("Lab Administrator controls", user_page)

    def test_health_endpoints_do_not_require_identity(self) -> None:
        with RunningDashboard() as dashboard:
            live = dashboard.get("/health/live")
            ready = dashboard.get("/health/ready")

        self.assertEqual(live, (200, {"status": "ok"}))
        self.assertEqual(ready, (200, {"status": "ready"}))


class ServerRegistrationTests(unittest.TestCase):
    def test_lab_administrator_registers_server_from_published_profile(self) -> None:
        administrator = identity_headers(
            "ada@example.com", "lab-administrator"
        )
        with RunningDashboard() as dashboard:
            profiles_status, profiles = dashboard.get(
                "/api/server-profiles", administrator
            )
            status, body = dashboard.post(
                "/api/servers",
                {
                    "displayName": "Training GPU 1",
                    "scrapeAddress": "https://10.40.0.12:9100/metrics",
                    "profileId": "nvidia-gpu-compute",
                    "reason": "Enroll the new training host",
                },
                administrator,
            )
            fleet_status, fleet = dashboard.get("/api/fleet", administrator)

        self.assertEqual(profiles_status, 200)
        profile_list = profiles["profiles"]
        self.assertEqual(
            [
                (profile["profileId"], profile["name"], profile["revision"])
                for profile in profile_list
            ],
            [
                ("general-linux", "General Linux Server", 1),
                (
                    "nvidia-gpu-compute",
                    "NVIDIA GPU Compute Server",
                    1,
                ),
            ],
        )
        self.assertEqual(
            [profile["state"] for profile in profile_list],
            ["published", "published"],
        )
        self.assertFalse(
            profile_list[0]["definition"]["capabilities"]["gpu"]
        )
        self.assertTrue(
            profile_list[1]["definition"]["capabilities"]["gpu"]
        )
        for profile in profile_list:
            self.assertIn(
                "reachability",
                profile["definition"]["requiredObservations"],
            )
            self.assertIn(
                "critical-errors",
                profile["definition"]["requiredObservations"],
            )
        self.assertEqual(status, 201)
        server = body["server"]
        self.assertRegex(
            str(server["serverId"]),
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        self.assertEqual(
            server,
            {
                "serverId": server["serverId"],
                "displayName": "Training GPU 1",
                "scrapeAddress": "https://10.40.0.12:9100/metrics",
                "profile": {
                    "profileId": "nvidia-gpu-compute",
                    "name": "NVIDIA GPU Compute Server",
                    "revision": 1,
                },
                "enrollmentState": "awaiting-first-contact",
                "serverHealth": None,
                "metricHistory": [],
                "criticalAlerts": [],
            },
        )
        self.assertEqual(fleet_status, 200)
        self.assertEqual(fleet["fleet"], [server])

    def test_duplicate_name_invalid_address_and_unknown_profile_are_rejected(
        self,
    ) -> None:
        administrator = identity_headers(
            "ada@example.com", "lab-administrator"
        )
        valid_registration = {
            "displayName": "Compute 1",
            "scrapeAddress": "https://192.168.10.8:9100/metrics",
            "profileId": "general-linux",
            "reason": "Add shared compute capacity",
        }
        with RunningDashboard() as dashboard:
            first = dashboard.post(
                "/api/servers", valid_registration, administrator
            )
            duplicate = dashboard.post(
                "/api/servers",
                {**valid_registration, "displayName": "compute 1"},
                administrator,
            )
            public_address = dashboard.post(
                "/api/servers",
                {
                    **valid_registration,
                    "displayName": "Compute 2",
                    "scrapeAddress": "https://203.0.113.8:9100/metrics",
                },
                administrator,
            )
            insecure_address = dashboard.post(
                "/api/servers",
                {
                    **valid_registration,
                    "displayName": "Compute 2",
                    "scrapeAddress": "http://192.168.10.9:9100/metrics",
                },
                administrator,
            )
            control_character_address = dashboard.post(
                "/api/servers",
                {
                    **valid_registration,
                    "displayName": "Compute 2",
                    "scrapeAddress": "https://192.168.10.9:9100/met\trics",
                },
                administrator,
            )
            unknown_profile = dashboard.post(
                "/api/servers",
                {
                    **valid_registration,
                    "displayName": "Compute 3",
                    "profileId": "draft-experiment",
                },
                administrator,
            )
            audit_status, audit = dashboard.get(
                "/api/audit-events", administrator
            )

        self.assertEqual(first[0], 201)
        self.assertEqual(duplicate, (409, {"error": "display_name_conflict"}))
        self.assertEqual(
            public_address, (400, {"error": "invalid_registration"})
        )
        self.assertEqual(
            insecure_address, (400, {"error": "invalid_registration"})
        )
        self.assertEqual(
            control_character_address,
            (400, {"error": "invalid_registration"}),
        )
        self.assertEqual(
            unknown_profile, (422, {"error": "profile_not_published"})
        )
        self.assertEqual(audit_status, 200)
        successful_event = audit["events"][0]
        self.assertEqual(
            successful_event,
            {
                "occurred_at": successful_event["occurred_at"],
                "actor": "ada@example.com",
                "action": "server-registration",
                "server_id": first[1]["server"]["serverId"],
                "reason": "Add shared compute capacity",
                "result": "succeeded",
            },
        )
        self.assertEqual(
            [event["result"] for event in audit["events"]],
            [
                "succeeded",
                "display-name-conflict",
                "invalid-registration",
                "invalid-registration",
                "invalid-registration",
                "profile-not-published",
            ],
        )


class CollectorBootstrapTests(unittest.TestCase):
    def test_lab_administrator_issues_one_time_fifteen_minute_token(self) -> None:
        administrator = identity_headers(
            "ada@example.com", "lab-administrator"
        )
        registration = {
            "displayName": "Compute 1",
            "scrapeAddress": "https://192.168.10.8:9100/metrics",
            "profileId": "general-linux",
            "reason": "Add shared compute capacity",
        }

        with RunningDashboard() as dashboard:
            _, registered = dashboard.post(
                "/api/servers", registration, administrator
            )
            server_id = registered["server"]["serverId"]
            status, issued = dashboard.post(
                f"/api/servers/{server_id}/bootstrap-tokens",
                {"reason": "Install the collector"},
                administrator,
            )
            audit_status, audit = dashboard.get(
                "/api/audit-events", administrator
            )

        self.assertEqual(status, 201)
        self.assertRegex(
            issued["bootstrapToken"], r"^[A-Za-z0-9_-]{40,}$"
        )
        self.assertEqual(issued["expiresInSeconds"], 900)
        installer = issued["installer"]
        self.assertEqual(installer["version"], "1.0.0")
        self.assertFalse(installer["requiresNvidia"])
        self.assertEqual(
            installer["signingKeySha256"],
            hashlib.sha256(
                installer["signingPublicKey"].encode()
            ).hexdigest(),
        )
        self.assertEqual(
            installer["sha256"],
            hashlib.sha256(installer["content"].encode()).hexdigest(),
        )
        with tempfile.TemporaryDirectory() as verification_directory:
            directory = Path(verification_directory)
            content_path = directory / "install.sh"
            signature_path = directory / "install.sh.sig"
            public_key_path = directory / "installer-signing.pub"
            content_path.write_text(installer["content"])
            signature_path.write_bytes(
                base64.b64decode(installer["signature"])
            )
            public_key_path.write_text(installer["signingPublicKey"])
            verified = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key_path),
                    "-rawin",
                    "-in",
                    str(content_path),
                    "-sigfile",
                    str(signature_path),
                ],
                capture_output=True,
            )
        self.assertEqual(verified.returncode, 0)
        self.assertEqual(audit_status, 200)
        self.assertEqual(audit["events"][-1]["action"], "bootstrap-token-issued")
        self.assertEqual(audit["events"][-1]["server_id"], server_id)
        self.assertEqual(audit["events"][-1]["result"], "succeeded")
        self.assertNotIn(issued["bootstrapToken"], json.dumps(audit))

    def test_first_valid_bootstrap_consumes_token_and_stages_server(self) -> None:
        administrator = identity_headers(
            "ada@example.com", "lab-administrator"
        )
        registration = {
            "displayName": "Compute 1",
            "scrapeAddress": "https://192.168.10.8:9100/metrics",
            "profileId": "general-linux",
            "reason": "Add shared compute capacity",
        }

        with tempfile.TemporaryDirectory() as key_directory:
            with RunningDashboard() as dashboard:
                _, registered = dashboard.post(
                    "/api/servers", registration, administrator
                )
                server_id = registered["server"]["serverId"]
                csr = create_csr(Path(key_directory), server_id)
                _, issued = dashboard.post(
                    f"/api/servers/{server_id}/bootstrap-tokens",
                    {"reason": "Install the collector"},
                    administrator,
                )
                request = {
                    "serverId": server_id,
                    "bootstrapToken": issued["bootstrapToken"],
                    "certificateSigningRequest": csr,
                    "hostname": "compute-1",
                    "osRelease": "Ubuntu 24.04 LTS",
                    "architecture": "x86_64",
                }
                first = dashboard.post("/api/enrollment/bootstrap", request)
                reuse = dashboard.post("/api/enrollment/bootstrap", request)
                _, fleet = dashboard.get("/api/fleet", administrator)
                _, audit = dashboard.get("/api/audit-events", administrator)
            certificate_path = Path(key_directory) / "collector.crt"
            certificate_path.write_text(first[1]["certificate"])
            certificate_details = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(certificate_path),
                    "-noout",
                    "-text",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout

        self.assertEqual(first[0], 201)
        self.assertIn("BEGIN CERTIFICATE", first[1]["certificate"])
        self.assertIn("BEGIN CERTIFICATE", first[1]["caCertificate"])
        self.assertIn(
            "BEGIN CERTIFICATE",
            first[1]["scrapeClientCaCertificate"],
        )
        self.assertEqual(first[1]["validForDays"], 30)
        self.assertEqual(first[1]["scrapeSet"], "staging")
        self.assertIn(f"urn:lab-server:{server_id}", certificate_details)
        self.assertIn("TLS Web Server Authentication", certificate_details)
        self.assertIn("TLS Web Client Authentication", certificate_details)
        self.assertEqual(
            reuse, (401, {"error": "invalid_bootstrap_credentials"})
        )
        self.assertEqual(
            fleet["fleet"][0]["enrollmentState"], "pending-verification"
        )
        self.assertIsNone(fleet["fleet"][0]["serverHealth"])
        self.assertEqual(fleet["fleet"][0]["metricHistory"], [])
        self.assertEqual(fleet["fleet"][0]["criticalAlerts"], [])
        serialized_audit = json.dumps(audit)
        self.assertNotIn(issued["bootstrapToken"], serialized_audit)
        self.assertEqual(
            [event["action"] for event in audit["events"][-3:]],
            [
                "bootstrap-token-consumed",
                "bootstrap-succeeded",
                "bootstrap-failed",
            ],
        )

    def test_concurrent_and_expired_token_use_fail_safely(self) -> None:
        administrator = identity_headers(
            "ada@example.com", "lab-administrator"
        )
        registration = {
            "displayName": "Compute 1",
            "scrapeAddress": "https://192.168.10.8:9100/metrics",
            "profileId": "general-linux",
            "reason": "Add shared compute capacity",
        }

        with tempfile.TemporaryDirectory() as key_directory:
            issued_at = datetime(2026, 7, 27, 2, 0, tzinfo=UTC)

            with patch(
                "lab_dashboard.database._now", return_value=issued_at
            ):
                with RunningDashboard() as dashboard:
                    _, registered = dashboard.post(
                        "/api/servers", registration, administrator
                    )
                    server_id = registered["server"]["serverId"]
                    csr = create_csr(Path(key_directory), server_id)
                    _, issued = dashboard.post(
                        f"/api/servers/{server_id}/bootstrap-tokens",
                        {"reason": "Install the collector"},
                        administrator,
                    )
                    request = {
                        "serverId": server_id,
                        "bootstrapToken": issued["bootstrapToken"],
                        "certificateSigningRequest": csr,
                        "hostname": "compute-1",
                        "osRelease": "Ubuntu 22.04 LTS",
                        "architecture": "x86_64",
                    }
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        responses = list(
                            executor.map(
                                lambda _: dashboard.post(
                                    "/api/enrollment/bootstrap", request
                                ),
                                range(2),
                            )
                        )

                    _, second_server = dashboard.post(
                        "/api/servers",
                        {**registration, "displayName": "Compute 2"},
                        administrator,
                    )
                    second_server_id = second_server["server"]["serverId"]
                    _, expiring = dashboard.post(
                        f"/api/servers/{second_server_id}/bootstrap-tokens",
                        {"reason": "Install the collector"},
                        administrator,
                    )
                    expired_request = {
                        **request,
                        "serverId": second_server_id,
                        "bootstrapToken": expiring["bootstrapToken"],
                    }
                    with patch(
                        "lab_dashboard.database._now",
                        return_value=issued_at + timedelta(minutes=16),
                    ):
                        expired = dashboard.post(
                            "/api/enrollment/bootstrap", expired_request
                        )
                    _, audit = dashboard.get(
                        "/api/audit-events", administrator
                    )

        self.assertEqual(
            sorted(status for status, _ in responses), [201, 401]
        )
        self.assertEqual(
            expired, (401, {"error": "invalid_bootstrap_credentials"})
        )
        self.assertIn(
            "bootstrap-token-expired",
            [event["action"] for event in audit["events"]],
        )

    def test_invalid_csr_is_audited_without_consuming_the_token(self) -> None:
        administrator = identity_headers(
            "ada@example.com", "lab-administrator"
        )
        with tempfile.TemporaryDirectory() as key_directory:
            with RunningDashboard() as dashboard:
                _, registered = dashboard.post(
                    "/api/servers",
                    {
                        "displayName": "Compute 1",
                        "scrapeAddress": "https://192.168.10.8:9100/metrics",
                        "profileId": "general-linux",
                        "reason": "Add shared compute capacity",
                    },
                    administrator,
                )
                server_id = registered["server"]["serverId"]
                _, issued = dashboard.post(
                    f"/api/servers/{server_id}/bootstrap-tokens",
                    {"reason": "Install the collector"},
                    administrator,
                )
                status, body = dashboard.post(
                    "/api/enrollment/bootstrap",
                    {
                        "serverId": server_id,
                        "bootstrapToken": issued["bootstrapToken"],
                        "certificateSigningRequest": create_csr(
                            Path(key_directory), "different-server"
                        ),
                        "hostname": "compute-1",
                        "osRelease": "Ubuntu 24.04 LTS",
                        "architecture": "x86_64",
                    },
                )
                _, audit = dashboard.get("/api/audit-events", administrator)

        self.assertEqual(
            (status, body),
            (400, {"error": "invalid_certificate_signing_request"}),
        )
        self.assertEqual(audit["events"][-1]["action"], "bootstrap-failed")
        self.assertEqual(audit["events"][-1]["result"], "invalid-csr")
        self.assertNotIn(issued["bootstrapToken"], json.dumps(audit))

    def test_gpu_profile_requirements_are_bound_to_the_token(self) -> None:
        administrator = identity_headers(
            "ada@example.com", "lab-administrator"
        )
        with RunningDashboard() as dashboard:
            _, registered = dashboard.post(
                "/api/servers",
                {
                    "displayName": "GPU 1",
                    "scrapeAddress": "https://192.168.10.9:9100/metrics",
                    "profileId": "nvidia-gpu-compute",
                    "reason": "Add GPU capacity",
                },
                administrator,
            )
            server_id = registered["server"]["serverId"]
            _, issued = dashboard.post(
                f"/api/servers/{server_id}/bootstrap-tokens",
                {"reason": "Install the collector"},
                administrator,
            )
            requirements = dashboard.post(
                "/api/enrollment/requirements",
                {
                    "serverId": server_id,
                    "bootstrapToken": issued["bootstrapToken"],
                },
            )

        self.assertEqual(requirements, (200, {"requiresNvidia": True}))

    def test_lab_user_cannot_access_server_enrollment_data(self) -> None:
        administrator = identity_headers(
            "ada@example.com", "lab-administrator"
        )
        lab_user = identity_headers("lin@example.com", "lab-user")
        registration = {
            "displayName": "Private GPU Host",
            "scrapeAddress": "https://[fd12:3456::8]:9100/metrics",
            "profileId": "nvidia-gpu-compute",
            "reason": "Add training capacity",
        }
        with RunningDashboard() as dashboard:
            dashboard.post("/api/servers", registration, administrator)
            fleet = dashboard.get("/api/fleet", lab_user)
            profiles = dashboard.get("/api/server-profiles", lab_user)
            audit = dashboard.get("/api/audit-events", lab_user)
            registration_attempt = dashboard.post(
                "/api/servers", registration, lab_user
            )

        self.assertEqual(fleet[0], 200)
        self.assertEqual(fleet[1]["fleet"], [])
        serialized_fleet = json.dumps(fleet[1])
        for restricted_value in (
            "Private GPU Host",
            "awaiting-first-contact",
            "fd12:3456::8",
            "nvidia-gpu-compute",
            "Add training capacity",
        ):
            self.assertNotIn(restricted_value, serialized_fleet)
        self.assertEqual(profiles, (403, {"error": "access_denied"}))
        self.assertEqual(audit, (403, {"error": "access_denied"}))
        self.assertEqual(
            registration_attempt, (403, {"error": "access_denied"})
        )


if __name__ == "__main__":
    unittest.main()
