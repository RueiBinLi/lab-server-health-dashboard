import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

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
