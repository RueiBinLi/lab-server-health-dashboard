import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import cast

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
    ) -> tuple[int, dict[str, object]]:
        request = urllib.request.Request(self.url + path, headers=headers or {})
        try:
            response = urllib.request.urlopen(request, timeout=2)
        except urllib.error.HTTPError as error:
            response = error

        with response:
            return response.status, json.load(response)

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


if __name__ == "__main__":
    unittest.main()
