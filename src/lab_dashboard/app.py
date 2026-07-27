from __future__ import annotations

import json
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

from lab_dashboard.auth import Role, Viewer, authorize
from lab_dashboard.config import DashboardConfig
from lab_dashboard.database import (
    DisplayNameConflict,
    ProfileNotPublished,
    RegisteredServer,
    initialize_database,
    is_ready,
    list_audit_events,
    list_published_profiles,
    list_registered_servers,
    record_failed_registration,
    register_server,
)
from lab_dashboard.enrollment import (
    InvalidRegistration,
    parse_registration,
    safe_audit_reason,
)
from lab_dashboard.presentation import empty_fleet_experience


MAX_REQUEST_BODY_BYTES = 16_384


class DashboardServer(ThreadingHTTPServer):
    config: DashboardConfig


def create_server(
    config: DashboardConfig, address: tuple[str, int]
) -> DashboardServer:
    initialize_database(config.database_path)
    server = DashboardServer(address, DashboardRequestHandler)
    server.config = config
    return server


class DashboardRequestHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def do_GET(self) -> None:
        if self.path == "/health/live":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if self.path == "/health/ready":
            self._send_readiness()
            return
        if self.path == "/api/fleet":
            self._send_fleet()
            return
        if self.path == "/api/server-profiles":
            self._send_server_profiles()
            return
        if self.path == "/api/audit-events":
            self._send_audit_events()
            return
        if self.path == "/":
            self._send_dashboard()
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path == "/api/servers":
            self._register_server()
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_fleet(self) -> None:
        viewer = self._authorized_viewer()
        if viewer is None:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "access_denied"})
            return

        experience = empty_fleet_experience(viewer.role)
        fleet = (
            [
                self._administrator_server_response(server)
                for server in list_registered_servers(
                    self.server.config.database_path
                )
            ]
            if viewer.role is Role.LAB_ADMINISTRATOR
            else []
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "viewer": {
                    "login": viewer.login,
                    "role": viewer.role.value,
                },
                "fleet": fleet,
                "emptyMessage": experience.message,
            },
        )

    def _send_server_profiles(self) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        profiles = list_published_profiles(self.server.config.database_path)
        self._send_json(
            HTTPStatus.OK,
            {
                "profiles": [
                    {
                        "profileId": profile.profile_id,
                        "name": profile.name,
                        "revision": profile.revision,
                        "state": profile.state,
                        "definition": profile.definition,
                    }
                    for profile in profiles
                ]
            },
        )

    def _send_audit_events(self) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "events": list_audit_events(
                    self.server.config.database_path
                )
            },
        )

    def _register_server(self) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        document = self._read_json()
        server_id = str(uuid4())
        try:
            registration = parse_registration(document)
        except InvalidRegistration:
            record_failed_registration(
                self.server.config.database_path,
                actor=viewer.login,
                server_id=server_id,
                reason=safe_audit_reason(document),
                result="invalid-registration",
            )
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": "invalid_registration"}
            )
            return

        try:
            server = register_server(
                self.server.config.database_path,
                server_id=server_id,
                display_name=registration.display_name,
                scrape_address=registration.scrape_address,
                profile_id=registration.profile_id,
                actor=viewer.login,
                reason=registration.reason,
            )
        except DisplayNameConflict:
            record_failed_registration(
                self.server.config.database_path,
                actor=viewer.login,
                server_id=server_id,
                reason=registration.reason,
                result="display-name-conflict",
            )
            self._send_json(
                HTTPStatus.CONFLICT, {"error": "display_name_conflict"}
            )
            return
        except ProfileNotPublished:
            record_failed_registration(
                self.server.config.database_path,
                actor=viewer.login,
                server_id=server_id,
                reason=registration.reason,
                result="profile-not-published",
            )
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"error": "profile_not_published"},
            )
            return

        self._send_json(
            HTTPStatus.CREATED,
            {"server": self._administrator_server_response(server)},
        )

    def _lab_administrator(self) -> Viewer | None:
        viewer = self._authorized_viewer()
        if viewer is None:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "access_denied"})
            return None
        if viewer.role is not Role.LAB_ADMINISTRATOR:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "access_denied"})
            return None
        return viewer

    def _read_json(self) -> object:
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return None
        if not 0 < content_length <= MAX_REQUEST_BODY_BYTES:
            return None
        try:
            return json.loads(self.rfile.read(content_length))
        except (json.JSONDecodeError, UnicodeError):
            return None

    @staticmethod
    def _administrator_server_response(
        server: RegisteredServer,
    ) -> dict[str, object]:
        return {
            "serverId": server.server_id,
            "displayName": server.display_name,
            "scrapeAddress": server.scrape_address,
            "profile": {
                "profileId": server.profile.profile_id,
                "name": server.profile.name,
                "revision": server.profile.revision,
            },
            "enrollmentState": server.enrollment_state,
            "serverHealth": None,
            "metricHistory": [],
            "criticalAlerts": [],
        }

    def _authorized_viewer(self) -> Viewer | None:
        return authorize(
            login=self.headers.get("Tailscale-User-Login", ""),
            capabilities_header=self.headers.get(
                "Tailscale-App-Capabilities", ""
            ),
            peer_address=self.client_address[0],
            trusted_proxy_networks=(
                self.server.config.trusted_proxy_networks
            ),
        )

    def _send_dashboard(self) -> None:
        viewer = self._authorized_viewer()
        if viewer is None:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "access_denied"})
            return

        experience = empty_fleet_experience(viewer.role)
        page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lab Server Health</title>
  <style>
    :root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
    body {{ margin: 0; background: #101827; color: #eef4ff; }}
    main {{ max-width: 72rem; margin: auto; padding: clamp(1rem, 5vw, 4rem); }}
    header {{ display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }}
    .role {{ color: #a9bad4; }}
    .empty {{ margin-top: 3rem; padding: 3rem 1.5rem; text-align: center;
      border: 1px solid #31415c; border-radius: 1rem; background: #172338; }}
  </style>
</head>
<body>
  <main>
    <header>
      <div><h1>Lab Server Health</h1><p>Fleet overview</p></div>
      <p class="role">
        {escape(viewer.role.value.replace("-", " ").title())}<br>
        {escape(viewer.login)}
      </p>
    </header>
    <section class="empty" aria-labelledby="empty-heading">
      <h2 id="empty-heading">{experience.message}</h2>
      <p>{experience.guidance}</p>
    </section>
  </main>
</body>
</html>
"""
        self._send_bytes(
            HTTPStatus.OK,
            page.encode(),
            "text/html; charset=utf-8",
        )

    def _send_readiness(self) -> None:
        if not is_ready(self.server.config.database_path):
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE, {"error": "not_ready"}
            )
            return
        self._send_json(HTTPStatus.OK, {"status": "ready"})

    def _send_json(self, status: HTTPStatus, body: object) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode()
        self._send_bytes(status, encoded, "application/json")

    def _send_bytes(
        self, status: HTTPStatus, body: bytes, content_type: str
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)
