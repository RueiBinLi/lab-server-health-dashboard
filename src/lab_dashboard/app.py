from __future__ import annotations

import json
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lab_dashboard.auth import Viewer, authorize
from lab_dashboard.config import DashboardConfig
from lab_dashboard.database import initialize_database, is_ready
from lab_dashboard.presentation import empty_fleet_experience


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
        if self.path == "/":
            self._send_dashboard()
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
        self._send_json(
            HTTPStatus.OK,
            {
                "viewer": {
                    "login": viewer.login,
                    "role": viewer.role.value,
                },
                "fleet": [],
                "emptyMessage": experience.message,
            },
        )

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
