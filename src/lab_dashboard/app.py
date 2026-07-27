from __future__ import annotations

import ipaddress
import json
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

from lab_dashboard.auth import Role, Viewer, authorize
from lab_dashboard.config import DashboardConfig
from lab_dashboard.database import (
    BOOTSTRAP_TOKEN_TTL_SECONDS,
    DisplayNameConflict,
    EnrollmentDecisionConflict,
    IncompleteObservations,
    InvalidBootstrapCredentials,
    ProfileNotPublished,
    RegisteredServer,
    ServerNotAwaitingFirstContact,
    VerificationCodeMismatch,
    consume_bootstrap_token,
    decide_enrollment,
    get_staging_observation_target,
    initialize_database,
    issue_bootstrap_token,
    is_ready,
    list_audit_events,
    list_published_profiles,
    list_registered_servers,
    record_bootstrap_failure,
    record_failed_registration,
    record_staged_observations,
    register_server,
    server_requires_nvidia,
    server_scrape_address,
    validate_bootstrap_token,
)
from lab_dashboard.enrollment import (
    EnrollmentDecisionKind,
    InvalidFirstContact,
    InvalidEnrollmentDecision,
    InvalidRegistration,
    parse_enrollment_decision,
    parse_first_contact,
    parse_registration,
    safe_audit_reason,
)
from lab_dashboard.installer import signed_installer
from lab_dashboard.observation import (
    ObservationEngine,
    TelemetryUnavailable,
    scrape_telemetry,
)
from lab_dashboard.pki import (
    CERTIFICATE_VALIDITY_DAYS,
    InvalidCertificateSigningRequest,
    issue_collector_certificate,
)
from lab_dashboard.presentation import empty_fleet_experience


MAX_REQUEST_BODY_BYTES = 16_384


class DashboardServer(ThreadingHTTPServer):
    config: DashboardConfig
    observation_engine: ObservationEngine

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        self.observation_engine.start()
        try:
            super().serve_forever(poll_interval)
        finally:
            self.observation_engine.stop()


def create_server(
    config: DashboardConfig, address: tuple[str, int]
) -> DashboardServer:
    initialize_database(config.database_path)
    server = DashboardServer(address, DashboardRequestHandler)
    server.config = config
    server.observation_engine = ObservationEngine(config.database_path)
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
        if self.path == "/api/enrollment/bootstrap":
            self._bootstrap_collector()
            return
        if self.path == "/api/enrollment/requirements":
            self._send_enrollment_requirements()
            return
        prefix = "/api/servers/"
        telemetry_suffix = "/staged-telemetry-checks"
        if self.path.startswith(prefix) and self.path.endswith(
            telemetry_suffix
        ):
            server_id = self.path[len(prefix) : -len(telemetry_suffix)]
            self._check_staged_telemetry(server_id)
            return
        decision_suffix = "/enrollment-decisions"
        if self.path.startswith(prefix) and self.path.endswith(
            decision_suffix
        ):
            server_id = self.path[len(prefix) : -len(decision_suffix)]
            self._decide_enrollment(server_id)
            return
        suffix = "/bootstrap-tokens"
        if self.path.startswith(prefix) and self.path.endswith(suffix):
            server_id = self.path[len(prefix) : -len(suffix)]
            self._issue_bootstrap_token(server_id)
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

    def _issue_bootstrap_token(self, server_id: str) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        document = self._read_json()
        if (
            not isinstance(document, dict)
            or set(document) != {"reason"}
            or not isinstance(document["reason"], str)
            or not 1 <= len(document["reason"].strip()) <= 500
        ):
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": "invalid_token_request"}
            )
            return
        installer = signed_installer(
            self.server.config.database_path.parent
        )
        try:
            token, expires_at, requires_nvidia = issue_bootstrap_token(
                self.server.config.database_path,
                server_id=server_id,
                actor=viewer.login,
                reason=document["reason"].strip(),
            )
        except ServerNotAwaitingFirstContact:
            self._send_json(
                HTTPStatus.CONFLICT,
                {"error": "server_not_awaiting_first_contact"},
            )
            return
        self._send_json(
            HTTPStatus.CREATED,
            {
                "bootstrapToken": token,
                "expiresAt": expires_at.isoformat(),
                "expiresInSeconds": BOOTSTRAP_TOKEN_TTL_SECONDS,
                "installer": {
                    "version": installer.version,
                    "content": installer.content,
                    "sha256": installer.sha256,
                    "signature": installer.signature,
                    "signingPublicKey": installer.signing_public_key,
                    "signingKeySha256": installer.signing_key_sha256,
                    "requiresNvidia": requires_nvidia,
                },
            },
        )

    def _bootstrap_collector(self) -> None:
        document = self._read_json()
        try:
            first_contact = parse_first_contact(document)
        except InvalidFirstContact:
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": "invalid_bootstrap_request"}
            )
            return
        server_id = first_contact.server_id
        if not validate_bootstrap_token(
            self.server.config.database_path,
            server_id=server_id,
            token=first_contact.bootstrap_token,
        ):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "invalid_bootstrap_credentials"},
            )
            return
        try:
            issued = issue_collector_certificate(
                self.server.config.database_path.parent,
                server_id=server_id,
                csr=first_contact.certificate_signing_request,
                scrape_address=server_scrape_address(
                    self.server.config.database_path,
                    server_id=server_id,
                ),
            )
        except InvalidCertificateSigningRequest:
            record_bootstrap_failure(
                self.server.config.database_path,
                server_id=server_id,
                result="invalid-csr",
            )
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_certificate_signing_request"},
            )
            return
        try:
            consume_bootstrap_token(
                self.server.config.database_path,
                server_id=server_id,
                token=first_contact.bootstrap_token,
                collector_public_key_fingerprint=(
                    issued.collector_public_key_fingerprint
                ),
                certificate_expires_at=issued.expires_at,
                scrape_client_certificate_path=(
                    issued.scrape_client_certificate_path
                ),
                scrape_client_key_path=issued.scrape_client_key_path,
                source_address=self._collector_source_address(),
                inventory=first_contact.inventory,
                verification_code=issued.verification_code,
            )
        except InvalidBootstrapCredentials:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "invalid_bootstrap_credentials"},
            )
            return
        self._send_json(
            HTTPStatus.CREATED,
            {
                "certificate": issued.certificate,
                "caCertificate": issued.ca_certificate,
                "scrapeClientCaCertificate": (
                    issued.scrape_client_ca_certificate
                ),
                "expiresAt": issued.expires_at.isoformat(),
                "validForDays": CERTIFICATE_VALIDITY_DAYS,
                "scrapeSet": "staging",
                "verificationCode": issued.verification_code,
            },
        )

    def _check_staged_telemetry(self, server_id: str) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        document = self._read_json()
        if not isinstance(document, dict) or document:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_telemetry_check"},
            )
            return
        try:
            target = get_staging_observation_target(
                self.server.config.database_path,
                server_id=server_id,
            )
            observations = scrape_telemetry(
                target,
                collector_ca_path=(
                    self.server.config.database_path.parent
                    / "pki"
                    / "collector-ca.crt"
                ),
            )
            server = record_staged_observations(
                self.server.config.database_path,
                server_id=server_id,
                observations=observations,
                actor=viewer.login,
            )
        except TelemetryUnavailable:
            self._send_json(
                HTTPStatus.BAD_GATEWAY,
                {"error": "staged_telemetry_unavailable"},
            )
            return
        except EnrollmentDecisionConflict:
            self._send_json(
                HTTPStatus.CONFLICT,
                {"error": "server_not_pending_verification"},
            )
            return
        self._send_json(
            HTTPStatus.OK,
            {"server": self._administrator_server_response(server)},
        )

    def _send_enrollment_requirements(self) -> None:
        document = self._read_json()
        if (
            not isinstance(document, dict)
            or set(document) != {"serverId", "bootstrapToken"}
            or not all(
                isinstance(document[field], str)
                and bool(document[field].strip())
                for field in document
            )
        ):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_bootstrap_request"},
            )
            return
        server_id = document["serverId"].strip()
        if not validate_bootstrap_token(
            self.server.config.database_path,
            server_id=server_id,
            token=document["bootstrapToken"],
        ):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "invalid_bootstrap_credentials"},
            )
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "requiresNvidia": server_requires_nvidia(
                    self.server.config.database_path,
                    server_id=server_id,
                )
            },
        )

    def _decide_enrollment(self, server_id: str) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        document = self._read_json()
        try:
            decision = parse_enrollment_decision(document)
        except InvalidEnrollmentDecision:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_enrollment_decision"},
            )
            return
        try:
            server = decide_enrollment(
                self.server.config.database_path,
                server_id=server_id,
                actor=viewer.login,
                decision=decision,
            )
        except VerificationCodeMismatch:
            self._send_json(
                HTTPStatus.CONFLICT,
                {"error": "verification_code_mismatch"},
            )
            return
        except IncompleteObservations:
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"error": "incomplete_observations"},
            )
            return
        except EnrollmentDecisionConflict:
            self._send_json(
                HTTPStatus.CONFLICT,
                {"error": "server_not_pending_verification"},
            )
            return
        self._send_json(
            HTTPStatus.OK,
            {"server": self._administrator_server_response(server)},
        )
        if decision.kind is EnrollmentDecisionKind.APPROVE:
            self.server.observation_engine.wake()

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
        response: dict[str, object] = {
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
        if server.enrollment_review is not None:
            review = server.enrollment_review
            response["enrollmentReview"] = {
                "verificationCode": review.verification_code,
                "sourceAddress": review.source_address,
                "inventory": review.inventory.as_document(),
                "observationChecks": [
                    {
                        "observation": check.observation,
                        "present": check.present,
                    }
                    for check in review.observation_checks
                ],
                "readyForApproval": review.ready_for_approval,
            }
            response["observationTargetSet"] = "staging"
        if server.inventory is not None:
            response["inventory"] = server.inventory.as_document()
            response["observationTargetSet"] = "active"
        if server.last_rejected_enrollment is not None:
            rejected = server.last_rejected_enrollment
            response["lastRejectedEnrollment"] = {
                "collectorPublicKeyFingerprint": (
                    rejected.collector_public_key_fingerprint
                ),
                "reason": rejected.reason,
            }
        if server.last_observation_result is not None:
            response["lastObservationResult"] = (
                server.last_observation_result
            )
        return response

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

    def _collector_source_address(self) -> str:
        peer_address = ipaddress.ip_address(self.client_address[0])
        trusted_peer = any(
            peer_address in ipaddress.ip_network(network)
            for network in self.server.config.trusted_proxy_networks
        )
        forwarded_for = self.headers.get("X-Forwarded-For", "")
        if trusted_peer and forwarded_for:
            candidate = forwarded_for.split(",", 1)[0].strip()
            try:
                forwarded_address = ipaddress.ip_address(candidate)
            except ValueError:
                pass
            else:
                if (
                    not forwarded_address.is_unspecified
                    and not forwarded_address.is_multicast
                ):
                    return str(forwarded_address)
        return str(peer_address)

    def _send_dashboard(self) -> None:
        viewer = self._authorized_viewer()
        if viewer is None:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "access_denied"})
            return

        experience = empty_fleet_experience(viewer.role)
        servers = (
            list_registered_servers(self.server.config.database_path)
            if viewer.role is Role.LAB_ADMINISTRATOR
            else []
        )
        content = (
            "".join(self._server_card(server) for server in servers)
            if servers
            else f"""
    <section class="empty" aria-labelledby="empty-heading">
      <h2 id="empty-heading">{experience.message}</h2>
      <p>{experience.guidance}</p>
    </section>"""
        )
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
    .server {{ margin-top: 2rem; padding: 1.5rem; border: 1px solid #31415c;
      border-radius: 1rem; background: #172338; }}
    .facts {{ display: grid; grid-template-columns: repeat(auto-fit,
      minmax(13rem, 1fr)); gap: .75rem 1.5rem; }}
    dt {{ color: #a9bad4; }} dd {{ margin: .2rem 0 0; }}
    code {{ font-size: 1.35rem; letter-spacing: .08em; }}
    pre {{ overflow: auto; padding: 1rem; background: #101827;
      border-radius: .5rem; }}
    .actions {{ display: flex; gap: .75rem; flex-wrap: wrap; }}
    button {{ padding: .65rem 1rem; border: 0; border-radius: .45rem;
      cursor: pointer; }}
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
    {content}
  </main>
  <script>
    document.addEventListener("click", async (event) => {{
      const button = event.target.closest("button[data-server-id]");
      if (!button) return;
      const serverId = button.dataset.serverId;
      const action = button.dataset.action;
      let path = `/api/servers/${{serverId}}/staged-telemetry-checks`;
      let body = {{}};
      if (action !== "check") {{
        const reason = window.prompt(`Reason to ${{action}} enrollment:`);
        if (!reason) return;
        path = `/api/servers/${{serverId}}/enrollment-decisions`;
        body = {{
          decision: action,
          verificationCode: button.dataset.verificationCode,
          reason
        }};
      }}
      button.disabled = true;
      const response = await fetch(path, {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify(body)
      }});
      if (!response.ok) {{
        const failure = await response.json();
        window.alert(failure.error);
      }}
      window.location.reload();
    }});
  </script>
</body>
</html>
"""
        self._send_bytes(
            HTTPStatus.OK,
            page.encode(),
            "text/html; charset=utf-8",
        )

    @staticmethod
    def _server_card(server: RegisteredServer) -> str:
        heading = escape(server.display_name)
        state = escape(server.enrollment_state)
        review_html = ""
        if server.enrollment_review is not None:
            review = server.enrollment_review
            inventory = review.inventory.as_document()
            checks = "".join(
                (
                    "<li>"
                    + escape(check.observation)
                    + (
                        ": present"
                        if check.present
                        else ": missing"
                    )
                    + "</li>"
                )
                for check in review.observation_checks
            )
            code = escape(review.verification_code)
            inventory_json = escape(
                json.dumps(inventory, indent=2, sort_keys=True)
            )
            review_html = f"""
      <h3>Explicit first-contact review</h3>
      <dl class="facts">
        <div><dt>Verification code</dt><dd><code>{code}</code></dd></div>
        <div><dt>Source address</dt><dd>{escape(review.source_address)}</dd></div>
        <div><dt>Hostname</dt><dd>{escape(str(inventory["hostname"]))}</dd></div>
        <div><dt>OS</dt><dd>{escape(str(inventory["osRelease"]))}</dd></div>
        <div><dt>CPU</dt><dd>{escape(str(inventory["cpu"]))}</dd></div>
        <div><dt>Memory</dt><dd>{escape(str(inventory["memory"]))}</dd></div>
      </dl>
      <h4>Disk, GPU, and stable-identifier inventory</h4>
      <pre>{inventory_json}</pre>
      <h4>Server Profile observation checks</h4>
      <ul>{checks}</ul>
      <div class="actions">
        <button data-server-id="{escape(server.server_id)}"
          data-action="check">Check staged telemetry</button>
        <button data-server-id="{escape(server.server_id)}"
          data-action="approve" data-verification-code="{code}"
          {"disabled" if not review.ready_for_approval else ""}>Approve</button>
        <button data-server-id="{escape(server.server_id)}"
          data-action="reject" data-verification-code="{code}">Reject</button>
      </div>"""
        elif server.inventory is not None:
            review_html = f"""
      <h3>Verified Server Inventory</h3>
      <pre>{escape(json.dumps(server.inventory.as_document(), indent=2, sort_keys=True))}</pre>"""
        return f"""
    <article class="server">
      <h2>{heading}</h2>
      <p>Server ID: {escape(server.server_id)} · Enrollment: {state}</p>
      {review_html}
    </article>"""

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
            "default-src 'none'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; connect-src 'self'; "
            "frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)
