from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from lab_dashboard.auth import Role, Viewer, authorize
from lab_dashboard.config import DashboardConfig
from lab_dashboard.database import (
    BOOTSTRAP_TOKEN_TTL_SECONDS,
    ConfigurationHashMismatch,
    DisplayNameConflict,
    EnrollmentDecisionConflict,
    IncompleteObservations,
    InvalidBootstrapCredentials,
    ProfileConflict,
    ProfileNotFound,
    ProfileNotPublished,
    ProfileInventoryMismatch,
    ProfilePublication,
    RegisteredServer,
    ServerProfile,
    StagedProfileConfiguration,
    StagedProfileVerificationFailed,
    ServerNotAwaitingFirstContact,
    VerificationCodeMismatch,
    activate_staged_profile_configuration,
    accept_inventory_change,
    clone_profile,
    consume_bootstrap_token,
    create_profile_draft,
    decide_enrollment,
    get_staging_observation_target,
    initialize_database,
    issue_bootstrap_token,
    is_ready,
    list_audit_events,
    list_profiles,
    list_published_profiles,
    list_registered_servers,
    profile_persistent_mountpoints,
    profile_required_observations,
    profile_required_services,
    profile_revision_at,
    profile_temperature_sensors,
    profile_threshold_overrides,
    publish_profile,
    record_bootstrap_failure,
    record_failed_registration,
    record_inventory_observation,
    record_staged_observations,
    register_server,
    retire_profile,
    server_requires_nvidia,
    server_scrape_address,
    stage_profile_configuration,
    staged_profile_configuration,
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
    server_inventory_from_document,
)
from lab_dashboard.installer import signed_installer
from lab_dashboard.health import (
    HealthEvaluation,
    evaluate_server_health,
    health_now,
    initialize_health_database,
)
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
from lab_dashboard.profile import (
    InvalidProfileDefinition,
    InvalidProfileRequest,
    parse_profile_clone,
    parse_profile_draft,
    parse_profile_activation,
    parse_profile_target,
    parse_reason,
)
from lab_dashboard.prometheus import (
    HISTORY_METRICS,
    InvalidHistoryQuery,
    PrometheusUnavailable,
    ResourceUsage,
    current_health_observation,
    current_resource_usage,
    query_metric_history,
    reconcile_prometheus,
    sync_prometheus_config,
    unavailable_health_observation,
    unavailable_resource_usage,
)


MAX_REQUEST_BODY_BYTES = 16_384


def _single_parameter(
    parameters: dict[str, list[str]], name: str
) -> str:
    values = parameters.get(name, [])
    if len(values) != 1 or not values[0]:
        raise InvalidHistoryQuery
    return values[0]


def _format_percent(value: object) -> str:
    number = _display_number(value)
    return "Missing" if number is None else f"{number:.1f}%"


def _format_capacity(used: object, total: object) -> str:
    if used is None or total is None:
        return "Missing"
    used_number = _display_number(used)
    total_number = _display_number(total)
    if used_number is None or total_number is None:
        return "Missing"
    gibibyte = 1024**3
    return (
        f"{used_number / gibibyte:.1f} GiB / "
        f"{total_number / gibibyte:.1f} GiB"
    )


def _format_age(value: object) -> str:
    number = _display_number(value)
    return (
        "last observation unavailable"
        if number is None
        else f"{number:.0f} s old"
    )


def _display_number(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None


def _format_success(value: object) -> str:
    if value is None:
        return "Unavailable"
    return "Succeeded" if value is True else "Failed"


class DashboardServer(ThreadingHTTPServer):
    config: DashboardConfig
    observation_engine: ObservationEngine

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        if self.config.run_observation_engine:
            self.observation_engine.start()
        try:
            super().serve_forever(poll_interval)
        finally:
            if self.config.run_observation_engine:
                self.observation_engine.stop()


def create_server(
    config: DashboardConfig, address: tuple[str, int]
) -> DashboardServer:
    initialize_database(config.database_path)
    initialize_health_database(config.database_path)
    sync_prometheus_config(config.database_path)
    server = DashboardServer(address, DashboardRequestHandler)
    server.config = config
    server.observation_engine = ObservationEngine(
        config.database_path, config.prometheus_url
    )
    return server


class DashboardRequestHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def do_GET(self) -> None:
        request = urlsplit(self.path)
        path = request.path
        if path == "/health/live":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/health/ready":
            self._send_readiness()
            return
        if path == "/api/fleet":
            self._send_fleet()
            return
        if path == "/api/server-profiles":
            self._send_server_profiles(
                include_all=(
                    parse_qs(request.query).get("include") == ["all"]
                )
            )
            return
        if path == "/api/audit-events":
            self._send_audit_events()
            return
        collector_prefix = "/api/collectors/"
        configuration_suffix = "/profile-configuration"
        if path.startswith(collector_prefix) and path.endswith(
            configuration_suffix
        ):
            server_id = path[
                len(collector_prefix) : -len(configuration_suffix)
            ]
            self._send_collector_profile_configuration(server_id)
            return
        server_prefix = "/api/servers/"
        history_suffix = "/metric-history"
        if path.startswith(server_prefix) and path.endswith(history_suffix):
            server_id = path[len(server_prefix) : -len(history_suffix)]
            self._send_metric_history(
                server_id, parse_qs(request.query, keep_blank_values=True)
            )
            return
        if path.startswith(server_prefix):
            server_id = path[len(server_prefix) :]
            if "/" not in server_id:
                self._send_server(server_id)
                return
        workspace_prefix = "/servers/"
        if path.startswith(workspace_prefix):
            server_id = path[len(workspace_prefix) :]
            if "/" not in server_id:
                self._send_dashboard(selected_server_id=server_id)
                return
        if path == "/":
            self._send_dashboard()
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        request = urlsplit(self.path)
        path = request.path
        if path == "/api/server-profiles":
            self._clone_server_profile()
            return
        profile_prefix = "/api/server-profiles/"
        if path.startswith(profile_prefix):
            profile_parts = path[len(profile_prefix) :].split("/")
            if len(profile_parts) == 2 and profile_parts[1] == "revisions":
                self._create_server_profile_draft(profile_parts[0])
                return
            if (
                len(profile_parts) == 4
                and profile_parts[1] == "revisions"
                and profile_parts[3] == "publish"
            ):
                try:
                    revision = int(profile_parts[2])
                except ValueError:
                    pass
                else:
                    self._publish_server_profile(
                        profile_parts[0], revision
                    )
                    return
            if (
                len(profile_parts) == 4
                and profile_parts[1] == "revisions"
                and profile_parts[3] == "retire"
            ):
                try:
                    revision = int(profile_parts[2])
                except ValueError:
                    pass
                else:
                    self._retire_server_profile(
                        profile_parts[0], revision
                    )
                    return
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
        activation_suffix = "/profile-activations"
        if self.path.startswith(prefix) and self.path.endswith(
            activation_suffix
        ):
            server_id = self.path[len(prefix) : -len(activation_suffix)]
            self._activate_server_profile(server_id)
            return
        assignment_suffix = "/profile-assignments"
        if self.path.startswith(prefix) and self.path.endswith(
            assignment_suffix
        ):
            server_id = self.path[len(prefix) : -len(assignment_suffix)]
            self._stage_server_profile(server_id, operation="assignment")
            return
        rollback_suffix = "/profile-rollbacks"
        if self.path.startswith(prefix) and self.path.endswith(
            rollback_suffix
        ):
            server_id = self.path[len(prefix) : -len(rollback_suffix)]
            self._stage_server_profile(server_id, operation="rollback")
            return
        inventory_observation_suffix = "/inventory-observations"
        if self.path.startswith(prefix) and self.path.endswith(
            inventory_observation_suffix
        ):
            server_id = self.path[
                len(prefix) : -len(inventory_observation_suffix)
            ]
            self._record_inventory_observation(server_id)
            return
        inventory_acceptance_suffix = "/inventory-acceptances"
        if self.path.startswith(prefix) and self.path.endswith(
            inventory_acceptance_suffix
        ):
            server_id = self.path[
                len(prefix) : -len(inventory_acceptance_suffix)
            ]
            self._accept_inventory_change(server_id)
            return
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
        servers = list_registered_servers(self.server.config.database_path)
        fleet = [
            self._fleet_server_response(server, viewer.role)
            for server in servers
            if (
                viewer.role is Role.LAB_ADMINISTRATOR
                or server.enrollment_state == "active"
            )
        ]
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

    def _send_server_profiles(self, *, include_all: bool = False) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        profiles = list_profiles(
            self.server.config.database_path, include_all=include_all
        )
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

    def _clone_server_profile(self) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        try:
            request = parse_profile_clone(self._read_json())
            profile = clone_profile(
                self.server.config.database_path,
                request=request,
                actor=viewer.login,
            )
        except InvalidProfileRequest:
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": "invalid_profile_request"}
            )
            return
        except ProfileNotFound:
            self._send_json(
                HTTPStatus.NOT_FOUND, {"error": "profile_not_found"}
            )
            return
        except ProfileConflict:
            self._send_json(
                HTTPStatus.CONFLICT, {"error": "profile_conflict"}
            )
            return
        self._send_json(
            HTTPStatus.CREATED, {"profile": self._profile_response(profile)}
        )

    def _create_server_profile_draft(self, profile_id: str) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        try:
            request = parse_profile_draft(self._read_json())
            profile = create_profile_draft(
                self.server.config.database_path,
                profile_id=profile_id,
                request=request,
                actor=viewer.login,
            )
        except InvalidProfileDefinition as error:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": "invalid_profile_definition",
                    "details": error.details,
                },
            )
            return
        except InvalidProfileRequest:
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": "invalid_profile_request"}
            )
            return
        except ProfileNotFound:
            self._send_json(
                HTTPStatus.NOT_FOUND, {"error": "profile_not_found"}
            )
            return
        except ProfileConflict:
            self._send_json(
                HTTPStatus.CONFLICT, {"error": "profile_conflict"}
            )
            return
        self._send_json(
            HTTPStatus.CREATED, {"profile": self._profile_response(profile)}
        )

    def _publish_server_profile(
        self, profile_id: str, revision: int
    ) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        try:
            reason = parse_reason(self._read_json())
            publication = publish_profile(
                self.server.config.database_path,
                profile_id=profile_id,
                revision=revision,
                actor=viewer.login,
                reason=reason,
            )
        except InvalidProfileRequest:
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": "invalid_profile_request"}
            )
            return
        except InvalidProfileDefinition as error:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": "invalid_profile_definition",
                    "details": error.details,
                },
            )
            return
        except ProfileNotFound:
            self._send_json(
                HTTPStatus.NOT_FOUND, {"error": "profile_not_found"}
            )
            return
        except ProfileConflict:
            self._send_json(
                HTTPStatus.CONFLICT, {"error": "profile_conflict"}
            )
            return
        self._send_json(
            HTTPStatus.OK, self._publication_response(publication)
        )

    def _retire_server_profile(
        self, profile_id: str, revision: int
    ) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        try:
            reason = parse_reason(self._read_json())
            profile = retire_profile(
                self.server.config.database_path,
                profile_id=profile_id,
                revision=revision,
                actor=viewer.login,
                reason=reason,
            )
        except InvalidProfileRequest:
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": "invalid_profile_request"}
            )
            return
        except ProfileNotFound:
            self._send_json(
                HTTPStatus.NOT_FOUND, {"error": "profile_not_found"}
            )
            return
        except ProfileConflict:
            self._send_json(
                HTTPStatus.CONFLICT, {"error": "profile_in_use_or_immutable"}
            )
            return
        self._send_json(
            HTTPStatus.OK, {"profile": self._profile_response(profile)}
        )

    @staticmethod
    def _profile_response(profile: ServerProfile) -> dict[str, object]:
        return {
            "profileId": profile.profile_id,
            "name": profile.name,
            "revision": profile.revision,
            "state": profile.state,
            "definition": profile.definition,
        }

    @classmethod
    def _publication_response(
        cls, publication: ProfilePublication
    ) -> dict[str, object]:
        return {
            "profile": cls._profile_response(publication.profile),
            "effectiveChanges": publication.effective_changes,
            "affectedServerIds": publication.affected_server_ids,
            "configurationHash": publication.configuration_hash,
        }

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

    def _send_collector_profile_configuration(
        self, server_id: str
    ) -> None:
        if not self._verified_collector(server_id):
            self._send_json(
                HTTPStatus.FORBIDDEN, {"error": "access_denied"}
            )
            return
        try:
            pending = staged_profile_configuration(
                self.server.config.database_path, server_id=server_id
            )
        except ProfileNotFound:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": "profile_configuration_not_staged"},
            )
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "profileId": pending.profile_id,
                "revision": pending.revision,
                "configurationHash": pending.configuration_hash,
                "configuration": pending.bundle,
            },
        )

    def _stage_server_profile(
        self, server_id: str, *, operation: str
    ) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        try:
            request = parse_profile_target(self._read_json())
            staged = stage_profile_configuration(
                self.server.config.database_path,
                server_id=server_id,
                profile_id=request.profile_id,
                revision=request.revision,
                operation=operation,
                actor=viewer.login,
                reason=request.reason,
            )
        except InvalidProfileRequest:
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": "invalid_profile_request"}
            )
            return
        except ProfileNotFound:
            self._send_json(
                HTTPStatus.NOT_FOUND, {"error": "profile_not_found"}
            )
            return
        except ProfileNotPublished:
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"error": "profile_not_published"},
            )
            return
        except ProfileConflict:
            self._send_json(
                HTTPStatus.CONFLICT, {"error": "profile_conflict"}
            )
            return
        self._send_json(
            HTTPStatus.ACCEPTED, self._staged_profile_response(staged)
        )

    def _record_inventory_observation(self, server_id: str) -> None:
        if not self._verified_collector(server_id):
            self._send_json(
                HTTPStatus.FORBIDDEN, {"error": "access_denied"}
            )
            return
        document = self._read_json()
        try:
            if (
                not isinstance(document, dict)
                or set(document) != {"inventory"}
            ):
                raise InvalidFirstContact
            inventory = server_inventory_from_document(
                document["inventory"]
            )
            pending = record_inventory_observation(
                self.server.config.database_path,
                server_id=server_id,
                inventory=inventory,
                actor=f"collector:{server_id}",
                reason="Collector reported current Server Inventory",
            )
        except InvalidFirstContact:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_inventory_observation"},
            )
            return
        except ProfileNotFound:
            self._send_json(
                HTTPStatus.NOT_FOUND, {"error": "server_not_found"}
            )
            return
        self._send_json(
            HTTPStatus.ACCEPTED,
            {
                "pendingInventoryChange": (
                    pending.as_document() if pending is not None else None
                )
            },
        )

    def _accept_inventory_change(self, server_id: str) -> None:
        viewer = self._lab_administrator()
        if viewer is None:
            return
        try:
            reason = parse_reason(self._read_json())
            server = accept_inventory_change(
                self.server.config.database_path,
                server_id=server_id,
                actor=viewer.login,
                reason=reason,
            )
        except InvalidProfileRequest:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_inventory_acceptance"},
            )
            return
        except ProfileConflict:
            self._send_json(
                HTTPStatus.CONFLICT,
                {"error": "inventory_change_not_pending"},
            )
            return
        self._send_json(
            HTTPStatus.OK,
            {"server": self._administrator_server_response(server)},
        )

    def _activate_server_profile(self, server_id: str) -> None:
        if not self._verified_collector(server_id):
            self._send_json(
                HTTPStatus.FORBIDDEN, {"error": "access_denied"}
            )
            return
        try:
            request = parse_profile_activation(self._read_json())
            inventory = server_inventory_from_document(request.inventory)
            server = activate_staged_profile_configuration(
                self.server.config.database_path,
                server_id=server_id,
                reported_configuration_hash=(
                    request.reported_configuration_hash
                ),
                observations=request.observations,
                inventory=inventory,
                actor=f"collector:{server_id}",
                reason="Collector reported applied configuration hash",
            )
        except (InvalidProfileRequest, InvalidFirstContact):
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": "invalid_profile_request"}
            )
            return
        except ProfileConflict:
            self._send_json(
                HTTPStatus.CONFLICT,
                {"error": "profile_activation_not_staged"},
            )
            return
        except ConfigurationHashMismatch as error:
            self._send_json(
                HTTPStatus.CONFLICT,
                {
                    "error": "configuration_hash_mismatch",
                    "activeProfileRevision": error.active_revision,
                },
            )
            return
        except StagedProfileVerificationFailed as error:
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {
                    "error": "profile_requirements_not_verified",
                    "activeProfileRevision": error.active_revision,
                },
            )
            return
        self._send_json(
            HTTPStatus.OK,
            {"server": self._administrator_server_response(server)},
        )

    def _verified_collector(self, server_id: str) -> bool:
        peer_address = ipaddress.ip_address(self.client_address[0])
        trusted_peer = any(
            peer_address in ipaddress.ip_network(network)
            for network in self.server.config.trusted_proxy_networks
        )
        return (
            trusted_peer
            and bool(server_id)
            and "/" not in server_id
            and self.headers.get("X-Verified-Collector-Server-ID", "")
            == server_id
        )

    @staticmethod
    def _staged_profile_response(
        staged: StagedProfileConfiguration,
    ) -> dict[str, object]:
        return {
            "profileId": staged.pending.profile_id,
            "revision": staged.pending.revision,
            "configurationHash": staged.pending.configuration_hash,
            "configuration": staged.pending.bundle,
            "operation": staged.pending.operation,
            "activeProfileRevision": staged.active_revision,
        }

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
            {
                "server": self._fleet_server_response(
                    server, Role.LAB_ADMINISTRATOR
                )
            },
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
        except ProfileInventoryMismatch:
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"error": "profile_inventory_mismatch"},
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
            {
                "server": self._fleet_server_response(
                    server, Role.LAB_ADMINISTRATOR
                )
            },
        )
        if decision.kind is EnrollmentDecisionKind.APPROVE:
            try:
                reconcile_prometheus(
                    self.server.config.database_path,
                    self.server.config.prometheus_url,
                )
            except PrometheusUnavailable:
                pass
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
        if server.pending_profile_configuration is not None:
            pending = server.pending_profile_configuration
            response["pendingProfileConfiguration"] = {
                "profileId": pending.profile_id,
                "revision": pending.revision,
                "configurationHash": pending.configuration_hash,
                "operation": pending.operation,
            }
        if server.pending_inventory_change is not None:
            response["pendingInventoryChange"] = (
                server.pending_inventory_change.as_document()
            )
        if server.active_configuration_hash is not None:
            response["activeConfigurationHash"] = (
                server.active_configuration_hash
            )
        return response

    def _fleet_server_response(
        self, server: RegisteredServer, role: Role
    ) -> dict[str, object]:
        if role is Role.LAB_ADMINISTRATOR:
            response = self._administrator_server_response(server)
        else:
            response = {
                "serverId": server.server_id,
                "displayName": server.display_name,
                "profile": {
                    "profileId": server.profile.profile_id,
                    "name": server.profile.name,
                    "revision": server.profile.revision,
                },
                "enrollmentState": server.enrollment_state,
                "serverHealth": None,
            }
        if server.enrollment_state == "active":
            evaluation = self._health_evaluation(server)
            response["serverHealth"] = evaluation["serverHealth"]
            if role is Role.LAB_ADMINISTRATOR:
                response["activeHealthCauses"] = evaluation[
                    "activeHealthCauses"
                ]
                response["serverIncidents"] = evaluation["serverIncidents"]
            resource_usage = dict(self._resource_usage(server))
            if role is Role.LAB_USER:
                resource_usage.pop("collector", None)
            response["resourceUsage"] = resource_usage
        return response

    def _health_evaluation(
        self, server: RegisteredServer
    ) -> HealthEvaluation:
        mountpoints = self._persistent_mountpoints(server)
        try:
            observation = current_health_observation(
                self.server.config.prometheus_url,
                server.server_id,
                mountpoints,
                required_observations=profile_required_observations(server),
                required_services=profile_required_services(server),
                temperature_sensors=profile_temperature_sensors(server),
            )
        except PrometheusUnavailable:
            observation = unavailable_health_observation(mountpoints)
        observation["inventoryMatchesProfile"] = (
            server.pending_inventory_change is None
        )
        return evaluate_server_health(
            self.server.config.database_path,
            server_id=server.server_id,
            observation=observation,
            now=health_now(),
            threshold_overrides=profile_threshold_overrides(server),
        )

    def _resource_usage(self, server: RegisteredServer) -> ResourceUsage:
        mountpoints = self._persistent_mountpoints(server)
        try:
            return current_resource_usage(
                self.server.config.prometheus_url,
                server.server_id,
                mountpoints,
            )
        except PrometheusUnavailable:
            return unavailable_resource_usage(mountpoints)

    def _persistent_mountpoints(
        self, server: RegisteredServer
    ) -> tuple[str, ...]:
        return profile_persistent_mountpoints(server)

    def _send_server(self, server_id: str) -> None:
        viewer = self._authorized_viewer()
        if viewer is None:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "access_denied"})
            return
        server = next(
            (
                candidate
                for candidate in list_registered_servers(
                    self.server.config.database_path
                )
                if candidate.server_id == server_id
            ),
            None,
        )
        if server is None or (
            viewer.role is Role.LAB_USER
            and server.enrollment_state != "active"
        ):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        self._send_json(
            HTTPStatus.OK,
            {"server": self._fleet_server_response(server, viewer.role)},
        )

    def _send_metric_history(
        self, server_id: str, parameters: dict[str, list[str]]
    ) -> None:
        viewer = self._authorized_viewer()
        if viewer is None:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "access_denied"})
            return
        server = next(
            (
                candidate
                for candidate in list_registered_servers(
                    self.server.config.database_path
                )
                if candidate.server_id == server_id
                and candidate.enrollment_state == "active"
            ),
            None,
        )
        try:
            metric = _single_parameter(parameters, "metric")
            start = datetime.fromisoformat(
                _single_parameter(parameters, "start")
            )
            end = datetime.fromisoformat(
                _single_parameter(parameters, "end")
            )
            step = int(_single_parameter(parameters, "step"))
            mountpoint = parameters.get("mountpoint", ["/"])
            persistent_mounts = (
                server.profile.definition.get("persistentMounts", ["/"])
                if server is not None
                else []
            )
            if (
                server is None
                or metric not in HISTORY_METRICS
                or len(mountpoint) != 1
                or not isinstance(persistent_mounts, list)
                or mountpoint[0] not in persistent_mounts
            ):
                raise InvalidHistoryQuery
            history = query_metric_history(
                self.server.config.prometheus_url,
                server_id=server_id,
                metric=metric,
                start=start,
                end=end,
                step=step,
                mountpoint=mountpoint[0],
            )
            points = history.get("points", [])
            if isinstance(points, list):
                for point in points:
                    if (
                        not isinstance(point, dict)
                        or not isinstance(point.get("observedAt"), str)
                    ):
                        continue
                    profile = profile_revision_at(
                        self.server.config.database_path,
                        server_id=server_id,
                        observed_at=point["observedAt"],
                    )
                    if profile is not None:
                        point["profileId"], point["profileRevision"] = profile
        except (InvalidHistoryQuery, TypeError, ValueError):
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": "invalid_history_query"}
            )
            return
        except PrometheusUnavailable:
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "metric_history_unavailable"},
            )
            return
        self._send_json(HTTPStatus.OK, history)

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

    def _send_dashboard(
        self, selected_server_id: str | None = None
    ) -> None:
        viewer = self._authorized_viewer()
        if viewer is None:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "access_denied"})
            return

        experience = empty_fleet_experience(viewer.role)
        servers = [
            server
            for server in list_registered_servers(
                self.server.config.database_path
            )
            if (
                viewer.role is Role.LAB_ADMINISTRATOR
                or server.enrollment_state == "active"
            )
        ]
        if selected_server_id is not None:
            servers = [
                server
                for server in servers
                if server.server_id == selected_server_id
            ]
            if not servers:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
        content = (
            "".join(
                self._server_card(
                    server,
                    viewer.role,
                    selected=selected_server_id is not None,
                )
                for server in servers
            )
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
    .usage {{ display: grid; grid-template-columns: repeat(auto-fit,
      minmax(12rem, 1fr)); gap: .75rem; }}
    .usage div {{ padding: 1rem; border-radius: .6rem; background: #101827; }}
    .history-output {{ min-height: 2rem; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <main>
    <header>
      <div><h1>Lab Server Health</h1><p>{
          "Selected-server workspace"
          if selected_server_id is not None
          else "Fleet overview"
      }</p>{
          '<a href="/">Back to fleet</a>'
          if selected_server_id is not None
          else ""
      }</div>
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
      if (button.dataset.action === "history") {{
        const workspace = button.closest(".history");
        const metric = workspace.querySelector("[name=metric]").value;
        const selectedEnd = workspace.querySelector("[name=end]").value;
        const end = selectedEnd ? new Date(selectedEnd) : new Date();
        const selectedStart = workspace.querySelector("[name=start]").value;
        const start = selectedStart
          ? new Date(selectedStart)
          : new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);
        const step = workspace.querySelector("[name=step]").value;
        const mountpoint = workspace.querySelector("[name=mountpoint]").value;
        const query = new URLSearchParams({{
          metric, start: start.toISOString(), end: end.toISOString(),
          step, mountpoint
        }});
        const response = await fetch(
          `/api/servers/${{serverId}}/metric-history?${{query}}`
        );
        const payload = await response.json();
        const output = workspace.querySelector(".history-output");
        output.replaceChildren();
        if (!response.ok) {{
          output.textContent = payload.error;
          return;
        }}
        for (const point of payload.points) {{
          const row = document.createElement("tr");
          for (const value of [point.observedAt, point.value ?? "Missing"]) {{
            const cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
          }}
          output.appendChild(row);
        }}
        return;
      }}
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

    def _server_card(
        self, server: RegisteredServer, role: Role, *, selected: bool
    ) -> str:
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
        elif (
            server.inventory is not None
            and role is Role.LAB_ADMINISTRATOR
        ):
            review_html = f"""
      <h3>Verified Server Inventory</h3>
      <pre>{escape(json.dumps(server.inventory.as_document(), indent=2, sort_keys=True))}</pre>"""
        usage_html = ""
        if server.enrollment_state == "active":
            evaluation = self._health_evaluation(server)
            health = evaluation["serverHealth"]
            health_html = (
                "<h3>Server Health</h3><p><strong>"
                + escape(health["state"])
                + "</strong> — "
                + escape(health["explanation"])
                + "</p>"
            )
            if role is Role.LAB_ADMINISTRATOR:
                causes = evaluation["activeHealthCauses"]
                cause_items = "".join(
                    "<li>"
                    + escape(cause["severity"])
                    + ": "
                    + escape(cause["summary"])
                    + "</li>"
                    for cause in causes
                )
                incidents = evaluation["serverIncidents"]
                incident_items = "".join(
                    "<li>Server Incident #"
                    + str(incident["incidentId"])
                    + " opened "
                    + escape(incident["openedAt"])
                    + (
                        " and remains open"
                        if incident["closedAt"] is None
                        else " and closed " + escape(incident["closedAt"])
                    )
                    + "</li>"
                    for incident in incidents
                )
                health_html += (
                    "<h4>Active health-rule causes</h4><ul>"
                    + (cause_items or "<li>None</li>")
                    + "</ul><h4>Server Incident timeline</h4><ul>"
                    + (incident_items or "<li>No Server Incidents</li>")
                    + "</ul>"
                )
            usage = self._resource_usage(server)
            cpu = _format_percent(usage["cpu"]["usedPercent"])
            memory = usage["systemMemory"]
            memory_value = _format_capacity(
                memory["usedBytes"], memory["totalBytes"]
            )
            filesystems = usage["filesystems"]
            disks = "".join(
                (
                    "<div><strong>Disk "
                    + escape(str(filesystem["mountpoint"]))
                    + "</strong><br>"
                    + escape(
                        _format_capacity(
                            filesystem["usedBytes"],
                            filesystem["totalBytes"],
                        )
                    )
                    + " · "
                    + escape(_format_percent(filesystem["usedPercent"]))
                    + "</div>"
                )
                for filesystem in filesystems
            )
            freshness = usage["freshness"]
            administrator_collector = ""
            if role is Role.LAB_ADMINISTRATOR:
                collector = usage["collector"]
                administrator_collector = (
                    "<div><strong>Collector scrape</strong><br>"
                    + escape(_format_success(collector["success"]))
                    + "</div>"
                )
            mount_options = "".join(
                (
                    '<option value="'
                    + escape(str(filesystem["mountpoint"]), quote=True)
                    + '">'
                    + escape(str(filesystem["mountpoint"]))
                    + "</option>"
                )
                for filesystem in filesystems
            )
            history_html = (
                f"""
      <section class="history">
        <h3>Metric History</h3>
        <p>Query any interval in the retained 30-day observation window.</p>
        <label>Metric
          <select name="metric">
            <option value="cpu">CPU used (%)</option>
            <option value="system-memory">System memory used (%)</option>
            <option value="disk">Persistent filesystem used (%)</option>
          </select>
        </label>
        <label>Filesystem
          <select name="mountpoint">{mount_options}</select>
        </label>
        <label>Start <input name="start" type="datetime-local"></label>
        <label>End <input name="end" type="datetime-local"></label>
        <label>Resolution
          <select name="step">
            <option value="300">5 minutes</option>
            <option value="3600" selected>1 hour</option>
            <option value="86400">1 day</option>
          </select>
        </label>
        <button data-server-id="{escape(server.server_id)}"
          data-action="history">Query history</button>
        <table>
          <thead><tr><th>Observed at</th><th>Value (%)</th></tr></thead>
          <tbody class="history-output" aria-live="polite"></tbody>
        </table>
      </section>"""
                if selected
                else (
                    '<p><a href="/servers/'
                    + escape(server.server_id, quote=True)
                    + '">Open selected-server workspace</a></p>'
                )
            )
            usage_html = f"""
      {health_html}
      <h3>Resource Usage</h3>
      <div class="usage">
        <div><strong>CPU</strong><br>{escape(cpu)}</div>
        <div><strong>System memory</strong><br>{escape(memory_value)}
          · {escape(_format_percent(memory["usedPercent"]))}</div>
        {disks}
        <div><strong>Data freshness</strong><br>
          {escape(str(freshness["state"]))} ·
          {escape(_format_age(freshness["ageSeconds"]))}</div>
        {administrator_collector}
      </div>
      {history_html}"""
        return f"""
    <article class="server">
      <h2>{heading}</h2>
      <p>Server ID: {escape(server.server_id)} · Enrollment: {state}</p>
      {usage_html}
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
