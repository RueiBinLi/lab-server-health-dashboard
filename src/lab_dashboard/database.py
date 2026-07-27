from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from lab_dashboard.enrollment import (
    EnrollmentDecision,
    EnrollmentDecisionKind,
    ServerInventory,
    server_inventory_from_document,
)


BOOTSTRAP_TOKEN_TTL_SECONDS = 15 * 60


GENERAL_LINUX_DEFINITION = {
    "capabilities": {"gpu": False},
    "requiredObservations": [
        "reachability",
        "cpu",
        "memory",
        "root-filesystem",
        "temperature-headroom",
        "critical-errors",
    ],
    "persistentMounts": ["/"],
    "requiredServices": [],
    "thresholdOverrides": [],
}
NVIDIA_GPU_DEFINITION = {
    "capabilities": {
        "gpu": True,
        "expectedDeviceCount": 1,
        "modelClass": "NVIDIA CUDA-capable GPU",
    },
    "requiredObservations": [
        "reachability",
        "cpu",
        "memory",
        "root-filesystem",
        "temperature-headroom",
        "critical-errors",
        "gpu-utilization",
        "gpu-vram",
        "gpu-temperature",
        "gpu-faults",
    ],
    "persistentMounts": ["/"],
    "requiredServices": [],
    "thresholdOverrides": [],
}
SEEDED_PROFILES = (
    (
        "general-linux",
        1,
        "General Linux Server",
        GENERAL_LINUX_DEFINITION,
    ),
    (
        "nvidia-gpu-compute",
        1,
        "NVIDIA GPU Compute Server",
        NVIDIA_GPU_DEFINITION,
    ),
)


@dataclass(frozen=True)
class ServerProfile:
    profile_id: str
    revision: int
    name: str
    state: str
    definition: dict[str, object]


@dataclass(frozen=True)
class ObservationCheck:
    observation: str
    present: bool


@dataclass(frozen=True)
class EnrollmentReview:
    verification_code: str
    source_address: str
    inventory: ServerInventory
    observation_checks: tuple[ObservationCheck, ...]
    ready_for_approval: bool


@dataclass(frozen=True)
class RejectedEnrollment:
    collector_public_key_fingerprint: str
    reason: str


@dataclass(frozen=True)
class ObservationTarget:
    server_id: str
    scrape_address: str
    scrape_client_certificate_path: str
    scrape_client_key_path: str


@dataclass(frozen=True)
class RegisteredServer:
    server_id: str
    display_name: str
    scrape_address: str
    profile: ServerProfile
    enrollment_state: str
    enrollment_review: EnrollmentReview | None
    inventory: ServerInventory | None
    last_rejected_enrollment: RejectedEnrollment | None
    last_observation_result: str | None


def profile_persistent_mountpoints(
    server: RegisteredServer,
) -> tuple[str, ...]:
    mounts = server.profile.definition.get("persistentMounts", ["/"])
    mount_values = mounts if isinstance(mounts, list) else ["/"]
    return tuple(mount for mount in mount_values if isinstance(mount, str))


def profile_required_observations(
    server: RegisteredServer,
) -> tuple[str, ...]:
    observations = server.profile.definition.get("requiredObservations", [])
    observation_values = (
        observations if isinstance(observations, list) else []
    )
    return tuple(
        observation
        for observation in observation_values
        if isinstance(observation, str)
    )


def profile_required_services(
    server: RegisteredServer,
) -> tuple[str, ...]:
    services = server.profile.definition.get("requiredServices", [])
    service_values = services if isinstance(services, list) else []
    return tuple(
        service for service in service_values if isinstance(service, str)
    )


class DisplayNameConflict(Exception):
    pass


class ProfileNotPublished(Exception):
    pass


class ServerNotAwaitingFirstContact(Exception):
    pass


class InvalidBootstrapCredentials(Exception):
    pass


class EnrollmentDecisionConflict(Exception):
    pass


class VerificationCodeMismatch(Exception):
    pass


class IncompleteObservations(Exception):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def initialize_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(_connect(path)) as connection:
        with connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS server_profiles (
                    profile_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    state TEXT NOT NULL,
                    definition_json TEXT NOT NULL,
                    seeded INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (profile_id, revision)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS servers (
                    server_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL
                )
                """
            )
            _add_server_columns(connection)
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS servers_display_name_unique
                ON servers (display_name COLLATE NOCASE)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    server_id TEXT,
                    reason TEXT NOT NULL,
                    result TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS bootstrap_tokens (
                    token_hash TEXT PRIMARY KEY,
                    server_id TEXT NOT NULL REFERENCES servers(server_id),
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS collector_certificates (
                    server_id TEXT PRIMARY KEY REFERENCES servers(server_id),
                    collector_public_key_fingerprint TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS staging_scrape_targets (
                    server_id TEXT PRIMARY KEY REFERENCES servers(server_id),
                    scrape_address TEXT NOT NULL,
                    added_at TEXT NOT NULL,
                    scrape_client_certificate_path TEXT NOT NULL,
                    scrape_client_key_path TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_enrollments (
                    server_id TEXT PRIMARY KEY REFERENCES servers(server_id),
                    source_address TEXT NOT NULL,
                    inventory_json TEXT NOT NULL,
                    observations_json TEXT NOT NULL,
                    verification_code TEXT NOT NULL,
                    first_contact_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS verified_server_inventory (
                    server_id TEXT PRIMARY KEY REFERENCES servers(server_id),
                    inventory_json TEXT NOT NULL,
                    verified_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS active_scrape_targets (
                    server_id TEXT PRIMARY KEY REFERENCES servers(server_id),
                    scrape_address TEXT NOT NULL,
                    activated_at TEXT NOT NULL,
                    scrape_client_certificate_path TEXT NOT NULL,
                    scrape_client_key_path TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS observation_runs (
                    observation_run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id TEXT NOT NULL REFERENCES servers(server_id),
                    observed_at TEXT NOT NULL,
                    result TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS revoked_collector_fingerprints (
                    collector_public_key_fingerprint TEXT PRIMARY KEY,
                    server_id TEXT NOT NULL REFERENCES servers(server_id),
                    revoked_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
                """
            )
            _rename_legacy_fingerprint_columns(connection)
            for profile_id, revision, name, definition in SEEDED_PROFILES:
                encoded_definition = json.dumps(
                    definition, separators=(",", ":")
                )
                existing_profile = connection.execute(
                    """
                    SELECT name, state, definition_json, seeded
                    FROM server_profiles
                    WHERE profile_id = ? AND revision = ?
                    """,
                    (profile_id, revision),
                ).fetchone()
                if existing_profile is None:
                    connection.execute(
                        """
                        INSERT INTO server_profiles (
                            profile_id, revision, name, state,
                            definition_json, seeded
                        ) VALUES (?, ?, ?, 'published', ?, 1)
                        """,
                        (profile_id, revision, name, encoded_definition),
                    )
                elif (
                    existing_profile["name"] != name
                    or existing_profile["state"] != "published"
                    or existing_profile["definition_json"]
                    != encoded_definition
                    or existing_profile["seeded"] != 1
                ):
                    raise sqlite3.IntegrityError(
                        "seeded profile revision conflicts with canonical seed"
                    )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS immutable_seeded_profile_update
                BEFORE UPDATE ON server_profiles
                WHEN OLD.seeded = 1
                BEGIN
                    SELECT RAISE(ABORT, 'seeded profile revision is immutable');
                END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS immutable_seeded_profile_delete
                BEFORE DELETE ON server_profiles
                WHEN OLD.seeded = 1
                BEGIN
                    SELECT RAISE(ABORT, 'seeded profile revision is immutable');
                END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS immutable_server_id
                BEFORE UPDATE OF server_id ON servers
                BEGIN
                    SELECT RAISE(ABORT, 'server ID is immutable');
                END
                """
            )


def _add_server_columns(connection: sqlite3.Connection) -> None:
    existing_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(servers)")
    }
    additions = {
        "scrape_address": "TEXT",
        "profile_id": "TEXT",
        "profile_revision": "INTEGER",
        "enrollment_state": "TEXT",
        "created_at": "TEXT",
    }
    for name, column_type in additions.items():
        if name not in existing_columns:
            connection.execute(
                f"ALTER TABLE servers ADD COLUMN {name} {column_type}"
            )


def _rename_legacy_fingerprint_columns(
    connection: sqlite3.Connection,
) -> None:
    for table in (
        "collector_certificates",
        "revoked_collector_fingerprints",
    ):
        columns = {
            row["name"]
            for row in connection.execute(f"PRAGMA table_info({table})")
        }
        if (
            "certificate_fingerprint" in columns
            and "collector_public_key_fingerprint" not in columns
        ):
            connection.execute(
                f"""
                ALTER TABLE {table}
                RENAME COLUMN certificate_fingerprint
                TO collector_public_key_fingerprint
                """
            )


def list_published_profiles(path: Path) -> list[ServerProfile]:
    with closing(_connect(path)) as connection:
        rows = connection.execute(
            """
            SELECT profile_id, revision, name, state, definition_json
            FROM server_profiles
            WHERE state = 'published'
            ORDER BY profile_id
            """
        ).fetchall()
    return [_profile_from_row(row) for row in rows]


def register_server(
    path: Path,
    *,
    server_id: str,
    display_name: str,
    scrape_address: str,
    profile_id: str,
    actor: str,
    reason: str,
) -> RegisteredServer:
    occurred_at = _now().isoformat()
    with closing(_connect(path)) as connection:
        try:
            with connection:
                profile_row = connection.execute(
                    """
                    SELECT
                        profile_id, revision, name, state, definition_json
                    FROM server_profiles
                    WHERE profile_id = ? AND state = 'published'
                    ORDER BY revision DESC
                    LIMIT 1
                    """,
                    (profile_id,),
                ).fetchone()
                if profile_row is None:
                    raise ProfileNotPublished
                connection.execute(
                    """
                    INSERT INTO servers (
                        server_id, display_name, scrape_address,
                        profile_id, profile_revision, enrollment_state,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, 'awaiting-first-contact', ?)
                    """,
                    (
                        server_id,
                        display_name,
                        scrape_address,
                        profile_id,
                        profile_row["revision"],
                        occurred_at,
                    ),
                )
                _insert_audit_event(
                    connection,
                    occurred_at=occurred_at,
                    actor=actor,
                    action="server-registration",
                    server_id=server_id,
                    reason=reason,
                    result="succeeded",
                )
        except sqlite3.IntegrityError as error:
            if "servers.display_name" not in str(error):
                raise
            raise DisplayNameConflict from error

    return RegisteredServer(
        server_id=server_id,
        display_name=display_name,
        scrape_address=scrape_address,
        profile=_profile_from_row(profile_row),
        enrollment_state="awaiting-first-contact",
        enrollment_review=None,
        inventory=None,
        last_rejected_enrollment=None,
        last_observation_result=None,
    )


def record_failed_registration(
    path: Path,
    *,
    actor: str,
    server_id: str | None,
    reason: str,
    result: str,
) -> None:
    with closing(_connect(path)) as connection:
        with connection:
            _insert_audit_event(
                connection,
                occurred_at=_now().isoformat(),
                actor=actor,
                action="server-registration",
                server_id=server_id,
                reason=reason,
                result=result,
            )


def _insert_audit_event(
    connection: sqlite3.Connection,
    *,
    occurred_at: str,
    actor: str,
    action: str,
    server_id: str | None,
    reason: str,
    result: str,
) -> None:
    connection.execute(
        """
        INSERT INTO audit_events (
            occurred_at, actor, action, server_id, reason, result
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (occurred_at, actor, action, server_id, reason, result),
    )


def issue_bootstrap_token(
    path: Path,
    *,
    server_id: str,
    actor: str,
    reason: str,
) -> tuple[str, datetime, bool]:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    issued_at = _now()
    expires_at = issued_at + timedelta(
        seconds=BOOTSTRAP_TOKEN_TTL_SECONDS
    )
    with closing(_connect(path)) as connection:
        with connection:
            server = connection.execute(
                """
                SELECT s.enrollment_state, p.definition_json
                FROM servers AS s
                JOIN server_profiles AS p
                  ON p.profile_id = s.profile_id
                 AND p.revision = s.profile_revision
                WHERE server_id = ?
                """,
                (server_id,),
            ).fetchone()
            if (
                server is None
                or server["enrollment_state"] != "awaiting-first-contact"
            ):
                raise ServerNotAwaitingFirstContact
            connection.execute(
                """
                INSERT INTO bootstrap_tokens (
                    token_hash, server_id, expires_at
                ) VALUES (?, ?, ?)
                """,
                (token_hash, server_id, expires_at.isoformat()),
            )
            _insert_audit_event(
                connection,
                occurred_at=issued_at.isoformat(),
                actor=actor,
                action="bootstrap-token-issued",
                server_id=server_id,
                reason=reason,
                result="succeeded",
            )
    profile_definition = cast(
        dict[str, object], json.loads(server["definition_json"])
    )
    capabilities = cast(
        dict[str, object], profile_definition["capabilities"]
    )
    return token, expires_at, capabilities.get("gpu") is True


def consume_bootstrap_token(
    path: Path,
    *,
    server_id: str,
    token: str,
    collector_public_key_fingerprint: str,
    certificate_expires_at: datetime,
    scrape_client_certificate_path: str,
    scrape_client_key_path: str,
    source_address: str,
    inventory: ServerInventory,
    verification_code: str,
) -> None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    occurred_at = _now()
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        revoked = connection.execute(
            """
            SELECT 1
            FROM revoked_collector_fingerprints
            WHERE collector_public_key_fingerprint = ?
            """,
            (collector_public_key_fingerprint,),
        ).fetchone()
        if revoked is not None:
            _record_bootstrap_failure(
                connection,
                occurred_at,
                server_id,
                "revoked-collector-fingerprint",
            )
            connection.commit()
            raise InvalidBootstrapCredentials
        if not _bootstrap_token_is_usable(
            connection,
            server_id=server_id,
            token_hash=token_hash,
            occurred_at=occurred_at,
        ):
            connection.commit()
            raise InvalidBootstrapCredentials

        updated = connection.execute(
            """
            UPDATE bootstrap_tokens
            SET consumed_at = ?
            WHERE token_hash = ? AND consumed_at IS NULL
            """,
            (occurred_at.isoformat(), token_hash),
        )
        if updated.rowcount != 1:
            connection.rollback()
            raise InvalidBootstrapCredentials
        server = connection.execute(
            """
            SELECT scrape_address, enrollment_state
            FROM servers
            WHERE server_id = ?
            """,
            (server_id,),
        ).fetchone()
        if (
            server is None
            or server["enrollment_state"] != "awaiting-first-contact"
        ):
            connection.rollback()
            raise InvalidBootstrapCredentials
        connection.execute(
            """
            UPDATE servers
            SET enrollment_state = 'pending-verification'
            WHERE server_id = ?
            """,
            (server_id,),
        )
        connection.execute(
            """
            INSERT INTO collector_certificates (
                server_id, collector_public_key_fingerprint, expires_at
            ) VALUES (?, ?, ?)
            """,
            (
                server_id,
                collector_public_key_fingerprint,
                certificate_expires_at.isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO staging_scrape_targets (
                server_id, scrape_address, added_at,
                scrape_client_certificate_path, scrape_client_key_path
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                server_id,
                server["scrape_address"],
                occurred_at.isoformat(),
                scrape_client_certificate_path,
                scrape_client_key_path,
            ),
        )
        connection.execute(
            """
            INSERT INTO pending_enrollments (
                server_id, source_address, inventory_json,
                observations_json, verification_code, first_contact_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                server_id,
                source_address,
                json.dumps(
                    inventory.as_document(), separators=(",", ":")
                ),
                "[]",
                verification_code,
                occurred_at.isoformat(),
            ),
        )
        _insert_audit_event(
            connection,
            occurred_at=occurred_at.isoformat(),
            actor="collector-bootstrap",
            action="bootstrap-token-consumed",
            server_id=server_id,
            reason="First valid bootstrap use",
            result="succeeded",
        )
        _insert_audit_event(
            connection,
            occurred_at=occurred_at.isoformat(),
            actor="collector-bootstrap",
            action="bootstrap-succeeded",
            server_id=server_id,
            reason="Collector certificate issued and staged",
            result="succeeded",
        )
        connection.commit()


def validate_bootstrap_token(
    path: Path, *, server_id: str, token: str
) -> bool:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    occurred_at = _now()
    with closing(_connect(path)) as connection:
        with connection:
            return _bootstrap_token_is_usable(
                connection,
                server_id=server_id,
                token_hash=token_hash,
                occurred_at=occurred_at,
            )


def _bootstrap_token_is_usable(
    connection: sqlite3.Connection,
    *,
    server_id: str,
    token_hash: str,
    occurred_at: datetime,
) -> bool:
    token_row = connection.execute(
        """
        SELECT expires_at, consumed_at
        FROM bootstrap_tokens
        WHERE token_hash = ? AND server_id = ?
        """,
        (token_hash, server_id),
    ).fetchone()
    if token_row is None or token_row["consumed_at"] is not None:
        _record_bootstrap_failure(
            connection, occurred_at, server_id, "invalid-credentials"
        )
        return False
    if datetime.fromisoformat(token_row["expires_at"]) <= occurred_at:
        _insert_audit_event(
            connection,
            occurred_at=occurred_at.isoformat(),
            actor="collector-bootstrap",
            action="bootstrap-token-expired",
            server_id=server_id,
            reason="Bootstrap token expired",
            result="expired",
        )
        _record_bootstrap_failure(
            connection, occurred_at, server_id, "expired-token"
        )
        return False
    return True


def _record_bootstrap_failure(
    connection: sqlite3.Connection,
    occurred_at: datetime,
    server_id: str,
    result: str,
) -> None:
    _insert_audit_event(
        connection,
        occurred_at=occurred_at.isoformat(),
        actor="collector-bootstrap",
        action="bootstrap-failed",
        server_id=server_id,
        reason="Collector bootstrap rejected",
        result=result,
    )


def record_bootstrap_failure(
    path: Path, *, server_id: str, result: str
) -> None:
    with closing(_connect(path)) as connection:
        with connection:
            _record_bootstrap_failure(connection, _now(), server_id, result)


def server_requires_nvidia(path: Path, *, server_id: str) -> bool:
    with closing(_connect(path)) as connection:
        row = connection.execute(
            """
            SELECT p.definition_json
            FROM servers AS s
            JOIN server_profiles AS p
              ON p.profile_id = s.profile_id
             AND p.revision = s.profile_revision
            WHERE s.server_id = ?
            """,
            (server_id,),
        ).fetchone()
    if row is None:
        raise ServerNotAwaitingFirstContact
    definition = cast(
        dict[str, object], json.loads(row["definition_json"])
    )
    capabilities = cast(dict[str, object], definition["capabilities"])
    return capabilities.get("gpu") is True


def server_scrape_address(path: Path, *, server_id: str) -> str:
    with closing(_connect(path)) as connection:
        row = connection.execute(
            "SELECT scrape_address FROM servers WHERE server_id = ?",
            (server_id,),
        ).fetchone()
    if row is None:
        raise ServerNotAwaitingFirstContact
    return cast(str, row["scrape_address"])


def list_registered_servers(path: Path) -> list[RegisteredServer]:
    with closing(_connect(path)) as connection:
        rows = connection.execute(
            """
            SELECT
                s.server_id, s.display_name, s.scrape_address,
                s.enrollment_state, p.profile_id, p.revision, p.name,
                p.state, p.definition_json,
                pe.source_address, pe.inventory_json AS pending_inventory_json,
                pe.observations_json, pe.verification_code,
                vi.inventory_json AS verified_inventory_json,
                rejected.collector_public_key_fingerprint
                    AS rejected_fingerprint,
                rejected.reason AS rejection_reason,
                (
                    SELECT runs.result
                    FROM observation_runs AS runs
                    WHERE runs.server_id = s.server_id
                    ORDER BY runs.observation_run_id DESC
                    LIMIT 1
                ) AS last_observation_result
            FROM servers AS s
            JOIN server_profiles AS p
              ON p.profile_id = s.profile_id
             AND p.revision = s.profile_revision
            LEFT JOIN pending_enrollments AS pe
              ON pe.server_id = s.server_id
            LEFT JOIN verified_server_inventory AS vi
              ON vi.server_id = s.server_id
            LEFT JOIN revoked_collector_fingerprints AS rejected
              ON rejected.collector_public_key_fingerprint = (
                SELECT latest.collector_public_key_fingerprint
                FROM revoked_collector_fingerprints AS latest
                WHERE latest.server_id = s.server_id
                ORDER BY latest.revoked_at DESC
                LIMIT 1
              )
            ORDER BY s.created_at, s.server_id
            """
        ).fetchall()
    return [
        RegisteredServer(
            server_id=row["server_id"],
            display_name=row["display_name"],
            scrape_address=row["scrape_address"],
            profile=_profile_from_row(row),
            enrollment_state=row["enrollment_state"],
            enrollment_review=_enrollment_review_from_row(row),
            inventory=(
                server_inventory_from_document(
                    json.loads(row["verified_inventory_json"])
                )
                if row["verified_inventory_json"] is not None
                else None
            ),
            last_rejected_enrollment=(
                RejectedEnrollment(
                    collector_public_key_fingerprint=(
                        row["rejected_fingerprint"]
                    ),
                    reason=row["rejection_reason"],
                )
                if row["rejected_fingerprint"] is not None
                else None
            ),
            last_observation_result=row["last_observation_result"],
        )
        for row in rows
    ]


def get_staging_observation_target(
    path: Path, *, server_id: str
) -> ObservationTarget:
    with closing(_connect(path)) as connection:
        row = connection.execute(
            """
            SELECT
                server_id, scrape_address,
                scrape_client_certificate_path, scrape_client_key_path
            FROM staging_scrape_targets
            WHERE server_id = ?
            """,
            (server_id,),
        ).fetchone()
    if row is None:
        raise EnrollmentDecisionConflict
    return _observation_target_from_row(row)


def list_active_observation_targets(path: Path) -> list[ObservationTarget]:
    with closing(_connect(path)) as connection:
        rows = connection.execute(
            """
            SELECT
                server_id, scrape_address,
                scrape_client_certificate_path, scrape_client_key_path
            FROM active_scrape_targets
            ORDER BY server_id
            """
        ).fetchall()
    return [_observation_target_from_row(row) for row in rows]


def _observation_target_from_row(
    row: sqlite3.Row,
) -> ObservationTarget:
    return ObservationTarget(
        server_id=row["server_id"],
        scrape_address=row["scrape_address"],
        scrape_client_certificate_path=(
            row["scrape_client_certificate_path"]
        ),
        scrape_client_key_path=row["scrape_client_key_path"],
    )


def record_staged_observations(
    path: Path,
    *,
    server_id: str,
    observations: set[str],
    actor: str,
) -> RegisteredServer:
    occurred_at = _now()
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        updated = connection.execute(
            """
            UPDATE pending_enrollments
            SET observations_json = ?
            WHERE server_id = ?
              AND EXISTS (
                SELECT 1
                FROM servers
                WHERE server_id = ?
                  AND enrollment_state = 'pending-verification'
              )
            """,
            (
                json.dumps(sorted(observations), separators=(",", ":")),
                server_id,
                server_id,
            ),
        )
        if updated.rowcount != 1:
            connection.rollback()
            raise EnrollmentDecisionConflict
        _insert_audit_event(
            connection,
            occurred_at=occurred_at.isoformat(),
            actor=actor,
            action="staged-telemetry-check",
            server_id=server_id,
            reason="Check staged collector telemetry",
            result="succeeded",
        )
        connection.commit()
    server = _registered_server(path, server_id)
    if server is None:
        raise EnrollmentDecisionConflict
    return server


def record_observation_run(
    path: Path,
    *,
    server_id: str,
    result: str,
) -> None:
    with closing(_connect(path)) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO observation_runs (
                    server_id, observed_at, result
                ) VALUES (?, ?, ?)
                """,
                (server_id, _now().isoformat(), result),
            )


def decide_enrollment(
    path: Path,
    *,
    server_id: str,
    actor: str,
    decision: EnrollmentDecision,
) -> RegisteredServer:
    occurred_at = _now()
    audit_action = (
        "enrollment-approval"
        if decision.kind is EnrollmentDecisionKind.APPROVE
        else "enrollment-rejection"
    )
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        pending = connection.execute(
            """
            SELECT
                s.enrollment_state, pe.inventory_json,
                pe.observations_json, pe.verification_code,
                p.definition_json,
                cc.collector_public_key_fingerprint
            FROM servers AS s
            JOIN pending_enrollments AS pe
              ON pe.server_id = s.server_id
            JOIN server_profiles AS p
              ON p.profile_id = s.profile_id
             AND p.revision = s.profile_revision
            JOIN collector_certificates AS cc
              ON cc.server_id = s.server_id
            WHERE s.server_id = ?
            """,
            (server_id,),
        ).fetchone()
        if pending is None or pending["enrollment_state"] != (
            "pending-verification"
        ):
            connection.rollback()
            raise EnrollmentDecisionConflict
        if not secrets.compare_digest(
            pending["verification_code"], decision.verification_code
        ):
            _insert_audit_event(
                connection,
                occurred_at=occurred_at.isoformat(),
                actor=actor,
                action=audit_action,
                server_id=server_id,
                reason=decision.reason,
                result="verification-code-mismatch",
            )
            connection.commit()
            raise VerificationCodeMismatch
        if decision.kind is EnrollmentDecisionKind.APPROVE:
            _approve_pending_enrollment(
                connection,
                pending=pending,
                server_id=server_id,
                occurred_at=occurred_at,
                actor=actor,
                reason=decision.reason,
                audit_action=audit_action,
            )
        else:
            _reject_pending_enrollment(
                connection,
                collector_public_key_fingerprint=(
                    pending["collector_public_key_fingerprint"]
                ),
                server_id=server_id,
                occurred_at=occurred_at,
                actor=actor,
                reason=decision.reason,
            )
        _insert_audit_event(
            connection,
            occurred_at=occurred_at.isoformat(),
            actor=actor,
            action=audit_action,
            server_id=server_id,
            reason=decision.reason,
            result="succeeded",
        )
        connection.commit()
    return _require_registered_server(path, server_id)


def _approve_pending_enrollment(
    connection: sqlite3.Connection,
    *,
    pending: sqlite3.Row,
    server_id: str,
    occurred_at: datetime,
    actor: str,
    reason: str,
    audit_action: str,
) -> None:
    definition = cast(
        dict[str, object], json.loads(pending["definition_json"])
    )
    required = set(_profile_observations(definition))
    present = set(
        cast(list[str], json.loads(pending["observations_json"]))
    )
    if not required <= present:
        _insert_audit_event(
            connection,
            occurred_at=occurred_at.isoformat(),
            actor=actor,
            action=audit_action,
            server_id=server_id,
            reason=reason,
            result="incomplete-observations",
        )
        connection.commit()
        raise IncompleteObservations
    connection.execute(
        """
        INSERT INTO verified_server_inventory (
            server_id, inventory_json, verified_at
        ) VALUES (?, ?, ?)
        """,
        (server_id, pending["inventory_json"], occurred_at.isoformat()),
    )
    activated = connection.execute(
        """
        INSERT INTO active_scrape_targets (
            server_id, scrape_address, activated_at,
            scrape_client_certificate_path, scrape_client_key_path
        )
        SELECT
            server_id, scrape_address, ?,
            scrape_client_certificate_path, scrape_client_key_path
        FROM staging_scrape_targets
        WHERE server_id = ?
        """,
        (occurred_at.isoformat(), server_id),
    )
    if activated.rowcount != 1:
        connection.rollback()
        raise EnrollmentDecisionConflict
    connection.execute(
        "DELETE FROM staging_scrape_targets WHERE server_id = ?",
        (server_id,),
    )
    connection.execute(
        "DELETE FROM pending_enrollments WHERE server_id = ?",
        (server_id,),
    )
    connection.execute(
        """
        UPDATE servers
        SET enrollment_state = 'active'
        WHERE server_id = ?
        """,
        (server_id,),
    )


def _reject_pending_enrollment(
    connection: sqlite3.Connection,
    *,
    collector_public_key_fingerprint: str,
    server_id: str,
    occurred_at: datetime,
    actor: str,
    reason: str,
) -> None:
    connection.execute(
        """
        INSERT INTO revoked_collector_fingerprints (
            collector_public_key_fingerprint,
            server_id, revoked_at, actor, reason
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            collector_public_key_fingerprint,
            server_id,
            occurred_at.isoformat(),
            actor,
            reason,
        ),
    )
    connection.execute(
        "DELETE FROM collector_certificates WHERE server_id = ?",
        (server_id,),
    )
    connection.execute(
        "DELETE FROM staging_scrape_targets WHERE server_id = ?",
        (server_id,),
    )
    connection.execute(
        "DELETE FROM pending_enrollments WHERE server_id = ?",
        (server_id,),
    )
    connection.execute(
        """
        UPDATE servers
        SET enrollment_state = 'awaiting-first-contact'
        WHERE server_id = ?
        """,
        (server_id,),
    )


def _require_registered_server(
    path: Path, server_id: str
) -> RegisteredServer:
    server = _registered_server(path, server_id)
    if server is None:
        raise EnrollmentDecisionConflict
    return server


def _registered_server(
    path: Path, server_id: str
) -> RegisteredServer | None:
    return next(
        (
            server
            for server in list_registered_servers(path)
            if server.server_id == server_id
        ),
        None,
    )


def _enrollment_review_from_row(
    row: sqlite3.Row,
) -> EnrollmentReview | None:
    if row["verification_code"] is None:
        return None
    definition = cast(
        dict[str, object], json.loads(row["definition_json"])
    )
    required = _profile_observations(definition)
    present = set(cast(list[str], json.loads(row["observations_json"])))
    checks = tuple(
        ObservationCheck(
            observation=observation,
            present=observation in present,
        )
        for observation in required
    )
    return EnrollmentReview(
        verification_code=row["verification_code"],
        source_address=row["source_address"],
        inventory=server_inventory_from_document(
            json.loads(row["pending_inventory_json"])
        ),
        observation_checks=checks,
        ready_for_approval=all(check.present for check in checks),
    )


def _profile_observations(
    definition: dict[str, object],
) -> list[str]:
    required = list(
        cast(list[str], definition["requiredObservations"])
    )
    required.extend(
        f"persistent-mount:{mount}"
        for mount in cast(list[str], definition["persistentMounts"])
    )
    required.extend(
        f"required-service:{service}"
        for service in cast(list[str], definition["requiredServices"])
    )
    return required


def list_audit_events(path: Path) -> list[dict[str, object]]:
    with closing(_connect(path)) as connection:
        rows = connection.execute(
            """
            SELECT occurred_at, actor, action, server_id, reason, result
            FROM audit_events
            ORDER BY audit_id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def _profile_from_row(row: sqlite3.Row) -> ServerProfile:
    return ServerProfile(
        profile_id=row["profile_id"],
        revision=row["revision"],
        name=row["name"],
        state=row["state"],
        definition=cast(
            dict[str, object], json.loads(row["definition_json"])
        ),
    )


def is_ready(path: Path) -> bool:
    try:
        with closing(_connect(path)) as connection:
            connection.execute("SELECT 1 FROM servers LIMIT 1").fetchall()
            connection.execute(
                "SELECT 1 FROM server_profiles LIMIT 1"
            ).fetchall()
    except sqlite3.Error:
        return False
    return True
