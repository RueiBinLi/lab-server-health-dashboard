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
from lab_dashboard.profile import (
    ProfileCloneRequest,
    ProfileDraftRequest,
    configuration_bundle,
    effective_changes,
    validate_profile_definition,
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
class ProfilePublication:
    profile: ServerProfile
    effective_changes: list[dict[str, object]]
    affected_server_ids: list[str]
    configuration_hash: str


@dataclass(frozen=True)
class PendingProfileConfiguration:
    profile_id: str
    revision: int
    configuration_hash: str
    bundle: dict[str, object]
    operation: str


@dataclass(frozen=True)
class StagedProfileConfiguration:
    pending: PendingProfileConfiguration
    active_revision: int


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
    pending_profile_configuration: PendingProfileConfiguration | None = None
    pending_inventory_change: ServerInventory | None = None
    active_configuration_hash: str | None = None


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


def profile_temperature_sensors(
    server: RegisteredServer,
) -> tuple[str, ...]:
    sensors = server.profile.definition.get("temperatureSensors", [])
    sensor_values = sensors if isinstance(sensors, list) else []
    return tuple(
        sensor["logicalName"]
        for sensor in sensor_values
        if isinstance(sensor, dict)
        and isinstance(sensor.get("logicalName"), str)
    )


def profile_expected_gpu_count(server: RegisteredServer) -> int | None:
    capabilities = cast(
        dict[str, object], server.profile.definition.get("capabilities", {})
    )
    count = capabilities.get("expectedDeviceCount")
    return (
        count
        if capabilities.get("gpu") is True and isinstance(count, int)
        else None
    )


def profile_threshold_overrides(
    server: RegisteredServer,
) -> tuple[dict[str, object], ...]:
    overrides = server.profile.definition.get("thresholdOverrides", [])
    override_values = overrides if isinstance(overrides, list) else []
    return tuple(
        cast(dict[str, object], override)
        for override in override_values
        if isinstance(override, dict)
    )


class DisplayNameConflict(Exception):
    pass


class ProfileNotPublished(Exception):
    pass


class ProfileNotFound(Exception):
    pass


class ProfileConflict(Exception):
    pass


class ConfigurationHashMismatch(Exception):
    def __init__(self, active_revision: int) -> None:
        super().__init__("collector configuration hash did not match")
        self.active_revision = active_revision


class StagedProfileVerificationFailed(Exception):
    def __init__(self, active_revision: int) -> None:
        super().__init__("target profile requirements were not verified")
        self.active_revision = active_revision


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


class ProfileInventoryMismatch(Exception):
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
                CREATE TABLE IF NOT EXISTS staged_profile_configurations (
                    server_id TEXT PRIMARY KEY REFERENCES servers(server_id),
                    profile_id TEXT NOT NULL,
                    profile_revision INTEGER NOT NULL,
                    configuration_hash TEXT NOT NULL,
                    bundle_json TEXT NOT NULL,
                    staged_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    FOREIGN KEY (profile_id, profile_revision)
                        REFERENCES server_profiles(profile_id, revision)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_inventory_changes (
                    server_id TEXT PRIMARY KEY REFERENCES servers(server_id),
                    inventory_json TEXT NOT NULL,
                    observed_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS server_profile_activations (
                    activation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id TEXT NOT NULL REFERENCES servers(server_id),
                    profile_id TEXT NOT NULL,
                    profile_revision INTEGER NOT NULL,
                    activated_at TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    FOREIGN KEY (profile_id, profile_revision)
                        REFERENCES server_profiles(profile_id, revision)
                )
                """
            )
            connection.execute(
                """
                INSERT INTO server_profile_activations (
                    server_id, profile_id, profile_revision,
                    activated_at, operation
                )
                SELECT
                    server_id, profile_id, profile_revision,
                    created_at, 'migration'
                FROM servers
                WHERE enrollment_state = 'active'
                  AND NOT EXISTS (
                    SELECT 1
                    FROM server_profile_activations AS activation
                    WHERE activation.server_id = servers.server_id
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
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS immutable_profile_identity
                BEFORE UPDATE OF profile_id, revision ON server_profiles
                BEGIN
                    SELECT RAISE(
                        ABORT, 'Server Profile ID and revision are immutable'
                    );
                END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS immutable_profile_revision_content
                BEFORE UPDATE OF name, definition_json ON server_profiles
                BEGIN
                    SELECT RAISE(
                        ABORT, 'Server Profile revision content is immutable'
                    );
                END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS valid_profile_lifecycle
                BEFORE UPDATE OF state ON server_profiles
                WHEN NOT (
                    OLD.state = NEW.state
                    OR (OLD.state = 'draft' AND NEW.state = 'published')
                    OR (OLD.state = 'published' AND NEW.state = 'retired')
                )
                BEGIN
                    SELECT RAISE(
                        ABORT, 'invalid Server Profile lifecycle transition'
                    );
                END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS retain_historical_profiles
                BEFORE DELETE ON server_profiles
                WHEN OLD.state != 'draft'
                  OR EXISTS (
                    SELECT 1 FROM servers
                    WHERE profile_id = OLD.profile_id
                      AND profile_revision = OLD.revision
                  )
                  OR EXISTS (
                    SELECT 1 FROM staged_profile_configurations
                    WHERE profile_id = OLD.profile_id
                      AND profile_revision = OLD.revision
                  )
                BEGIN
                    SELECT RAISE(
                        ABORT, 'historical Server Profile revision is retained'
                    );
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
        "active_configuration_hash": "TEXT",
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


def list_profiles(path: Path, *, include_all: bool) -> list[ServerProfile]:
    with closing(_connect(path)) as connection:
        rows = connection.execute(
            f"""
            SELECT profile_id, revision, name, state, definition_json
            FROM server_profiles
            {" " if include_all else "WHERE state = 'published'"}
            ORDER BY profile_id, revision
            """
        ).fetchall()
    return [_profile_from_row(row) for row in rows]


def clone_profile(
    path: Path, *, request: ProfileCloneRequest, actor: str
) -> ServerProfile:
    occurred_at = _now().isoformat()
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        source = connection.execute(
            """
            SELECT definition_json
            FROM server_profiles
            WHERE profile_id = ? AND revision = ?
              AND state IN ('published', 'retired')
            """,
            (request.source_profile_id, request.source_revision),
        ).fetchone()
        conflict = connection.execute(
            """
            SELECT 1
            FROM server_profiles
            WHERE profile_id = ? OR (name = ? AND profile_id != ?)
            LIMIT 1
            """,
            (request.profile_id, request.name, request.profile_id),
        ).fetchone()
        if source is None:
            connection.rollback()
            raise ProfileNotFound
        if conflict is not None:
            connection.rollback()
            raise ProfileConflict
        definition = cast(
            dict[str, object], json.loads(source["definition_json"])
        )
        validate_profile_definition(definition)
        connection.execute(
            """
            INSERT INTO server_profiles (
                profile_id, revision, name, state, definition_json
            ) VALUES (?, 1, ?, 'draft', ?)
            """,
            (
                request.profile_id,
                request.name,
                json.dumps(definition, separators=(",", ":"), sort_keys=True),
            ),
        )
        _insert_audit_event(
            connection,
            occurred_at=occurred_at,
            actor=actor,
            action="server-profile-cloned",
            server_id=None,
            reason=request.reason,
            result=f"succeeded:{request.profile_id}:1",
        )
        connection.commit()
    return ServerProfile(
        profile_id=request.profile_id,
        revision=1,
        name=request.name,
        state="draft",
        definition=definition,
    )


def create_profile_draft(
    path: Path,
    *,
    profile_id: str,
    request: ProfileDraftRequest,
    actor: str,
) -> ServerProfile:
    occurred_at = _now().isoformat()
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        latest = connection.execute(
            """
            SELECT MAX(revision) AS revision
            FROM server_profiles
            WHERE profile_id = ?
            """,
            (profile_id,),
        ).fetchone()
        name_conflict = connection.execute(
            """
            SELECT 1
            FROM server_profiles
            WHERE name = ? AND profile_id != ?
            LIMIT 1
            """,
            (request.name, profile_id),
        ).fetchone()
        if latest is None or latest["revision"] is None:
            connection.rollback()
            raise ProfileNotFound
        if name_conflict is not None:
            connection.rollback()
            raise ProfileConflict
        revision = cast(int, latest["revision"]) + 1
        connection.execute(
            """
            INSERT INTO server_profiles (
                profile_id, revision, name, state, definition_json
            ) VALUES (?, ?, ?, 'draft', ?)
            """,
            (
                profile_id,
                revision,
                request.name,
                json.dumps(
                    request.definition,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ),
        )
        _insert_audit_event(
            connection,
            occurred_at=occurred_at,
            actor=actor,
            action="server-profile-draft-created",
            server_id=None,
            reason=request.reason,
            result=f"succeeded:{profile_id}:{revision}",
        )
        connection.commit()
    return ServerProfile(
        profile_id=profile_id,
        revision=revision,
        name=request.name,
        state="draft",
        definition=request.definition,
    )


def publish_profile(
    path: Path,
    *,
    profile_id: str,
    revision: int,
    actor: str,
    reason: str,
) -> ProfilePublication:
    occurred_at = _now().isoformat()
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        draft = connection.execute(
            """
            SELECT profile_id, revision, name, state, definition_json
            FROM server_profiles
            WHERE profile_id = ? AND revision = ?
            """,
            (profile_id, revision),
        ).fetchone()
        if draft is None:
            connection.rollback()
            raise ProfileNotFound
        if draft["state"] != "draft":
            connection.rollback()
            raise ProfileConflict
        definition = cast(
            dict[str, object], json.loads(draft["definition_json"])
        )
        validate_profile_definition(definition)
        previous = connection.execute(
            """
            SELECT definition_json
            FROM server_profiles
            WHERE profile_id = ? AND revision < ?
            ORDER BY revision DESC
            LIMIT 1
            """,
            (profile_id, revision),
        ).fetchone()
        before = (
            cast(dict[str, object], json.loads(previous["definition_json"]))
            if previous is not None
            else {}
        )
        bundle, configuration_hash = configuration_bundle(
            profile_id=profile_id,
            revision=revision,
            definition=definition,
        )
        affected_rows = connection.execute(
            """
            SELECT server_id
            FROM servers
            WHERE profile_id = ? AND profile_revision != ?
            ORDER BY server_id
            """,
            (profile_id, revision),
        ).fetchall()
        affected_server_ids = [
            cast(str, row["server_id"]) for row in affected_rows
        ]
        connection.execute(
            """
            UPDATE server_profiles
            SET state = 'published'
            WHERE profile_id = ? AND revision = ? AND state = 'draft'
            """,
            (profile_id, revision),
        )
        for server_id in affected_server_ids:
            server_bundle, server_configuration_hash = configuration_bundle(
                profile_id=profile_id,
                revision=revision,
                definition=definition,
                temperature_sensor_bindings=(
                    _temperature_sensor_binding_documents(
                        connection, server_id=server_id, definition=definition
                    )
                ),
            )
            connection.execute(
                """
                INSERT INTO staged_profile_configurations (
                    server_id, profile_id, profile_revision,
                    configuration_hash, bundle_json, staged_at,
                    actor, reason, operation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'publication')
                ON CONFLICT(server_id) DO UPDATE SET
                    profile_id = excluded.profile_id,
                    profile_revision = excluded.profile_revision,
                    configuration_hash = excluded.configuration_hash,
                    bundle_json = excluded.bundle_json,
                    staged_at = excluded.staged_at,
                    actor = excluded.actor,
                    reason = excluded.reason,
                    operation = excluded.operation
                WHERE staged_profile_configurations.operation = 'publication'
                """,
                (
                    server_id,
                    profile_id,
                    revision,
                    server_configuration_hash,
                    json.dumps(
                        server_bundle,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    occurred_at,
                    actor,
                    reason,
                ),
            )
        _insert_audit_event(
            connection,
            occurred_at=occurred_at,
            actor=actor,
            action="server-profile-published",
            server_id=None,
            reason=reason,
            result=f"succeeded:{profile_id}:{revision}",
        )
        connection.commit()
    return ProfilePublication(
        profile=_profile_from_row(draft, state="published"),
        effective_changes=effective_changes(before, definition),
        affected_server_ids=affected_server_ids,
        configuration_hash=configuration_hash,
    )


def retire_profile(
    path: Path,
    *,
    profile_id: str,
    revision: int,
    actor: str,
    reason: str,
) -> ServerProfile:
    occurred_at = _now().isoformat()
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """
            SELECT profile_id, revision, name, state, definition_json, seeded
            FROM server_profiles
            WHERE profile_id = ? AND revision = ?
            """,
            (profile_id, revision),
        ).fetchone()
        if row is None:
            connection.rollback()
            raise ProfileNotFound
        if row["state"] != "published" or row["seeded"] == 1:
            connection.rollback()
            raise ProfileConflict
        connection.execute(
            """
            UPDATE server_profiles
            SET state = 'retired'
            WHERE profile_id = ? AND revision = ?
            """,
            (profile_id, revision),
        )
        _insert_audit_event(
            connection,
            occurred_at=occurred_at,
            actor=actor,
            action="server-profile-retired",
            server_id=None,
            reason=reason,
            result=f"succeeded:{profile_id}:{revision}",
        )
        connection.commit()
    return _profile_from_row(row, state="retired")


def stage_profile_configuration(
    path: Path,
    *,
    server_id: str,
    profile_id: str,
    revision: int,
    operation: str,
    actor: str,
    reason: str,
) -> StagedProfileConfiguration:
    if operation not in {"assignment", "rollback"}:
        raise ValueError("unsupported profile configuration operation")
    occurred_at = _now().isoformat()
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        server = connection.execute(
            """
            SELECT profile_id, profile_revision
            FROM servers
            WHERE server_id = ?
            """,
            (server_id,),
        ).fetchone()
        profile = connection.execute(
            """
            SELECT definition_json, state
            FROM server_profiles
            WHERE profile_id = ? AND revision = ?
            """,
            (profile_id, revision),
        ).fetchone()
        allowed_states = (
            {"published"} if operation == "assignment" else {"published", "retired"}
        )
        if server is None or profile is None:
            connection.rollback()
            raise ProfileNotFound
        if profile["state"] not in allowed_states:
            connection.rollback()
            raise ProfileNotPublished
        active_revision = cast(int, server["profile_revision"])
        if operation == "rollback" and (
            server["profile_id"] != profile_id or revision >= active_revision
        ):
            connection.rollback()
            raise ProfileConflict
        definition = cast(
            dict[str, object], json.loads(profile["definition_json"])
        )
        validate_profile_definition(definition)
        bundle, configuration_hash = configuration_bundle(
            profile_id=profile_id,
            revision=revision,
            definition=definition,
            temperature_sensor_bindings=(
                _temperature_sensor_binding_documents(
                    connection, server_id=server_id, definition=definition
                )
            ),
        )
        connection.execute(
            """
            INSERT INTO staged_profile_configurations (
                server_id, profile_id, profile_revision,
                configuration_hash, bundle_json, staged_at,
                actor, reason, operation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                profile_id = excluded.profile_id,
                profile_revision = excluded.profile_revision,
                configuration_hash = excluded.configuration_hash,
                bundle_json = excluded.bundle_json,
                staged_at = excluded.staged_at,
                actor = excluded.actor,
                reason = excluded.reason,
                operation = excluded.operation
            """,
            (
                server_id,
                profile_id,
                revision,
                configuration_hash,
                json.dumps(bundle, separators=(",", ":"), sort_keys=True),
                occurred_at,
                actor,
                reason,
                operation,
            ),
        )
        _insert_audit_event(
            connection,
            occurred_at=occurred_at,
            actor=actor,
            action=f"server-profile-{operation}-staged",
            server_id=server_id,
            reason=reason,
            result=f"succeeded:{profile_id}:{revision}",
        )
        connection.commit()
    return StagedProfileConfiguration(
        pending=PendingProfileConfiguration(
            profile_id=profile_id,
            revision=revision,
            configuration_hash=configuration_hash,
            bundle=bundle,
            operation=operation,
        ),
        active_revision=active_revision,
    )


def activate_staged_profile_configuration(
    path: Path,
    *,
    server_id: str,
    reported_configuration_hash: str,
    observations: tuple[str, ...],
    inventory: ServerInventory,
    actor: str,
    reason: str,
) -> RegisteredServer:
    occurred_at = _now().isoformat()
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        staged = connection.execute(
            """
            SELECT
                staged.profile_id, staged.profile_revision,
                staged.configuration_hash, staged.operation,
                servers.profile_revision AS active_revision,
                profiles.definition_json
            FROM staged_profile_configurations AS staged
            JOIN servers ON servers.server_id = staged.server_id
            JOIN server_profiles AS profiles
              ON profiles.profile_id = staged.profile_id
             AND profiles.revision = staged.profile_revision
            WHERE staged.server_id = ?
            """,
            (server_id,),
        ).fetchone()
        if staged is None:
            connection.rollback()
            raise ProfileConflict
        if not secrets.compare_digest(
            staged["configuration_hash"], reported_configuration_hash
        ):
            _insert_audit_event(
                connection,
                occurred_at=occurred_at,
                actor=actor,
                action="server-profile-activation-failed",
                server_id=server_id,
                reason=reason,
                result="configuration-hash-mismatch",
            )
            connection.commit()
            raise ConfigurationHashMismatch(staged["active_revision"])
        definition = cast(
            dict[str, object], json.loads(staged["definition_json"])
        )
        verified_row = connection.execute(
            """
            SELECT inventory_json
            FROM verified_server_inventory
            WHERE server_id = ?
            """,
            (server_id,),
        ).fetchone()
        verified_inventory = (
            server_inventory_from_document(
                json.loads(verified_row["inventory_json"])
            )
            if verified_row is not None
            else None
        )
        required_observations = set(_profile_observations(definition))
        if (
            not required_observations <= set(observations)
            or not _inventory_satisfies_profile(inventory, definition)
        ):
            _insert_audit_event(
                connection,
                occurred_at=occurred_at,
                actor=actor,
                action="server-profile-activation-failed",
                server_id=server_id,
                reason=reason,
                result="target-requirements-not-verified",
            )
            connection.commit()
            raise StagedProfileVerificationFailed(
                staged["active_revision"]
            )
        if (
            verified_inventory is None
            or _required_inventory_signature(
                verified_inventory, definition
            )
            != _required_inventory_signature(inventory, definition)
        ):
            encoded_inventory = json.dumps(
                inventory.as_document(),
                separators=(",", ":"),
                sort_keys=True,
            )
            connection.execute(
                """
                INSERT INTO pending_inventory_changes (
                    server_id, inventory_json, observed_at
                ) VALUES (?, ?, ?)
                ON CONFLICT(server_id) DO UPDATE SET
                    inventory_json = excluded.inventory_json,
                    observed_at = excluded.observed_at
                """,
                (server_id, encoded_inventory, occurred_at),
            )
            _insert_audit_event(
                connection,
                occurred_at=occurred_at,
                actor=actor,
                action="server-inventory-change-observed",
                server_id=server_id,
                reason="Profile activation reported changed required hardware",
                result="degraded-pending-acceptance",
            )
            _insert_audit_event(
                connection,
                occurred_at=occurred_at,
                actor=actor,
                action="server-profile-activation-failed",
                server_id=server_id,
                reason=reason,
                result="inventory-acceptance-required",
            )
            connection.commit()
            raise StagedProfileVerificationFailed(
                staged["active_revision"]
            )
        connection.execute(
            """
            UPDATE servers
            SET profile_id = ?, profile_revision = ?,
                active_configuration_hash = ?
            WHERE server_id = ?
            """,
            (
                staged["profile_id"],
                staged["profile_revision"],
                staged["configuration_hash"],
                server_id,
            ),
        )
        connection.execute(
            """
            INSERT INTO server_profile_activations (
                server_id, profile_id, profile_revision,
                activated_at, operation
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                server_id,
                staged["profile_id"],
                staged["profile_revision"],
                occurred_at,
                staged["operation"],
            ),
        )
        connection.execute(
            "DELETE FROM staged_profile_configurations WHERE server_id = ?",
            (server_id,),
        )
        _insert_audit_event(
            connection,
            occurred_at=occurred_at,
            actor=actor,
            action="server-profile-activated",
            server_id=server_id,
            reason=reason,
            result=(
                f"succeeded:{staged['operation']}:"
                f"{staged['profile_id']}:{staged['profile_revision']}"
            ),
        )
        connection.commit()
    return _require_registered_server(path, server_id)


def record_inventory_observation(
    path: Path,
    *,
    server_id: str,
    inventory: ServerInventory,
    actor: str,
    reason: str,
) -> ServerInventory | None:
    occurred_at = _now().isoformat()
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """
            SELECT
                verified.inventory_json,
                profile.definition_json,
                pending.inventory_json AS pending_inventory_json
            FROM servers AS server
            JOIN verified_server_inventory AS verified
              ON verified.server_id = server.server_id
            JOIN server_profiles AS profile
              ON profile.profile_id = server.profile_id
             AND profile.revision = server.profile_revision
            LEFT JOIN pending_inventory_changes AS pending
              ON pending.server_id = server.server_id
            WHERE server.server_id = ? AND server.enrollment_state = 'active'
            """,
            (server_id,),
        ).fetchone()
        if row is None:
            connection.rollback()
            raise ProfileNotFound
        if row["pending_inventory_json"] is not None:
            connection.commit()
            return server_inventory_from_document(
                json.loads(row["pending_inventory_json"])
            )
        verified = server_inventory_from_document(
            json.loads(row["inventory_json"])
        )
        definition = cast(
            dict[str, object], json.loads(row["definition_json"])
        )
        if _required_inventory_signature(
            verified, definition
        ) == _required_inventory_signature(inventory, definition):
            connection.execute(
                """
                UPDATE verified_server_inventory
                SET inventory_json = ?, verified_at = ?
                WHERE server_id = ?
                """,
                (
                    json.dumps(
                        inventory.as_document(),
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    occurred_at,
                    server_id,
                ),
            )
            connection.commit()
            return None
        encoded = json.dumps(
            inventory.as_document(), separators=(",", ":"), sort_keys=True
        )
        connection.execute(
            """
            INSERT INTO pending_inventory_changes (
                server_id, inventory_json, observed_at
            ) VALUES (?, ?, ?)
            """,
            (server_id, encoded, occurred_at),
        )
        _insert_audit_event(
            connection,
            occurred_at=occurred_at,
            actor=actor,
            action="server-inventory-change-observed",
            server_id=server_id,
            reason=reason,
            result="degraded-pending-acceptance",
        )
        connection.commit()
    return inventory


def accept_inventory_change(
    path: Path,
    *,
    server_id: str,
    actor: str,
    reason: str,
) -> RegisteredServer:
    occurred_at = _now().isoformat()
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        pending = connection.execute(
            """
            SELECT inventory_json
            FROM pending_inventory_changes
            WHERE server_id = ?
            """,
            (server_id,),
        ).fetchone()
        if pending is None:
            connection.rollback()
            raise ProfileConflict
        connection.execute(
            """
            UPDATE verified_server_inventory
            SET inventory_json = ?, verified_at = ?
            WHERE server_id = ?
            """,
            (pending["inventory_json"], occurred_at, server_id),
        )
        connection.execute(
            "DELETE FROM pending_inventory_changes WHERE server_id = ?",
            (server_id,),
        )
        _insert_audit_event(
            connection,
            occurred_at=occurred_at,
            actor=actor,
            action="server-inventory-change-accepted",
            server_id=server_id,
            reason=reason,
            result="succeeded",
        )
        connection.commit()
    return _require_registered_server(path, server_id)


def staged_profile_configuration(
    path: Path, *, server_id: str
) -> PendingProfileConfiguration:
    with closing(_connect(path)) as connection:
        row = connection.execute(
            """
            SELECT
                profile_id, profile_revision, configuration_hash,
                bundle_json, operation
            FROM staged_profile_configurations
            WHERE server_id = ?
            """,
            (server_id,),
        ).fetchone()
    if row is None:
        raise ProfileNotFound
    return PendingProfileConfiguration(
        profile_id=row["profile_id"],
        revision=row["profile_revision"],
        configuration_hash=row["configuration_hash"],
        bundle=cast(dict[str, object], json.loads(row["bundle_json"])),
        operation=row["operation"],
    )


def profile_revision_at(
    path: Path, *, server_id: str, observed_at: str
) -> tuple[str, int] | None:
    try:
        normalized = datetime.fromisoformat(observed_at).astimezone(UTC)
    except ValueError:
        return None
    with closing(_connect(path)) as connection:
        row = connection.execute(
            """
            SELECT profile_id, profile_revision
            FROM server_profile_activations
            WHERE server_id = ? AND activated_at <= ?
            ORDER BY activated_at DESC, activation_id DESC
            LIMIT 1
            """,
            (server_id, normalized.isoformat()),
        ).fetchone()
    if row is None:
        return None
    return cast(str, row["profile_id"]), cast(int, row["profile_revision"])


def _required_inventory_signature(
    inventory: ServerInventory, definition: dict[str, object]
) -> dict[str, object]:
    mounts = set(
        value
        for value in cast(
            list[object], definition.get("persistentMounts", ["/"])
        )
        if isinstance(value, str)
    )
    capabilities = cast(
        dict[str, object], definition.get("capabilities", {})
    )
    return {
        "stableIdentifiers": inventory.stable_identifiers,
        "cpu": inventory.cpu,
        "memory": inventory.memory,
        "requiredDisks": tuple(
            sorted(
                (disk.stable_id, disk.model, disk.size_bytes)
                for disk in inventory.disks
                if mounts.intersection(disk.mounts)
            )
        ),
        "requiredGpus": (
            tuple(
                sorted(
                    (gpu.stable_id, gpu.model, gpu.memory_bytes)
                    for gpu in inventory.gpus
                )
            )
            if capabilities.get("gpu") is True
            else ()
        ),
        "temperatureSensorBindings": tuple(
            sorted(
                (
                    binding.logical_name,
                    binding.sensor_id,
                    binding.limit_source,
                )
                for binding in inventory.temperature_sensor_bindings
                if binding.logical_name
                in {
                    cast(str, sensor["logicalName"])
                    for sensor in cast(
                        list[dict[str, object]],
                        definition.get("temperatureSensors", []),
                    )
                }
            )
        ),
    }


def _temperature_sensor_binding_documents(
    connection: sqlite3.Connection,
    *,
    server_id: str,
    definition: dict[str, object],
) -> list[dict[str, object]]:
    row = connection.execute(
        """
        SELECT inventory_json
        FROM verified_server_inventory
        WHERE server_id = ?
        """,
        (server_id,),
    ).fetchone()
    if row is None:
        return []
    inventory = server_inventory_from_document(
        json.loads(row["inventory_json"])
    )
    required_names = {
        cast(str, sensor["logicalName"])
        for sensor in cast(
            list[dict[str, object]],
            definition.get("temperatureSensors", []),
        )
    }
    return [
        {
            "logicalName": binding.logical_name,
            "sensorId": binding.sensor_id,
            "limitSource": binding.limit_source,
        }
        for binding in inventory.temperature_sensor_bindings
        if binding.logical_name in required_names
    ]


def _inventory_satisfies_profile(
    inventory: ServerInventory, definition: dict[str, object]
) -> bool:
    capabilities = cast(
        dict[str, object], definition.get("capabilities", {})
    )
    if capabilities.get("gpu") is True:
        expected_count = capabilities.get("expectedDeviceCount")
        model_class = capabilities.get("modelClass")
        if (
            not isinstance(expected_count, int)
            or len(inventory.gpus) != expected_count
            or not isinstance(model_class, str)
        ):
            return False
        if model_class == "NVIDIA CUDA-capable GPU":
            if any(
                not gpu.model.casefold().startswith("nvidia")
                for gpu in inventory.gpus
            ):
                return False
        elif any(
            model_class.casefold() not in gpu.model.casefold()
            for gpu in inventory.gpus
        ):
            return False
    expected_sensors = {
        cast(str, sensor["logicalName"]): cast(str, sensor["limitSource"])
        for sensor in cast(
            list[dict[str, object]],
            definition.get("temperatureSensors", []),
        )
    }
    actual_sensors = {
        binding.logical_name: binding.limit_source
        for binding in inventory.temperature_sensor_bindings
    }
    return all(
        actual_sensors.get(logical_name) == limit_source
        for logical_name, limit_source in expected_sensors.items()
    )


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
                s.enrollment_state, s.active_configuration_hash,
                p.profile_id, p.revision, p.name,
                p.state, p.definition_json,
                pe.source_address, pe.inventory_json AS pending_inventory_json,
                pe.observations_json, pe.verification_code,
                vi.inventory_json AS verified_inventory_json,
                rejected.collector_public_key_fingerprint
                    AS rejected_fingerprint,
                rejected.reason AS rejection_reason,
                staged.profile_id AS staged_profile_id,
                staged.profile_revision AS staged_profile_revision,
                staged.configuration_hash AS staged_configuration_hash,
                staged.bundle_json AS staged_bundle_json,
                staged.operation AS staged_operation,
                inventory_change.inventory_json
                    AS pending_inventory_change_json,
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
            LEFT JOIN staged_profile_configurations AS staged
              ON staged.server_id = s.server_id
            LEFT JOIN pending_inventory_changes AS inventory_change
              ON inventory_change.server_id = s.server_id
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
            pending_profile_configuration=(
                PendingProfileConfiguration(
                    profile_id=row["staged_profile_id"],
                    revision=row["staged_profile_revision"],
                    configuration_hash=row["staged_configuration_hash"],
                    bundle=cast(
                        dict[str, object],
                        json.loads(row["staged_bundle_json"]),
                    ),
                    operation=row["staged_operation"],
                )
                if row["staged_profile_id"] is not None
                else None
            ),
            pending_inventory_change=(
                server_inventory_from_document(
                    json.loads(row["pending_inventory_change_json"])
                )
                if row["pending_inventory_change_json"] is not None
                else None
            ),
            active_configuration_hash=row["active_configuration_hash"],
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
    inventory = server_inventory_from_document(
        json.loads(pending["inventory_json"])
    )
    if not _inventory_satisfies_profile(inventory, definition):
        _insert_audit_event(
            connection,
            occurred_at=occurred_at.isoformat(),
            actor=actor,
            action=audit_action,
            server_id=server_id,
            reason=reason,
            result="profile-inventory-mismatch",
        )
        connection.commit()
        raise ProfileInventoryMismatch
    profile_identity = connection.execute(
        """
        SELECT profile_id, profile_revision
        FROM servers
        WHERE server_id = ?
        """,
        (server_id,),
    ).fetchone()
    if profile_identity is None:
        connection.rollback()
        raise EnrollmentDecisionConflict
    _, active_configuration_hash = configuration_bundle(
        profile_id=profile_identity["profile_id"],
        revision=profile_identity["profile_revision"],
        definition=definition,
        temperature_sensor_bindings=[
            {
                "logicalName": binding.logical_name,
                "sensorId": binding.sensor_id,
                "limitSource": binding.limit_source,
            }
            for binding in inventory.temperature_sensor_bindings
        ],
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
        SET enrollment_state = 'active', active_configuration_hash = ?
        WHERE server_id = ?
        """,
        (active_configuration_hash, server_id),
    )
    connection.execute(
        """
        INSERT INTO server_profile_activations (
            server_id, profile_id, profile_revision,
            activated_at, operation
        ) VALUES (?, ?, ?, ?, 'enrollment')
        """,
        (
            server_id,
            profile_identity["profile_id"],
            profile_identity["profile_revision"],
            occurred_at.isoformat(),
        ),
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
    required.extend(
        f"temperature-sensor:{sensor['logicalName']}"
        for sensor in cast(
            list[dict[str, object]],
            definition.get("temperatureSensors", []),
        )
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


def _profile_from_row(
    row: sqlite3.Row, *, state: str | None = None
) -> ServerProfile:
    return ServerProfile(
        profile_id=row["profile_id"],
        revision=row["revision"],
        name=row["name"],
        state=state if state is not None else row["state"],
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
