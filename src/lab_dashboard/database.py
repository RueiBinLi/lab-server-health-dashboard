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
class RegisteredServer:
    server_id: str
    display_name: str
    scrape_address: str
    profile: ServerProfile
    enrollment_state: str


class DisplayNameConflict(Exception):
    pass


class ProfileNotPublished(Exception):
    pass


class ServerNotAwaitingFirstContact(Exception):
    pass


class InvalidBootstrapCredentials(Exception):
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
                    certificate_fingerprint TEXT NOT NULL,
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
    certificate_fingerprint: str,
    certificate_expires_at: datetime,
    scrape_client_certificate_path: str,
    scrape_client_key_path: str,
) -> None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    occurred_at = _now()
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
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
                server_id, certificate_fingerprint, expires_at
            ) VALUES (?, ?, ?)
            """,
            (
                server_id,
                certificate_fingerprint,
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


def list_registered_servers(path: Path) -> list[RegisteredServer]:
    with closing(_connect(path)) as connection:
        rows = connection.execute(
            """
            SELECT
                server_id, display_name, scrape_address,
                enrollment_state, p.profile_id, p.revision, p.name,
                p.state, p.definition_json
            FROM servers AS s
            JOIN server_profiles AS p
              ON p.profile_id = s.profile_id
             AND p.revision = s.profile_revision
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
        )
        for row in rows
    ]


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
