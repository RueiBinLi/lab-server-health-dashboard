from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast


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
    occurred_at = datetime.now(UTC).isoformat()
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
                occurred_at=datetime.now(UTC).isoformat(),
                actor=actor,
                server_id=server_id,
                reason=reason,
                result=result,
            )


def _insert_audit_event(
    connection: sqlite3.Connection,
    *,
    occurred_at: str,
    actor: str,
    server_id: str | None,
    reason: str,
    result: str,
) -> None:
    connection.execute(
        """
        INSERT INTO audit_events (
            occurred_at, actor, action, server_id, reason, result
        ) VALUES (?, ?, 'server-registration', ?, ?, ?)
        """,
        (occurred_at, actor, server_id, reason, result),
    )


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
