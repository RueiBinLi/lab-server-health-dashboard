from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict, cast


GIBIBYTE = 1024**3


class FilesystemHealthObservation(TypedDict):
    mountpoint: str
    freePercent: float | None
    freeBytes: float | None
    exhaustionWithin24Hours: bool | None


class HealthObservation(TypedDict):
    primaryTelemetrySuccessful: bool | None
    requiredObservationsComplete: bool | None
    cpuUsedPercent: float | None
    normalizedLoad5: float | None
    memoryAvailablePercent: float | None
    filesystems: list[FilesystemHealthObservation]


class HealthCause(TypedDict):
    rule: str
    severity: str
    summary: str


class IncidentTransition(TypedDict):
    occurredAt: str
    severity: str
    causes: list[str]


class ServerIncident(TypedDict):
    incidentId: int
    openedAt: str
    closedAt: str | None
    currentSeverity: str
    transitions: list[IncidentTransition]


class ServerHealth(TypedDict):
    state: str
    explanation: str


class HealthEvaluation(TypedDict):
    serverHealth: ServerHealth
    activeHealthCauses: list[HealthCause]
    serverIncidents: list[ServerIncident]


class _RuleState(TypedDict):
    active: bool
    firingSince: str | None
    clearingSince: str | None


@dataclass(frozen=True)
class _RuleCondition:
    firing: bool | None
    clearing: bool | None
    firing_seconds: int
    clearing_seconds: int


_RULE_ORDER = (
    "primary-telemetry",
    "required-observations",
    "cpu-pressure",
    "memory-pressure",
)

_SUMMARIES = {
    "primary-telemetry": "Primary telemetry is unavailable.",
    "required-observations": "Required observations are incomplete.",
    "cpu-pressure": "CPU utilization and normalized load are both sustained.",
    "memory-pressure": "Available system memory is low.",
}


def health_now() -> datetime:
    return datetime.now(UTC)


def initialize_health_database(path: Path) -> None:
    with closing(_connect(path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS server_health_evaluations (
                    server_id TEXT PRIMARY KEY REFERENCES servers(server_id),
                    rule_state_json TEXT NOT NULL,
                    current_health TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS server_incidents (
                    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id TEXT NOT NULL REFERENCES servers(server_id),
                    opened_at TEXT NOT NULL,
                    closed_at TEXT,
                    current_severity TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS one_open_server_incident
                ON server_incidents(server_id)
                WHERE closed_at IS NULL
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS server_incident_transitions (
                    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL
                        REFERENCES server_incidents(incident_id),
                    occurred_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    causes_json TEXT NOT NULL
                )
                """
            )


def evaluate_server_health(
    path: Path,
    *,
    server_id: str,
    observation: HealthObservation,
    now: datetime,
) -> HealthEvaluation:
    if now.tzinfo is None:
        raise ValueError("health evaluation time must be timezone-aware")
    now = now.astimezone(UTC)
    with closing(_connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        stored = connection.execute(
            """
            SELECT rule_state_json
            FROM server_health_evaluations
            WHERE server_id = ?
            """,
            (server_id,),
        ).fetchone()
        states = (
            cast(dict[str, _RuleState], json.loads(stored["rule_state_json"]))
            if stored is not None
            else {}
        )
        conditions = _rule_conditions(observation)
        states = {
            rule: state for rule, state in states.items() if rule in conditions
        }
        for rule, condition in conditions.items():
            states[rule] = _advance_rule(
                states.get(rule),
                now=now,
                firing=condition.firing,
                clearing=condition.clearing,
                firing_seconds=condition.firing_seconds,
                clearing_seconds=condition.clearing_seconds,
            )

        active_rules = [
            rule
            for rule in _ordered_rules(states)
            if states[rule]["active"]
        ]
        health = (
            "Unavailable"
            if "primary-telemetry" in active_rules
            else "Degraded"
            if active_rules
            else "Healthy"
        )
        causes: list[HealthCause] = [
            {
                "rule": rule,
                "severity": (
                    "Unavailable"
                    if rule == "primary-telemetry"
                    else "Degraded"
                ),
                "summary": _summary(rule),
            }
            for rule in active_rules
        ]
        _record_incident_transition(
            connection,
            server_id=server_id,
            health=health,
            causes=active_rules,
            occurred_at=now,
        )
        encoded_states = json.dumps(states, separators=(",", ":"), sort_keys=True)
        connection.execute(
            """
            INSERT INTO server_health_evaluations (
                server_id, rule_state_json, current_health, evaluated_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                rule_state_json = excluded.rule_state_json,
                current_health = excluded.current_health,
                evaluated_at = excluded.evaluated_at
            """,
            (server_id, encoded_states, health, now.isoformat()),
        )
        incidents = _list_incidents(connection, server_id)
        connection.commit()
    return {
        "serverHealth": {
            "state": health,
            "explanation": _explanation(health),
        },
        "activeHealthCauses": causes,
        "serverIncidents": incidents,
    }


def _rule_conditions(
    observation: HealthObservation,
) -> dict[str, _RuleCondition]:
    primary = observation.get("primaryTelemetrySuccessful")
    complete = observation.get("requiredObservationsComplete")
    cpu = _number(observation.get("cpuUsedPercent"))
    load = _number(observation.get("normalizedLoad5"))
    memory = _number(observation.get("memoryAvailablePercent"))
    conditions: dict[str, _RuleCondition] = {
        "primary-telemetry": _RuleCondition(
            firing=None if primary is None else not primary,
            clearing=primary,
            firing_seconds=2 * 60,
            clearing_seconds=60,
        ),
        "required-observations": _RuleCondition(
            firing=None if complete is None else not complete,
            clearing=complete,
            firing_seconds=10 * 60,
            clearing_seconds=5 * 60,
        ),
        "cpu-pressure": _RuleCondition(
            firing=(
                None
                if cpu is None or load is None
                else cpu >= 95 and load > 1.5
            ),
            clearing=(
                None
                if cpu is None or load is None
                else cpu < 85 or load < 1.1
            ),
            firing_seconds=10 * 60,
            clearing_seconds=5 * 60,
        ),
        "memory-pressure": _RuleCondition(
            firing=None if memory is None else memory < 10,
            clearing=None if memory is None else memory > 15,
            firing_seconds=5 * 60,
            clearing_seconds=5 * 60,
        ),
    }
    for filesystem in observation.get("filesystems", []):
        mountpoint = filesystem.get("mountpoint")
        if not isinstance(mountpoint, str):
            continue
        free_percent = _number(filesystem.get("freePercent"))
        free_bytes = _number(filesystem.get("freeBytes"))
        forecast = filesystem.get("exhaustionWithin24Hours")
        capacity_rule = f"disk-capacity:{mountpoint}"
        forecast_rule = f"disk-exhaustion:{mountpoint}"
        enough_headroom = (
            None
            if free_percent is None or free_bytes is None
            else free_percent > 15 or free_bytes > 30 * GIBIBYTE
        )
        conditions[capacity_rule] = _RuleCondition(
            firing=(
                None
                if free_percent is None or free_bytes is None
                else free_percent < 10 and free_bytes < 20 * GIBIBYTE
            ),
            clearing=enough_headroom,
            firing_seconds=10 * 60,
            clearing_seconds=10 * 60,
        )
        conditions[forecast_rule] = _RuleCondition(
            firing=forecast if isinstance(forecast, bool) else None,
            clearing=(
                None
                if not isinstance(forecast, bool) or enough_headroom is None
                else not forecast and enough_headroom
            ),
            firing_seconds=0,
            clearing_seconds=10 * 60,
        )
    return conditions


def _advance_rule(
    state: _RuleState | None,
    *,
    now: datetime,
    firing: bool | None,
    clearing: bool | None,
    firing_seconds: int,
    clearing_seconds: int,
) -> _RuleState:
    current: _RuleState = (
        cast(_RuleState, dict(state))
        if state is not None
        else {"active": False, "firingSince": None, "clearingSince": None}
    )
    if current["active"]:
        current["firingSince"] = None
        if clearing is True:
            current["clearingSince"] = _timer_start(
                current["clearingSince"], now
            )
            if _elapsed(current["clearingSince"], now) >= clearing_seconds:
                current["active"] = False
                current["clearingSince"] = None
        else:
            current["clearingSince"] = None
    else:
        current["clearingSince"] = None
        if firing is True:
            current["firingSince"] = _timer_start(
                current["firingSince"], now
            )
            if _elapsed(current["firingSince"], now) >= firing_seconds:
                current["active"] = True
                current["firingSince"] = None
        else:
            current["firingSince"] = None
    return current


def _timer_start(value: str | None, now: datetime) -> str:
    if value is None:
        return now.isoformat()
    try:
        started = datetime.fromisoformat(value)
    except ValueError:
        return now.isoformat()
    return value if started <= now else now.isoformat()


def _elapsed(value: str | None, now: datetime) -> float:
    if value is None:
        return 0
    return max(0.0, (now - datetime.fromisoformat(value)).total_seconds())


def _record_incident_transition(
    connection: sqlite3.Connection,
    *,
    server_id: str,
    health: str,
    causes: list[str],
    occurred_at: datetime,
) -> None:
    open_incident = connection.execute(
        """
        SELECT incident_id, current_severity
        FROM server_incidents
        WHERE server_id = ? AND closed_at IS NULL
        """,
        (server_id,),
    ).fetchone()
    encoded_causes = json.dumps(causes, separators=(",", ":"))
    if health == "Healthy":
        if open_incident is None:
            return
        connection.execute(
            """
            UPDATE server_incidents
            SET closed_at = ?, current_severity = 'Healthy'
            WHERE incident_id = ?
            """,
            (occurred_at.isoformat(), open_incident["incident_id"]),
        )
        connection.execute(
            """
            INSERT INTO server_incident_transitions (
                incident_id, occurred_at, severity, causes_json
            ) VALUES (?, ?, 'Healthy', '[]')
            """,
            (open_incident["incident_id"], occurred_at.isoformat()),
        )
        return
    if open_incident is None:
        cursor = connection.execute(
            """
            INSERT INTO server_incidents (
                server_id, opened_at, current_severity
            ) VALUES (?, ?, ?)
            """,
            (server_id, occurred_at.isoformat(), health),
        )
        incident_id = cast(int, cursor.lastrowid)
        connection.execute(
            """
            INSERT INTO server_incident_transitions (
                incident_id, occurred_at, severity, causes_json
            ) VALUES (?, ?, ?, ?)
            """,
            (incident_id, occurred_at.isoformat(), health, encoded_causes),
        )
        return
    latest = connection.execute(
        """
        SELECT severity, causes_json
        FROM server_incident_transitions
        WHERE incident_id = ?
        ORDER BY transition_id DESC
        LIMIT 1
        """,
        (open_incident["incident_id"],),
    ).fetchone()
    if (
        latest is not None
        and latest["severity"] == health
        and latest["causes_json"] == encoded_causes
    ):
        return
    connection.execute(
        """
        UPDATE server_incidents
        SET current_severity = ?
        WHERE incident_id = ?
        """,
        (health, open_incident["incident_id"]),
    )
    connection.execute(
        """
        INSERT INTO server_incident_transitions (
            incident_id, occurred_at, severity, causes_json
        ) VALUES (?, ?, ?, ?)
        """,
        (
            open_incident["incident_id"],
            occurred_at.isoformat(),
            health,
            encoded_causes,
        ),
    )


def _list_incidents(
    connection: sqlite3.Connection, server_id: str
) -> list[ServerIncident]:
    rows = connection.execute(
        """
        SELECT incident_id, opened_at, closed_at, current_severity
        FROM server_incidents
        WHERE server_id = ?
        ORDER BY incident_id DESC
        """,
        (server_id,),
    ).fetchall()
    incidents: list[ServerIncident] = []
    for row in rows:
        transition_rows = connection.execute(
            """
            SELECT occurred_at, severity, causes_json
            FROM server_incident_transitions
            WHERE incident_id = ?
            ORDER BY transition_id
            """,
            (row["incident_id"],),
        ).fetchall()
        incidents.append(
            {
                "incidentId": row["incident_id"],
                "openedAt": row["opened_at"],
                "closedAt": row["closed_at"],
                "currentSeverity": row["current_severity"],
                "transitions": [
                    {
                        "occurredAt": transition["occurred_at"],
                        "severity": transition["severity"],
                        "causes": cast(
                            list[str],
                            json.loads(transition["causes_json"]),
                        ),
                    }
                    for transition in transition_rows
                ],
            }
        )
    return incidents


def _ordered_rules(states: dict[str, _RuleState]) -> list[str]:
    fixed = [rule for rule in _RULE_ORDER if rule in states]
    disk = sorted(rule for rule in states if rule not in _RULE_ORDER)
    return fixed + disk


def _summary(rule: str) -> str:
    if rule.startswith("disk-capacity:"):
        return f"Persistent filesystem {rule.split(':', 1)[1]} is low on space."
    if rule.startswith("disk-exhaustion:"):
        return (
            f"Persistent filesystem {rule.split(':', 1)[1]} "
            "may exhaust within 24 hours."
        )
    return _SUMMARIES[rule]


def _explanation(health: str) -> str:
    if health == "Healthy":
        return "No active baseline health rules."
    if health == "Unavailable":
        return (
            "Trustworthy observation is unavailable; "
            "Lab Administrator attention is required."
        )
    return "One or more health checks need Lab Administrator attention."


def _number(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection
