from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


GATE_CHECKS = (
    (
        "central-lan-access",
        "resource-limits",
        "protected-secrets",
        "component-health",
        "durable-persistence",
        "reboot-recovery",
        "monitored-workloads-unaffected",
    ),
    ("server-1-enrollment", "server-1-profile-observation"),
    (
        "server-2-enrollment",
        "server-2-profile-observation",
        "72-hour-capacity-soak",
        "training-throughput",
    ),
    (
        "health-causes-and-precedence",
        "incident-transitions-and-recovery",
        "alert-channels-and-failure-isolation",
        "maintenance-window",
        "backup-restoration",
        "certificate-rotation-revocation-re-enrollment",
        "collector-and-central-upgrade",
        "collector-rollback",
        "central-stack-rollback",
    ),
    (
        "lab-administrator-access",
        "lab-user-access",
        "neither-role-denied",
        "malformed-identity-denied",
        "tagged-device-denied",
        "direct-backend-denied",
        "spoofed-headers-denied",
    ),
)
EVIDENCE_FIELDS = (
    "actor",
    "versions",
    "configurationRevisions",
    "serverIds",
    "expected",
    "actual",
    "result",
    "evidenceCapturedAt",
    "evidenceLinks",
    "rollbackOutcome",
)
SECRET_TERMS = (
    "password",
    "secret",
    "privatekey",
    "private_key",
    "token",
    "webhook",
    "credential",
)


class QualificationError(Exception):
    pass


def _is_present(value: object) -> bool:
    return value is not None and value != "" and value != []


def _find_secret_fields(value: object, path: str = "record") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "").replace(" ", "")
            if any(term.replace("_", "") in normalized for term in SECRET_TERMS):
                found.append(f"{path}.{key}")
            found.extend(_find_secret_fields(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_find_secret_fields(child, f"{path}[{index}]"))
    return found


def _number(value: object, label: str, errors: list[str]) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{label} must be a number")
        return 0
    return float(value)


def _aware_timestamp(value: object, label: str, errors: list[str]) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        errors.append(f"{label} must be an ISO timestamp")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(f"{label} must include a timezone")
        return None
    return parsed


def validate_record(record: dict[str, Any]) -> dict[str, object]:
    errors: list[str] = []
    secret_fields = _find_secret_fields(record)
    if secret_fields:
        errors.append("potential secret field is forbidden: " + ", ".join(secret_fields))

    gates = record.get("gates")
    if not isinstance(gates, list) or len(gates) != len(GATE_CHECKS):
        errors.append("record must contain exactly five gates")
        gates = []
    gate_numbers = [
        gate.get("gate") for gate in gates if isinstance(gate, dict)
    ]
    if gate_numbers != [1, 2, 3, 4, 5]:
        errors.append("gates must be recorded in sequential order 1 through 5")

    observed_server_ids: set[str] = set()
    completed_at: list[datetime] = []
    enrollment_server_ids: list[set[str]] = []
    for index, required_ids in enumerate(GATE_CHECKS):
        if index >= len(gates) or not isinstance(gates[index], dict):
            continue
        gate = gates[index]
        if gate.get("result") != "pass":
            errors.append(f"gate {index + 1} must pass before production sign-off")
        completed = _aware_timestamp(
            gate.get("completedAt"), f"gate {index + 1}.completedAt", errors
        )
        if completed is not None:
            completed_at.append(completed)
        checks = gate.get("checks")
        if not isinstance(checks, list):
            errors.append(f"gate {index + 1}.checks must be a list")
            continue
        ids = [
            check.get("id") for check in checks if isinstance(check, dict)
        ]
        if ids != list(required_ids):
            errors.append(
                f"gate {index + 1} must contain every mandatory check in order"
            )
        for check in checks:
            if not isinstance(check, dict):
                errors.append(f"gate {index + 1} contains an invalid check")
                continue
            check_id = str(check.get("id", "<unknown>"))
            for field in EVIDENCE_FIELDS:
                if not _is_present(check.get(field)):
                    errors.append(
                        f"gate {index + 1} check {check_id}: {field} is required"
                    )
            if check.get("result") != "pass":
                errors.append(
                    f"gate {index + 1} check {check_id} must pass; "
                    "mandatory checks cannot be waived"
                )
            _aware_timestamp(
                check.get("evidenceCapturedAt"),
                f"gate {index + 1} check {check_id}.evidenceCapturedAt",
                errors,
            )
            server_ids = check.get("serverIds", [])
            if isinstance(server_ids, list):
                observed_server_ids.update(
                    item for item in server_ids if isinstance(item, str) and item
                )
        if index in (1, 2):
            enrollment_server_ids.append(
                {
                    item
                    for check in checks
                    if isinstance(check, dict)
                    for item in check.get("serverIds", [])
                    if isinstance(item, str) and item
                }
            )

    if len(observed_server_ids) < 2:
        errors.append("acceptance evidence must identify both initial Server IDs")
    if (
        len(enrollment_server_ids) != 2
        or any(len(ids) != 1 for ids in enrollment_server_ids)
        or enrollment_server_ids[0] == enrollment_server_ids[1]
    ):
        errors.append("Gates 2 and 3 must enroll distinct Server IDs")
    if len(completed_at) == 5 and completed_at != sorted(completed_at):
        errors.append("gate completion timestamps must be sequential")

    measurements = record.get("measurements", {})
    if not isinstance(measurements, dict):
        measurements = {}
    soak = measurements.get("soak", {})
    if not isinstance(soak, dict):
        soak = {}
    if _number(soak.get("continuousHours"), "continuousHours", errors) < 72:
        errors.append("soak must run for at least 72 continuous hours")
    if _number(
        soak.get("projectedRetentionDays"), "projectedRetentionDays", errors
    ) < 30:
        errors.append("soak must project at least 30 days of complete Metric History")
    if soak.get("swappingObserved") is not False:
        errors.append("soak must observe no swapping")
    if _number(
        soak.get("minimumDiskFreePercent"), "minimumDiskFreePercent", errors
    ) < 20:
        errors.append("soak must retain at least 20% disk free")
    if _number(soak.get("scrapeCadenceSeconds"), "scrapeCadenceSeconds", errors) != 30:
        errors.append("soak must use the 30-second scrape cadence")
    hourly_growth = _number(
        soak.get("observedMetricHistoryBytesPerHour"),
        "observedMetricHistoryBytesPerHour",
        errors,
    )
    projected_bytes = _number(
        soak.get("projectedMetricHistoryBytes"),
        "projectedMetricHistoryBytes",
        errors,
    )
    capacity_bytes = _number(
        soak.get("stateVolumeCapacityBytes"), "stateVolumeCapacityBytes", errors
    )
    non_metric_bytes = _number(
        soak.get("nonMetricUsedBytes"), "nonMetricUsedBytes", errors
    )
    expected_projected_bytes = hourly_growth * 24 * 30
    if projected_bytes != expected_projected_bytes:
        errors.append(
            "projectedMetricHistoryBytes must equal observed hourly growth "
            "projected over 30 days"
        )
    if capacity_bytes > 0:
        projected_free_percent = (
            (capacity_bytes - non_metric_bytes - projected_bytes)
            / capacity_bytes
            * 100
        )
        if projected_free_percent < 20:
            errors.append("30-day capacity projection leaves less than 20% disk free")

    throughput = measurements.get("trainingThroughput", {})
    if not isinstance(throughput, dict):
        throughput = {}
    samples: dict[str, list[float]] = {}
    for name in ("before", "after"):
        values = throughput.get(name)
        if (
            not isinstance(values, list)
            or len(values) != 3
            or any(
                isinstance(value, bool) or not isinstance(value, (int, float))
                for value in values
            )
        ):
            errors.append(f"trainingThroughput.{name} must contain three matched runs")
            samples[name] = []
        else:
            samples[name] = [float(value) for value in values]
    reduction_percent: float | None = None
    if samples["before"] and samples["after"]:
        before_median = statistics.median(samples["before"])
        after_median = statistics.median(samples["after"])
        if before_median <= 0:
            errors.append("trainingThroughput.before median must be positive")
        else:
            reduction_percent = (before_median - after_median) / before_median * 100
            if reduction_percent > 2:
                errors.append("median training throughput reduction exceeds 2%")

    sign_off = record.get("signOff", {})
    if not isinstance(sign_off, dict):
        sign_off = {}
    if sign_off.get("decision") not in ("go", "no-go"):
        errors.append("signOff.decision must be go or no-go")
    for field in ("labAdministrator", "recordedAt", "productionRollbackOwner"):
        if not _is_present(sign_off.get(field)):
            errors.append(f"signOff.{field} is required")
    _aware_timestamp(sign_off.get("recordedAt"), "signOff.recordedAt", errors)
    if sign_off.get("decision") != "go":
        errors.append("production qualification requires an explicit go decision")

    if errors:
        raise QualificationError("\n".join(errors))
    return {
        "status": "qualified",
        "gatesPassed": 5,
        "serverCount": len(observed_server_ids),
        "trainingThroughputReductionPercent": round(reduction_percent or 0, 3),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Production qualification records")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("record", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        loaded = json.loads(arguments.record.read_text())
        if not isinstance(loaded, dict):
            raise QualificationError("acceptance record must be a JSON object")
        result = validate_record(loaded)
    except (OSError, json.JSONDecodeError, QualificationError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
