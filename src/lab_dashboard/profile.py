from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import cast


MANDATORY_OBSERVATIONS = frozenset(
    {
        "reachability",
        "cpu",
        "memory",
        "root-filesystem",
        "temperature-headroom",
        "critical-errors",
    }
)
SUPPORTED_OBSERVATIONS = MANDATORY_OBSERVATIONS | {
    "gpu-utilization",
    "gpu-vram",
    "gpu-temperature",
    "gpu-faults",
}
_PROFILE_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_SYSTEMD_SERVICE = re.compile(r"^[A-Za-z0-9:_.@-]+\.service$")
_LOGICAL_NAME = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_OVERRIDE_SHAPES = {
    "memory-available-percent": ("fireBelow", "clearAbove", "percent", "below"),
    "filesystem-free-percent": ("fireBelow", "clearAbove", "percent", "below"),
    "filesystem-free-bytes": ("fireBelow", "clearAbove", "bytes", "below"),
    "temperature-headroom": ("fireBelow", "clearAbove", "celsius", "below"),
    "cpu-used-percent": ("fireAbove", "clearBelow", "percent", "above"),
    "normalized-load": ("fireAbove", "clearBelow", "ratio", "above"),
}
_OVERRIDE_BASELINES = {
    "memory-available-percent": (10.0, 15.0, "below"),
    "filesystem-free-percent": (10.0, 15.0, "below"),
    "filesystem-free-bytes": (
        float(20 * 1024**3),
        float(30 * 1024**3),
        "below",
    ),
    "temperature-headroom": (10.0, 15.0, "below"),
    "cpu-used-percent": (95.0, 85.0, "above"),
    "normalized-load": (1.5, 1.1, "above"),
}


@dataclass(frozen=True)
class ProfileDraftRequest:
    name: str
    definition: dict[str, object]
    reason: str


@dataclass(frozen=True)
class ProfileCloneRequest:
    profile_id: str
    name: str
    source_profile_id: str
    source_revision: int
    reason: str


@dataclass(frozen=True)
class ProfileTargetRequest:
    profile_id: str
    revision: int
    reason: str


@dataclass(frozen=True)
class ProfileActivationRequest:
    reported_configuration_hash: str
    observations: tuple[str, ...]
    inventory: object


class InvalidProfileRequest(Exception):
    pass


class InvalidProfileDefinition(Exception):
    def __init__(self, details: list[str]) -> None:
        super().__init__("; ".join(details))
        self.details = details


def parse_profile_clone(document: object) -> ProfileCloneRequest:
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "profileId",
            "name",
            "sourceProfileId",
            "sourceRevision",
            "reason",
        }
    ):
        raise InvalidProfileRequest
    profile_id = _text(document["profileId"], maximum=100)
    name = _text(document["name"], maximum=100)
    source_profile_id = _text(document["sourceProfileId"], maximum=100)
    reason = _text(document["reason"], maximum=500)
    source_revision = document["sourceRevision"]
    if (
        not _PROFILE_ID.fullmatch(profile_id)
        or not _PROFILE_ID.fullmatch(source_profile_id)
        or not isinstance(source_revision, int)
        or isinstance(source_revision, bool)
        or source_revision < 1
    ):
        raise InvalidProfileRequest
    return ProfileCloneRequest(
        profile_id=profile_id,
        name=name,
        source_profile_id=source_profile_id,
        source_revision=source_revision,
        reason=reason,
    )


def parse_profile_draft(document: object) -> ProfileDraftRequest:
    if (
        not isinstance(document, dict)
        or set(document) != {"name", "definition", "reason"}
    ):
        raise InvalidProfileRequest
    name = _text(document["name"], maximum=100)
    reason = _text(document["reason"], maximum=500)
    definition = document["definition"]
    if not isinstance(definition, dict):
        raise InvalidProfileRequest
    typed_definition = cast(dict[str, object], definition)
    validate_profile_definition(typed_definition)
    return ProfileDraftRequest(
        name=name,
        definition=typed_definition,
        reason=reason,
    )


def parse_reason(document: object) -> str:
    if not isinstance(document, dict) or set(document) != {"reason"}:
        raise InvalidProfileRequest
    return _text(document["reason"], maximum=500)


def parse_profile_target(document: object) -> ProfileTargetRequest:
    if (
        not isinstance(document, dict)
        or set(document) != {"profileId", "revision", "reason"}
    ):
        raise InvalidProfileRequest
    profile_id = _text(document["profileId"], maximum=100)
    revision = document["revision"]
    if (
        not _PROFILE_ID.fullmatch(profile_id)
        or not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision < 1
    ):
        raise InvalidProfileRequest
    return ProfileTargetRequest(
        profile_id=profile_id,
        revision=revision,
        reason=_text(document["reason"], maximum=500),
    )


def parse_profile_activation(document: object) -> ProfileActivationRequest:
    if (
        not isinstance(document, dict)
        or set(document)
        != {"reportedConfigurationHash", "observations", "inventory"}
    ):
        raise InvalidProfileRequest
    configuration_hash = _text(
        document["reportedConfigurationHash"], maximum=100
    )
    if not configuration_hash.startswith("sha256:"):
        raise InvalidProfileRequest
    observations = document["observations"]
    if (
        not isinstance(observations, list)
        or not all(isinstance(value, str) and value for value in observations)
    ):
        raise InvalidProfileRequest
    return ProfileActivationRequest(
        reported_configuration_hash=configuration_hash,
        observations=tuple(observations),
        inventory=document["inventory"],
    )


def validate_profile_definition(definition: dict[str, object]) -> None:
    details: list[str] = []
    allowed_fields = {
        "capabilities",
        "requiredObservations",
        "persistentMounts",
        "requiredServices",
        "temperatureSensors",
        "thresholdOverrides",
    }
    if not set(definition) <= allowed_fields:
        details.append(
            "arbitrary queries, scripts, commands, and collector flags are forbidden"
        )

    observations = definition.get("requiredObservations")
    observation_set = (
        set(observations)
        if isinstance(observations, list)
        and all(isinstance(value, str) for value in observations)
        else set()
    )
    if not MANDATORY_OBSERVATIONS <= observation_set:
        details.append("mandatory required observations cannot be removed")
    if not observation_set <= SUPPORTED_OBSERVATIONS:
        details.append("required observations must use the fixed allowlist")

    capabilities = definition.get("capabilities")
    if (
        not isinstance(capabilities, dict)
        or not isinstance(capabilities.get("gpu"), bool)
        or not set(capabilities)
        <= {"gpu", "expectedDeviceCount", "modelClass"}
    ):
        details.append("capabilities must use the supported typed fields")
    elif capabilities["gpu"] is True:
        count = capabilities.get("expectedDeviceCount")
        model = capabilities.get("modelClass")
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
            or not isinstance(model, str)
            or not model.strip()
        ):
            details.append(
                "GPU profiles require an expected device count and model class"
            )
    elif set(capabilities) != {"gpu"}:
        details.append("non-GPU profiles cannot declare GPU expectations")

    mounts = definition.get("persistentMounts")
    if (
        not isinstance(mounts, list)
        or not mounts
        or "/" not in mounts
        or len(set(_strings(mounts))) != len(mounts)
        or any(
            not isinstance(mount, str)
            or not mount.startswith("/")
            or mount != "/" and mount.endswith("/")
            or any(character in mount for character in "*?[]\n\r\t")
            for mount in mounts
        )
    ):
        details.append(
            "persistent mounts must be unique stable absolute paths including root"
        )

    services = definition.get("requiredServices")
    if (
        not isinstance(services, list)
        or len(set(_strings(services))) != len(services)
        or any(
            not isinstance(service, str)
            or _SYSTEMD_SERVICE.fullmatch(service) is None
            or "@." in service
            for service in services
        )
    ):
        details.append("Required Services must be exact systemd service units")

    sensors = definition.get("temperatureSensors", [])
    if not _valid_temperature_sensors(sensors):
        details.append(
            "temperature sensors require logical names and hardware limit sources"
        )

    overrides = definition.get("thresholdOverrides")
    if not isinstance(overrides, list):
        details.append("threshold overrides must be a list")
    else:
        for override in overrides:
            override_error = _override_error(override)
            if override_error is not None and override_error not in details:
                details.append(override_error)

    if details:
        raise InvalidProfileDefinition(details)


def configuration_bundle(
    *,
    profile_id: str,
    revision: int,
    definition: dict[str, object],
    temperature_sensor_bindings: list[dict[str, object]] | None = None,
) -> tuple[dict[str, object], str]:
    bundle = {
        "schemaVersion": 1,
        "profileId": profile_id,
        "revision": revision,
        "collector": {
            "persistentMounts": definition["persistentMounts"],
            "requiredServices": definition["requiredServices"],
            "temperatureSensors": definition.get("temperatureSensors", []),
            "temperatureSensorBindings": (
                temperature_sensor_bindings
                if temperature_sensor_bindings is not None
                else []
            ),
        },
        "evaluation": {
            "requiredObservations": definition["requiredObservations"],
            "thresholdOverrides": definition["thresholdOverrides"],
        },
    }
    _validate_configuration_bundle(bundle)
    encoded = json.dumps(
        bundle, separators=(",", ":"), sort_keys=True
    ).encode()
    return bundle, f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _validate_configuration_bundle(bundle: dict[str, object]) -> None:
    collector = bundle.get("collector")
    evaluation = bundle.get("evaluation")
    if (
        set(bundle)
        != {
            "schemaVersion",
            "profileId",
            "revision",
            "collector",
            "evaluation",
        }
        or bundle["schemaVersion"] != 1
        or not isinstance(bundle["profileId"], str)
        or not isinstance(bundle["revision"], int)
        or not isinstance(collector, dict)
        or set(collector)
        != {
            "persistentMounts",
            "requiredServices",
            "temperatureSensors",
            "temperatureSensorBindings",
        }
        or not all(isinstance(value, list) for value in collector.values())
        or not isinstance(evaluation, dict)
        or set(evaluation)
        != {"requiredObservations", "thresholdOverrides"}
        or not all(isinstance(value, list) for value in evaluation.values())
    ):
        raise InvalidProfileDefinition(
            ["generated declarative configuration failed schema validation"]
        )


def effective_changes(
    before: dict[str, object], after: dict[str, object]
) -> list[dict[str, object]]:
    return [
        {"path": key, "before": before.get(key), "after": after.get(key)}
        for key in sorted(set(before) | set(after))
        if before.get(key) != after.get(key)
    ]


def _valid_temperature_sensors(value: object) -> bool:
    if not isinstance(value, list):
        return False
    logical_names: set[str] = set()
    for sensor in value:
        if (
            not isinstance(sensor, dict)
            or set(sensor) != {"logicalName", "kind", "limitSource"}
            or not isinstance(sensor["logicalName"], str)
            or _LOGICAL_NAME.fullmatch(sensor["logicalName"]) is None
            or sensor["logicalName"] in logical_names
            or sensor["kind"] not in {"cpu", "gpu"}
            or sensor["limitSource"]
            not in {"hardware-critical", "hardware-slowdown"}
        ):
            return False
        logical_names.add(sensor["logicalName"])
    return True


def _override_error(value: object) -> str | None:
    if not isinstance(value, dict):
        return "threshold overrides must use the fixed typed allowlist"
    key = value.get("key")
    if not isinstance(key, str) or key not in _OVERRIDE_SHAPES:
        return "threshold overrides must use the fixed typed allowlist"
    fire_key, clear_key, unit, direction = _OVERRIDE_SHAPES[key]
    if set(value) != {fire_key, clear_key, "key", "unit", "rationale"}:
        return "threshold overrides cannot change global timing or semantics"
    fire = value[fire_key]
    clear = value[clear_key]
    rationale = value["rationale"]
    if (
        value["unit"] != unit
        or not _is_nonnegative_number(fire)
        or not _is_nonnegative_number(clear)
        or not isinstance(rationale, str)
        or not rationale.strip()
        or len(rationale.strip()) > 500
    ):
        return "every override needs typed values, units, and a rationale"
    if (direction == "below" and float(fire) >= float(clear)) or (
        direction == "above" and float(fire) <= float(clear)
    ):
        return "threshold override hysteresis bands must not overlap"
    baseline_fire, baseline_clear, _ = _OVERRIDE_BASELINES[key]
    if (
        direction == "below"
        and (
            float(fire) < baseline_fire
            or float(clear) < baseline_clear
        )
    ) or (
        direction == "above"
        and (
            float(fire) > baseline_fire
            or float(clear) > baseline_clear
        )
    ):
        return "threshold overrides cannot weaken mandatory global rules"
    return None


def _is_nonnegative_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def _strings(values: list[object]) -> list[str]:
    return [value for value in values if isinstance(value, str)]


def _text(value: object, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise InvalidProfileRequest
    text = value.strip()
    if not 1 <= len(text) <= maximum or any(
        character in text for character in "\x00\r\n"
    ):
        raise InvalidProfileRequest
    return text
