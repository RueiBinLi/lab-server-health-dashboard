from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import cast
from urllib.parse import urlsplit


PRIVATE_SCRAPE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


@dataclass(frozen=True)
class Registration:
    display_name: str
    scrape_address: str
    profile_id: str
    reason: str


@dataclass(frozen=True)
class CpuInventory:
    model: str
    logical_count: int


@dataclass(frozen=True)
class MemoryInventory:
    total_bytes: int


@dataclass(frozen=True)
class DiskInventory:
    stable_id: str
    model: str
    size_bytes: int
    mounts: tuple[str, ...]


@dataclass(frozen=True)
class GpuInventory:
    stable_id: str
    model: str
    memory_bytes: int


@dataclass(frozen=True)
class StableIdentifiers:
    machine_id: str
    system_uuid: str


@dataclass(frozen=True)
class ServerInventory:
    hostname: str
    os_release: str
    architecture: str
    cpu: CpuInventory
    memory: MemoryInventory
    disks: tuple[DiskInventory, ...]
    gpus: tuple[GpuInventory, ...]
    stable_identifiers: StableIdentifiers

    def as_document(self) -> dict[str, object]:
        return {
            "hostname": self.hostname,
            "osRelease": self.os_release,
            "architecture": self.architecture,
            "cpu": {
                "model": self.cpu.model,
                "logicalCount": self.cpu.logical_count,
            },
            "memory": {"totalBytes": self.memory.total_bytes},
            "disks": [
                {
                    "stableId": disk.stable_id,
                    "model": disk.model,
                    "sizeBytes": disk.size_bytes,
                    "mounts": list(disk.mounts),
                }
                for disk in self.disks
            ],
            "gpus": [
                {
                    "stableId": gpu.stable_id,
                    "model": gpu.model,
                    "memoryBytes": gpu.memory_bytes,
                }
                for gpu in self.gpus
            ],
            "stableIdentifiers": {
                "machineId": self.stable_identifiers.machine_id,
                "systemUuid": self.stable_identifiers.system_uuid,
            },
        }


@dataclass(frozen=True)
class FirstContact:
    server_id: str
    bootstrap_token: str
    certificate_signing_request: str
    inventory: ServerInventory


class EnrollmentDecisionKind(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


@dataclass(frozen=True)
class EnrollmentDecision:
    kind: EnrollmentDecisionKind
    verification_code: str
    reason: str


class InvalidRegistration(Exception):
    pass


class InvalidFirstContact(Exception):
    pass


class InvalidEnrollmentDecision(Exception):
    pass


def parse_registration(document: object) -> Registration:
    if not isinstance(document, dict) or set(document) != {
        "displayName",
        "scrapeAddress",
        "profileId",
        "reason",
    }:
        raise InvalidRegistration
    values = tuple(document.values())
    if not all(isinstance(value, str) for value in values):
        raise InvalidRegistration

    display_name = document["displayName"].strip()
    scrape_address = document["scrapeAddress"].strip()
    profile_id = document["profileId"].strip()
    reason = document["reason"].strip()
    if (
        not 1 <= len(display_name) <= 100
        or not _printable(display_name)
        or not 1 <= len(profile_id) <= 100
        or not 1 <= len(reason) <= 500
        or not _printable(reason)
        or not _printable(scrape_address)
        or not _valid_private_scrape_address(scrape_address)
    ):
        raise InvalidRegistration
    return Registration(
        display_name=display_name,
        scrape_address=scrape_address,
        profile_id=profile_id,
        reason=reason,
    )


def safe_audit_reason(document: object) -> str:
    if not isinstance(document, dict):
        return "Invalid registration request"
    reason = document.get("reason")
    if not isinstance(reason, str):
        return "Invalid registration request"
    normalized = reason.strip()
    if not 1 <= len(normalized) <= 500 or not _printable(normalized):
        return "Invalid registration request"
    return normalized


def parse_first_contact(document: object) -> FirstContact:
    scalar_fields = {
        "serverId",
        "bootstrapToken",
        "certificateSigningRequest",
        "hostname",
        "osRelease",
        "architecture",
    }
    structured_fields = {
        "cpu",
        "memory",
        "disks",
        "gpus",
        "stableIdentifiers",
    }
    if (
        not isinstance(document, dict)
        or set(document) != scalar_fields | structured_fields
        or not all(
            isinstance(document[field], str)
            and 1 <= len(document[field].strip()) <= 16_384
            for field in scalar_fields
        )
    ):
        raise InvalidFirstContact
    inventory_document = {
        "hostname": document["hostname"].strip(),
        "osRelease": document["osRelease"].strip(),
        "architecture": document["architecture"].strip(),
        "cpu": document["cpu"],
        "memory": document["memory"],
        "disks": document["disks"],
        "gpus": document["gpus"],
        "stableIdentifiers": document["stableIdentifiers"],
    }
    return FirstContact(
        server_id=document["serverId"].strip(),
        bootstrap_token=document["bootstrapToken"],
        certificate_signing_request=document[
            "certificateSigningRequest"
        ],
        inventory=server_inventory_from_document(inventory_document),
    )


def server_inventory_from_document(document: object) -> ServerInventory:
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "hostname",
            "osRelease",
            "architecture",
            "cpu",
            "memory",
            "disks",
            "gpus",
            "stableIdentifiers",
        }
        or not all(
            _nonempty_string(document[field])
            for field in ("hostname", "osRelease", "architecture")
        )
        or not _valid_cpu(document["cpu"])
        or not _valid_memory(document["memory"])
        or not _valid_devices(document["disks"], disk=True)
        or not _valid_devices(document["gpus"], disk=False)
        or not _valid_stable_identifiers(document["stableIdentifiers"])
    ):
        raise InvalidFirstContact
    cpu = cast(dict[str, object], document["cpu"])
    memory = cast(dict[str, object], document["memory"])
    disks = cast(list[dict[str, object]], document["disks"])
    gpus = cast(list[dict[str, object]], document["gpus"])
    stable = cast(dict[str, object], document["stableIdentifiers"])
    return ServerInventory(
        hostname=cast(str, document["hostname"]),
        os_release=cast(str, document["osRelease"]),
        architecture=cast(str, document["architecture"]),
        cpu=CpuInventory(
            model=cast(str, cpu["model"]),
            logical_count=cast(int, cpu["logicalCount"]),
        ),
        memory=MemoryInventory(
            total_bytes=cast(int, memory["totalBytes"])
        ),
        disks=tuple(
            DiskInventory(
                stable_id=cast(str, disk["stableId"]),
                model=cast(str, disk["model"]),
                size_bytes=cast(int, disk["sizeBytes"]),
                mounts=tuple(cast(list[str], disk["mounts"])),
            )
            for disk in disks
        ),
        gpus=tuple(
            GpuInventory(
                stable_id=cast(str, gpu["stableId"]),
                model=cast(str, gpu["model"]),
                memory_bytes=cast(int, gpu["memoryBytes"]),
            )
            for gpu in gpus
        ),
        stable_identifiers=StableIdentifiers(
            machine_id=cast(str, stable["machineId"]),
            system_uuid=cast(str, stable["systemUuid"]),
        ),
    )


def parse_enrollment_decision(document: object) -> EnrollmentDecision:
    if (
        not isinstance(document, dict)
        or set(document)
        != {"decision", "verificationCode", "reason"}
        or not isinstance(document["decision"], str)
        or not isinstance(document["verificationCode"], str)
        or not isinstance(document["reason"], str)
    ):
        raise InvalidEnrollmentDecision
    try:
        kind = EnrollmentDecisionKind(document["decision"])
    except ValueError as error:
        raise InvalidEnrollmentDecision from error
    verification_code = document["verificationCode"].strip()
    reason = document["reason"].strip()
    if (
        not 1 <= len(verification_code) <= 100
        or not _printable(verification_code)
        or not 1 <= len(reason) <= 500
        or not _printable(reason)
    ):
        raise InvalidEnrollmentDecision
    return EnrollmentDecision(
        kind=kind,
        verification_code=verification_code,
        reason=reason,
    )


def _valid_cpu(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"model", "logicalCount"}
        and _nonempty_string(value["model"])
        and isinstance(value["logicalCount"], int)
        and not isinstance(value["logicalCount"], bool)
        and 1 <= value["logicalCount"] <= 65_536
    )


def _valid_memory(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"totalBytes"}
        and isinstance(value["totalBytes"], int)
        and not isinstance(value["totalBytes"], bool)
        and value["totalBytes"] > 0
    )


def _valid_devices(value: object, *, disk: bool) -> bool:
    if not isinstance(value, list) or len(value) > 256:
        return False
    expected = (
        {"stableId", "model", "sizeBytes", "mounts"}
        if disk
        else {"stableId", "model", "memoryBytes"}
    )
    size_field = "sizeBytes" if disk else "memoryBytes"
    for device in value:
        if (
            not isinstance(device, dict)
            or set(device) != expected
            or not _nonempty_string(device["stableId"])
            or not _nonempty_string(device["model"])
            or not isinstance(device[size_field], int)
            or isinstance(device[size_field], bool)
            or device[size_field] <= 0
        ):
            return False
        if disk and (
            not isinstance(device["mounts"], list)
            or not all(_nonempty_string(mount) for mount in device["mounts"])
        ):
            return False
    return True


def _valid_stable_identifiers(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"machineId", "systemUuid"}
        and _nonempty_string(value["machineId"])
        and _nonempty_string(value["systemUuid"])
    )


def _nonempty_string(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value.strip()) <= 500
        and _printable(value)
    )


def _printable(value: str) -> bool:
    return all(character.isprintable() for character in value)


def _valid_private_scrape_address(address: str) -> bool:
    try:
        parsed = urlsplit(address)
        host = parsed.hostname
        port = parsed.port
        network_address = ipaddress.ip_address(host or "")
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.username is None
        and parsed.password is None
        and host is not None
        and port is not None
        and parsed.path == "/metrics"
        and not parsed.query
        and not parsed.fragment
        and any(network_address in network for network in PRIVATE_SCRAPE_NETWORKS)
    )
