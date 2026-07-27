from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from enum import Enum


CAPABILITY_NAME = "rueibinli.github.io/cap/lab-server-health"
MAX_CAPABILITIES_HEADER_BYTES = 16_384
LOCAL_PART_PATTERN = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
DOMAIN_LABEL_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


class Role(str, Enum):
    LAB_ADMINISTRATOR = "lab-administrator"
    LAB_USER = "lab-user"


@dataclass(frozen=True)
class Viewer:
    login: str
    role: Role


def authorize(
    login: str,
    capabilities_header: str,
    peer_address: str,
    trusted_proxy_networks: tuple[str, ...],
    auth_mode: str = "capabilities",
    lab_administrator_logins: tuple[str, ...] = (),
    lab_user_logins: tuple[str, ...] = (),
) -> Viewer | None:
    if not _trusted_peer(peer_address, trusted_proxy_networks):
        return None
    if not _valid_login(login):
        return None
    if auth_mode == "identity-allowlist":
        role = _role_from_allowlist(
            login, lab_administrator_logins, lab_user_logins
        )
    elif auth_mode == "capabilities":
        role = _role_from_capabilities(capabilities_header)
    else:
        return None
    if role is None:
        return None
    return Viewer(login=login, role=role)


def _role_from_allowlist(
    login: str,
    administrator_logins: tuple[str, ...],
    user_logins: tuple[str, ...],
) -> Role | None:
    if login in administrator_logins and login not in user_logins:
        return Role.LAB_ADMINISTRATOR
    if login in user_logins and login not in administrator_logins:
        return Role.LAB_USER
    return None


def _trusted_peer(peer_address: str, trusted_networks: tuple[str, ...]) -> bool:
    try:
        peer = ipaddress.ip_address(peer_address)
        return any(
            peer in ipaddress.ip_network(network) for network in trusted_networks
        )
    except ValueError:
        return False


def _valid_login(login: str) -> bool:
    if len(login) > 254 or login.count("@") != 1:
        return False
    local_part, domain = login.split("@")
    if (
        not local_part
        or len(local_part) > 64
        or LOCAL_PART_PATTERN.fullmatch(local_part) is None
        or local_part.startswith(".")
        or local_part.endswith(".")
        or ".." in local_part
    ):
        return False
    labels = domain.split(".")
    return (
        len(labels) >= 2
        and all(DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels)
    )


def _role_from_capabilities(header: str) -> Role | None:
    if not header or len(header.encode()) > MAX_CAPABILITIES_HEADER_BYTES:
        return None
    try:
        document = json.loads(header)
    except (json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(document, dict):
        return None

    entries = document.get(CAPABILITY_NAME)
    if not isinstance(entries, list) or not entries:
        return None
    if any(
        not isinstance(entry, dict) or set(entry) != {"role"}
        for entry in entries
    ):
        return None
    try:
        roles = {Role(entry["role"]) for entry in entries}
    except (KeyError, TypeError, ValueError):
        return None
    if len(roles) != 1:
        return None
    return roles.pop()
