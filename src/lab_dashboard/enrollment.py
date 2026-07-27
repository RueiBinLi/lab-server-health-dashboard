from __future__ import annotations

import ipaddress
from dataclasses import dataclass
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


class InvalidRegistration(Exception):
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
