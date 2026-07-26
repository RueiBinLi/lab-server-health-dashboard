from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DashboardConfig:
    database_path: Path
    trusted_proxy_networks: tuple[str, ...]


class ConfigurationError(Exception):
    """A fail-closed startup configuration error safe to report."""


def load_config(environment: Mapping[str, str] | None = None) -> DashboardConfig:
    values = os.environ if environment is None else environment
    trusted_proxy_networks = tuple(
        network.strip()
        for network in values.get(
            "DASHBOARD_TRUSTED_PROXY_CIDRS", "127.0.0.0/8,::1/128"
        ).split(",")
        if network.strip()
    )
    if not trusted_proxy_networks:
        raise ConfigurationError("trusted proxy networks are required")
    try:
        for network in trusted_proxy_networks:
            ipaddress.ip_network(network)
    except ValueError as error:
        raise ConfigurationError("trusted proxy networks are invalid") from error

    return DashboardConfig(
        database_path=Path(
            values.get(
                "DASHBOARD_DB_PATH",
                "/var/lib/lab-dashboard/dashboard.sqlite3",
            )
        ),
        trusted_proxy_networks=trusted_proxy_networks,
    )
