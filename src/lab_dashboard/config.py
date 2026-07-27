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
    auth_mode: str = "capabilities"
    lab_administrator_logins: tuple[str, ...] = ()
    lab_user_logins: tuple[str, ...] = ()
    prometheus_url: str = "http://127.0.0.1:9090"
    public_url: str = "http://127.0.0.1:3000"
    run_observation_engine: bool = True


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
    auth_mode = values.get("DASHBOARD_AUTH_MODE", "capabilities")
    if auth_mode not in {"capabilities", "identity-allowlist"}:
        raise ConfigurationError("authentication mode is invalid")
    administrator_logins = _comma_separated(
        values.get("DASHBOARD_LAB_ADMINISTRATOR_LOGINS", "")
    )
    user_logins = _comma_separated(
        values.get("DASHBOARD_LAB_USER_LOGINS", "")
    )
    if auth_mode == "identity-allowlist" and not (
        administrator_logins or user_logins
    ):
        raise ConfigurationError("allowlist identities are required")
    if set(administrator_logins) & set(user_logins):
        raise ConfigurationError("allowlist roles must not overlap")

    return DashboardConfig(
        database_path=Path(
            values.get(
                "DASHBOARD_DB_PATH",
                "/var/lib/lab-dashboard/dashboard.sqlite3",
            )
        ),
        trusted_proxy_networks=trusted_proxy_networks,
        auth_mode=auth_mode,
        lab_administrator_logins=administrator_logins,
        lab_user_logins=user_logins,
        prometheus_url=values.get(
            "DASHBOARD_PROMETHEUS_URL", "http://127.0.0.1:9090"
        ).rstrip("/"),
        public_url=values.get(
            "DASHBOARD_PUBLIC_URL", "http://127.0.0.1:3000"
        ).rstrip("/"),
    )


def _comma_separated(value: str) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(item.strip() for item in value.split(",") if item.strip())
    )
