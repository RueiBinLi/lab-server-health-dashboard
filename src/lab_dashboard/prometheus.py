from __future__ import annotations

import json
import math
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypedDict, cast

from lab_dashboard.database import (
    ObservationTarget,
    list_active_observation_targets,
)


SCRAPE_INTERVAL_SECONDS = 30
FRESH_AFTER_SECONDS = 3 * SCRAPE_INTERVAL_SECONDS
MAX_HISTORY = timedelta(days=30)
HISTORY_METRICS = {"cpu", "system-memory", "disk"}


class PercentageUsage(TypedDict):
    usedPercent: float | None


class CapacityUsage(PercentageUsage):
    usedBytes: float | None
    totalBytes: float | None


class FilesystemUsage(CapacityUsage):
    mountpoint: str


class Freshness(TypedDict):
    observedAt: str | None
    ageSeconds: float | None
    state: str


class CollectorSuccess(TypedDict):
    success: bool | None


class ResourceUsage(TypedDict):
    cpu: PercentageUsage
    systemMemory: CapacityUsage
    filesystems: list[FilesystemUsage]
    freshness: Freshness
    collector: CollectorSuccess


class PrometheusUnavailable(Exception):
    pass


class InvalidHistoryQuery(Exception):
    pass


def current_resource_usage(
    prometheus_url: str,
    server_id: str,
    mountpoints: tuple[str, ...],
) -> ResourceUsage:
    cpu = _instant_value(prometheus_url, _cpu_expression(server_id))
    memory_total = _instant_value(
        prometheus_url,
        f'node_memory_MemTotal_bytes{{server_id="{server_id}"}}',
    )
    memory_available = _instant_value(
        prometheus_url,
        f'node_memory_MemAvailable_bytes{{server_id="{server_id}"}}',
    )
    memory_used = _difference(memory_total, memory_available)
    filesystems: list[FilesystemUsage] = []
    for mountpoint in mountpoints:
        selector = (
            f'server_id="{server_id}",mountpoint="{_label(mountpoint)}",'
            'fstype!~"tmpfs|overlay|squashfs"'
        )
        total = _instant_value(
            prometheus_url,
            f"max(node_filesystem_size_bytes{{{selector}}})",
        )
        available = _instant_value(
            prometheus_url,
            f"max(node_filesystem_avail_bytes{{{selector}}})",
        )
        used = _difference(total, available)
        used_percent = _instant_value(
            prometheus_url, _disk_expression(server_id, mountpoint)
        )
        filesystems.append(
            {
                "mountpoint": mountpoint,
                "usedBytes": used,
                "totalBytes": total,
                "usedPercent": _rounded(used_percent),
            }
        )

    up = _instant_sample(prometheus_url, f'up{{server_id="{server_id}"}}')
    last_success_timestamp = _instant_value(
        prometheus_url,
        (
            "max_over_time(timestamp("
            f'up{{server_id="{server_id}"}} == 1)[30d:])'
        ),
    )
    if up is None:
        freshness: Freshness = {
            "observedAt": None,
            "ageSeconds": None,
            "state": "unavailable",
        }
        collector_success: bool | None = None
    else:
        _, up_value = up
        observed_at = (
            datetime.fromtimestamp(last_success_timestamp, UTC)
            if last_success_timestamp is not None
            else None
        )
        age = (
            max(0.0, (datetime.now(UTC) - observed_at).total_seconds())
            if observed_at is not None
            else None
        )
        freshness = {
            "observedAt": (
                observed_at.isoformat() if observed_at is not None else None
            ),
            "ageSeconds": round(age, 3) if age is not None else None,
            "state": (
                "unavailable"
                if age is None
                else "fresh"
                if age <= FRESH_AFTER_SECONDS
                else "stale"
            ),
        }
        collector_success = up_value == 1.0

    return {
        "cpu": {"usedPercent": _rounded(cpu)},
        "systemMemory": {
            "usedBytes": _rounded(memory_used),
            "totalBytes": _rounded(memory_total),
            "usedPercent": _percent(memory_used, memory_total),
        },
        "filesystems": filesystems,
        "freshness": freshness,
        "collector": {"success": collector_success},
    }


def query_metric_history(
    prometheus_url: str,
    *,
    server_id: str,
    metric: str,
    start: datetime,
    end: datetime,
    step: int,
    mountpoint: str = "/",
) -> dict[str, object]:
    if (
        metric not in HISTORY_METRICS
        or start.tzinfo is None
        or end.tzinfo is None
        or start >= end
        or end - start > MAX_HISTORY
        or end > datetime.now(UTC) + timedelta(minutes=1)
        or not 30 <= step <= 86_400
    ):
        raise InvalidHistoryQuery
    expressions = {
        "cpu": _cpu_expression(server_id),
        "system-memory": (
            "100 * (1 - node_memory_MemAvailable_bytes"
            f'{{server_id="{server_id}"}} / node_memory_MemTotal_bytes'
            f'{{server_id="{server_id}"}})'
        ),
        "disk": _disk_expression(server_id, mountpoint),
    }
    points = _range_values(
        prometheus_url,
        expressions[metric],
        start=start,
        end=end,
        step=step,
    )
    return {
        "metric": metric,
        "unit": "percent",
        "points": [
            {"observedAt": observed_at.isoformat(), "value": value}
            for observed_at, value in points
        ],
    }


def write_scrape_config(
    path: Path,
    targets: list[ObservationTarget],
    *,
    collector_ca_path: Path,
) -> None:
    jobs: list[dict[str, object]] = []
    for target in targets:
        address = urllib.parse.urlsplit(target.scrape_address)
        if address.hostname is None:
            continue
        host = address.hostname
        if ":" in host:
            host = f"[{host}]"
        jobs.append(
            {
                "job_name": f"server-{target.server_id}",
                "scheme": address.scheme,
                "metrics_path": address.path or "/metrics",
                "scrape_interval": f"{SCRAPE_INTERVAL_SECONDS}s",
                "scrape_timeout": "10s",
                "static_configs": [
                    {
                        "targets": [
                            f"{host}:{address.port or 443}"
                        ],
                        "labels": {"server_id": target.server_id},
                    }
                ],
                "tls_config": {
                    "ca_file": str(collector_ca_path),
                    "cert_file": target.scrape_client_certificate_path,
                    "key_file": target.scrape_client_key_path,
                },
            }
        )
    document = {
        "global": {
            "scrape_interval": f"{SCRAPE_INTERVAL_SECONDS}s",
            "evaluation_interval": f"{SCRAPE_INTERVAL_SECONDS}s",
        },
        "scrape_configs": jobs,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    data_path = path.parent / "prometheus-data"
    data_path.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(document, indent=2) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, delete=False
    ) as temporary:
        temporary.write(encoded)
        temporary_path = Path(temporary.name)
    os.chmod(temporary_path, 0o600)
    temporary_path.replace(path)


def sync_prometheus_config(database_path: Path) -> None:
    write_scrape_config(
        database_path.parent / "prometheus.yml",
        list_active_observation_targets(database_path),
        collector_ca_path=database_path.parent / "pki" / "collector-ca.crt",
    )


def reconcile_prometheus(database_path: Path, prometheus_url: str) -> None:
    sync_prometheus_config(database_path)
    reload_prometheus(prometheus_url)


def unavailable_resource_usage(
    mountpoints: tuple[str, ...],
) -> ResourceUsage:
    return {
        "cpu": {"usedPercent": None},
        "systemMemory": {
            "usedBytes": None,
            "totalBytes": None,
            "usedPercent": None,
        },
        "filesystems": [
            {
                "mountpoint": mountpoint,
                "usedBytes": None,
                "totalBytes": None,
                "usedPercent": None,
            }
            for mountpoint in mountpoints
        ],
        "freshness": {
            "observedAt": None,
            "ageSeconds": None,
            "state": "unavailable",
        },
        "collector": {"success": None},
    }


def reload_prometheus(prometheus_url: str) -> None:
    request = urllib.request.Request(
        prometheus_url.rstrip("/") + "/-/reload", data=b"", method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            if response.status >= 300:
                raise PrometheusUnavailable
    except (OSError, urllib.error.URLError) as error:
        raise PrometheusUnavailable from error


def _instant_value(url: str, expression: str) -> float | None:
    sample = _instant_sample(url, expression)
    return None if sample is None else sample[1]


def _instant_sample(
    url: str, expression: str
) -> tuple[datetime, float | None] | None:
    result = _api(
        url, "/api/v1/query", {"query": expression}
    )
    series = cast(list[dict[str, object]], result.get("result", []))
    if not series:
        return None
    value = cast(list[object], series[0]["value"])
    return _sample(value)


def _range_values(
    url: str,
    expression: str,
    *,
    start: datetime,
    end: datetime,
    step: int,
) -> list[tuple[datetime, float | None]]:
    result = _api(
        url,
        "/api/v1/query_range",
        {
            "query": expression,
            "start": start.isoformat(),
            "end": end.isoformat(),
            "step": str(step),
        },
    )
    series = cast(list[dict[str, object]], result.get("result", []))
    if not series:
        return []
    values = cast(list[list[object]], series[0].get("values", []))
    return [_sample(value) for value in values]


def _api(
    url: str, path: str, parameters: dict[str, str]
) -> dict[str, object]:
    endpoint = (
        url.rstrip("/")
        + path
        + "?"
        + urllib.parse.urlencode(parameters)
    )
    try:
        with urllib.request.urlopen(endpoint, timeout=3) as response:
            document = json.load(response)
    except (
        OSError,
        UnicodeError,
        ValueError,
        urllib.error.URLError,
    ) as error:
        raise PrometheusUnavailable from error
    if (
        not isinstance(document, dict)
        or document.get("status") != "success"
        or not isinstance(document.get("data"), dict)
    ):
        raise PrometheusUnavailable
    return cast(dict[str, object], document["data"])


def _sample(value: list[object]) -> tuple[datetime, float | None]:
    try:
        timestamp = value[0]
        sample_value = value[1]
        if not isinstance(timestamp, (int, float, str)) or not isinstance(
            sample_value, (int, float, str)
        ):
            raise PrometheusUnavailable
        observed_at = datetime.fromtimestamp(float(timestamp), UTC)
        number = float(sample_value)
    except (IndexError, ValueError) as error:
        raise PrometheusUnavailable from error
    return observed_at, number if math.isfinite(number) else None


def _difference(
    total: float | None, available: float | None
) -> float | None:
    if total is None or available is None:
        return None
    return max(0.0, total - available)


def _percent(value: float | None, total: float | None) -> float | None:
    if value is None or total is None or total <= 0:
        return None
    return round(100 * value / total, 3)


def _rounded(value: float | None) -> float | None:
    return None if value is None else round(value, 3)


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _cpu_expression(server_id: str) -> str:
    return (
        "100 * (1 - sum(rate(node_cpu_seconds_total"
        f'{{server_id="{server_id}",mode="idle"}}[2m])) / '
        "sum(rate(node_cpu_seconds_total"
        f'{{server_id="{server_id}"}}[2m])))'
    )


def _disk_expression(server_id: str, mountpoint: str) -> str:
    selector = (
        f'server_id="{server_id}",mountpoint="{_label(mountpoint)}",'
        'fstype!~"tmpfs|overlay|squashfs"'
    )
    return (
        "100 * max(1 - node_filesystem_avail_bytes"
        f"{{{selector}}} / node_filesystem_size_bytes{{{selector}}})"
    )
