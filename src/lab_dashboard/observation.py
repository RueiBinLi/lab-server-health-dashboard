from __future__ import annotations

import re
import ssl
import threading
import urllib.error
import urllib.request
from pathlib import Path

from lab_dashboard.database import (
    ObservationTarget,
    list_active_observation_targets,
    record_observation_run,
)
from lab_dashboard.prometheus import (
    PrometheusUnavailable,
    reconcile_prometheus,
)


MAX_METRICS_BYTES = 4 * 1024 * 1024
METRIC_NAME = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)")
MOUNTPOINT_LABEL = re.compile(r'mountpoint="([^"]+)"')
SYSTEMD_NAME_LABEL = re.compile(r'name="([^"]+)"')
OBSERVATION_METRICS = {
    "cpu": ({"node_cpu_seconds_total"},),
    "memory": ({"node_memory_MemTotal_bytes"},),
    "root-filesystem": ({"node_filesystem_size_bytes"},),
    "temperature-headroom": (
        {"node_hwmon_temp_celsius", "node_thermal_zone_temp"},
    ),
    "critical-errors": ({"lab_critical_errors_total"},),
    "gpu-utilization": ({"lab_gpu_utilization_ratio"},),
    "gpu-vram": (
        {"lab_gpu_vram_used_bytes"},
        {"lab_gpu_vram_total_bytes"},
    ),
    "gpu-temperature": ({"lab_gpu_temperature_celsius"},),
    "gpu-faults": ({"lab_gpu_faults_total"},),
}


class TelemetryUnavailable(Exception):
    pass


class ObservationEngine:
    def __init__(self, database_path: Path, prometheus_url: str) -> None:
        self._database_path = database_path
        self._prometheus_url = prometheus_url
        self._wake = threading.Event()
        self._stopping = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="normal-observation",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def wake(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stopping.set()
        self._wake.set()
        if self._thread.is_alive():
            self._thread.join(timeout=10)

    def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                reconcile_prometheus(
                    self._database_path, self._prometheus_url
                )
            except PrometheusUnavailable:
                pass
            self._observe_active_targets()
            self._wake.wait(timeout=30)
            self._wake.clear()

    def _observe_active_targets(self) -> None:
        collector_ca_path = (
            self._database_path.parent / "pki" / "collector-ca.crt"
        )
        for target in list_active_observation_targets(
            self._database_path
        ):
            try:
                scrape_telemetry(
                    target,
                    collector_ca_path=collector_ca_path,
                )
            except TelemetryUnavailable:
                result = "failed"
            else:
                result = "succeeded"
            record_observation_run(
                self._database_path,
                server_id=target.server_id,
                result=result,
            )


def scrape_telemetry(
    target: ObservationTarget,
    *,
    collector_ca_path: Path,
) -> set[str]:
    context = ssl.create_default_context(cafile=str(collector_ca_path))
    context.load_cert_chain(
        certfile=target.scrape_client_certificate_path,
        keyfile=target.scrape_client_key_path,
    )
    request = urllib.request.Request(
        target.scrape_address,
        headers={"Accept": "text/plain"},
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )
    try:
        with opener.open(request, timeout=2) as response:
            document = response.read(MAX_METRICS_BYTES + 1)
    except (OSError, urllib.error.URLError) as error:
        raise TelemetryUnavailable from error
    if len(document) > MAX_METRICS_BYTES:
        raise TelemetryUnavailable
    try:
        metrics_document = document.decode()
    except UnicodeError as error:
        raise TelemetryUnavailable from error
    observations = {"reachability"}
    metric_names = _metric_names(metrics_document)
    for observation, required_metric_groups in OBSERVATION_METRICS.items():
        if all(
            bool(metric_names & alternatives)
            for alternatives in required_metric_groups
        ):
            observations.add(observation)
    for line in metrics_document.splitlines():
        if line.startswith("node_filesystem_size_bytes{"):
            mountpoint = MOUNTPOINT_LABEL.search(line)
            if mountpoint is not None:
                observations.add(
                    f"persistent-mount:{mountpoint.group(1)}"
                )
        if (
            line.startswith("node_systemd_unit_state{")
            and 'state="active"' in line
            and line.rsplit(maxsplit=1)[-1] == "1"
        ):
            service = SYSTEMD_NAME_LABEL.search(line)
            if service is not None:
                observations.add(
                    f"required-service:{service.group(1)}"
                )
    return observations


def _metric_names(document: str) -> set[str]:
    names: set[str] = set()
    for line in document.splitlines():
        if not line or line.startswith("#"):
            continue
        match = METRIC_NAME.match(line)
        if match is not None:
            names.add(match.group(1))
    return names
