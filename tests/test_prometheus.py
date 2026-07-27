from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest.mock import patch

from lab_dashboard.database import ObservationTarget
from lab_dashboard.prometheus import (
    current_health_observation,
    current_resource_usage,
    query_metric_history,
    reconcile_prometheus,
    write_scrape_config,
)


class PrometheusIngestionTests(unittest.TestCase):
    def test_captured_dcgm_contracts_keep_stable_identity_and_optional_gaps(
        self,
    ) -> None:
        fixtures = Path(__file__).parent / "fixtures" / "dcgm"
        single = (fixtures / "single_gpu.prom").read_text()
        multiple = (fixtures / "multi_gpu_optional_fields.prom").read_text()

        for contract in (single, multiple):
            self.assertIn("DCGM_FI_DEV_GPU_UTIL", contract)
            self.assertIn("DCGM_FI_DEV_FB_USED", contract)
            self.assertIn("DCGM_FI_DEV_FB_FREE", contract)
            self.assertIn('gpu_uuid="GPU-', contract)
            self.assertIn("pci_bus_id=", contract)
        self.assertNotIn("DCGM_FI_DEV_FB_RESERVED{", multiple)
        self.assertNotIn("DCGM_FI_DEV_SLOWDOWN_TEMP{", multiple)

    def test_health_observation_preserves_required_values_and_disk_forecast(
        self,
    ) -> None:
        observed_at = datetime(2026, 7, 27, tzinfo=UTC)
        with patch(
            "lab_dashboard.prometheus._instant_sample",
            side_effect=[
                (observed_at, 1.0),
                (observed_at, 96.0),
                (observed_at, 8.0),
                (observed_at, 12.8),
                (observed_at, 9.0),
                (observed_at, 19 * 1024**3),
                (observed_at, 9.0),
                (observed_at, 1.0),
                (observed_at, 1.0),
                (observed_at, 0.0),
                (observed_at, 10.0),
                (observed_at, 1.0),
                (observed_at, 0.0),
                (observed_at, 0.0),
                (observed_at, 0.0),
                (observed_at, 0.0),
                (observed_at, 0.0),
                (observed_at, 1.0),
                (observed_at, 1.0),
                (observed_at, 1.0),
                (observed_at, 1.0),
                (observed_at, 1.0),
                (observed_at, 1.0),
            ],
        ):
            observation = current_health_observation(
                "http://127.0.0.1:9090",
                "server-1",
                ("/",),
                required_observations=(
                    "reachability",
                    "cpu",
                    "memory",
                    "root-filesystem",
                    "temperature-headroom",
                    "critical-errors",
                ),
                required_services=("sshd.service",),
            )

        self.assertEqual(observation["primaryTelemetrySuccessful"], True)
        self.assertEqual(observation["cpuUsedPercent"], 96.0)
        self.assertEqual(observation["normalizedLoad5"], 1.6)
        self.assertEqual(observation["memoryAvailablePercent"], 9.0)
        self.assertEqual(
            observation["filesystems"],
            [
                {
                    "mountpoint": "/",
                    "freePercent": 9.0,
                    "freeBytes": float(19 * 1024**3),
                    "exhaustionWithin24Hours": True,
                }
            ],
        )
        self.assertEqual(observation["requiredObservationsComplete"], True)

    def test_missing_health_series_are_incomplete_instead_of_zero(
        self,
    ) -> None:
        observed_at = datetime(2026, 7, 27, tzinfo=UTC)
        with patch(
            "lab_dashboard.prometheus._instant_sample",
            side_effect=[
                (observed_at, 1.0),
                (observed_at, 25.0),
                (observed_at, 8.0),
                (observed_at, 4.0),
                (observed_at, 50.0),
                None,
                None,
                None,
            ],
        ):
            observation = current_health_observation(
                "http://127.0.0.1:9090", "server-1", ("/",)
            )

        self.assertEqual(observation["requiredObservationsComplete"], False)
        filesystem = observation["filesystems"][0]
        self.assertIsNone(filesystem["freePercent"])
        self.assertIsNone(filesystem["freeBytes"])
        self.assertIsNone(filesystem["exhaustionWithin24Hours"])

    def test_missing_profile_required_series_makes_observation_incomplete(
        self,
    ) -> None:
        observed_at = datetime(2026, 7, 27, tzinfo=UTC)
        with patch(
            "lab_dashboard.prometheus._instant_sample",
            side_effect=[
                (observed_at, 1.0),
                (observed_at, 25.0),
                (observed_at, 8.0),
                (observed_at, 4.0),
                (observed_at, 50.0),
                (observed_at, 750 * 1024**3),
                (observed_at, 75.0),
                (observed_at, 0.0),
                None,
            ],
        ):
            observation = current_health_observation(
                "http://127.0.0.1:9090",
                "server-1",
                ("/",),
                required_observations=("temperature-headroom",),
            )

        self.assertEqual(observation["requiredObservationsComplete"], False)

    def test_gpu_profile_validates_runtime_emission_of_custom_fields(
        self,
    ) -> None:
        observed_at = datetime(2026, 7, 27, tzinfo=UTC)
        complete_sample = (observed_at, 1.0)
        with (
            patch(
                "lab_dashboard.prometheus._instant_label_values",
                return_value=["GPU-5ee4"],
            ),
            patch(
                "lab_dashboard.prometheus._instant_sample",
                side_effect=[
                    complete_sample,
                    (observed_at, 25.0),
                    (observed_at, 8.0),
                    (observed_at, 4.0),
                    (observed_at, 50.0),
                    (observed_at, 750 * 1024**3),
                    (observed_at, 75.0),
                    (observed_at, 0.0),
                    (observed_at, 70.0),
                    (observed_at, 85.0),
                    (observed_at, 0.0),
                    None,
                    (observed_at, 0.0),
                    (observed_at, 0.0),
                    (observed_at, 0.0),
                ],
            ) as query,
        ):
            observation = current_health_observation(
                "http://127.0.0.1:9090",
                "server-1",
                ("/",),
                expected_gpu_count=1,
            )

        self.assertEqual(observation["requiredObservationsComplete"], False)
        self.assertIsNone(observation["gpus"][0]["xidEvent"])
        self.assertTrue(
            any(
                'xid=~"31|32|43|45|48|63|64|74|79|92|94|95"'
                in call.args[1]
                for call in query.call_args_list
            )
        )

    def test_generated_jobs_preserve_per_server_mtls_and_thirty_second_scrape(
        self,
    ) -> None:
        target = ObservationTarget(
            server_id="server-1",
            scrape_address="https://10.40.0.8:9100/metrics",
            scrape_client_certificate_path="/state/server-1/client.crt",
            scrape_client_key_path="/state/server-1/client.key",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "prometheus.yml"
            write_scrape_config(
                path,
                [target],
                collector_ca_path=Path("/state/collector-ca.crt"),
            )
            document = json.loads(path.read_text())

        self.assertEqual(document["global"]["scrape_interval"], "30s")
        self.assertEqual(
            document["alerting"]["alertmanagers"][0]["static_configs"][0][
                "targets"
            ],
            ["127.0.0.1:19093"],
        )
        self.assertEqual(
            document["rule_files"],
            ["/var/lib/lab-dashboard/critical-alerts.yml"],
        )
        self.assertEqual(
            document["scrape_configs"][0]["static_configs"][0]["targets"],
            ["127.0.0.1:3000"],
        )
        job = document["scrape_configs"][1]
        self.assertEqual(job["static_configs"][0]["targets"], ["10.40.0.8:9100"])
        self.assertEqual(
            job["static_configs"][0]["labels"], {"server_id": "server-1"}
        )
        self.assertEqual(
            job["tls_config"],
            {
                "ca_file": "/state/collector-ca.crt",
                "cert_file": "/state/server-1/client.crt",
                "key_file": "/state/server-1/client.key",
            },
        )

    def test_missing_optional_series_remain_missing_in_resource_usage(
        self,
    ) -> None:
        observed_at = datetime(2026, 7, 27, tzinfo=UTC)
        with patch(
            "lab_dashboard.prometheus._instant_sample",
            side_effect=[
                None,
                (observed_at, 16_000.0),
                None,
                (observed_at, 1_000.0),
                None,
                None,
                None,
                None,
            ],
        ):
            usage = current_resource_usage(
                "http://127.0.0.1:9090", "server-1", ("/",)
            )

        cpu = usage["cpu"]
        memory = usage["systemMemory"]
        filesystems = usage["filesystems"]
        freshness = usage["freshness"]
        collector = usage["collector"]
        self.assertIsNone(cpu["usedPercent"])
        self.assertIsNone(memory["usedBytes"])
        self.assertIsNone(memory["usedPercent"])
        filesystem = filesystems[0]
        self.assertIsNone(filesystem["usedBytes"])
        self.assertIsNone(filesystem["usedPercent"])
        self.assertEqual(freshness["state"], "unavailable")
        self.assertIsNone(collector["success"])

    def test_failed_scrape_uses_last_success_for_observation_freshness(
        self,
    ) -> None:
        now = datetime.now(UTC)
        last_success = now.timestamp() - 120
        with patch(
            "lab_dashboard.prometheus._instant_sample",
            side_effect=[
                None,
                None,
                None,
                None,
                None,
                None,
                (now, 0.0),
                (now, last_success),
            ],
        ):
            usage = current_resource_usage(
                "http://127.0.0.1:9090", "server-1", ("/",)
            )

        freshness = usage["freshness"]
        collector = usage["collector"]
        self.assertEqual(collector["success"], False)
        self.assertEqual(freshness["state"], "stale")
        self.assertGreaterEqual(cast(float, freshness["ageSeconds"]), 119)

    def test_gpu_resource_usage_aggregates_devices_and_marks_low_headroom(
        self,
    ) -> None:
        observed_at = datetime.now(UTC)
        with patch(
            "lab_dashboard.prometheus._instant_sample",
            side_effect=[
                None,
                None,
                None,
                None,
                None,
                None,
                (observed_at, 1.0),
                (observed_at, observed_at.timestamp()),
                (observed_at, 80.0),
                (observed_at, 31_000.0),
                (observed_at, 1_000.0),
                (observed_at, 200.0),
                (observed_at, 78.0),
                (observed_at, 83.0),
            ],
        ):
            usage = current_resource_usage(
                "http://127.0.0.1:9090",
                "server-1",
                ("/",),
                include_gpu=True,
            )

        self.assertEqual(
            usage["gpu"],
            {
                "utilizationPercent": 80.0,
                "vramUsedBytes": 31_000.0,
                "vramFreeBytes": 1_000.0,
                "vramReservedBytes": 200.0,
                "vramTotalBytes": 32_200.0,
                "vramUsedPercent": 96.273,
                "lowVramHeadroom": True,
                "temperatureCelsius": 78.0,
                "slowdownLimitCelsius": 83.0,
            },
        )

    def test_gpu_history_uses_fixed_aggregate_contract(self) -> None:
        start = datetime(2026, 7, 26, tzinfo=UTC)
        end = datetime(2026, 7, 27, tzinfo=UTC)
        with patch(
            "lab_dashboard.prometheus._range_values",
            return_value=[(start, 75.0)],
        ) as query:
            history = query_metric_history(
                "http://127.0.0.1:9090",
                server_id="server-1",
                metric="gpu-vram",
                start=start,
                end=end,
                step=3600,
            )

        self.assertEqual(history["metric"], "gpu-vram")
        self.assertEqual(history["points"][0]["value"], 75.0)
        self.assertIn("DCGM_FI_DEV_FB_USED", query.call_args.args[1])

    def test_reconciliation_retries_reload_even_when_config_is_unchanged(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "dashboard.sqlite3"
            with patch(
                "lab_dashboard.prometheus.list_active_observation_targets",
                return_value=[],
            ), patch(
                "lab_dashboard.prometheus.reload_prometheus",
            ) as reload:
                reconcile_prometheus(
                    database_path, "http://127.0.0.1:9090"
                )
                reconcile_prometheus(
                    database_path, "http://127.0.0.1:9090"
                )

        self.assertEqual(reload.call_count, 2)


if __name__ == "__main__":
    unittest.main()
