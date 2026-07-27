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
    current_resource_usage,
    reconcile_prometheus,
    write_scrape_config,
)


class PrometheusIngestionTests(unittest.TestCase):
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
        job = document["scrape_configs"][0]
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
