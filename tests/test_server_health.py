from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from test_http import RunningDashboard
from test_resource_usage import ADMINISTRATOR, LAB_USER, activate_server
from lab_dashboard.prometheus import PrometheusUnavailable


GIBIBYTE = 1024**3


def complete_observation() -> dict[str, object]:
    return {
        "primaryTelemetrySuccessful": True,
        "requiredObservationsComplete": True,
        "cpuUsedPercent": 25.0,
        "normalizedLoad5": 0.5,
        "memoryAvailablePercent": 50.0,
        "filesystems": [
            {
                "mountpoint": "/",
                "freePercent": 75.0,
                "freeBytes": 750 * GIBIBYTE,
                "exhaustionWithin24Hours": False,
            }
        ],
    }


def complete_gpu_observation() -> dict[str, object]:
    observation = complete_observation()
    observation["gpus"] = [
        {
            "gpuUuid": "GPU-5ee4",
            "headroomCelsius": 20.0,
            "thermalThrottling": False,
            "xidEvent": False,
            "resetEvent": False,
            "volatileUncorrectableEccEvent": False,
            "aggregateUncorrectableEcc": 0.0,
        }
    ]
    return observation


class ServerHealthHttpTests(unittest.TestCase):
    def _run_health_requests(
        self,
        dashboard: RunningDashboard,
        observation: dict[str, object],
        now: list[datetime],
    ) -> tuple[str, dict[str, Any]]:
        with (
            patch(
                "lab_dashboard.app.current_health_observation",
                return_value=observation,
            ),
            patch(
                "lab_dashboard.app.health_now",
                side_effect=lambda: now[0],
            ),
            patch(
                "lab_dashboard.app.current_resource_usage",
                return_value={
                    "cpu": {"usedPercent": observation["cpuUsedPercent"]},
                    "systemMemory": {
                        "usedBytes": None,
                        "totalBytes": None,
                        "usedPercent": None,
                    },
                    "filesystems": [],
                    "freshness": {
                        "observedAt": now[0].isoformat(),
                        "ageSeconds": 0.0,
                        "state": "fresh",
                    },
                    "collector": {"success": True},
                },
            ),
        ):
            response = dashboard.get("/api/fleet", ADMINISTRATOR)
        return (
            response[1]["fleet"][0]["serverHealth"]["state"],
            response[1]["fleet"][0],
        )

    def test_primary_telemetry_loss_opens_one_unavailable_incident_and_recovers(
        self,
    ) -> None:
        now = datetime(2026, 7, 27, 1, 0, tzinfo=UTC)
        observation = complete_observation()

        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                server_id = activate_server(dashboard, Path(temporary))
                with (
                    patch(
                        "lab_dashboard.app.current_health_observation",
                        return_value=observation,
                        create=True,
                    ),
                    patch(
                        "lab_dashboard.app.health_now",
                        side_effect=lambda: now,
                        create=True,
                    ),
                    patch(
                        "lab_dashboard.app.current_resource_usage",
                        return_value={
                            "cpu": {"usedPercent": 25.0},
                            "systemMemory": {
                                "usedBytes": 8 * GIBIBYTE,
                                "totalBytes": 16 * GIBIBYTE,
                                "usedPercent": 50.0,
                            },
                            "filesystems": [
                                {
                                    "mountpoint": "/",
                                    "usedBytes": 250 * GIBIBYTE,
                                    "totalBytes": 1000 * GIBIBYTE,
                                    "usedPercent": 25.0,
                                }
                            ],
                            "freshness": {
                                "observedAt": now.isoformat(),
                                "ageSeconds": 0.0,
                                "state": "fresh",
                            },
                            "collector": {"success": True},
                        },
                    ),
                ):
                    healthy = dashboard.get("/api/fleet", LAB_USER)
                    observation["primaryTelemetrySuccessful"] = False
                    pending = dashboard.get("/api/fleet", LAB_USER)
                    now += timedelta(minutes=2)
                    unavailable = dashboard.get("/api/fleet", ADMINISTRATOR)
                    unavailable_page = dashboard.get_text("/", LAB_USER)
                    administrator_workspace = dashboard.get_text(
                        f"/servers/{server_id}", ADMINISTRATOR
                    )
                    observation["primaryTelemetrySuccessful"] = True
                    clearing = dashboard.get("/api/fleet", ADMINISTRATOR)
                    now += timedelta(minutes=1)
                    recovered = dashboard.get("/api/fleet", ADMINISTRATOR)

        self.assertEqual(
            healthy[1]["fleet"][0]["serverHealth"]["state"], "Healthy"
        )
        self.assertEqual(
            pending[1]["fleet"][0]["serverHealth"]["state"], "Healthy"
        )
        active = unavailable[1]["fleet"][0]
        self.assertEqual(active["serverHealth"]["state"], "Unavailable")
        self.assertEqual(
            active["activeHealthCauses"],
            [
                {
                    "rule": "primary-telemetry",
                    "severity": "Unavailable",
                    "summary": "Primary telemetry is unavailable.",
                }
            ],
        )
        self.assertEqual(len(active["serverIncidents"]), 1)
        self.assertIn("Server Health", unavailable_page[1])
        self.assertIn("Unavailable", unavailable_page[1])
        self.assertIn(
            "Lab Administrator attention is required", unavailable_page[1]
        )
        self.assertNotIn("Primary telemetry", unavailable_page[1])
        self.assertIn("Active health-rule causes", administrator_workspace[1])
        self.assertIn("Primary telemetry is unavailable", administrator_workspace[1])
        self.assertIn("Server Incident timeline", administrator_workspace[1])
        incident = active["serverIncidents"][0]
        self.assertIsNone(incident["closedAt"])
        self.assertEqual(incident["currentSeverity"], "Unavailable")
        self.assertEqual(
            clearing[1]["fleet"][0]["serverHealth"]["state"], "Unavailable"
        )
        final = recovered[1]["fleet"][0]
        self.assertEqual(final["serverHealth"]["state"], "Healthy")
        self.assertEqual(final["activeHealthCauses"], [])
        self.assertEqual(len(final["serverIncidents"]), 1)
        self.assertEqual(
            final["serverIncidents"][0]["closedAt"], now.isoformat()
        )
        self.assertEqual(
            final["serverIncidents"][0]["transitions"],
            [
                {
                    "occurredAt": (
                        datetime(2026, 7, 27, 1, 2, tzinfo=UTC).isoformat()
                    ),
                    "severity": "Unavailable",
                    "causes": ["primary-telemetry"],
                },
                {
                    "occurredAt": now.isoformat(),
                    "severity": "Healthy",
                    "causes": [],
                },
            ],
        )
        self.assertNotIn("activeHealthCauses", healthy[1]["fleet"][0])
        self.assertNotIn("serverIncidents", healthy[1]["fleet"][0])

    def test_missing_observations_fire_and_clear_with_continuous_holds(
        self,
    ) -> None:
        now = [datetime(2026, 7, 27, 2, 0, tzinfo=UTC)]
        observation = complete_observation()
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                activate_server(dashboard, Path(temporary))
                self._run_health_requests(dashboard, observation, now)
                observation["requiredObservationsComplete"] = False
                pending = self._run_health_requests(
                    dashboard, observation, now
                )
                now[0] += timedelta(minutes=9, seconds=59)
                nearly = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["requiredObservationsComplete"] = True
                interrupted = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["requiredObservationsComplete"] = False
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=10)
                degraded = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["requiredObservationsComplete"] = True
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=5)
                recovered = self._run_health_requests(
                    dashboard, observation, now
                )

        self.assertEqual(pending[0], "Healthy")
        self.assertEqual(nearly[0], "Healthy")
        self.assertEqual(interrupted[0], "Healthy")
        self.assertEqual(degraded[0], "Degraded")
        self.assertEqual(
            degraded[1]["activeHealthCauses"][0]["rule"],
            "required-observations",
        )
        self.assertEqual(recovered[0], "Healthy")

    def test_gpu_events_use_discrete_and_persistent_lifecycles(self) -> None:
        now = [datetime(2026, 7, 27, 2, 20, tzinfo=UTC)]
        observation = complete_gpu_observation()
        gpu = cast(list[dict[str, object]], observation["gpus"])[0]
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                activate_server(dashboard, Path(temporary))
                self._run_health_requests(dashboard, observation, now)
                gpu["xidEvent"] = True
                xid = self._run_health_requests(dashboard, observation, now)
                gpu["xidEvent"] = False
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=5)
                xid_cleared = self._run_health_requests(
                    dashboard, observation, now
                )
                gpu["aggregateUncorrectableEcc"] = 1.0
                aggregate = self._run_health_requests(
                    dashboard, observation, now
                )
                gpu["aggregateUncorrectableEcc"] = 0.0
                now[0] += timedelta(hours=1)
                aggregate_persists = self._run_health_requests(
                    dashboard, observation, now
                )

        self.assertEqual(xid[0], "Degraded")
        self.assertEqual(
            xid[1]["activeHealthCauses"][0]["rule"],
            "gpu-xid:GPU-5ee4",
        )
        self.assertEqual(xid_cleared[0], "Healthy")
        self.assertEqual(aggregate[0], "Degraded")
        self.assertEqual(aggregate_persists[0], "Degraded")
        self.assertEqual(
            aggregate_persists[1]["activeHealthCauses"][0]["rule"],
            "gpu-ecc-aggregate:GPU-5ee4",
        )

    def test_central_observation_loss_starts_primary_telemetry_timer(
        self,
    ) -> None:
        now = datetime(2026, 7, 27, 2, 30, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                activate_server(dashboard, Path(temporary))
                with (
                    patch(
                        "lab_dashboard.app.current_health_observation",
                        side_effect=PrometheusUnavailable,
                    ),
                    patch(
                        "lab_dashboard.app.health_now",
                        side_effect=lambda: now,
                    ),
                    patch(
                        "lab_dashboard.app.current_resource_usage",
                        side_effect=PrometheusUnavailable,
                    ),
                ):
                    pending = dashboard.get("/api/fleet", ADMINISTRATOR)
                    now += timedelta(minutes=2)
                    unavailable = dashboard.get(
                        "/api/fleet", ADMINISTRATOR
                    )

        self.assertEqual(
            pending[1]["fleet"][0]["serverHealth"]["state"], "Healthy"
        )
        self.assertEqual(
            unavailable[1]["fleet"][0]["serverHealth"]["state"],
            "Unavailable",
        )
        self.assertEqual(
            unavailable[1]["fleet"][0]["activeHealthCauses"][0]["rule"],
            "primary-telemetry",
        )

    def test_cpu_requires_both_signals_and_memory_uses_hysteresis(
        self,
    ) -> None:
        now = [datetime(2026, 7, 27, 3, 0, tzinfo=UTC)]
        observation = complete_observation()
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                activate_server(dashboard, Path(temporary))
                self._run_health_requests(dashboard, observation, now)
                observation["cpuUsedPercent"] = 98.0
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=10)
                activity_only = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["normalizedLoad5"] = 1.6
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=10)
                cpu_degraded = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["cpuUsedPercent"] = None
                observation["normalizedLoad5"] = None
                observation["requiredObservationsComplete"] = False
                now[0] += timedelta(minutes=1)
                reset_gap = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["cpuUsedPercent"] = 25.0
                observation["normalizedLoad5"] = 0.5
                observation["requiredObservationsComplete"] = True
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=5)
                cpu_recovered = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["cpuUsedPercent"] = 25.0
                observation["memoryAvailablePercent"] = 9.0
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=5)
                memory_degraded = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["memoryAvailablePercent"] = 12.0
                now[0] += timedelta(minutes=5)
                hysteresis_band = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["memoryAvailablePercent"] = 16.0
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=5)
                memory_recovered = self._run_health_requests(
                    dashboard, observation, now
                )

        self.assertEqual(activity_only[0], "Healthy")
        self.assertEqual(cpu_degraded[0], "Degraded")
        self.assertEqual(
            cpu_degraded[1]["activeHealthCauses"][0]["rule"],
            "cpu-pressure",
        )
        self.assertEqual(reset_gap[0], "Degraded")
        self.assertEqual(
            [cause["rule"] for cause in reset_gap[1]["activeHealthCauses"]],
            ["cpu-pressure"],
        )
        self.assertEqual(len(reset_gap[1]["serverIncidents"]), 1)
        self.assertEqual(cpu_recovered[0], "Healthy")
        self.assertEqual(memory_degraded[0], "Degraded")
        self.assertEqual(hysteresis_band[0], "Degraded")
        self.assertEqual(memory_recovered[0], "Healthy")

    def test_disk_capacity_and_exhaustion_forecast_have_distinct_causes(
        self,
    ) -> None:
        now = [datetime(2026, 7, 27, 4, 0, tzinfo=UTC)]
        observation = complete_observation()
        filesystems = observation["filesystems"]
        assert isinstance(filesystems, list)
        filesystem = filesystems[0]
        assert isinstance(filesystem, dict)
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                activate_server(dashboard, Path(temporary))
                self._run_health_requests(dashboard, observation, now)
                filesystem["freePercent"] = 9.0
                filesystem["freeBytes"] = 19 * GIBIBYTE
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=10)
                capacity = self._run_health_requests(
                    dashboard, observation, now
                )
                filesystem["freePercent"] = 16.0
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=10)
                capacity_recovered = self._run_health_requests(
                    dashboard, observation, now
                )
                filesystem["freeBytes"] = 100 * GIBIBYTE
                filesystem["exhaustionWithin24Hours"] = True
                forecast = self._run_health_requests(
                    dashboard, observation, now
                )
                filesystem["exhaustionWithin24Hours"] = False
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=10)
                forecast_recovered = self._run_health_requests(
                    dashboard, observation, now
                )
                data_filesystem = {
                    "mountpoint": "/data",
                    "freePercent": 9.0,
                    "freeBytes": 19 * GIBIBYTE,
                    "exhaustionWithin24Hours": False,
                }
                filesystems.append(data_filesystem)
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=10)
                removed_mount_active = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["filesystems"] = [filesystem]
                removed_mount_cleared = self._run_health_requests(
                    dashboard, observation, now
                )

        self.assertEqual(capacity[0], "Degraded")
        self.assertEqual(
            capacity[1]["activeHealthCauses"][0]["rule"],
            "disk-capacity:/",
        )
        self.assertEqual(capacity_recovered[0], "Healthy")
        self.assertEqual(forecast[0], "Degraded")
        self.assertEqual(
            forecast[1]["activeHealthCauses"][0]["rule"],
            "disk-exhaustion:/",
        )
        self.assertEqual(forecast_recovered[0], "Healthy")
        self.assertEqual(removed_mount_active[0], "Degraded")
        self.assertEqual(
            removed_mount_active[1]["activeHealthCauses"][0]["rule"],
            "disk-capacity:/data",
        )
        self.assertEqual(removed_mount_cleared[0], "Healthy")

    def test_overlapping_causes_and_severity_changes_stay_in_one_incident(
        self,
    ) -> None:
        now = [datetime(2026, 7, 27, 5, 0, tzinfo=UTC)]
        observation = complete_observation()
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                activate_server(dashboard, Path(temporary))
                self._run_health_requests(dashboard, observation, now)
                observation["memoryAvailablePercent"] = 9.0
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=5)
                degraded = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["primaryTelemetrySuccessful"] = False
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=2)
                unavailable = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["primaryTelemetrySuccessful"] = True
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=1)
                improved = self._run_health_requests(
                    dashboard, observation, now
                )
                observation["memoryAvailablePercent"] = 16.0
                self._run_health_requests(dashboard, observation, now)
                now[0] += timedelta(minutes=5)
                recovered = self._run_health_requests(
                    dashboard, observation, now
                )

        self.assertEqual(degraded[0], "Degraded")
        self.assertEqual(unavailable[0], "Unavailable")
        self.assertEqual(
            [cause["rule"] for cause in unavailable[1]["activeHealthCauses"]],
            ["primary-telemetry", "memory-pressure"],
        )
        self.assertEqual(improved[0], "Degraded")
        self.assertEqual(recovered[0], "Healthy")
        incidents = recovered[1]["serverIncidents"]
        self.assertEqual(len(incidents), 1)
        self.assertEqual(
            [transition["severity"] for transition in incidents[0]["transitions"]],
            ["Degraded", "Unavailable", "Degraded", "Healthy"],
        )

    def test_pending_health_state_and_server_incident_survive_restart(
        self,
    ) -> None:
        now = [datetime(2026, 7, 27, 6, 0, tzinfo=UTC)]
        observation = complete_observation()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            database_path = directory / "dashboard.sqlite3"
            with RunningDashboard(database_path=database_path) as dashboard:
                activate_server(dashboard, directory)
                self._run_health_requests(dashboard, observation, now)
                observation["primaryTelemetrySuccessful"] = False
                self._run_health_requests(dashboard, observation, now)

            now[0] += timedelta(minutes=2)
            with RunningDashboard(database_path=database_path) as restarted:
                unavailable = self._run_health_requests(
                    restarted, observation, now
                )

            with RunningDashboard(database_path=database_path) as restarted:
                persisted = self._run_health_requests(
                    restarted, observation, now
                )

        self.assertEqual(unavailable[0], "Unavailable")
        self.assertEqual(len(unavailable[1]["serverIncidents"]), 1)
        self.assertEqual(persisted[0], "Unavailable")
        self.assertEqual(
            persisted[1]["serverIncidents"],
            unavailable[1]["serverIncidents"],
        )


if __name__ == "__main__":
    unittest.main()
