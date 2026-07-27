from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_http import (
    RunningDashboard,
    bootstrap_request,
    create_csr,
    identity_headers,
)


ADMINISTRATOR = identity_headers("ada@example.com", "lab-administrator")
LAB_USER = identity_headers("lin@example.com", "lab-user")


def activate_server(dashboard: RunningDashboard, directory: Path) -> str:
    _, registered = dashboard.post(
        "/api/servers",
        {
            "displayName": "Compute 1",
            "scrapeAddress": "https://192.168.10.8:9100/metrics",
            "profileId": "general-linux",
            "reason": "Add shared compute capacity",
        },
        ADMINISTRATOR,
    )
    server_id = str(registered["server"]["serverId"])
    csr = create_csr(directory, server_id)
    _, issued = dashboard.post(
        f"/api/servers/{server_id}/bootstrap-tokens",
        {"reason": "Install the collector"},
        ADMINISTRATOR,
    )
    _, contacted = dashboard.post(
        "/api/enrollment/bootstrap",
        bootstrap_request(
            server_id=server_id,
            token=str(issued["bootstrapToken"]),
            csr=csr,
        ),
    )
    with patch(
        "lab_dashboard.app.scrape_telemetry",
        return_value={
            "reachability",
            "cpu",
            "memory",
            "root-filesystem",
            "temperature-headroom",
            "critical-errors",
            "persistent-mount:/",
        },
    ):
        dashboard.post(
            f"/api/servers/{server_id}/staged-telemetry-checks",
            {},
            ADMINISTRATOR,
        )
    approved = dashboard.post(
        f"/api/servers/{server_id}/enrollment-decisions",
        {
            "decision": "approve",
            "verificationCode": contacted["verificationCode"],
            "reason": "Collector identity and observations match",
        },
        ADMINISTRATOR,
    )
    assert approved[0] == 200
    return server_id


class ResourceUsageHttpTests(unittest.TestCase):
    def test_fleet_and_selected_server_show_safe_current_resource_usage(
        self,
    ) -> None:
        snapshot = {
            "cpu": {"usedPercent": 25.0},
            "systemMemory": {
                "usedBytes": 6_442_450_944,
                "totalBytes": 17_179_869_184,
                "usedPercent": 37.5,
            },
            "filesystems": [
                {
                    "mountpoint": "/",
                    "usedBytes": 274_877_906_944,
                    "totalBytes": 1_099_511_627_776,
                    "usedPercent": 25.0,
                }
            ],
            "freshness": {
                "observedAt": "2026-07-27T10:00:00+00:00",
                "ageSeconds": 12.0,
                "state": "fresh",
            },
            "collector": {"success": True},
        }
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                server_id = activate_server(dashboard, Path(temporary))
                with patch(
                    "lab_dashboard.app.current_resource_usage",
                    return_value=snapshot,
                ):
                    administrator = dashboard.get("/api/fleet", ADMINISTRATOR)
                    lab_user = dashboard.get("/api/fleet", LAB_USER)
                    selected = dashboard.get(
                        f"/api/servers/{server_id}", LAB_USER
                    )
                    user_page = dashboard.get_text("/", LAB_USER)
                    workspace = dashboard.get_text(
                        f"/servers/{server_id}", LAB_USER
                    )

        administrator_server = administrator[1]["fleet"][0]
        user_server = lab_user[1]["fleet"][0]
        self.assertEqual(administrator_server["resourceUsage"], snapshot)
        safe_snapshot = {
            key: value for key, value in snapshot.items() if key != "collector"
        }
        self.assertEqual(user_server["resourceUsage"], safe_snapshot)
        self.assertEqual(
            selected[1]["server"]["resourceUsage"], safe_snapshot
        )
        self.assertIn("scrapeAddress", administrator_server)
        self.assertNotIn("scrapeAddress", user_server)
        self.assertNotIn("inventory", user_server)
        self.assertNotIn("observationTargetSet", user_server)
        self.assertEqual(user_page[0], 200)
        self.assertIn("Resource Usage", user_page[1])
        self.assertIn("25.0%", user_page[1])
        self.assertIn("6.0 GiB / 16.0 GiB", user_page[1])
        self.assertNotIn("Metric History", user_page[1])
        self.assertIn(f'href="/servers/{server_id}"', user_page[1])
        self.assertNotIn("192.168.10.8", user_page[1])
        self.assertNotIn("Verified Server Inventory", user_page[1])
        self.assertEqual(workspace[0], 200)
        self.assertIn("Selected-server workspace", workspace[1])
        self.assertIn('type="datetime-local"', workspace[1])
        self.assertIn('name="mountpoint"', workspace[1])
        self.assertIn("<table", workspace[1])

    def test_metric_history_is_fixed_scope_and_preserves_missing_series(
        self,
    ) -> None:
        history = {
            "metric": "cpu",
            "unit": "percent",
            "points": [
                {"observedAt": "2026-07-26T10:00:00+00:00", "value": 12.5},
                {"observedAt": "2026-07-27T10:00:00+00:00", "value": None},
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                server_id = activate_server(dashboard, Path(temporary))
                with patch(
                    "lab_dashboard.app.query_metric_history",
                    return_value=history,
                ) as query:
                    response = dashboard.get(
                        (
                            f"/api/servers/{server_id}/metric-history"
                            "?metric=cpu&start=2026-07-26T10%3A00%3A00%2B00%3A00"
                            "&end=2026-07-27T10%3A00%3A00%2B00%3A00&step=3600"
                        ),
                        LAB_USER,
                    )
                    unrestricted = dashboard.get(
                        (
                            f"/api/servers/{server_id}/metric-history"
                            "?metric=up%7Bjob%3D%22prometheus%22%7D"
                        ),
                        LAB_USER,
                    )

        self.assertEqual(response, (200, history))
        self.assertEqual(unrestricted, (400, {"error": "invalid_history_query"}))
        query.assert_called_once()
        self.assertIsNone(response[1]["points"][1]["value"])
        self.assertEqual(
            {
                (
                    point["profileId"],
                    point["profileRevision"],
                )
                for point in response[1]["points"]
            },
            {("general-linux", 1)},
        )


if __name__ == "__main__":
    unittest.main()
