from __future__ import annotations

import json
import sqlite3
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from lab_dashboard.health import (
    acknowledge_critical_error,
    evaluate_server_health,
    initialize_health_database,
    list_critical_error_acknowledgments,
)


HELPER = (
    Path(__file__).parent.parent
    / "deploy"
    / "collector"
    / "lab-critical-errors-helper"
)


def observation(*, persistent: bool = False, event: bool = False) -> dict[str, object]:
    return {
        "primaryTelemetrySuccessful": True,
        "requiredObservationsComplete": True,
        "cpuUsedPercent": 20.0,
        "normalizedLoad5": 0.2,
        "memoryAvailablePercent": 60.0,
        "filesystems": [],
        "criticalErrors": {
            "oomKillEvent": event,
            "readOnlyFilesystems": ["/srv"] if persistent else [],
            "storageIoErrorCount": 0.0,
            "previousPanicCount": 0.0,
            "watchdogResetCount": 0.0,
            "helperFresh": True,
            "evidenceAvailable": True,
            "textfileScrapeSuccessful": True,
        },
    }


def initialize(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE servers (server_id TEXT PRIMARY KEY, profile_id TEXT, profile_revision INTEGER)"
        )
        connection.execute(
            "INSERT INTO servers VALUES ('server-1', 'general-linux', 1)"
        )
    initialize_health_database(path)


class CriticalErrorHealthTests(unittest.TestCase):
    def test_acknowledgment_records_seen_event_without_changing_health(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dashboard.sqlite3"
            initialize(path)
            now = datetime(2026, 7, 27, tzinfo=UTC)
            before = evaluate_server_health(
                path,
                server_id="server-1",
                observation=observation(event=True),
                now=now,
            )
            acknowledgment = acknowledge_critical_error(
                path,
                server_id="server-1",
                rule="oom-kill",
                actor="ada@example.com",
                now=now + timedelta(minutes=1),
            )
            after = evaluate_server_health(
                path,
                server_id="server-1",
                observation=observation(),
                now=now + timedelta(minutes=1),
            )
            acknowledgments = list_critical_error_acknowledgments(
                path, "server-1"
            )

        self.assertEqual(before["serverHealth"], after["serverHealth"])
        self.assertEqual(
            acknowledgments["oom-kill"],
            acknowledgment,
        )

    def test_persistent_fault_clears_after_five_continuous_minutes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dashboard.sqlite3"
            initialize(path)
            now = datetime(2026, 7, 27, tzinfo=UTC)
            active = evaluate_server_health(
                path, server_id="server-1", observation=observation(persistent=True), now=now
            )
            evaluate_server_health(
                path,
                server_id="server-1",
                observation=observation(),
                now=now + timedelta(seconds=1),
            )
            clearing = evaluate_server_health(
                path,
                server_id="server-1",
                observation=observation(),
                now=now + timedelta(minutes=5),
            )
            cleared = evaluate_server_health(
                path,
                server_id="server-1",
                observation=observation(),
                now=now + timedelta(minutes=5, seconds=1),
            )

        self.assertEqual(active["serverHealth"]["state"], "Degraded")
        self.assertEqual(clearing["serverHealth"]["state"], "Degraded")
        self.assertEqual(cleared["serverHealth"]["state"], "Healthy")

    def test_discrete_counter_event_latches_for_thirty_minutes_and_handles_reset(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dashboard.sqlite3"
            initialize(path)
            now = datetime(2026, 7, 27, tzinfo=UTC)
            evaluate_server_health(
                path, server_id="server-1", observation=observation(), now=now
            )
            event = evaluate_server_health(
                path,
                server_id="server-1",
                observation=observation(event=True),
                now=now + timedelta(minutes=1),
            )
            evaluate_server_health(
                path,
                server_id="server-1",
                observation=observation(),
                now=now + timedelta(minutes=1, seconds=1),
            )
            reset = evaluate_server_health(
                path,
                server_id="server-1",
                observation=observation(),
                now=now + timedelta(minutes=31),
            )
            cleared = evaluate_server_health(
                path,
                server_id="server-1",
                observation=observation(),
                now=now + timedelta(minutes=31, seconds=1),
            )

        self.assertEqual(event["serverHealth"]["state"], "Degraded")
        self.assertEqual(reset["serverHealth"]["state"], "Degraded")
        self.assertEqual(cleared["serverHealth"]["state"], "Healthy")


class CriticalErrorHelperTests(unittest.TestCase):
    def test_repeated_execution_deduplicates_events_and_publishes_atomically(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence.json"
            evidence.write_text(
                json.dumps(
                    {
                        "bootId": "boot-a",
                        "storageIoErrors": [
                            {"id": "journal:7", "class": "block", "device": "nvme0n1"},
                            {"id": "journal:8", "class": "filesystem", "device": "sda"},
                        ],
                        "previousPanic": {"id": "pstore:1", "detected": True},
                        "watchdogReset": {"id": "boot-status:1", "detected": True},
                        "availability": {"journal": True, "pstore": True, "watchdog": True},
                    }
                )
            )
            command = [
                str(HELPER),
                "--evidence",
                str(evidence),
                "--state",
                str(root / "state.json"),
                "--output",
                str(root / "critical-errors.prom"),
                "--now",
                "1785110400",
            ]
            subprocess.run(command, check=True)
            first = (root / "critical-errors.prom").read_text()
            subprocess.run(command, check=True)
            second = (root / "critical-errors.prom").read_text()
            document = json.loads(evidence.read_text())
            document["bootId"] = "boot-b"
            evidence.write_text(json.dumps(document))
            subprocess.run(command, check=True)
            after_reboot = (root / "critical-errors.prom").read_text()

        self.assertEqual(first, second)
        self.assertIn(
            'lab_health_storage_io_errors_total{class="block",device="nvme0n1"} 1',
            first,
        )
        self.assertIn("lab_health_previous_panic_events_total 1", first)
        self.assertIn("lab_health_watchdog_reset_events_total 1", first)
        self.assertIn(
            'lab_health_storage_io_errors_total{class="filesystem",device="sda"} 1',
            first,
        )
        self.assertIn("lab_health_previous_panic_events_total 1", after_reboot)
        self.assertNotIn(".tmp", first)

    def test_malformed_and_missing_evidence_fail_closed_without_replacing_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence.json"
            output = root / "critical-errors.prom"
            output.write_text("known-good\n")
            evidence.write_text("{")
            result = subprocess.run(
                [
                    str(HELPER),
                    "--evidence",
                    str(evidence),
                    "--state",
                    str(root / "state.json"),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "known-good\n")
            evidence.unlink()
            missing = subprocess.run(
                [
                    str(HELPER),
                    "--evidence",
                    str(evidence),
                    "--state",
                    str(root / "state.json"),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(missing.returncode, 0)
            self.assertEqual(output.read_text(), "known-good\n")


if __name__ == "__main__":
    unittest.main()
