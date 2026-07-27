import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class QualificationCliTests(unittest.TestCase):
    def run_qualification(
        self, record: dict[str, object]
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as handle:
            json.dump(record, handle)
            path = handle.name
        self.addCleanup(Path(path).unlink, missing_ok=True)
        environment = dict(os.environ)
        environment["PYTHONPATH"] = "src"
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "lab_dashboard.qualification",
                "validate",
                path,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def complete_record(self) -> dict[str, object]:
        template = json.loads(
            Path("docs/operations/production-acceptance-record.json").read_text()
        )
        for gate_index, gate in enumerate(template["gates"]):
            gate["result"] = "pass"
            gate["completedAt"] = (
                f"2026-07-{20 + gate_index:02d}T10:00:00+08:00"
            )
            for check in gate["checks"]:
                if gate["gate"] == 2:
                    server_ids = ["server-1"]
                elif gate["gate"] == 3:
                    server_ids = ["server-2"]
                else:
                    server_ids = ["server-1", "server-2"]
                check.update(
                    {
                        "actor": "Lab Administrator",
                        "versions": ["dashboard:0.1.0"],
                        "configurationRevisions": ["sha256:configuration"],
                        "serverIds": server_ids,
                        "expected": "documented expected result",
                        "actual": "observed expected result",
                        "result": "pass",
                        "evidenceCapturedAt": "2026-07-27T09:00:00+08:00",
                        "evidenceLinks": ["evidence/check.txt"],
                        "rollbackOutcome": "not-applicable",
                    }
                )
        template["measurements"] = {
            "soak": {
                "continuousHours": 72,
                "projectedRetentionDays": 30,
                "swappingObserved": False,
                "minimumDiskFreePercent": 20,
                "scrapeCadenceSeconds": 30,
                "observedMetricHistoryBytesPerHour": 1000,
                "projectedMetricHistoryBytes": 720000,
                "stateVolumeCapacityBytes": 1000000,
                "nonMetricUsedBytes": 80000,
            },
            "trainingThroughput": {
                "before": [100.0, 101.0, 99.0],
                "after": [99.0, 100.0, 98.0],
            },
        }
        template["signOff"] = {
            "decision": "go",
            "labAdministrator": "Accountable Person",
            "recordedAt": "2026-07-27T10:00:00+08:00",
            "productionRollbackOwner": "Rollback Owner",
        }
        return template

    def test_complete_five_gate_record_passes(self) -> None:
        result = self.run_qualification(self.complete_record())

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "qualified")

    def test_missing_mandatory_check_cannot_be_waived(self) -> None:
        record = self.complete_record()
        record["gates"][3]["checks"][0]["result"] = "waived"  # type: ignore[index]

        result = self.run_qualification(record)

        self.assertEqual(result.returncode, 1)
        self.assertIn("must pass; mandatory checks cannot be waived", result.stderr)

    def test_soak_and_training_thresholds_block_sign_off(self) -> None:
        record = self.complete_record()
        record["measurements"]["soak"]["continuousHours"] = 71.9  # type: ignore[index]
        record["measurements"]["trainingThroughput"]["after"] = [97, 98, 96]  # type: ignore[index]

        result = self.run_qualification(record)

        self.assertEqual(result.returncode, 1)
        self.assertIn("at least 72 continuous hours", result.stderr)
        self.assertIn("exceeds 2%", result.stderr)

    def test_gate_order_and_accountable_sign_off_are_enforced(self) -> None:
        record = self.complete_record()
        record["gates"][0], record["gates"][1] = (  # type: ignore[index]
            record["gates"][1],  # type: ignore[index]
            record["gates"][0],  # type: ignore[index]
        )
        record["signOff"]["productionRollbackOwner"] = ""  # type: ignore[index]

        result = self.run_qualification(record)

        self.assertEqual(result.returncode, 1)
        self.assertIn("gates must be recorded in sequential order", result.stderr)
        self.assertIn("productionRollbackOwner is required", result.stderr)

    def test_evidence_rejects_secret_bearing_fields(self) -> None:
        record = self.complete_record()
        record["gates"][0]["checks"][0]["smtpPassword"] = "secret"  # type: ignore[index]

        result = self.run_qualification(record)

        self.assertEqual(result.returncode, 1)
        self.assertIn("potential secret field", result.stderr)

    def test_each_enrollment_gate_requires_a_distinct_server_id(self) -> None:
        record = self.complete_record()
        record["gates"][2]["checks"][0]["serverIds"] = ["server-1"]  # type: ignore[index]
        record["gates"][2]["checks"][1]["serverIds"] = ["server-1"]  # type: ignore[index]

        result = self.run_qualification(record)

        self.assertEqual(result.returncode, 1)
        self.assertIn("must enroll distinct Server IDs", result.stderr)

    def test_capacity_projection_requires_objective_inputs(self) -> None:
        record = self.complete_record()
        record["measurements"]["soak"]["projectedMetricHistoryBytes"] = 1  # type: ignore[index]

        result = self.run_qualification(record)

        self.assertEqual(result.returncode, 1)
        self.assertIn("must equal observed hourly growth", result.stderr)


if __name__ == "__main__":
    unittest.main()
