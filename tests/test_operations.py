import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


class OperationsCliTests(unittest.TestCase):
    def run_operations(
        self, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = "src"
        return subprocess.run(
            [sys.executable, "-m", "lab_dashboard.operations", *arguments],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_validate_fails_closed_for_group_readable_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "backup-key"
            secret.write_text("test key")
            secret.chmod(0o640)

            result = self.run_operations(
                "validate", "--secret", str(secret), "--allow-owner", str(os.getuid())
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("must have mode 0600", result.stderr)

    def test_backup_manifest_excludes_metric_history_and_offline_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            destination = root / "backups"
            (state / "generated").mkdir(parents=True)
            (state / "alertmanager-data").mkdir()
            (state / "online-intermediate").mkdir()
            (state / "prometheus-data").mkdir()
            (state / "offline-root-ca").mkdir()
            with sqlite3.connect(state / "dashboard.sqlite3") as connection:
                connection.execute("CREATE TABLE durable (value TEXT)")
                connection.execute("INSERT INTO durable VALUES ('kept')")
            (state / "generated" / "prometheus.yml").write_text("global: {}")
            (state / "alertmanager-data" / "nflog").write_text("state")
            (state / "online-intermediate" / "intermediate.key").write_text("key")
            (state / "prometheus-data" / "chunks").write_text("history")
            (state / "offline-root-ca" / "root.key").write_text("root")

            result = self.run_operations(
                "backup",
                "--state-directory",
                str(state),
                "--destination",
                str(destination),
                "--unencrypted-for-test",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            archive = Path(report["archive"])
            with tarfile.open(archive, "r:gz") as backup:
                names = backup.getnames()
                manifest = json.load(backup.extractfile("manifest.json"))  # type: ignore[arg-type]

        self.assertIn("dashboard.sqlite3", names)
        self.assertIn("generated/prometheus.yml", names)
        self.assertIn("alertmanager-data/nflog", names)
        self.assertIn("online-intermediate/intermediate.key", names)
        self.assertFalse(any("prometheus-data" in name for name in names))
        self.assertFalse(any("offline-root-ca" in name for name in names))
        self.assertEqual(manifest["metricHistory"], "excluded")

    def test_restore_is_isolated_and_reports_metric_history_not_restored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            with sqlite3.connect(state / "dashboard.sqlite3") as connection:
                connection.execute("CREATE TABLE durable (value TEXT)")
                connection.execute("INSERT INTO durable VALUES ('restored')")
            backup = self.run_operations(
                "backup",
                "--state-directory",
                str(state),
                "--destination",
                str(root / "backups"),
                "--unencrypted-for-test",
            )
            archive = json.loads(backup.stdout)["archive"]
            restore_directory = root / "isolated-restore"

            restored = self.run_operations(
                "restore",
                "--archive",
                archive,
                "--target",
                str(restore_directory),
                "--unencrypted-for-test",
            )

            self.assertEqual(restored.returncode, 0, restored.stderr)
            report = json.loads(restored.stdout)
            with sqlite3.connect(
                restore_directory / "dashboard.sqlite3"
            ) as connection:
                value = connection.execute("SELECT value FROM durable").fetchone()

        self.assertEqual(value, ("restored",))
        self.assertEqual(report["metricHistory"], "not-restored")
        self.assertEqual(report["restoreMode"], "isolated")


if __name__ == "__main__":
    unittest.main()
