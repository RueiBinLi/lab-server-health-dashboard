from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


REQUIRED_BACKUP_PATHS = (
    "dashboard.sqlite3",
    "prometheus.yml",
    "alertmanager.yml",
    "alertmanager-data",
    "pki",
)
BACKUP_PATHS = (*REQUIRED_BACKUP_PATHS, "generated")
EXCLUDED_PATHS = ("prometheus-data", "offline-root-ca")


class OperationsError(Exception):
    pass


def validate_secret(path: Path, allowed_owners: set[int]) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError as error:
        raise OperationsError(f"{path}: secret does not exist") from error
    if not stat.S_ISREG(details.st_mode) or path.is_symlink():
        raise OperationsError(f"{path}: secret must be a regular file")
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise OperationsError(f"{path}: secret must have mode 0600")
    if details.st_uid not in allowed_owners:
        raise OperationsError(f"{path}: secret must be root-owned")
    if details.st_size == 0:
        raise OperationsError(f"{path}: secret must not be empty")


def _copy_consistent_database(source: Path, destination: Path) -> None:
    try:
        with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as existing:
            with sqlite3.connect(destination) as snapshot:
                existing.backup(snapshot)
    except sqlite3.Error as error:
        raise OperationsError(f"{source}: SQLite backup failed: {error}") from error


def create_backup(
    state_directory: Path,
    destination: Path,
    *,
    recipient_file: Path | None,
    unencrypted_for_test: bool,
) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    if not unencrypted_for_test and not os.path.ismount(destination):
        raise OperationsError(
            f"{destination}: backup destination is not a mounted filesystem"
        )
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    with tempfile.TemporaryDirectory(prefix="lab-health-backup-") as temporary:
        temporary_root = Path(temporary)
        staging = temporary_root / "content"
        staging.mkdir()
        included: list[str] = []
        for relative_name in BACKUP_PATHS:
            source = state_directory / relative_name
            if not source.exists():
                continue
            target = staging / relative_name
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative_name == "dashboard.sqlite3":
                _copy_consistent_database(source, target)
            elif source.is_dir():
                shutil.copytree(
                    source,
                    target,
                    ignore=shutil.ignore_patterns(*EXCLUDED_PATHS),
                )
            else:
                shutil.copy2(source, target)
            included.append(relative_name)
        missing = [
            path for path in REQUIRED_BACKUP_PATHS if path not in included
        ]
        if missing:
            raise OperationsError(
                "required backup state is missing: " + ", ".join(missing)
            )
        manifest = {
            "createdAt": datetime.now(UTC).isoformat(),
            "included": included,
            "excluded": list(EXCLUDED_PATHS),
            "metricHistory": "excluded",
            "recoveryPointObjectiveHours": 24,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )
        archive_name = f"lab-server-health-{timestamp}.tar.gz"
        archive = (
            destination / archive_name
            if unencrypted_for_test
            else temporary_root / archive_name
        )
        with tarfile.open(archive, "w:gz") as output:
            for item in sorted(staging.iterdir()):
                output.add(item, arcname=item.name)
        if unencrypted_for_test:
            return archive
        if recipient_file is None:
            raise OperationsError("an age recipient file is required")
        validate_secret(recipient_file, {0})
        encrypted = destination / f"{archive_name}.age"
        try:
            encryption_result = subprocess.run(
                [
                    "age",
                    "--encrypt",
                    "--recipients-file",
                    str(recipient_file),
                    "--output",
                    str(encrypted),
                    str(archive),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if encryption_result.returncode != 0:
                raise OperationsError(
                    "age encryption failed: "
                    f"{encryption_result.stderr.strip()}"
                )
        except OperationsError:
            encrypted.unlink(missing_ok=True)
            raise
        except OSError as error:
            encrypted.unlink(missing_ok=True)
            raise OperationsError(f"age encryption failed: {error}") from error
        finally:
            archive.unlink(missing_ok=True)
        if not encrypted.is_file():
            encrypted.unlink(missing_ok=True)
            raise OperationsError("age encryption produced no archive")
        return encrypted


def restore_backup(
    archive: Path,
    target: Path,
    *,
    identity_file: Path | None,
    unencrypted_for_test: bool,
) -> dict[str, str]:
    if target.exists() and any(target.iterdir()):
        raise OperationsError(f"{target}: isolated restore target must be empty")
    target.mkdir(parents=True, exist_ok=True)
    decrypted: Path | None = None
    source = archive
    try:
        if not unencrypted_for_test:
            if identity_file is None:
                raise OperationsError("an age identity file is required")
            validate_secret(identity_file, {0})
            handle, temporary_name = tempfile.mkstemp(
                prefix="lab-health-restore-", suffix=".tar.gz"
            )
            os.close(handle)
            decrypted = Path(temporary_name)
            decryption_result = subprocess.run(
                [
                    "age",
                    "--decrypt",
                    "--identity",
                    str(identity_file),
                    "--output",
                    str(decrypted),
                    str(archive),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if decryption_result.returncode != 0:
                raise OperationsError(
                    "age decryption failed: "
                    f"{decryption_result.stderr.strip()}"
                )
            source = decrypted
        with tarfile.open(source, "r:gz") as backup:
            backup.extractall(target, filter="data")
        manifest_path = target / "manifest.json"
        if not manifest_path.is_file():
            raise OperationsError("backup manifest is missing")
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("metricHistory") != "excluded":
            raise OperationsError("backup does not declare Metric History excluded")
        database = target / "dashboard.sqlite3"
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
            quick_check_row = connection.execute(
                "PRAGMA quick_check"
            ).fetchone()
        if quick_check_row != ("ok",):
            raise OperationsError("restored SQLite durable state failed validation")
    except (OSError, tarfile.TarError, sqlite3.Error, json.JSONDecodeError) as error:
        raise OperationsError(f"restore validation failed: {error}") from error
    finally:
        if decrypted is not None:
            decrypted.unlink(missing_ok=True)
    return {
        "status": "validated",
        "restoreMode": "isolated",
        "target": str(target),
        "metricHistory": "not-restored",
    }


def operational_status(
    state_directory: Path,
    backup_directory: Path,
    *,
    prometheus_url: str,
    alertmanager_url: str,
) -> dict[str, object]:
    now = datetime.now(UTC)
    components: dict[str, str] = {}
    for name, url in (
        ("prometheus", prometheus_url),
        ("alertmanager", alertmanager_url),
    ):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                components[name] = (
                    "ready" if response.status == 200 else "unhealthy"
                )
        except (OSError, urllib.error.URLError):
            components[name] = "unreachable"
    usage = shutil.disk_usage(state_directory)
    archives = sorted(
        backup_directory.glob("lab-server-health-*.tar.gz.age"),
        key=lambda path: path.stat().st_mtime,
    )
    backup_age_hours = (
        (now.timestamp() - archives[-1].stat().st_mtime) / 3600
        if archives
        else None
    )
    enrollment: dict[str, int] = {}
    certificate_expiry_days: float | None = None
    channel_test_age_hours: float | None = None
    database = state_directory / "dashboard.sqlite3"
    try:
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
            enrollment = {
                str(state): int(count)
                for state, count in connection.execute(
                    """
                    SELECT enrollment_state, COUNT(*)
                    FROM servers GROUP BY enrollment_state
                    """
                )
            }
            certificate_row = connection.execute(
                "SELECT MIN(expires_at) FROM collector_certificates"
            ).fetchone()
            test_row = connection.execute(
                "SELECT MAX(requested_at) FROM notification_delivery_tests"
            ).fetchone()
        if certificate_row and certificate_row[0]:
            certificate_expiry_days = (
                datetime.fromisoformat(certificate_row[0]) - now
            ).total_seconds() / 86400
        if test_row and test_row[0]:
            channel_test_age_hours = (
                now - datetime.fromisoformat(test_row[0])
            ).total_seconds() / 3600
    except sqlite3.Error as error:
        raise OperationsError(f"operational status unavailable: {error}") from error
    return {
        "components": components,
        "enrollment": enrollment,
        "storage": {
            "capacityBytes": usage.total,
            "availableBytes": usage.free,
            "usedPercent": round(usage.used / usage.total * 100, 1),
        },
        "certificateExpiryDays": certificate_expiry_days,
        "backupAgeHours": backup_age_hours,
        "backupHealthy": (
            backup_age_hours is not None and backup_age_hours <= 24
        ),
        "channelTestAgeHours": channel_test_age_hours,
        "channelTestRequestedWithin24Hours": (
            channel_test_age_hours is not None and channel_test_age_hours <= 24
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Central stack operations")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--secret", action="append", type=Path, required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("--state-directory", type=Path, required=True)
    backup.add_argument("--destination", type=Path, required=True)
    backup.add_argument("--recipient-file", type=Path)
    backup.add_argument("--unencrypted-for-test", action="store_true")
    restore = commands.add_parser("restore")
    restore.add_argument("--archive", type=Path, required=True)
    restore.add_argument("--target", type=Path, required=True)
    restore.add_argument("--identity-file", type=Path)
    restore.add_argument("--unencrypted-for-test", action="store_true")
    status = commands.add_parser("status")
    status.add_argument("--state-directory", type=Path, required=True)
    status.add_argument("--backup-directory", type=Path, required=True)
    status.add_argument(
        "--prometheus-url",
        default="http://127.0.0.1:19090/-/ready",
    )
    status.add_argument(
        "--alertmanager-url",
        default="http://127.0.0.1:19093/-/ready",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "validate":
            for secret in arguments.secret:
                validate_secret(secret, {0})
            print(json.dumps({"status": "valid"}))
        elif arguments.command == "backup":
            archive = create_backup(
                arguments.state_directory,
                arguments.destination,
                recipient_file=arguments.recipient_file,
                unencrypted_for_test=arguments.unencrypted_for_test,
            )
            print(json.dumps({"archive": str(archive), "status": "created"}))
        elif arguments.command == "restore":
            print(
                json.dumps(
                    restore_backup(
                        arguments.archive,
                        arguments.target,
                        identity_file=arguments.identity_file,
                        unencrypted_for_test=arguments.unencrypted_for_test,
                    )
                )
            )
        elif arguments.command == "status":
            print(
                json.dumps(
                    operational_status(
                        arguments.state_directory,
                        arguments.backup_directory,
                        prometheus_url=arguments.prometheus_url,
                        alertmanager_url=arguments.alertmanager_url,
                    )
                )
            )
    except OperationsError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
