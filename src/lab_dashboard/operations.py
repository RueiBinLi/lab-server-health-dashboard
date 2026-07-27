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
from datetime import UTC, datetime
from pathlib import Path


BACKUP_PATHS = (
    "dashboard.sqlite3",
    "generated",
    "prometheus.yml",
    "alertmanager.yml",
    "alertmanager-data",
    "online-intermediate",
)
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
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    with tempfile.TemporaryDirectory(prefix="lab-health-backup-") as temporary:
        staging = Path(temporary)
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
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)
            included.append(relative_name)
        if "dashboard.sqlite3" not in included:
            raise OperationsError("dashboard.sqlite3 is required for backup")
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
        archive = destination / f"lab-server-health-{timestamp}.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for item in sorted(staging.iterdir()):
                output.add(item, arcname=item.name)
        if unencrypted_for_test:
            return archive
        if recipient_file is None:
            raise OperationsError("an age recipient file is required")
        validate_secret(recipient_file, {0})
        encrypted = archive.with_suffix(archive.suffix + ".age")
        result = subprocess.run(
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
        archive.unlink(missing_ok=True)
        if result.returncode != 0:
            encrypted.unlink(missing_ok=True)
            raise OperationsError(f"age encryption failed: {result.stderr.strip()}")
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
            result = subprocess.run(
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
            if result.returncode != 0:
                raise OperationsError(
                    f"age decryption failed: {result.stderr.strip()}"
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
            result = connection.execute("PRAGMA quick_check").fetchone()
        if result != ("ok",):
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Central stack operations")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--secret", action="append", type=Path, required=True)
    validate.add_argument("--allow-owner", action="append", type=int, default=[])
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
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "validate":
            allowed = set(arguments.allow_owner) or {0}
            for secret in arguments.secret:
                validate_secret(secret, allowed)
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
    except OperationsError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
