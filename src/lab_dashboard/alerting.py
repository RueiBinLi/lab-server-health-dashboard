from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any


class AlertingConfigurationError(Exception):
    """A fail-closed alerting configuration error safe to report."""


_NOTIFICATION_TEXT_TEMPLATE = (
    "Server: {{ .CommonAnnotations.server_name }} "
    "({{ .CommonLabels.server_id }})\n"
    "Server Health: {{ .CommonLabels.severity }}\n"
    "Causes: {{ .CommonAnnotations.causes }}\n"
    "Duration: {{ .CommonAnnotations.duration }}\n"
    "Transition: {{ .CommonLabels.transition }}\n"
    "Maintenance: {{ .CommonAnnotations.maintenance }}\n"
    "Administrator: {{ .CommonAnnotations.administrator_url }}"
)


def validate_secret_file(
    path: Path, *, expected_owner_uid: int | None = None
) -> None:
    try:
        metadata = path.stat()
    except FileNotFoundError as error:
        raise AlertingConfigurationError(
            f"required secret file is missing: {path}"
        ) from error
    if not stat.S_ISREG(metadata.st_mode):
        raise AlertingConfigurationError(
            f"required secret path is not a regular file: {path}"
        )
    if expected_owner_uid is not None and metadata.st_uid != expected_owner_uid:
        raise AlertingConfigurationError(
            f"required secret file has an unsafe owner: {path}"
        )
    if not metadata.st_mode & stat.S_IRUSR:
        raise AlertingConfigurationError(
            f"required secret file must be owner-readable: {path}"
        )
    if metadata.st_mode & 0o077:
        raise AlertingConfigurationError(
            f"required secret file must be owner-readable only: {path}"
        )
    if metadata.st_size == 0:
        raise AlertingConfigurationError(
            f"required secret file is empty: {path}"
        )


def _channel_route(receiver: str, *, continue_: bool = False) -> dict[str, Any]:
    route: dict[str, Any] = {
        "receiver": receiver,
        "matchers": [
            'alertname=~"ServerIncident|ServerIncidentRecovery|'
            'NotificationChannelTest|NotificationChannelTestRecovery"'
        ],
        "routes": [
            {
                "receiver": receiver,
                "matchers": [
                    'severity="Unavailable"',
                ],
                "group_wait": "0s",
            },
            {
                "receiver": receiver,
                "matchers": [
                    'transition=~"escalation|improvement|recovery"',
                ],
                "group_wait": "0s",
            },
        ],
    }
    if continue_:
        route["continue"] = True
    return route


def build_alertmanager_config(
    *,
    smtp_smarthost: str,
    smtp_from: str,
    smtp_to: str,
    smtp_username: str,
    smtp_password_file: str,
    slack_webhook_file: str,
) -> dict[str, Any]:
    email = {
        "to": smtp_to,
        "from": smtp_from,
        "smarthost": smtp_smarthost,
        "auth_username": smtp_username,
        "auth_password_file": smtp_password_file,
        "require_tls": True,
        "send_resolved": True,
        "headers": {
            "subject": (
                '[{{ .Status | toUpper }}] {{ .CommonLabels.severity }} '
                "{{ .CommonAnnotations.server_name }}"
            )
        },
        "text": _NOTIFICATION_TEXT_TEMPLATE,
        "html": "",
    }
    slack = {
        "api_url_file": slack_webhook_file,
        "send_resolved": True,
        "title": (
            "{{ .CommonLabels.severity }} — "
            "{{ .CommonAnnotations.server_name }}"
        ),
        "text": _NOTIFICATION_TEXT_TEMPLATE,
    }
    return {
        "route": {
            "receiver": "discard",
            "group_by": ["server_id", "incident_id"],
            "group_wait": "30s",
            "group_interval": "5m",
            "repeat_interval": "4h",
            "routes": [
                _channel_route("email", continue_=True),
                _channel_route("slack"),
            ],
        },
        "receivers": [
            {"name": "discard"},
            {"name": "email", "email_configs": [email]},
            {"name": "slack", "slack_configs": [slack]},
        ],
    }


def build_prometheus_rules() -> dict[str, Any]:
    info = (
        '{{ with query (printf "lab_server_incident_info'
        '{server_id=%q,incident_id=%q}" $labels.server_id '
        '$labels.incident_id) }}{{ . | first | label "FIELD" }}{{ end }}'
    )
    annotations = {
        field: info.replace("FIELD", field)
        for field in (
            "server_name",
            "causes",
            "duration",
            "maintenance",
            "administrator_url",
        )
    }
    return {
        "groups": [
            {
                "name": "critical-alerts",
                "interval": "5s",
                "rules": [
                    {
                        "alert": "ServerIncident",
                        "expr": "lab_server_incident == 1",
                        "for": "0s",
                        "labels": {
                            "server_id": "{{ $labels.server_id }}",
                            "incident_id": "{{ $labels.incident_id }}",
                            "severity": "{{ $labels.severity }}",
                            "transition": "{{ $labels.transition }}",
                        },
                        "annotations": annotations,
                    },
                    {
                        "alert": "ServerIncidentRecovery",
                        "expr": "lab_server_incident_recovery == 1",
                        "for": "0s",
                        "labels": {
                            "server_id": "{{ $labels.server_id }}",
                            "incident_id": "{{ $labels.incident_id }}",
                            "severity": "Healthy",
                            "transition": "recovery",
                        },
                        "annotations": annotations,
                    },
                    {
                        "alert": "NotificationChannelTest",
                        "expr": "lab_notification_delivery_test == 1",
                        "for": "0s",
                        "labels": {
                            "server_id": "delivery-test",
                            "incident_id": "{{ $labels.delivery_test_id }}",
                            "severity": "Degraded",
                            "transition": "opening",
                        },
                        "annotations": {
                            field: "Notification channel delivery test."
                            for field in annotations
                        },
                    },
                    {
                        "alert": "NotificationChannelTestRecovery",
                        "expr": (
                            "lab_notification_delivery_test_recovery == 1"
                        ),
                        "for": "0s",
                        "labels": {
                            "server_id": "delivery-test",
                            "incident_id": "{{ $labels.delivery_test_id }}",
                            "severity": "Healthy",
                            "transition": "recovery",
                        },
                        "annotations": {
                            field: "Notification channel delivery test."
                            for field in annotations
                        },
                    },
                ],
            }
        ]
    }


def write_alerting_configuration(
    output_directory: Path, environment: Mapping[str, str]
) -> None:
    required = (
        "ALERT_SMTP_SMARTHOST",
        "ALERT_SMTP_FROM",
        "ALERT_SMTP_TO",
        "ALERT_SMTP_USERNAME",
        "ALERT_SMTP_PASSWORD_FILE",
        "ALERT_SLACK_WEBHOOK_FILE",
    )
    missing = [name for name in required if not environment.get(name)]
    if missing:
        raise AlertingConfigurationError(
            "required alerting settings are missing: " + ", ".join(missing)
        )
    smtp_password = Path(environment["ALERT_SMTP_PASSWORD_FILE"])
    slack_webhook = Path(environment["ALERT_SLACK_WEBHOOK_FILE"])
    validate_secret_file(smtp_password, expected_owner_uid=0)
    validate_secret_file(slack_webhook, expected_owner_uid=0)
    document = build_alertmanager_config(
        smtp_smarthost=environment["ALERT_SMTP_SMARTHOST"],
        smtp_from=environment["ALERT_SMTP_FROM"],
        smtp_to=environment["ALERT_SMTP_TO"],
        smtp_username=environment["ALERT_SMTP_USERNAME"],
        smtp_password_file=str(smtp_password),
        slack_webhook_file=str(slack_webhook),
    )
    output_directory.mkdir(parents=True, exist_ok=True)
    _atomic_json(output_directory / "alertmanager.yml", document)
    _atomic_json(output_directory / "critical-alerts.yml", build_prometheus_rules())


def _atomic_json(path: Path, document: dict[str, Any]) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, delete=False
    ) as temporary:
        json.dump(document, temporary, indent=2)
        temporary.write("\n")
        temporary_path = Path(temporary.name)
    # Generated files contain only non-secret settings and protected file paths.
    # Alertmanager and Prometheus run under separate unprivileged identities.
    os.chmod(temporary_path, 0o644)
    temporary_path.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path("/var/lib/lab-dashboard"),
    )
    arguments = parser.parse_args()
    try:
        write_alerting_configuration(arguments.output_directory, os.environ)
    except AlertingConfigurationError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
