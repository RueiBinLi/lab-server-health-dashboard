from __future__ import annotations

import fcntl
import json
import hashlib
import http.server
import ipaddress
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast


CAPABILITY_NAME = "rueibinli.github.io/cap/lab-server-health"


def get(
    base_url: str, path: str, identity: str | None, role: str | None
) -> tuple[int, dict[str, Any]]:
    headers = {}
    if identity is not None:
        headers["Tailscale-User-Login"] = identity
    if role is not None:
        headers["Tailscale-App-Capabilities"] = json.dumps(
            {CAPABILITY_NAME: [{"role": role}]}
        )
    request = urllib.request.Request(base_url + path, headers=headers)
    try:
        response = urllib.request.urlopen(request, timeout=2)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, cast(dict[str, Any], json.load(response))


def get_text(
    base_url: str, path: str, identity: str, role: str
) -> tuple[int, str]:
    request = urllib.request.Request(
        base_url + path,
        headers={
            "Tailscale-User-Login": identity,
            "Tailscale-App-Capabilities": json.dumps(
                {CAPABILITY_NAME: [{"role": role}]}
            ),
        },
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, response.read().decode()


def post(
    base_url: str,
    path: str,
    body: Mapping[str, object],
    identity: str,
    role: str,
    extra_headers: Mapping[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        base_url + path,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Tailscale-User-Login": identity,
            "Tailscale-App-Capabilities": json.dumps(
                {CAPABILITY_NAME: [{"role": role}]}
            ),
            **(extra_headers or {}),
        },
        method="POST",
    )
    try:
        response = urllib.request.urlopen(request, timeout=2)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, cast(dict[str, Any], json.load(response))


def create_csr(
    directory: Path, server_id: str
) -> tuple[str, str, Path]:
    key_path = directory / f"{server_id}.key"
    csr_path = directory / f"{server_id}.csr"
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            f"/CN={server_id}",
            "-keyout",
            str(key_path),
            "-out",
            str(csr_path),
        ],
        check=True,
        capture_output=True,
    )
    public_key = subprocess.run(
        ["openssl", "req", "-in", str(csr_path), "-pubkey", "-noout"],
        check=True,
        capture_output=True,
    ).stdout
    public_key_der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=public_key,
        check=True,
        capture_output=True,
    ).stdout
    return (
        csr_path.read_text(),
        hashlib.sha256(public_key_der).hexdigest(),
        key_path,
    )


def first_contact(
    base_url: str,
    server_id: str,
    token: str,
    csr: str,
    source_address: str,
) -> tuple[int, dict[str, Any]]:
    return post(
        base_url,
        "/api/enrollment/bootstrap",
        {
            "serverId": server_id,
            "bootstrapToken": token,
            "certificateSigningRequest": csr,
            "hostname": "system-test-server",
            "osRelease": "Ubuntu 24.04 LTS",
            "architecture": "x86_64",
            "cpu": {"model": "Test CPU", "logicalCount": 8},
            "memory": {"totalBytes": 17_179_869_184},
            "disks": [
                {
                    "stableId": "test-disk-1",
                    "model": "Test Disk",
                    "sizeBytes": 1_099_511_627_776,
                    "mounts": ["/"],
                }
            ],
            "gpus": [],
            "stableIdentifiers": {
                "machineId": "system-test-machine-id",
                "systemUuid": "system-test-system-uuid",
            },
        },
        "collector-bootstrap",
        "lab-administrator",
        {"X-Forwarded-For": source_address},
    )


class MetricsHandler(http.server.BaseHTTPRequestHandler):
    document = b"""# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{cpu="0",mode="idle"} 1
node_memory_MemTotal_bytes 17179869184
node_filesystem_size_bytes{mountpoint="/"} 1099511627776
node_hwmon_temp_celsius{sensor="temp1"} 42
lab_critical_errors_total 0
"""

    def do_GET(self) -> None:
        if self.path != "/metrics":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.document)))
        self.end_headers()
        self.wfile.write(self.document)

    def log_message(self, format: str, *args: object) -> None:
        return


class RunningTestCollector:
    def __init__(
        self,
        *,
        address: tuple[str, int],
        certificate: str,
        private_key_path: Path,
        scrape_client_ca_certificate: str,
        directory: Path,
    ) -> None:
        certificate_path = directory / "collector.crt"
        client_ca_path = directory / "scrape-client-ca.crt"
        certificate_path.write_text(certificate)
        client_ca_path.write_text(scrape_client_ca_certificate)
        self.server = http.server.ThreadingHTTPServer(
            address, MetricsHandler
        )
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile=certificate_path,
            keyfile=private_key_path,
        )
        context.load_verify_locations(cafile=client_ca_path)
        context.verify_mode = ssl.CERT_REQUIRED
        self.server.socket = context.wrap_socket(
            self.server.socket, server_side=True
        )
        self.thread = threading.Thread(target=self.server.serve_forever)

    def __enter__(self) -> "RunningTestCollector":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def private_source_address() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        for _, name in socket.if_nameindex():
            try:
                packed = struct.pack("256s", name[:15].encode())
                address_bytes = fcntl.ioctl(
                    probe.fileno(), 0x8915, packed
                )[20:24]
            except OSError:
                continue
            address = socket.inet_ntoa(address_bytes)
            parsed = ipaddress.ip_address(address)
            if parsed.is_private and not parsed.is_loopback:
                return address
    raise RuntimeError("no private collector test address is available")


def available_port(address: str) -> int:
    with socket.socket() as probe:
        probe.bind((address, 0))
        return cast(tuple[str, int], probe.getsockname())[1]


def registered_server(
    fleet: list[dict[str, Any]], display_name: str
) -> dict[str, Any] | None:
    return next(
        (
            server
            for server in fleet
            if server["displayName"] == display_name
        ),
        None,
    )


def main() -> None:
    base_url = sys.argv[1]
    expected_server_id = sys.argv[2] if len(sys.argv) > 2 else None
    source_address = private_source_address()
    collector_port = available_port(source_address)
    registration_body = {
        "displayName": "System Test Server",
        "scrapeAddress": (
            f"https://{source_address}:{collector_port}/metrics"
        ),
        "profileId": "general-linux",
        "reason": "Exercise deployed enrollment boundary",
    }
    administrator = get(
        base_url, "/api/fleet", "ada@example.com", "lab-administrator"
    )
    profiles = get(
        base_url,
        "/api/server-profiles",
        "ada@example.com",
        "lab-administrator",
    )
    system_server = registered_server(
        administrator[1]["fleet"], "System Test Server"
    )
    if system_server is None:
        registration = post(
            base_url,
            "/api/servers",
            registration_body,
            "ada@example.com",
            "lab-administrator",
        )
        assert registration[0] == 201
        system_server = registration[1]["server"]
        administrator = get(
            base_url, "/api/fleet", "ada@example.com", "lab-administrator"
        )
    with tempfile.TemporaryDirectory() as temporary_directory:
        directory = Path(temporary_directory)
        if system_server["enrollmentState"] == "awaiting-first-contact":
            token = post(
                base_url,
                f"/api/servers/{system_server['serverId']}/bootstrap-tokens",
                {"reason": "Exercise deployed approval"},
                "ada@example.com",
                "lab-administrator",
            )
            assert token[0] == 201
            csr, fingerprint, private_key_path = create_csr(
                directory, system_server["serverId"]
            )
            contact = first_contact(
                base_url,
                system_server["serverId"],
                token[1]["bootstrapToken"],
                csr,
                source_address,
            )
            assert contact[0] == 201
            expected_code = "-".join(
                fingerprint[:12].upper()[index : index + 4]
                for index in range(0, 12, 4)
            )
            assert contact[1]["verificationCode"] == expected_code
            pending = get(
                base_url,
                "/api/fleet",
                "ada@example.com",
                "lab-administrator",
            )
            pending_server = registered_server(
                pending[1]["fleet"], "System Test Server"
            )
            assert pending_server is not None
            assert (
                pending_server["enrollmentReview"]["verificationCode"]
                == expected_code
            )
            with RunningTestCollector(
                address=(source_address, collector_port),
                certificate=contact[1]["certificate"],
                private_key_path=private_key_path,
                scrape_client_ca_certificate=contact[1][
                    "scrapeClientCaCertificate"
                ],
                directory=directory,
            ):
                telemetry_check = post(
                    base_url,
                    (
                        f"/api/servers/{system_server['serverId']}"
                        "/staged-telemetry-checks"
                    ),
                    {},
                    "ada@example.com",
                    "lab-administrator",
                )
                assert telemetry_check[0] == 200, telemetry_check
                assert telemetry_check[1]["server"][
                    "enrollmentReview"
                ]["readyForApproval"] is True
                dashboard_page = get_text(
                    base_url,
                    "/",
                    "ada@example.com",
                    "lab-administrator",
                )
                assert dashboard_page[0] == 200
                for value in (
                    expected_code,
                    source_address,
                    "system-test-server",
                    "Ubuntu 24.04 LTS",
                    "Test CPU",
                    "Test Disk",
                    "Approve",
                    "Reject",
                ):
                    assert value in dashboard_page[1]
                approval = post(
                    base_url,
                    (
                        f"/api/servers/{system_server['serverId']}"
                        "/enrollment-decisions"
                    ),
                    {
                        "decision": "approve",
                        "verificationCode": expected_code,
                        "reason": "Deployed test code and inventory match",
                    },
                    "ada@example.com",
                    "lab-administrator",
                )
                assert approval[0] == 200
                system_server = approval[1]["server"]
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    observed_fleet = get(
                        base_url,
                        "/api/fleet",
                        "ada@example.com",
                        "lab-administrator",
                    )
                    observed = registered_server(
                        observed_fleet[1]["fleet"], "System Test Server"
                    )
                    if (
                        observed is not None
                        and observed.get("lastObservationResult")
                        == "succeeded"
                    ):
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("normal observation did not begin")

        rejection_server = registered_server(
            administrator[1]["fleet"], "Rejected System Test Server"
        )
        if rejection_server is None:
            rejection_registration = post(
                base_url,
                "/api/servers",
                {
                    **registration_body,
                    "displayName": "Rejected System Test Server",
                    "reason": "Exercise deployed rejection boundary",
                },
                "ada@example.com",
                "lab-administrator",
            )
            assert rejection_registration[0] == 201
            rejection_server = rejection_registration[1]["server"]
        rejection_token = post(
            base_url,
            (
                f"/api/servers/{rejection_server['serverId']}"
                "/bootstrap-tokens"
            ),
            {"reason": "Exercise deployed rejection"},
            "ada@example.com",
            "lab-administrator",
        )
        assert rejection_token[0] == 201
        rejection_csr, rejection_fingerprint, _ = create_csr(
            directory, rejection_server["serverId"]
        )
        rejection_contact = first_contact(
            base_url,
            rejection_server["serverId"],
            rejection_token[1]["bootstrapToken"],
            rejection_csr,
            source_address,
        )
        assert rejection_contact[0] == 201
        rejection = post(
            base_url,
            (
                f"/api/servers/{rejection_server['serverId']}"
                "/enrollment-decisions"
            ),
            {
                "decision": "reject",
                "verificationCode": rejection_contact[1][
                    "verificationCode"
                ],
                "reason": "Deployed test intentionally rejects collector",
            },
            "ada@example.com",
            "lab-administrator",
        )
        assert rejection[0] == 200
        assert (
            rejection[1]["server"]["lastRejectedEnrollment"][
                "collectorPublicKeyFingerprint"
            ]
            == rejection_fingerprint
        )
        rejected_reuse = first_contact(
            base_url,
            rejection_server["serverId"],
            rejection_token[1]["bootstrapToken"],
            rejection_csr,
            source_address,
        )
        assert rejected_reuse == (
            401,
            {"error": "invalid_bootstrap_credentials"},
        )
    administrator = get(
        base_url, "/api/fleet", "ada@example.com", "lab-administrator"
    )
    duplicate = post(
        base_url,
        "/api/servers",
        registration_body,
        "ada@example.com",
        "lab-administrator",
    )
    invalid_address = post(
        base_url,
        "/api/servers",
        {
            **registration_body,
            "displayName": "Invalid Address",
            "scrapeAddress": "https://203.0.113.8:9100/metrics",
        },
        "ada@example.com",
        "lab-administrator",
    )
    unpublished_profile = post(
        base_url,
        "/api/servers",
        {
            **registration_body,
            "displayName": "Unpublished Profile",
            "profileId": "draft-experiment",
        },
        "ada@example.com",
        "lab-administrator",
    )
    lab_user = get(base_url, "/api/fleet", "lin@example.com", "lab-user")
    user_profiles = get(
        base_url, "/api/server-profiles", "lin@example.com", "lab-user"
    )
    user_registration = post(
        base_url,
        "/api/servers",
        registration_body,
        "lin@example.com",
        "lab-user",
    )
    audit = get(
        base_url,
        "/api/audit-events",
        "ada@example.com",
        "lab-administrator",
    )
    denied = (
        get(base_url, "/api/fleet", None, None),
        get(base_url, "/api/fleet", "not an identity", "lab-user"),
        get(base_url, "/api/fleet", "unknown@example.com", None),
        get(base_url, "/api/fleet", "roleless@example.com", None),
        get(base_url, "/api/fleet", "tag:build-server", "lab-user"),
    )

    assert administrator[0] == 200
    administrator_fleet = administrator[1]["fleet"]
    assert len(administrator_fleet) == 2
    server = registered_server(administrator_fleet, "System Test Server")
    assert server is not None
    assert server["displayName"] == "System Test Server"
    assert server["enrollmentState"] == "active"
    assert server["observationTargetSet"] == "active"
    assert server["inventory"]["hostname"] == "system-test-server"
    assert server["serverHealth"] is None
    assert server["metricHistory"] == []
    assert server["criticalAlerts"] == []
    if expected_server_id is not None:
        assert server["serverId"] == expected_server_id
    assert profiles[0] == 200
    assert [
        (profile["name"], profile["state"])
        for profile in profiles[1]["profiles"]
    ] == [
        ("General Linux Server", "published"),
        ("NVIDIA GPU Compute Server", "published"),
    ]
    general, gpu = profiles[1]["profiles"]
    assert general["definition"]["capabilities"]["gpu"] is False
    assert gpu["definition"]["capabilities"]["gpu"] is True
    for profile in (general, gpu):
        assert "reachability" in profile["definition"]["requiredObservations"]
        assert "critical-errors" in profile["definition"]["requiredObservations"]
    assert lab_user == (
        200,
        {
            "viewer": {"login": "lin@example.com", "role": "lab-user"},
            "fleet": [],
            "emptyMessage": "No servers are available yet.",
        },
    )
    assert user_profiles == (403, {"error": "access_denied"})
    assert user_registration == (403, {"error": "access_denied"})
    assert duplicate == (409, {"error": "display_name_conflict"})
    assert invalid_address == (400, {"error": "invalid_registration"})
    assert unpublished_profile == (
        422,
        {"error": "profile_not_published"},
    )
    assert audit[0] == 200
    assert audit[1]["events"][0]["server_id"] == server["serverId"]
    assert audit[1]["events"][0]["result"] == "succeeded"
    audit_results = {event["result"] for event in audit[1]["events"]}
    assert {
        "succeeded",
        "display-name-conflict",
        "invalid-registration",
        "profile-not-published",
    } <= audit_results
    assert denied == ((403, {"error": "access_denied"}),) * 5
    print(server["serverId"])


if __name__ == "__main__":
    main()
