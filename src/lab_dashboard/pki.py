from __future__ import annotations

import fcntl
import hashlib
import os
import secrets
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path


CERTIFICATE_VALIDITY_DAYS = 30


class InvalidCertificateSigningRequest(Exception):
    pass


@dataclass(frozen=True)
class IssuedCertificate:
    certificate: str
    ca_certificate: str
    fingerprint: str
    expires_at: datetime
    scrape_client_ca_certificate: str
    scrape_client_certificate_path: str
    scrape_client_key_path: str


def issue_collector_certificate(
    state_directory: Path, *, server_id: str, csr: str
) -> IssuedCertificate:
    pki_directory = state_directory / "pki"
    ca_key = pki_directory / "collector-ca.key"
    ca_certificate = pki_directory / "collector-ca.crt"
    _ensure_collector_ca(pki_directory, ca_key, ca_certificate)
    (
        scrape_client_ca_certificate,
        scrape_client_certificate_path,
        scrape_client_key_path,
    ) = _ensure_per_server_scrape_client(pki_directory, server_id)

    with tempfile.TemporaryDirectory(dir=state_directory) as temporary:
        temporary_path = Path(temporary)
        csr_path = temporary_path / "collector.csr"
        certificate_path = temporary_path / "collector.crt"
        extensions_path = temporary_path / "collector.ext"
        csr_path.write_text(csr)
        extensions_path.write_text(
            "\n".join(
                (
                    "basicConstraints=critical,CA:FALSE",
                    "keyUsage=critical,digitalSignature,keyEncipherment",
                    "extendedKeyUsage=critical,clientAuth,serverAuth",
                    (
                        "subjectAltName="
                        f"URI:urn:lab-server:{server_id},DNS:{server_id}"
                    ),
                )
            )
            + "\n"
        )
        try:
            verified_csr = subprocess.run(
                ["openssl", "req", "-in", str(csr_path), "-noout", "-verify"],
                check=True,
                capture_output=True,
                timeout=10,
            )
            csr_subject = subprocess.run(
                [
                    "openssl",
                    "req",
                    "-in",
                    str(csr_path),
                    "-noout",
                    "-subject",
                    "-nameopt",
                    "RFC2253",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
            if verified_csr.returncode != 0 or csr_subject != (
                f"subject=CN={server_id}"
            ):
                raise InvalidCertificateSigningRequest
            subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(csr_path),
                    "-CA",
                    str(ca_certificate),
                    "-CAkey",
                    str(ca_key),
                    "-set_serial",
                    f"0x{secrets.token_hex(16)}",
                    "-days",
                    str(CERTIFICATE_VALIDITY_DAYS),
                    "-sha256",
                    "-extfile",
                    str(extensions_path),
                    "-out",
                    str(certificate_path),
                ],
                check=True,
                capture_output=True,
                timeout=10,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            raise InvalidCertificateSigningRequest from error
        certificate = certificate_path.read_text()

    expires_at = datetime.now(UTC) + timedelta(
        days=CERTIFICATE_VALIDITY_DAYS
    )
    return IssuedCertificate(
        certificate=certificate,
        ca_certificate=ca_certificate.read_text(),
        fingerprint=hashlib.sha256(certificate.encode()).hexdigest(),
        expires_at=expires_at,
        scrape_client_ca_certificate=scrape_client_ca_certificate,
        scrape_client_certificate_path=str(scrape_client_certificate_path),
        scrape_client_key_path=str(scrape_client_key_path),
    )


def _ensure_collector_ca(
    directory: Path, key_path: Path, certificate_path: Path
) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    with (directory / "collector-ca.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if key_path.exists() and certificate_path.exists():
            return
        try:
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-subj",
                    "/CN=Lab Server Health Collector CA",
                    "-days",
                    "3650",
                    "-sha256",
                    "-keyout",
                    str(key_path),
                    "-out",
                    str(certificate_path),
                ],
                check=True,
                capture_output=True,
                timeout=10,
            )
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as error:
            raise RuntimeError("could not initialize collector CA") from error
        os.chmod(key_path, 0o600)
        os.chmod(certificate_path, 0o644)


def _ensure_per_server_scrape_client(
    pki_directory: Path, server_id: str
) -> tuple[str, Path, Path]:
    directory = pki_directory / "scrape-clients" / server_id
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    ca_key = directory / "ca.key"
    ca_certificate = directory / "ca.crt"
    client_key = directory / "client.key"
    client_csr = directory / "client.csr"
    client_certificate = directory / "client.crt"
    client_extensions = directory / "client.ext"
    with (directory / "identity.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not all(
            path.exists()
            for path in (
                ca_key,
                ca_certificate,
                client_key,
                client_certificate,
            )
        ):
            try:
                subprocess.run(
                    [
                        "openssl",
                        "req",
                        "-x509",
                        "-newkey",
                        "ec",
                        "-pkeyopt",
                        "ec_paramgen_curve:P-256",
                        "-nodes",
                        "-subj",
                        f"/CN=Lab Scrape Client CA {server_id}",
                        "-days",
                        "3650",
                        "-sha256",
                        "-keyout",
                        str(ca_key),
                        "-out",
                        str(ca_certificate),
                    ],
                    check=True,
                    capture_output=True,
                    timeout=10,
                )
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
                        f"/CN=dashboard-scraper-{server_id}",
                        "-keyout",
                        str(client_key),
                        "-out",
                        str(client_csr),
                    ],
                    check=True,
                    capture_output=True,
                    timeout=10,
                )
                client_extensions.write_text(
                    "\n".join(
                        (
                            "basicConstraints=critical,CA:FALSE",
                            "keyUsage=critical,digitalSignature",
                            "extendedKeyUsage=critical,clientAuth",
                        )
                    )
                    + "\n"
                )
                subprocess.run(
                    [
                        "openssl",
                        "x509",
                        "-req",
                        "-in",
                        str(client_csr),
                        "-CA",
                        str(ca_certificate),
                        "-CAkey",
                        str(ca_key),
                        "-set_serial",
                        f"0x{secrets.token_hex(16)}",
                        "-days",
                        "365",
                        "-sha256",
                        "-extfile",
                        str(client_extensions),
                        "-out",
                        str(client_certificate),
                    ],
                    check=True,
                    capture_output=True,
                    timeout=10,
                )
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
            ) as error:
                raise RuntimeError(
                    "could not initialize per-server scrape trust"
                ) from error
            os.chmod(ca_key, 0o600)
            os.chmod(client_key, 0o600)
            os.chmod(ca_certificate, 0o644)
            os.chmod(client_certificate, 0o644)
            client_csr.unlink(missing_ok=True)
            client_extensions.unlink(missing_ok=True)
    return ca_certificate.read_text(), client_certificate, client_key
