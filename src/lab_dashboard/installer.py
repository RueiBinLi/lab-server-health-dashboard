from __future__ import annotations

import base64
import hashlib
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


PINNED_SIGNING_KEY_SHA256 = (
    "f15fe9bb9de08d4255affa754393ff216878ef996347c02c59a61fa871134c22"
)


@dataclass(frozen=True)
class SignedInstaller:
    version: str
    content: str
    sha256: str
    signature: str
    signing_public_key: str
    signing_key_sha256: str


def signed_installer(state_directory: Path) -> SignedInstaller:
    installer_path = (
        Path(__file__).parents[2] / "deploy" / "collector" / "install.sh"
    )
    signature_path = installer_path.with_suffix(".sh.sig")
    public_key_path = installer_path.with_suffix(".sh.pub")
    content = installer_path.read_text()
    signature = signature_path.read_text().strip()
    signing_public_key = public_key_path.read_text()
    signing_key_sha256 = hashlib.sha256(
        signing_public_key.encode()
    ).hexdigest()
    if signing_key_sha256 != PINNED_SIGNING_KEY_SHA256:
        raise RuntimeError("installer signing key does not match pinned key")

    with tempfile.TemporaryDirectory(dir=state_directory) as temporary:
        content_path = Path(temporary) / "install.sh"
        decoded_signature_path = Path(temporary) / "install.sh.sig"
        content_path.write_text(content)
        decoded_signature_path.write_bytes(base64.b64decode(signature))
        verification = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-rawin",
                "-in",
                str(content_path),
                "-sigfile",
                str(decoded_signature_path),
            ],
            capture_output=True,
            timeout=10,
        )
    if verification.returncode != 0:
        raise RuntimeError("installer signature verification failed")
    version_match = re.search(
        r"^INSTALLER_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$",
        content,
        re.MULTILINE,
    )
    if version_match is None:
        raise RuntimeError("installer version is missing")

    return SignedInstaller(
        version=version_match.group(1),
        content=content,
        sha256=hashlib.sha256(content.encode()).hexdigest(),
        signature=signature,
        signing_public_key=signing_public_key,
        signing_key_sha256=signing_key_sha256,
    )
