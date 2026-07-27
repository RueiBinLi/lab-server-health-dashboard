#!/usr/bin/env bash
set -euo pipefail

INSTALLER_VERSION=1.0.0
NODE_EXPORTER_VERSION=1.11.1
NODE_EXPORTER_AMD64_SHA256=9f5ea48e5bc7b656f8a91a32e7d7deb89f70f73dabd0d974418aca15f37d6810
NODE_EXPORTER_ARM64_SHA256=ba1886efbd76cb96b0087c695ea8d1b9cb6e8aa946c996d744e9ee16c8e3591a

fail() {
  echo "collector installer: $*" >&2
  exit 1
}

if (( $# != 0 )); then
  fail "bootstrap tokens are accepted only through standard input or hidden prompt"
fi

OS_RELEASE_FILE=${LAB_OS_RELEASE_FILE:-/etc/os-release}
[[ -r "$OS_RELEASE_FILE" ]] || fail "cannot read operating-system release"
# shellcheck disable=SC1090
source "$OS_RELEASE_FILE"
[[ ${ID:-} == ubuntu && ( ${VERSION_ID:-} == 22.04 || ${VERSION_ID:-} == 24.04 ) ]] \
  || fail "only Ubuntu 22.04 or 24.04 LTS is supported"

case "$(uname -m)" in
  x86_64)
    NODE_EXPORTER_ARCH=amd64
    NODE_EXPORTER_SHA256=$NODE_EXPORTER_AMD64_SHA256
    ;;
  aarch64)
    NODE_EXPORTER_ARCH=arm64
    NODE_EXPORTER_SHA256=$NODE_EXPORTER_ARM64_SHA256
    ;;
  *)
    fail "unsupported machine architecture"
    ;;
esac

if [[ ${LAB_INSTALLER_PREFLIGHT_ONLY:-0} == 1 ]]; then
  echo "collector installer ${INSTALLER_VERSION}: prerequisites satisfied"
  exit 0
fi

(( EUID == 0 )) || fail "installation must run as root"
[[ ${LAB_SERVER_ID:-} =~ ^[0-9a-f-]{36}$ ]] || fail "LAB_SERVER_ID is required"
[[ ${LAB_ENROLLMENT_URL:-} == https://* ]] || fail "LAB_ENROLLMENT_URL must use HTTPS"

if [[ -t 0 ]]; then
  read -r -s -p "Bootstrap token: " bootstrap_token
  echo >&2
else
  IFS= read -r bootstrap_token
fi
[[ -n "$bootstrap_token" ]] || fail "bootstrap token is required"

requires_nvidia=$(
  printf '%s\n' "$bootstrap_token" | python3 -c '
import json, os, sys, urllib.request

request = urllib.request.Request(
    os.environ["LAB_ENROLLMENT_URL"].rstrip("/")
    + "/api/enrollment/requirements",
    data=json.dumps(
        {
            "serverId": os.environ["LAB_SERVER_ID"],
            "bootstrapToken": sys.stdin.readline().rstrip("\n"),
        }
    ).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=30) as response:
    requirements = json.load(response)
print("1" if requirements["requiresNvidia"] else "0")
'
)
if [[ $requires_nvidia == 1 ]]; then
  command -v nvidia-smi >/dev/null \
    || fail "nvidia-smi is required by this Server Profile"
  nvidia-smi --query-gpu=uuid --format=csv,noheader >/dev/null \
    || fail "the NVIDIA driver cannot enumerate GPUs"
fi

id lab-node-exporter >/dev/null 2>&1 \
  || useradd --system --no-create-home --shell /usr/sbin/nologin lab-node-exporter
install -d -m 0700 -o root -g root /etc/lab-collector/private
install -d -m 0755 -o root -g root /etc/lab-collector

temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"; unset bootstrap_token' EXIT
archive="node_exporter-${NODE_EXPORTER_VERSION}.linux-${NODE_EXPORTER_ARCH}.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/${archive}" \
  --output "$temporary_directory/$archive"
printf '%s  %s\n' "$NODE_EXPORTER_SHA256" "$temporary_directory/$archive" \
  | sha256sum --check --status \
  || fail "node_exporter checksum verification failed"
tar -xzf "$temporary_directory/$archive" -C "$temporary_directory"
install -m 0755 \
  "$temporary_directory/node_exporter-${NODE_EXPORTER_VERSION}.linux-${NODE_EXPORTER_ARCH}/node_exporter" \
  /usr/local/bin/node_exporter

private_key=/etc/lab-collector/private/collector.key
csr=/etc/lab-collector/private/collector.csr
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out "$private_key"
chmod 0600 "$private_key"
openssl req -new -key "$private_key" \
  -subj "/CN=${LAB_SERVER_ID}" \
  -out "$csr"
chmod 0600 "$csr"

export LAB_BOOTSTRAP_CSR_PATH=$csr
export LAB_BOOTSTRAP_CERT_PATH=/etc/lab-collector/private/collector.crt
export LAB_BOOTSTRAP_CA_PATH=/etc/lab-collector/collector-ca.crt
export LAB_SCRAPE_CLIENT_CA_PATH=/etc/lab-collector/scrape-client-ca.crt
printf '%s\n' "$bootstrap_token" | python3 -c '
import json, os, platform, urllib.request
import sys
from pathlib import Path

payload = {
    "serverId": os.environ["LAB_SERVER_ID"],
    "bootstrapToken": sys.stdin.readline().rstrip("\n"),
    "certificateSigningRequest": Path(
        os.environ["LAB_BOOTSTRAP_CSR_PATH"]
    ).read_text(),
    "hostname": platform.node(),
    "osRelease": platform.freedesktop_os_release()["PRETTY_NAME"],
    "architecture": platform.machine(),
}
request = urllib.request.Request(
    os.environ["LAB_ENROLLMENT_URL"].rstrip("/") + "/api/enrollment/bootstrap",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=30) as response:
    issued = json.load(response)
Path(os.environ["LAB_BOOTSTRAP_CERT_PATH"]).write_text(issued["certificate"])
Path(os.environ["LAB_BOOTSTRAP_CA_PATH"]).write_text(issued["caCertificate"])
Path(os.environ["LAB_SCRAPE_CLIENT_CA_PATH"]).write_text(
    issued["scrapeClientCaCertificate"]
)
'
unset bootstrap_token
chmod 0600 /etc/lab-collector/private/collector.crt
chmod 0644 /etc/lab-collector/collector-ca.crt
chmod 0644 /etc/lab-collector/scrape-client-ca.crt

cat >/etc/lab-collector/web-config.yml <<'WEB_CONFIG'
tls_server_config:
  cert_file: /run/credentials/lab-node-exporter.service/collector.crt
  key_file: /run/credentials/lab-node-exporter.service/collector.key
  client_auth_type: RequireAndVerifyClientCert
  client_ca_file: /etc/lab-collector/scrape-client-ca.crt
WEB_CONFIG
chmod 0644 /etc/lab-collector/web-config.yml

cat >/etc/systemd/system/lab-node-exporter.service <<'UNIT'
[Unit]
Description=Lab node exporter
After=network-online.target
Wants=network-online.target

[Service]
User=lab-node-exporter
Group=lab-node-exporter
LoadCredential=collector.key:/etc/lab-collector/private/collector.key
LoadCredential=collector.crt:/etc/lab-collector/private/collector.crt
ExecStart=/usr/local/bin/node_exporter --web.config.file=/etc/lab-collector/web-config.yml
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now lab-node-exporter.service
echo "collector bootstrap complete; server is Pending Verification"
