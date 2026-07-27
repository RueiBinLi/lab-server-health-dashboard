#!/usr/bin/env bash
set -euo pipefail

INSTALLER_VERSION=1.2.0
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
import json, os, platform, subprocess, urllib.request
import sys
from pathlib import Path

def read_text(path, fallback):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return fallback

cpu_model = "Unknown CPU"
for line in read_text("/proc/cpuinfo", "").splitlines():
    if line.startswith(("model name", "Model")) and ":" in line:
        cpu_model = line.split(":", 1)[1].strip()
        break
cpu = {"model": cpu_model, "logicalCount": os.cpu_count() or 1}

memory_kib = 0
for line in read_text("/proc/meminfo", "").splitlines():
    if line.startswith("MemTotal:"):
        memory_kib = int(line.split()[1])
        break
memory = {"totalBytes": memory_kib * 1024}

block_devices = json.loads(
    subprocess.run(
        [
            "lsblk", "--json", "--bytes",
            "--output", "NAME,TYPE,MODEL,SERIAL,WWN,SIZE,MOUNTPOINTS",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
)["blockdevices"]
disks = []
for device in block_devices:
    if device["type"] != "disk":
        continue
    mounts = [
        mount for mount in (device.get("mountpoints") or []) if mount
    ]
    disks.append(
        {
            "stableId": (
                device.get("wwn")
                or device.get("serial")
                or device["name"]
            ),
            "model": (device.get("model") or "Unknown disk").strip(),
            "sizeBytes": int(device["size"]),
            "mounts": mounts,
        }
    )

gpus = []
if subprocess.run(
    ["sh", "-c", "command -v nvidia-smi"],
    capture_output=True,
).returncode == 0:
    gpu_rows = subprocess.run(
        [
            "nvidia-smi",
            "--query-gpu=uuid,name,memory.total",
            "--format=csv,noheader,nounits",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    for row in gpu_rows:
        stable_id, model, memory_mib = (
            value.strip() for value in row.split(",", 2)
        )
        gpus.append(
            {
                "stableId": stable_id,
                "model": model,
                "memoryBytes": int(memory_mib) * 1024 * 1024,
            }
        )

stable_identifiers = {
    "machineId": read_text("/etc/machine-id", "unavailable"),
    "systemUuid": read_text(
        "/sys/class/dmi/id/product_uuid", "unavailable"
    ),
}
payload = {
    "serverId": os.environ["LAB_SERVER_ID"],
    "bootstrapToken": sys.stdin.readline().rstrip("\n"),
    "certificateSigningRequest": Path(
        os.environ["LAB_BOOTSTRAP_CSR_PATH"]
    ).read_text(),
    "hostname": platform.node(),
    "osRelease": platform.freedesktop_os_release()["PRETTY_NAME"],
    "architecture": platform.machine(),
    "cpu": cpu,
    "memory": memory,
    "disks": disks,
    "gpus": gpus,
    "stableIdentifiers": stable_identifiers,
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
print("Verification code: {}".format(issued["verificationCode"]))
'
unset bootstrap_token
chmod 0600 /etc/lab-collector/private/collector.crt
chmod 0644 /etc/lab-collector/collector-ca.crt
chmod 0644 /etc/lab-collector/scrape-client-ca.crt

install -d -m 0755 -o lab-node-exporter -g lab-node-exporter \
  /var/lib/lab-node-exporter/textfile
cat >/usr/local/bin/lab-collector-textfile <<'TEXTFILE_COLLECTOR'
#!/usr/bin/env bash
set -euo pipefail

directory=/var/lib/lab-node-exporter/textfile
temporary="$directory/enrollment.prom.$$"
critical_errors=$(
  journalctl --boot --priority=crit --quiet --no-pager 2>/dev/null \
    | wc -l || true
)
printf 'lab_critical_errors_total %d\n' "$critical_errors" >"$temporary"

if command -v nvidia-smi >/dev/null; then
  gpu_faults=$(
    journalctl --boot --dmesg --quiet --no-pager 2>/dev/null \
      | grep -c 'NVRM: Xid' || true
  )
  nvidia-smi \
    --query-gpu=uuid,utilization.gpu,memory.used,memory.total,temperature.gpu \
    --format=csv,noheader,nounits \
    | while IFS=, read -r uuid utilization memory_used memory_total temperature
      do
        uuid=${uuid// /}
        utilization=${utilization// /}
        printf 'lab_gpu_utilization_ratio{gpu="%s"} %s\n' \
          "$uuid" "$(awk -v value="$utilization" \
            'BEGIN { printf "%.4f", value / 100 }')"
        printf 'lab_gpu_vram_used_bytes{gpu="%s"} %d\n' \
          "$uuid" "$(( ${memory_used// /} * 1024 * 1024 ))"
        printf 'lab_gpu_vram_total_bytes{gpu="%s"} %d\n' \
          "$uuid" "$(( ${memory_total// /} * 1024 * 1024 ))"
        printf 'lab_gpu_temperature_celsius{gpu="%s"} %s\n' \
          "$uuid" "${temperature// /}"
        printf 'lab_gpu_faults_total{gpu="%s"} %d\n' \
          "$uuid" "$gpu_faults"
      done >>"$temporary"
fi
chmod 0644 "$temporary"
mv "$temporary" "$directory/enrollment.prom"
TEXTFILE_COLLECTOR
chmod 0755 /usr/local/bin/lab-collector-textfile
/usr/local/bin/lab-collector-textfile

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
ExecStart=/usr/local/bin/node_exporter --web.config.file=/etc/lab-collector/web-config.yml --collector.textfile.directory=/var/lib/lab-node-exporter/textfile --collector.systemd
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

cat >/etc/systemd/system/lab-collector-textfile.service <<'UNIT'
[Unit]
Description=Update Lab Server Health collector metrics

[Service]
Type=oneshot
ExecStart=/usr/local/bin/lab-collector-textfile
UNIT

cat >/etc/systemd/system/lab-collector-textfile.timer <<'UNIT'
[Unit]
Description=Refresh Lab Server Health collector metrics

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now lab-node-exporter.service
systemctl enable --now lab-collector-textfile.timer
echo "collector bootstrap complete; server is Pending Verification"
