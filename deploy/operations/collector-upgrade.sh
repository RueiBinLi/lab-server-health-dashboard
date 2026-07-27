#!/bin/sh
set -eu

installer=${1:?usage: collector-upgrade.sh INSTALLER SIGNATURE PUBLIC_KEY}
signature=${2:?usage: collector-upgrade.sh INSTALLER SIGNATURE PUBLIC_KEY}
public_key=${3:?usage: collector-upgrade.sh INSTALLER SIGNATURE PUBLIC_KEY}
test "$(id -u)" -eq 0
test -f "$installer"
test -f "$signature"
test -f "$public_key"
openssl pkeyutl -verify -pubin -inkey "$public_key" -rawin \
    -in "$installer" -sigfile "$signature"
install -d -m 0700 /var/lib/lab-server-health-collector/rollback
rollback=$(mktemp -d \
    /var/lib/lab-server-health-collector/rollback/release.XXXXXX)
find /etc/lab-collector /usr/local/bin /usr/local/libexec \
    /etc/systemd/system -type f \
    \( -path '/etc/lab-collector/*' \
    -o -name 'node_exporter' \
    -o -name 'lab-collector-*' \
    -o -name 'lab-critical-errors-*' \
    -o -name 'lab-node-exporter.service' \
    -o -name 'lab-dcgm-exporter.service' \) \
    >"$rollback/package-files"
tar -C / -czf "$rollback/previous-package.tar.gz" \
    -T "$rollback/package-files"
tar -C /etc -czf "$rollback/configuration.tar.gz" lab-collector
find /etc/lab-collector -type f -exec sha256sum {} + \
    >"$rollback/config.sha256"
printf '%s\n' "$rollback" \
    >/var/lib/lab-server-health-collector/rollback/last-valid
systemctl stop lab-node-exporter.service
if ! /bin/sh "$installer"; then
    tar -C / -xzf "$rollback/previous-package.tar.gz"
    tar -C /etc -xzf "$rollback/configuration.tar.gz"
    systemctl daemon-reload
    systemctl start lab-node-exporter.service
    exit 1
fi
systemctl start lab-node-exporter.service
systemctl is-active --quiet lab-node-exporter.service
sha256sum --check "$rollback/config.sha256"
