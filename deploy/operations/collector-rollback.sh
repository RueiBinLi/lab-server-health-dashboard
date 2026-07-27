#!/bin/sh
set -eu

test "$(id -u)" -eq 0
rollback=$(cat /var/lib/lab-server-health-collector/rollback/last-valid)
test -f "$rollback/previous-package.tar.gz"
test -f "$rollback/configuration.tar.gz"
systemctl stop lab-node-exporter.service
tar -C / -xzf "$rollback/previous-package.tar.gz"
tar -C /etc -xzf "$rollback/configuration.tar.gz"
systemctl daemon-reload
sha256sum --check "$rollback/config.sha256"
systemctl start lab-node-exporter.service
systemctl is-active --quiet lab-node-exporter.service
