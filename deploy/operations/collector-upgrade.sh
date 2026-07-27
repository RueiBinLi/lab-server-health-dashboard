#!/bin/sh
set -eu

package=${1:?usage: collector-upgrade.sh PACKAGE}
test "$(id -u)" -eq 0
test -f "$package"
install -d -m 0700 /var/lib/lab-server-health-collector/rollback
package_name=$(dpkg-deb --field "$package" Package)
installed_version=$(dpkg-query --showformat='${Version}' --show "$package_name")
(
    cd /var/lib/lab-server-health-collector/rollback
    apt-get download "$package_name=$installed_version"
)
previous_package=$(find /var/lib/lab-server-health-collector/rollback \
    -maxdepth 1 -type f -name '*.deb' | head -n 1)
sha256sum /etc/lab-server-health-collector/* \
    >/var/lib/lab-server-health-collector/rollback/config.sha256
systemctl stop lab-server-health-collector.service
if ! dpkg --install "$package"; then
    dpkg --install "$previous_package"
    systemctl start lab-server-health-collector.service
    exit 1
fi
systemctl start lab-server-health-collector.service
systemctl is-active --quiet lab-server-health-collector.service
