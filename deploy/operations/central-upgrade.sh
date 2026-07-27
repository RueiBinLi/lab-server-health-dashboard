#!/bin/sh
set -eu

release=${1:?usage: central-upgrade.sh RELEASE_CHECKOUT}
state=/var/lib/lab-server-health-upgrades
stamp=$(date -u +%Y%m%dT%H%M%SZ)
record="$state/$stamp"

test "$(id -u)" -eq 0
test -f "$release/compose.yaml"
install -d -m 0700 "$record"
docker compose --profile operations run --rm backup
docker compose config --quiet
cp compose.yaml "$record/compose.yaml"
docker compose images --format json >"$record/images.json"
cp "$release/compose.yaml" compose.yaml.next
docker compose -f compose.yaml.next config --quiet
mv compose.yaml compose.yaml.previous
mv compose.yaml.next compose.yaml
if ! docker compose up --detach --wait; then
    mv compose.yaml compose.yaml.failed
    mv compose.yaml.previous compose.yaml
    docker compose up --detach --wait
    exit 1
fi
printf '%s\n' "$record" >"$state/last-successful"
