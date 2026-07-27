#!/bin/sh
set -eu

release=${1:?usage: central-upgrade.sh RELEASE_CHECKOUT}
deployment=/opt/lab-server-health-dashboard
state="$deployment/upgrades"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
record="$state/$stamp"
candidate="$deployment/releases/$stamp"
rollback_image="lab-server-health-dashboard:rollback-$stamp"

test "$(id -u)" -eq 0
test -f "$release/compose.yaml"
test -L "$deployment/current"
cd "$deployment/current"
install -d -m 0700 "$record" "$candidate"
docker compose --profile operations run --rm backup
docker compose config --quiet
cp compose.yaml "$record/compose.yaml"
docker compose images --format json >"$record/images.json"
docker image tag lab-server-health-dashboard:0.1.0 "$rollback_image"
printf '%s\n' "$rollback_image" >"$record/rollback-image"
cp -a "$release"/. "$candidate"/
docker compose -f "$candidate/compose.yaml" --project-directory "$candidate" \
    config --quiet
if ! docker compose -f "$candidate/compose.yaml" \
    --project-directory "$candidate" up --detach --build --wait; then
    docker image tag "$rollback_image" lab-server-health-dashboard:0.1.0
    docker compose up --detach --wait
    exit 1
fi
ln -sfn "$(readlink -f "$deployment/current")" "$deployment/previous.next"
mv -Tf "$deployment/previous.next" "$deployment/previous"
ln -sfn "$candidate" "$deployment/current.next"
mv -Tf "$deployment/current.next" "$deployment/current"
printf '%s\n' "$record" >"$state/last-successful"
