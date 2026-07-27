#!/bin/sh
set -eu

test "$(id -u)" -eq 0
deployment=/opt/lab-server-health-dashboard
record=$(cat "$deployment/upgrades/last-successful")
rollback_image=$(cat "$record/rollback-image")
test -L "$deployment/previous"
docker image tag "$rollback_image" lab-server-health-dashboard:0.1.0
ln -sfn "$(readlink -f "$deployment/previous")" "$deployment/current.next"
mv -Tf "$deployment/current.next" "$deployment/current"
cd "$deployment/current"
docker compose config --quiet
docker compose up --detach --wait --no-build
curl --fail --silent http://127.0.0.1:3000/health/ready >/dev/null
