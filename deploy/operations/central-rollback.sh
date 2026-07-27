#!/bin/sh
set -eu

test "$(id -u)" -eq 0
test -f compose.yaml.previous
docker compose config --quiet
mv compose.yaml compose.yaml.rolled-back
mv compose.yaml.previous compose.yaml
docker compose config --quiet
docker compose up --detach --wait
curl --fail --silent http://127.0.0.1:3000/health/ready >/dev/null
