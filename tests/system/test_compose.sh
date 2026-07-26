#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export COMPOSE_PROJECT_NAME="lab-server-health-system-test"
export DASHBOARD_PORT="18080"

cd "$repository_root"

cleanup() {
  docker compose down --volumes --remove-orphans
}
trap cleanup EXIT

docker compose up --detach --build --wait
python3 tests/system/assert_http.py "http://127.0.0.1:$DASHBOARD_PORT"

database_mode="$(
  docker compose exec -T dashboard python -c \
    "import os,sqlite3; connection=sqlite3.connect(os.environ['DASHBOARD_DB_PATH']); print(connection.execute('PRAGMA journal_mode').fetchone()[0])"
)"
test "$database_mode" = "wal"

container_logs="$(docker compose logs --no-color dashboard)"
! grep -F "Tailscale-User-Login" <<<"$container_logs"
! grep -F "Tailscale-App-Capabilities" <<<"$container_logs"
! grep -F "ada@example.com" <<<"$container_logs"
! grep -F "unknown@example.com" <<<"$container_logs"

docker compose stop
docker compose start --wait
python3 tests/system/assert_http.py "http://127.0.0.1:$DASHBOARD_PORT"
