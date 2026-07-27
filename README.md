# Lab Server Health Dashboard

The dashboard is a private, role-aware service backed by SQLite and Prometheus.
Both services bind only to loopback so Tailscale Serve can be the production
entry point. Prometheus scrapes each verified collector over its per-server
mTLS identity every 30 seconds and retains Metric History locally for 30 days.
Identity and application-capability headers are accepted only from configured
trusted proxy networks. Tailscale Grants map `group:lab-admins` and
`group:lab-users` to the Lab Administrator and Lab User roles.

## Run the central stack

Create `/etc/lab-server-health/dashboard.env`:

```text
DASHBOARD_PORT=3000
DASHBOARD_PUBLIC_URL=https://lab-dashboard.example.ts.net
ALERT_SMTP_SMARTHOST=smtp.example.com:465
ALERT_SMTP_FROM=lab-alerts@example.com
ALERT_SMTP_TO=lab-administrators@example.com
ALERT_SMTP_USERNAME=lab-alerts@example.com
ALERT_SMTP_PASSWORD_PATH=/etc/lab-server-health/secrets/smtp-password
ALERT_SLACK_WEBHOOK_PATH=/etc/lab-server-health/secrets/slack-webhook
BACKUP_RECIPIENTS_PATH=/etc/lab-server-health/secrets/backup-recipients
BACKUP_DESTINATION=/mnt/off-host-backups/lab-server-health
```

Create both credential files as root-owned regular files with mode `0600`.
The SMTP relay must use TLS, and the Slack file contains the incoming webhook
URL for the private Lab Administrator channel. The stack refuses to generate
Alertmanager configuration when either file is missing, empty, or accessible
by group or other users. Credentials are referenced by protected file path and
are never copied into generated configuration.

Start and inspect the pinned stack:

```bash
sudo systemctl enable --now lab-server-health.service
docker compose ps
curl http://127.0.0.1:3000/health/ready
```

Install `deploy/systemd/lab-server-health.service` under `/etc/systemd/system/`
and place the checkout at `/opt/lab-server-health-dashboard`. Configure the
tailnet policy so each group receives exactly one
`rueibinli.github.io/cap/lab-server-health` capability:

```json
{
  "grants": [
    {
      "src": ["group:lab-admins"],
      "dst": ["tag:lab-dashboard"],
      "app": {
        "rueibinli.github.io/cap/lab-server-health": [
          {"role": "lab-administrator"}
        ]
      }
    },
    {
      "src": ["group:lab-users"],
      "dst": ["tag:lab-dashboard"],
      "app": {
        "rueibinli.github.io/cap/lab-server-health": [
          {"role": "lab-user"}
        ]
      }
    }
  ]
}
```

Then make Tailscale Serve the only normal entry point:

```bash
tailscale serve --bg \
  --accept-app-caps=rueibinli.github.io/cap/lab-server-health \
  3000
```

Do not change `DASHBOARD_HOST` to a non-loopback address.
Prometheus also listens only on `127.0.0.1:19090`; do not proxy that port through
Tailscale Serve. Alertmanager listens only on `127.0.0.1:19093` and is likewise
not proxied. The dashboard offers only server-scoped CPU, system-memory,
and disk history queries to authorized viewers, rather than raw Prometheus or
unrestricted PromQL access.

Application capabilities are mandatory by default. If the deployed Tailscale
version cannot supply them, fallback must be selected explicitly with
`DASHBOARD_AUTH_MODE=identity-allowlist` and at least one exact login in
`DASHBOARD_LAB_ADMINISTRATOR_LOGINS` or `DASHBOARD_LAB_USER_LOGINS`
(comma-separated). The dashboard does not switch modes automatically; unknown
and unlisted identities remain denied. Keep the backend loopback-bound in
either mode.

Daily encrypted backup, isolated restoration, controlled upgrade, and rollback
procedures are documented in
[`docs/operations/stack-operations.md`](docs/operations/stack-operations.md).
The initial two-server rollout must also pass the sequential, evidence-driven
[`production qualification`](docs/operations/production-qualification.md);
its machine-checkable record cannot substitute for real-host evidence or an
accountable Lab Administrator's sign-off.

Verified servers are classified as Healthy, Degraded, or Unavailable from
primary telemetry, required observation completeness, paired CPU pressure,
available system memory, and persistent-filesystem capacity and exhaustion
forecasting. Server Incidents retain cause and severity changes for each
continuous non-Healthy period in SQLite, including across central service
restarts. Lab Users receive explicit safe explanations; Lab Administrators
also receive active causes and incident timing.

Alertmanager is the only component that sends Critical Alerts externally.
It groups and deduplicates by immutable Server ID and Server Incident identity:
initial Degraded delivery waits 30 seconds, Unavailable and severity transitions
route immediately, cause additions consolidate for five minutes, open incidents
repeat every four hours, and a short-lived recovery signal sends immediately.
Email and Slack are separate receivers with resolved delivery enabled. Delivery
is best-effort at least once, so downstream test and operational receivers must
tolerate duplicates.

Resource Usage reports CPU as percent used, memory and persistent filesystems
as used/total GiB plus percent, and the age of the newest scrape. Missing series
are displayed as missing instead of zero. Lab Administrators additionally see
collector scrape success, while Lab Users do not receive scrape addresses,
collector internals, or verified inventory.

## Verify the collector installer

The collector installer is pinned at version `1.2.0`. Its offline Ed25519
signing public key has this SHA-256 fingerprint:

```text
a1aa38ed95a8a0409642d2d1775d159dc9005a29441def0a86113f6e6de65942
```

Compare that fingerprint with the independently trusted checkout before using
installer metadata returned with a bootstrap token. The dashboard verifies the
committed detached signature before returning the installer; the response
contains the same script, base64 signature, public key, and fingerprint so a
Lab Administrator can verify it again before execution.

## Test

Run the Python suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Run the deployed-system authorization and lifecycle test:

```bash
tests/system/test_compose.sh
```
