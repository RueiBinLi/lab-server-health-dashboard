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
```

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
Tailscale Serve. The dashboard offers only server-scoped CPU, system-memory,
and disk history queries to authorized viewers, rather than raw Prometheus or
unrestricted PromQL access.

Verified servers are classified as Healthy, Degraded, or Unavailable from
primary telemetry, required observation completeness, paired CPU pressure,
available system memory, and persistent-filesystem capacity and exhaustion
forecasting. Server Incidents retain cause and severity changes for each
continuous non-Healthy period in SQLite, including across central service
restarts. Lab Users receive explicit safe explanations; Lab Administrators
also receive active causes and incident timing.

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
