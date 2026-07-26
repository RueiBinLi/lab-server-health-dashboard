# Lab Server Health Dashboard

The walking skeleton is a private, role-aware dashboard backed by SQLite. It
binds only to loopback so Tailscale Serve can be the production entry point.
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

## Test

Run the Python suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Run the deployed-system authorization and lifecycle test:

```bash
tests/system/test_compose.sh
```
