# Central stack and collector operations

These procedures are for a Lab Administrator on dedicated Ubuntu 24.04 LTS
infrastructure. The central host must not run lab workloads.

## Deploy and validate

Install each checkout under `/opt/lab-server-health-dashboard/releases/` and
make `/opt/lab-server-health-dashboard/current` point to the active release.
Install the three units in `deploy/systemd/`, then run from the active checkout:

```sh
sudo install -d -m 0700 /etc/lab-server-health/secrets
sudo env PYTHONPATH=src python3 -m lab_dashboard.operations validate \
  --secret /etc/lab-server-health/secrets/smtp-password \
  --secret /etc/lab-server-health/secrets/slack-webhook \
  --secret /etc/lab-server-health/secrets/backup-recipients
sudo docker compose config --quiet
sudo systemctl enable --now lab-server-health.service
sudo systemctl enable --now lab-server-health-backup.timer
curl --fail http://127.0.0.1:3000/health/ready
```

Secret files must be root-owned regular files with mode `0600`. This includes
backup recipients/identities, collector trust, SMTP and Slack credentials, and
online intermediate material. Keep the offline root CA physically offline; it
must never be placed in the state volume or a backup.

Inspect `docker compose ps`, Prometheus targets, Alertmanager status, the fleet
enrollment view, storage with `df`, collector certificate expiry in the Lab
Administrator fleet view, `systemctl list-timers`, and the notification-channel
test endpoint. Alert on central filesystem use above 80%, any unhealthy
container, a collector certificate inside its renewal window, a backup older
than 24 hours, or a failed channel test.

The local machine-readable summary combines those checks:

```sh
sudo docker compose --profile operations run --rm operations-status
```

For Server Enrollment, register the Server Profile and server in the Lab
Administrator dashboard, run the returned signed collector installer, compare
its verification code and Server Inventory, then approve first contact. For channel testing,
choose **Test notification channels** in the Lab Administrator dashboard,
confirm both email and Slack delivery, and verify
`channelTestRequestedWithin24Hours` here. That field proves the exercise is
recent; the human delivery confirmation determines channel-test health.

## Backup and restore

`lab-server-health-backup.timer` runs daily and writes age-encrypted archives
to `BACKUP_DESTINATION`, which must be an off-host mounted destination. Each
archive contains a transactionally consistent SQLite snapshot, generated
configuration, Alertmanager state, and online intermediate material.
Prometheus TSDB and the offline root CA are explicitly excluded.

Quarterly, copy one archive and the age identity to an isolated Ubuntu host:

```sh
sudo docker run --rm --network none --user 0:0 --entrypoint python \
  -v "$PWD:/backup:ro" \
  -v /run/restore/identity:/run/restore/identity:ro \
  -v /srv/lab-server-health-restore:/restore \
  lab-server-health-dashboard:0.1.0 \
  -m lab_dashboard.operations restore \
  --archive /backup/BACKUP.tar.gz.age \
  --identity-file /run/restore/identity --target /restore
```

The command refuses a non-empty target, safely extracts, validates the manifest,
and runs SQLite `quick_check`. Start a separate stack against that target and
complete Server Enrollment, notification-channel, and certificate checks within
one working day. Record the archive timestamp (no more than 24 hours old), start
and finish times, and results. Metric History is not restored: Prometheus
rebuilds new history after collectors reconnect.

For certificate recovery, keep the online intermediate in the encrypted backup.
If it is suspected compromised, use the dashboard recovery action, replace it
from the offline root ceremony, and re-enroll every affected collector.

## Upgrade and roll back

Run `deploy/operations/central-upgrade.sh RELEASE_CHECKOUT` as root. It first
backs up, validates Compose, records current image/configuration identity, and
retains the previous Compose file. Failed health checks automatically restore
the prior configuration. Exercise `central-rollback.sh` quarterly and confirm
the ready endpoint and collector observation without stopping monitored lab
workloads.

Upgrade collectors one server at a time with
`collector-upgrade.sh INSTALLER SIGNATURE PUBLIC_KEY`. The script verifies the
signed installer and retains the current installed binaries, units, and
configuration as the prior package before running it.
Wait until the server's Server Health is Healthy and compare the retained
configuration hashes before continuing to the next server. On failure the
script reinstalls the retained package. Never restart a monitored workload as
part of collector upgrade or rollback.

To roll a collector back explicitly, run `collector-rollback.sh`; it restores
the exact retained package and configuration, verifies the saved hashes, and
restarts only the collector service.
