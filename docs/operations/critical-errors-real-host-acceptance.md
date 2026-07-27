# Critical Errors real-host acceptance

Run this acceptance on every supported Server Profile and operating-system
image before enabling Critical Error alerting.

## Required permissions and isolation

- Confirm `lab-node-exporter.service` runs as `lab-node-exporter` without
  journal, pstore, watchdog, or root access.
- Confirm `lab-critical-errors.service` is a root-owned oneshot with
  `PrivateNetwork=true`, fixed executables and inputs, and write access limited
  to `/var/lib/lab-critical-errors` and the node-exporter textfile directory.
- Confirm the textfile directory and helper state are not writable by the
  network-facing exporter account.
- Run the timer repeatedly against unchanged evidence. All durable counters
  must remain unchanged and the published `.prom` file must always parse.

## Platform-dependent evidence

- **Journal:** persistent journaling must retain the previous boot when journal
  fallback is expected. Validate the kernel journal permissions and generate a
  harmless representative fixture; do not create a real storage fault.
- **Pstore:** `/sys/fs/pstore` requires kernel support and a firmware/platform
  backend. Where `systemd-pstore` archives and clears live pstore, verify that
  the previous-boot journal remains available. Absence must produce
  `lab_health_evidence_available{source="pstore"} 0`, never a false zero-event
  claim.
- **Watchdog:** validate the meaning and reset behavior of each platform's
  `/sys/class/watchdog/watchdog*/bootstatus`. Drivers that expose no boot cause
  must produce availability `0`; they require a documented BMC/platform adapter
  before watchdog detection can be accepted.

## Observation and lifecycle checks

1. Verify `node_vmstat_oom_kill` and `node_filesystem_readonly` are present for
   every configured persistent mount.
2. Verify helper last-success age, all evidence-availability series, and
   `node_textfile_scrape_error` are visible in Prometheus.
3. Feed fixture evidence for two simultaneous storage errors, a prior panic,
   and a watchdog reset. Verify bounded labels, one increment per durable event,
   and no increment on a repeated timer run.
4. Reboot the host and restart node_exporter. Verify counter resets do not
   manufacture events and previously deduplicated helper evidence is not
   counted again.
5. Verify a read-only condition clears only after five continuous healthy
   minutes and a discrete event remains Degraded for 30 minutes.
6. Acknowledge the event as a Lab Administrator. Verify the acknowledgment is
   recorded, Server Health is unchanged, Lab Users cannot see Critical Error
   detail, and the `critical-errors` Metric History remains queryable after the
   latch clears.
