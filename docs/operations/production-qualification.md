# Initial two-server production qualification

This runbook is the five-gate production acceptance procedure for the initial
fleet. A Lab Administrator performs it on the production-shaped LAN deployment.
Keep evidence outside the repository in an access-controlled, non-secret
location and copy
`production-acceptance-record.json` there before recording results. Never put
credentials, private keys, bootstrap tokens, webhook URLs, raw logs, or
unredacted configuration in the record or its linked artifacts.

Run gates in order. A failed or incomplete check stops progression. Mandatory
telemetry, security, identity, retention, restoration,
notification-isolation, and rollback checks cannot be waived.

Every check records:

- the accountable Lab Administrator;
- pinned component versions and configuration revisions;
- applicable immutable Server IDs;
- expected and actual results and pass/fail;
- links to timestamped, non-secret evidence; and
- the rollback result, or `not-applicable` with a reason in `actual`.

Each gate also records its ISO-8601 `completedAt` timestamp. Gate completion
timestamps must remain in sequence.

For each check object in the record, add `actor`, `versions`,
`configurationRevisions`, `serverIds`, `expected`, `actual`, `result`,
`evidenceCapturedAt`, `evidenceLinks`, and `rollbackOutcome`. All timestamps
include an explicit timezone.

## Gate 1: central LAN commissioning

Commission through a Lab Administrator SSH port forward before enabling
Tailscale Serve.

1. Record the central host OS, checkout commit, image digests, Compose
   configuration hash, and the resource limits shown by `docker inspect`.
2. Run the deployment validation in `stack-operations.md`. Prove required
   secrets are root-owned mode `0600`, without displaying their contents.
3. Save `docker compose ps`, readiness responses, the machine-readable
   operations summary, filesystem capacity, and swap counters.
4. Create durable test state, restart the stack, and reboot the central host.
   Prove the state, Server Incidents, and audit data survive and all components
   recover.
5. Compare monitored workload processes and training availability before,
   during, and after central restart and reboot. Central operations must not
   restart, pause, or reconfigure either monitored workload.

Set Gate 1 to `pass` only when all seven checks pass.

## Gate 2: first-server enrollment

Assign the intended published Server Profile, register the server, and record
its Server ID. Verify the signed installer fingerprint through the independent
checkout, supply the bootstrap token through hidden input or standard input,
and compare the fingerprint-derived verification code over the existing SSH
session.

Before approval, compare hostname, source address, OS, CPU, memory, persistent
filesystems, GPU devices, Required Services, sensors, and stable identifiers
with Server Inventory. Query Prometheus for every series and label required by
the assigned Server Profile. Missing hardware-dependent evidence is not zero
and blocks approval. Approve first contact only after complete observation.

## Gate 3: second-server enrollment and 72-hour soak

Repeat Gate 2 independently for the second Server ID and its assigned Server
Profile. Then run a continuous representative 72-hour soak with both servers
observed at the 30-second scrape cadence.

Capture timestamped samples of component health, scrape completeness, CPU and
memory, swap in/out counters, state-volume capacity, and Prometheus TSDB growth.
Use observed bytes per hour, including WAL and block growth, to project the
complete 30-day Metric History footprint. Qualification requires no swapping
and at least 20% projected disk free after 30 days. Record the 30-second scrape
cadence, observed Metric History bytes per hour, projected 30-day bytes, state
volume capacity, and non-Metric-History bytes so the validator can independently
recalculate the projection.

For each server and the same representative training workload, collect three
matched throughput runs before collector activation and three after activation.
Keep workload, dataset, accelerator allocation, warm-up, duration, power mode,
and competing activity matched. Enter raw throughput values in the record.
The validator compares medians; a reduction greater than 2% blocks rollout.

## Gate 4: safe failure, recovery, and rollback exercises

Use controlled observation streams and clearly labelled synthetic fixtures.
Do not create real OOM kills, filesystem corruption, storage faults, thermal
pressure, GPU faults, kernel panics, or watchdog resets on production servers.
The existing real-host checks in `critical-errors-real-host-acceptance.md`
cover host integration without dangerous failures.

Exercise every supported Degraded and Unavailable cause, simultaneous-cause
worst-condition precedence, hold/clear timing, counter reset, Server Incident
cause and severity transitions, recovery, and deduplication. Confirm safe Lab
User explanations and detailed Lab Administrator evidence.

With controlled SMTP and Slack endpoints, exercise opening, escalation,
improvement, consolidation, reminder, and recovery delivery. Make each channel
fail independently and prove the other continues. Exercise a Maintenance
Window containing a complete incident and one ending during an active incident.

Complete and retain the results of:

- an isolated restoration from an encrypted off-host backup, within one
  working day, while acknowledging Metric History is rebuilt rather than
  restored;
- planned certificate rotation with overlap, revocation, Re-enrollment
  Required, and re-enrollment preserving Server ID and durable history;
- pinned collector and central-stack upgrades, proving health after each
  upgrade and retaining the exact prior artifacts and configuration;
- one-server-at-a-time collector rollback with workload processes untouched;
  and
- central-stack rollback with readiness, observation, audit, and alerting
  rechecked.

## Gate 5: Tailscale authorization and sign-off

Enable Tailscale Serve as the only normal dashboard entry. For each scenario,
record both the HTTP outcome and absence or presence of role-appropriate fields:

- a Lab Administrator application capability;
- a Lab User application capability;
- a valid identity with neither role;
- missing and malformed identity or capability headers;
- a tagged-device identity;
- direct access to the loopback backend from an unauthorized path; and
- spoofed identity and capability headers sent outside the trusted proxy path.

Confirm Prometheus, Alertmanager, and enrollment interfaces are not exposed
through Tailscale Serve or a public interface. A named Lab Administrator then
records `go` or `no-go`, the timestamp, and the named production rollback owner.

## Validate the record

From the pinned checkout:

```sh
PYTHONPATH=src python3 -m lab_dashboard.qualification validate \
  /path/to/non-secret-production-acceptance-record.json
```

The command returning `qualified` proves that the required record is complete
and its numeric thresholds pass. It does not replace review of linked evidence
or the accountable Lab Administrator's observation.
