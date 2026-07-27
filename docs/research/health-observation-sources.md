# V1 health-observation sources

Research date: 2026-07-26

## Question

Can Prometheus, `node_exporter`, NVIDIA `dcgm-exporter`, and (where
necessary) the `node_exporter` textfile collector expose every observation
needed by the agreed Server Health rules?

## Conclusion

Not entirely with their stock configurations.

- Prometheus plus `node_exporter` directly cover primary scrape status,
  CPU/load, available memory, host OOM-kill count, filesystem capacity and
  current read-only state, hardware temperatures, CPU thermal-throttle
  counters, and—after explicitly enabling it—systemd unit state.
- `dcgm-exporter` directly covers GPU inventory labels, utilization, VRAM,
  and temperature. Reliable XID history, uncorrectable ECC, GPU thermal
  limiting, and the hardware slowdown temperature require opt-in or custom
  DCGM fields; they are not all active in the shipped default collector.
- The selected exporters do **not** provide a generic kernel storage-I/O-error
  event counter, an unambiguous GPU-reset event counter, or universal evidence
  of a panic/watchdog reset from the preceding boot. Those require a separate,
  least-privileged helper or another specialized exporter/log pipeline.

Versions must be pinned. The metric inventory below reflects current upstream
documentation and source on the research date. Deployment acceptance should
also inspect the actual `/metrics` output on every Server Profile because
kernel, driver, hardware, permissions, and exporter version determine whether
optional fields exist. NVIDIA explicitly warns that selecting a DCGM field
does not guarantee runtime emission ([DCGM Exporter metrics]).

## Coverage matrix

| Required observation | Source and exact series | Coverage and caveats |
| --- | --- | --- |
| Primary target reachability | Prometheus-generated `up{job="node-exporter", instance="…"}` | Direct. `1` means the scrape succeeded and `0` means it failed. This proves reachability of the exporter endpoint, not ICMP, SSH, or workloads. A removed target, or an unhealthy Prometheus server, needs separate control-plane detection rather than `up == 0` alone. Prometheus also creates `scrape_duration_seconds` and scrape sample-count series ([Prometheus jobs and instances]). |
| CPU utilization | `node_cpu_seconds_total{cpu,mode}` from the default `cpu` collector | Direct but derived, not a percent gauge. For example, use `1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m]))`; multiply by 100 for percent. The collector reads `/proc/stat` ([node_exporter CPU source]). |
| Five-minute load and logical CPU count | `node_load5`; count the per-CPU `node_cpu_seconds_total{mode="idle"}` series | Direct. The default `loadavg` collector also exposes `node_load1` and `node_load15` from `/proc/loadavg` ([node_exporter load source]). Normalize `node_load5` by the observed logical-CPU count. |
| Available and total memory | `node_memory_MemAvailable_bytes`, `node_memory_MemTotal_bytes` from the default `meminfo` collector | Direct when the Linux kernel exports `MemAvailable`. Linux defines it as an estimate of memory available for new applications without swapping, accounting for reclaimable cache and watermarks ([Linux `/proc` documentation], [node_exporter meminfo source]). |
| OOM kill | `node_vmstat_oom_kill` from the default `vmstat` collector | Direct host counter from `/proc/vmstat`; detect events with `increase(…[window]) > 0`. It is not durable evidence across every reboot/retention gap, so use Prometheus history rather than treating the current scalar as an event log ([node_exporter vmstat source]). |
| Filesystem capacity and trend | `node_filesystem_avail_bytes`, `node_filesystem_size_bytes` from the default `filesystem` collector | Direct. `avail_bytes` is space available to non-root users. Calculate percent headroom and the 24-hour exhaustion forecast in PromQL or application logic. Use the collector's mount-point and filesystem-type filters to match profile-selected persistent filesystems ([node_exporter filesystem source], [node_exporter collector filters]). |
| Filesystem read-only state | `node_filesystem_readonly{device,mountpoint,fstype}` | Direct current state. This supports the persistent read-only fault rule. A transient remount that begins and ends between scrapes is not guaranteed to be observed ([node_exporter filesystem source]). |
| Storage I/O errors | No generic error-event series in the selected exporters | **Gap.** `node_filesystem_device_error` only means `node_exporter` failed while obtaining filesystem statistics; it is not a media, controller, or kernel I/O-error counter. The `diskstats` collector exposes operations, bytes, and time, not generic I/O error events ([node_exporter filesystem source], [node_exporter diskstats source]). Use a journal/kernel-event helper, or a device-specific SMART/NVMe/RAID exporter. Do not infer an I/O error solely from high latency. |
| CPU temperature and hardware limit | `node_hwmon_temp_celsius`; where the driver supplies them, `node_hwmon_temp_crit_celsius`, `node_hwmon_temp_max_celsius`, and related properties, labeled by `chip` and `sensor` | Direct but hardware-dependent. The `hwmon` collector dynamically maps `tempN_input`, `tempN_crit`, `tempN_max`, and other sysfs properties, and those sysfs properties are optional ([node_exporter hwmon source], [Linux hwmon ABI]). Profiles therefore must identify required `chip`/`sensor` series and treat missing required readings/limits as incomplete coverage. |
| CPU thermal throttling | `node_cpu_core_throttles_total{package,core}`, `node_cpu_package_throttles_total{package}` | Direct where the kernel/platform provides the corresponding `thermal_throttle/*_throttle_count` sysfs files. Absence is possible and must not be interpreted as zero throttling ([node_exporter CPU source]). |
| GPU presence and identity | Distinct GPU entity labels on DCGM series: `gpu`, `gpu_uuid`, `pci_bus_id`, `device`, and `model_name` when populated | Direct. Compare the set/count of `gpu_uuid` labels on a required DCGM metric with the profile's expected inventory. `up{job="dcgm-exporter"} == 1` is insufficient because the exporter may be reachable while a GPU or field is missing ([DCGM Exporter metrics]). |
| GPU utilization | `DCGM_FI_DEV_GPU_UTIL` | Direct and active in the shipped default collector. Current DCGM names its canonical source `DCGM_FI_DEV_GPU_UTIL_RATIO`, while retaining the configured exporter name shown here ([DCGM Exporter metrics]). |
| GPU VRAM | `DCGM_FI_DEV_FB_USED`, `DCGM_FI_DEV_FB_FREE`, and `DCGM_FI_DEV_FB_RESERVED` | Direct and active in the shipped default collector. Values are framebuffer memory quantities; high use alone is not an error ([DCGM Exporter metrics]). |
| GPU temperature and slowdown headroom | `DCGM_FI_DEV_GPU_TEMP` is active by default; add `DCGM_FI_DEV_SLOWDOWN_TEMP` (canonical `DCGM_FI_DEV_GPU_TEMP_SLOWDOWN_CELSIUS`) to a custom collector | Supported, but the limit needs custom configuration and compatible DCGM/hardware. Calculate headroom from slowdown temperature minus current temperature. Validate names against the pinned exporter/DCGM pair because DCGM has introduced canonical-name changes ([DCGM Exporter metrics], [DCGM release notes]). |
| GPU thermal throttling | Opt in to `DCGM_FI_DEV_THERMAL_VIOLATION`, or the exporter-owned `DCGM_EXP_CLOCK_EVENTS_TOTAL{clock_event=~"sw_thermal|hw_thermal"}` | Supported but not active by default. The former is shipped as a commented optional field; exporter-owned clock-event totals are also opt-in and reset when the exporter restarts or reloads. `hw_slowdown` is broader than temperature alone and should not be relabeled as thermal without checking the reason ([DCGM Exporter metrics], [dcgm-exporter command reference]). |
| GPU XID event | Default `DCGM_FI_DEV_XID_ERRORS`; preferably opt-in `DCGM_EXP_XID_ERRORS_TOTAL{xid}` | Partial by default. The default field is a last-XID gauge, not a durable incident counter. The opt-in exporter-owned total counts nonzero XID records observed since collector start, but resets on exporter restart/reload and a series appears only after that XID occurs. Persist events in Prometheus and handle counter resets; use kernel-log ingestion if events must survive collection gaps ([DCGM Exporter metrics], [NVIDIA XID introduction]). |
| GPU uncorrectable ECC | Add `DCGM_FI_DEV_ECC_DBE_VOL_TOTAL` and `DCGM_FI_DEV_ECC_DBE_AGG_TOTAL` | Supported but shipped commented/disabled. Alert on an increase in volatile double-bit errors or an unexpected increase in the monotonically increasing aggregate total. Emission depends on ECC-capable hardware and driver/DCGM support ([DCGM Exporter metrics], [DCGM field identifiers]). |
| GPU reset event | No unambiguous shipped reset-event counter | **Gap.** XIDs can indicate faults or a recovery action, but neither the default XID gauge nor an inferred disappearance proves that a reset occurred. Use NVIDIA kernel-log/event ingestion or a version-pinned custom DCGM/NVML source if the rule must literally detect reset events ([NVIDIA XID introduction], [NVIDIA XID catalog]). |
| Required systemd service active/failed/inactive | `node_systemd_unit_state{name,state,type}` with states `active`, `activating`, `deactivating`, `inactive`, and `failed` | Direct after enabling the default-disabled `systemd` collector. Restrict it using `--collector.systemd.unit-include` to the profile's required units. Compare the expected names with returned names: an absent required unit is an absence condition, not `state="failed"`. Also check `node_scrape_collector_success{collector="systemd"}` ([node_exporter systemd source], [node_exporter collector inventory]). |
| Prior kernel panic | No stock node_exporter series | **Gap.** A boot-time helper can inspect pstore when the kernel and platform provide a persistent backend. Linux documents `/sys/fs/pstore` as retaining kernel logs over reset, and `systemd-pstore` can archive them to `/var/lib/systemd/pstore` before clearing the live store ([Linux pstore documentation]). Persistent previous-boot journal records are a fallback, not universal proof. |
| Prior watchdog reset | `watchdog` collector data from `/sys/class/watchdog` when supported; otherwise no universal series | Partial and platform-dependent. Current `node_exporter` includes the Linux watchdog collector, but a driver may expose no usable boot-status cause, and its absence cannot prove there was no watchdog reset ([node_exporter collector inventory]). Export a boot-scoped result from a helper that understands the actual watchdog/BMC/platform source. Keep `watchdog_boot_status_available` distinct from `previous_panic_evidence_available`. |

## Required v1 configuration

1. Keep the default `cpu`, `loadavg`, `meminfo`, `vmstat`, `filesystem`,
   `hwmon`, and `diskstats` collectors enabled.
2. Explicitly enable `--collector.systemd`, restricted to the required-unit
   patterns. Validate that the intended runtime identity can query the system
   D-Bus; do not enable node_exporter's discouraged private-systemd mode merely
   to gain root access ([node_exporter systemd source]).
3. Configure the filesystem collector to include only profile-selected
   persistent mounts or to exclude pseudo, temporary, container-overlay, and
   image filesystems.
4. Pin a paired DCGM and `dcgm-exporter` release. Use a custom DCGM collector
   that retains the active defaults and adds:

   - `DCGM_FI_DEV_SLOWDOWN_TEMP`
   - `DCGM_FI_DEV_THERMAL_VIOLATION` or
     `DCGM_EXP_CLOCK_EVENTS_TOTAL`
   - `DCGM_EXP_XID_ERRORS_TOTAL`
   - `DCGM_FI_DEV_ECC_DBE_VOL_TOTAL`
   - `DCGM_FI_DEV_ECC_DBE_AGG_TOTAL`

   NVIDIA's install documentation notes that `customMetrics` replaces rather
   than extends the shipped list, so the complete desired field set must be
   declared ([install DCGM Exporter]).
5. At enrollment, inventory the actual series and labels for the Server
   Profile. Missing required observations must feed the agreed incomplete
   coverage rule; unsupported optional properties must not silently become
   zero.
6. Add a root-owned or otherwise narrowly privileged boot/timer helper for:

   - kernel storage-I/O error events,
   - an explicit GPU-reset event source,
   - pstore/previous-boot panic evidence, and
   - platform watchdog-reset evidence not covered by sysfs.

## Supplemental helper and textfile design

The `node_exporter` textfile collector reads every `*.prom` file in its
configured directory and does not support client timestamps. Upstream
recommends writing a temporary file and atomically renaming it into place
([node_exporter textfile collector]). It also exposes
`node_textfile_scrape_error` and per-file modification-time data
([node_exporter textfile source]).

The helper should export monotonic counters and/or a Unix event time as the
metric **value**, plus explicit availability and freshness series. Suggested
families—not upstream names—are:

```text
lab_health_storage_io_errors_total{class,device}
lab_health_gpu_resets_total{gpu_uuid}
lab_health_previous_panic_detected
lab_health_previous_panic_unixtime
lab_health_watchdog_reset_detected
lab_health_watchdog_reset_unixtime
lab_health_evidence_available{source}
lab_health_observer_last_success_unixtime{observer}
```

These names are an application contract and need their own specification.
Persist a deduplication key such as boot ID plus source event identity in the
helper's private state so each timer execution does not count the same event
again; do not use the ever-changing boot ID as a Prometheus label. Because
client timestamps are rejected, export the event time as its own metric value
and do not put timestamps after samples in the Prometheus text format.

### Security boundary

- Run `node_exporter` without root privileges. A separate helper may need
  privileged reads, but granting journal/pstore/device access to the exporter
  would unnecessarily enlarge the long-running network service's authority.
- Give the helper fixed commands and inputs, no user-controlled shell
  fragments, no network access, read-only access to the minimum journal,
  pstore, or device paths, and write access only to a private staging/output
  location.
- Make the final textfile directory writable only by the dedicated helper
  identity. Anyone who can write there can inject or replace host metrics,
  manufacture label cardinality, or supply malformed input.
- Write with a temporary file and atomic rename; use fixed metric and label
  sets; monitor `node_textfile_scrape_error` and observer freshness.
- Reading all system journal entries normally requires root or membership in
  `systemd-journal`, `adm`, or `wheel`. The latter groups may carry unrelated
  distribution-specific privileges, so a tightly sandboxed root oneshot can be
  safer than adding the network-facing exporter account to them
  ([journalctl]).
- Restrict both exporter endpoints to the private monitoring network and use
  TLS/authentication where the chosen deployment supports it. Prometheus warns
  that HTTP endpoints should not be exposed publicly and can be denial-of-
  service targets ([Prometheus security model]). `dcgm-exporter`'s documented
  direct-container example adds `SYS_ADMIN`, which is a significant privilege;
  prefer a package-managed service or separated DCGM host engine where feasible
  and protect any container deployment accordingly ([dcgm-exporter upstream]).

## Operational limits

- `up` and all scrape-derived health depend on Prometheus itself. Monitor the
  Prometheus service and rule-evaluation path separately.
- Scrape interval and timeout must be short enough to support the agreed
  two-minute/one-minute transition windows. The configured cadence, rather
  than product defaults, is the contract.
- Prometheus counters can reset on host reboot, exporter restart, or collector
  reload. Use `increase`/`resets`-aware evaluation and retain event history in
  Prometheus or application storage.
- `node_scrape_collector_success` detects a collector failure, but not a
  semantically missing profile-required series inside an otherwise successful
  scrape. Required-series set comparison is still necessary.
- Profiles should identify sensors, filesystems, units, and GPUs by stable
  labels. `hwmon` numbering can vary with module/device discovery; validate
  `chip`/`sensor` mappings on each hardware profile.
- Journal-only evidence has retention and permission dependencies. Configure
  persistent journaling if it is part of the contract; `journalctl -k -b -1`
  can query the previous boot only when those records still exist
  ([journalctl]). pstore also requires kernel support and a platform backend.

## Primary sources

- [Prometheus jobs and instances]
- [Prometheus scrape configuration]
- [Prometheus security model]
- [node_exporter collector inventory and filters]
- [node_exporter CPU source]
- [node_exporter load source]
- [node_exporter meminfo source]
- [node_exporter vmstat source]
- [node_exporter filesystem source]
- [node_exporter diskstats source]
- [node_exporter hwmon source]
- [node_exporter systemd source]
- [node_exporter textfile source]
- [Linux `/proc` documentation]
- [Linux hwmon ABI]
- [Linux pstore documentation]
- [journalctl]
- [DCGM Exporter metrics]
- [dcgm-exporter command reference]
- [install DCGM Exporter]
- [DCGM field identifiers]
- [DCGM release notes]
- [NVIDIA XID introduction]
- [NVIDIA XID catalog]
- [dcgm-exporter upstream]

[Prometheus jobs and instances]: https://prometheus.io/docs/concepts/jobs_instances/
[Prometheus scrape configuration]: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config
[Prometheus security model]: https://prometheus.io/docs/operating/security/
[node_exporter collector inventory and filters]: https://github.com/prometheus/node_exporter
[node_exporter collector inventory]: https://github.com/prometheus/node_exporter#collectors
[node_exporter collector filters]: https://github.com/prometheus/node_exporter#collectors
[node_exporter CPU source]: https://github.com/prometheus/node_exporter/blob/master/collector/cpu_linux.go
[node_exporter load source]: https://github.com/prometheus/node_exporter/blob/master/collector/loadavg.go
[node_exporter meminfo source]: https://github.com/prometheus/node_exporter/blob/master/collector/meminfo_linux.go
[node_exporter vmstat source]: https://github.com/prometheus/node_exporter/blob/master/collector/vmstat_linux.go
[node_exporter filesystem source]: https://github.com/prometheus/node_exporter/blob/master/collector/filesystem_common.go
[node_exporter diskstats source]: https://github.com/prometheus/node_exporter/blob/master/collector/diskstats_linux.go
[node_exporter hwmon source]: https://github.com/prometheus/node_exporter/blob/master/collector/hwmon_linux.go
[node_exporter systemd source]: https://github.com/prometheus/node_exporter/blob/master/collector/systemd_linux.go
[node_exporter textfile collector]: https://github.com/prometheus/node_exporter#textfile-collector
[node_exporter textfile source]: https://github.com/prometheus/node_exporter/blob/master/collector/textfile.go
[Linux `/proc` documentation]: https://www.kernel.org/doc/html/latest/filesystems/proc.html
[Linux hwmon ABI]: https://www.kernel.org/doc/html/latest/hwmon/sysfs-interface.html
[Linux pstore documentation]: https://www.kernel.org/doc/html/latest/power/shutdown-debugging.html
[journalctl]: https://www.freedesktop.org/software/systemd/man/latest/journalctl.html
[DCGM Exporter metrics]: https://docs.nvidia.com/datacenter/dcgm/latest/reference/dcgm-exporter-metrics.html
[dcgm-exporter command reference]: https://docs.nvidia.com/datacenter/dcgm/latest/reference/command-line-reference/dcgm-exporter.html
[install DCGM Exporter]: https://docs.nvidia.com/datacenter/dcgm/latest/installation/install-dcgm-exporter.html
[DCGM field identifiers]: https://docs.nvidia.com/datacenter/dcgm/latest/dcgm-api/index.html
[DCGM release notes]: https://docs.nvidia.com/datacenter/dcgm/latest/release-notes/changelog.html
[NVIDIA XID introduction]: https://docs.nvidia.com/deploy/xid-errors/introduction.html
[NVIDIA XID catalog]: https://docs.nvidia.com/deploy/xid-errors/analyzing-xid-catalog.html
[dcgm-exporter upstream]: https://github.com/NVIDIA/dcgm-exporter
