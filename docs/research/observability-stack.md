# Observability Stack for Server Collectors and 30-Day History

## Decision

Use the **Prometheus ecosystem** for v1:

- **Per monitored server:** Prometheus `node_exporter` for host and required-service metrics, plus NVIDIA `dcgm-exporter` for GPU and VRAM metrics.
- **Central services:** one Prometheus server with 30-day local TSDB retention, and one Alertmanager.
- **Product interface:** the role-aware dashboard backend queries Prometheus's stable HTTP API; Prometheus, Alertmanager, and exporter endpoints are not exposed to browsers.
- **Optional operator tool:** Grafana may be deployed for Lab Administrator diagnostics, but it is not the Lab User-facing product interface.

This is the smallest established stack that covers every mandatory signal without introducing a second telemetry model. It fits two initial servers, retains a straightforward path to more servers, and can be replaced or extended later through Prometheus-compatible APIs and protocols.

## Why this stack fits

### Mandatory host signals

`node_exporter` is the Prometheus exporter for hardware and operating-system metrics. Its Linux collectors cover CPU, memory, filesystem capacity, disk activity, hardware-monitoring sensors, and thermal zones. Its optional `systemd` collector exposes unit state, and its textfile collector accepts machine-bound custom metrics. These are suitable building blocks for reachability, CPU, memory, disk, temperature headroom, and required-service operation. Prometheus's own `up` metric supplies the scrape-reachability signal. [Prometheus node_exporter guide](https://prometheus.io/docs/guides/node-exporter/), [node_exporter collector reference](https://github.com/prometheus/node_exporter)

The initial collector policy should be:

- enable the normal host collectors, including `cpu`, `meminfo`, `filesystem`, `diskstats`, and `hwmon`;
- enable `thermal_zone` where the kernel exposes useful thermal-zone data;
- enable `systemd` with an allowlist of required units rather than exporting every unit;
- reserve the textfile collector for small, explicitly defined machine-bound checks that have no native exporter.

Temperature availability depends on what the server firmware, kernel, and sensors expose. Enrollment verification must therefore report unsupported or missing sensors instead of silently classifying absent temperature data as Healthy.

### Mandatory GPU and VRAM signals

NVIDIA's `dcgm-exporter` exposes DCGM telemetry in Prometheus format at `/metrics`, runs on Linux, and can be installed as a package-managed systemd service or container. Its selectable DCGM fields cover GPU activity, framebuffer memory, temperatures, power, errors, and GPU health; supported fields still depend on the installed GPU and DCGM version. [NVIDIA dcgm-exporter installation](https://docs.nvidia.com/datacenter/dcgm/latest/installation/install-dcgm-exporter.html), [NVIDIA DCGM exporter metrics](https://docs.nvidia.com/datacenter/dcgm/latest/reference/dcgm-exporter-metrics.html), [NVIDIA DCGM field identifiers](https://docs.nvidia.com/datacenter/dcgm/latest/dcgm-api/dcgm-api-field-ids.html)

The collector configuration must explicitly verify these mandatory series during Server Enrollment:

- GPU utilization;
- framebuffer/VRAM used and total (or used and free from which total is derived);
- GPU temperature;
- exporter and scrape health.

DCGM XID and health metrics are useful inputs to later Server Health rules, but the exact Degraded/Unavailable thresholds remain a separate decision.

### 30-day history

Prometheus stores scraped samples in its local time-series database and supports time- and size-based retention. Set `--storage.tsdb.retention.time=30d`; also set a size limit below the volume capacity so disk exhaustion fails by dropping oldest data rather than filling the host. Prometheus recommends sizing the retention cap to at most 80–85% of allocated disk. Local storage is single-node and must use a local POSIX filesystem rather than NFS. [Prometheus storage documentation](https://prometheus.io/docs/prometheus/latest/storage/)

For two servers and 30 days, single-node local storage is the proportionate choice. Back up configuration, alert rules, certificates, and enrollment metadata; treat Metric History as operational data that can be lost if the single monitoring host fails unless a later requirement introduces backups or high availability.

### Alert lifecycle and notifications

Prometheus alert rules send alerts to Alertmanager. Alertmanager provides aggregation, silencing, inhibition, routing, and notification delivery, including email and Slack. Both receiver types support resolved notifications, but their documented default is `false`, so v1 must explicitly set `send_resolved: true` for both. Routing/grouping intervals implement notification grouping and repeat control; alert labels should include stable `server_id`, health state, and reason. [Prometheus alerting overview](https://prometheus.io/docs/alerting/latest/overview/), [Alertmanager configuration reference](https://prometheus.io/docs/alerting/latest/configuration/)

Alertmanager should remain the notification authority. The custom dashboard may display alert state, but should not independently send email or Slack messages; two notification engines would make deduplication and recovery behavior inconsistent.

### Role-aware custom dashboard

Prometheus exposes a stable JSON API under `/api/v1`, including instant and range queries. The dashboard backend can issue fixed or server-scoped PromQL queries for overview cards and 30-day charts. [Prometheus HTTP API](https://prometheus.io/docs/prometheus/latest/querying/api/), [Prometheus querying basics](https://prometheus.io/docs/prometheus/latest/querying/basics/)

Prometheus itself is not the authorization boundary:

1. The browser talks only to the custom dashboard through the existing Tailscale identity boundary.
2. The dashboard maps the authenticated identity to Lab Administrator or Lab User.
3. Backend endpoints select pre-defined queries and response fields for that role.
4. Prometheus and Alertmanager listen on localhost or a private service network and are reachable only by the dashboard and operators.

This keeps sensitive required-service names, detailed errors, configuration labels, and raw query capability away from Lab Users. Grafana can be useful for unrestricted Lab Administrator investigation, but embedding Grafana panels into the Lab User experience would create a second authorization surface and is unnecessary for v1.

## Secure collection and Server Enrollment

Prometheus is pull-based here: the central server scrapes each enrolled server. Prometheus scrape clients support CA validation, client certificates, authorization credentials, and TLS settings. Prometheus exporters commonly use the shared exporter-toolkit web configuration; `node_exporter` supports it, and NVIDIA documents `dcgm-exporter --web-config-file` for TLS or basic authentication. Prometheus's security guidance states that most exporters support TLS and client authentication with certificates. [Prometheus scrape TLS configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#tls_config), [Prometheus exporter-toolkit web configuration](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md), [Prometheus security model](https://prometheus.io/docs/operating/security/), [NVIDIA dcgm-exporter installation](https://docs.nvidia.com/datacenter/dcgm/latest/installation/install-dcgm-exporter.html)

Recommended transport:

- bind exporters only to the lab LAN or Tailscale interface;
- use TLS with a lab-controlled CA and require a Prometheus client certificate (mTLS);
- issue a distinct server certificate during enrollment and store keys with service-user-only permissions;
- firewall exporter ports so only the central monitoring host can connect;
- never place credentials in generated command-line arguments or labels.

Server Enrollment should install a version-pinned collector bundle, install certificates, start the services, and atomically add exporter targets with a stable opaque `server_id`. Prometheus file-based service discovery watches target-file changes and updates targets without restarting, which supports register–install–verify enrollment without a code change or dashboard redeployment. [Prometheus file-based service discovery guide](https://prometheus.io/docs/guides/file-sd/)

Enrollment verification should fail until all applicable checks pass:

- node exporter is reachable and authenticated;
- CPU, memory, filesystem, and disk series exist;
- at least one expected temperature source exists, or the server is explicitly marked temperature-unsupported;
- every configured required service produces a state series;
- on a GPU server, DCGM exporter is reachable and mandatory GPU utilization and VRAM series exist;
- central Prometheus has ingested fresh samples bearing the expected `server_id`.

## Alternatives considered

| Option | Coverage and strengths | Cost or mismatch for this project | Verdict |
| --- | --- | --- | --- |
| **Prometheus + node_exporter + dcgm-exporter + Alertmanager** | Native fit for both standard host exporters and NVIDIA's supported DCGM exporter; local 30-day TSDB; mature PromQL/API; first-party email and Slack routing; dynamic file discovery. | Several small processes; pull endpoints and certificates must be operated; local TSDB is single-node. | **Choose for v1.** Lowest conceptual and operational complexity while retaining extensibility. |
| **VictoriaMetrics single-node + Prometheus exporters + vmalert + Alertmanager** | Can scrape `node_exporter` directly, provides Prometheus-compatible query and write APIs, and configures retention with `-retentionPeriod`; `vmalert` evaluates Prometheus-style rules and sends to Alertmanager. [VictoriaMetrics quick start](https://docs.victoriametrics.com/victoriametrics/quick-start/), [VictoriaMetrics retention and query API](https://docs.victoriametrics.com/victoriametrics/), [vmalert documentation](https://docs.victoriametrics.com/victoriametrics/vmalert/) | Adds a non-Prometheus storage/query implementation without a present scale or durability need. Alerting still needs separate `vmalert` and Alertmanager. Its retention cleanup is partition/merge based, so “30 days” is not an exact per-sample deletion boundary. | Strong fallback if measured Prometheus disk use or query performance becomes a problem; premature for two servers. |
| **InfluxDB OSS + Telegraf** | Telegraf has host inputs, a `systemd_units` input, and an `nvidia_smi` input that gathers GPU usage, memory, and temperature. InfluxDB buckets support retention and token-authenticated APIs. [Telegraf plugin directory](https://docs.influxdata.com/telegraf/v1/plugins/), [Telegraf NVIDIA SMI input](https://docs.influxdata.com/telegraf/v1/input-plugins/nvidia_smi/), [Telegraf systemd units input](https://docs.influxdata.com/telegraf/v1/input-plugins/systemd_units/), [InfluxDB retention](https://docs.influxdata.com/influxdb/v2/reference/internals/data-retention/), [InfluxDB API authentication](https://docs.influxdata.com/influxdb/v2/api/authentication/) | Uses Telegraf/Influx schemas and query tooling instead of the ecosystem NVIDIA directly documents for DCGM. The cited OSS v2 retention documentation itself identifies v2 as an earlier generation, adding avoidable product-version and migration decisions. Alerting and visualization would need additional choices. | Viable, but worse fit and more unresolved lifecycle risk for a new v1. |
| **OpenTelemetry Collector + metrics backend** | The Collector is a vendor-neutral receive/process/export pipeline, and its host-metrics receiver covers common CPU, memory, disk, filesystem, network, and process metrics. OTLP exporters support HTTPS and client certificates. [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/), [host-metrics receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver), [OTLP exporter security](https://opentelemetry.io/docs/specs/otel/protocol/exporter/) | It is not a 30-day database, alert manager, or visualization system. The host receiver does not remove the need for DCGM and additional temperature/systemd coverage, so v1 gains a translation/gateway layer but still needs a Prometheus-like backend. Prometheus explicitly cautions that its OTLP receiver is not an efficient replacement for scraping. [Prometheus OTLP receiver](https://prometheus.io/docs/prometheus/latest/querying/api/#otlp-receiver) | Revisit if traces, logs, backend portability, or outbound-only collection become strategic requirements. |
| **Zabbix Agent 2 + Zabbix Server** | Established integrated monitoring system with agent active checks, history retention, autoregistration, TLS PSK/certificates, notification media, an API, and an official NVIDIA integration. [Zabbix agent](https://www.zabbix.com/documentation/current/en/manual/concepts/agent), [history and trends](https://www.zabbix.com/documentation/current/en/manual/config/items/history_and_trends), [autoregistration](https://www.zabbix.com/documentation/current/en/manual/discovery/auto_registration), [Zabbix integrations](https://www.zabbix.com/integrations), [Zabbix API](https://www.zabbix.com/documentation/current/en/manual/api) | Heavier central deployment (server, SQL database, and frontend), and a custom dashboard adapter would work with Zabbix host/item/API objects instead of a simple PromQL metrics model. Its own users and permissions still do not automatically implement the agreed Tailscale group contract. | Best fallback if the lab later prefers an all-in-one operations product over a small composable stack. |

## Operational shape for v1

The central deployment should contain:

- the custom dashboard/API;
- Prometheus with a persistent local volume, `30d` time retention, and a conservative size cap;
- Alertmanager with email and Slack secrets mounted from protected files;
- optionally Grafana restricted to Lab Administrators;
- generated file-discovery targets and rule files sourced from dashboard enrollment metadata.

Each monitored server should contain:

- `node_exporter` as a restricted systemd service;
- `dcgm-exporter` on NVIDIA GPU servers;
- exporter TLS configuration and a per-server certificate;
- a small enrollment-owned configuration describing stable server identity and required-service allowlists.

Keep component versions pinned and expose their own health metrics. Adding a server changes enrollment metadata and generated scrape targets, not application source code.

## Consequences and follow-up decisions

This research resolves the stack choice, not the health policy. The next decisions still need to define:

- exact Healthy, Degraded, and Unavailable expressions and their hold times;
- which services are “required” per server and how that allowlist is administered;
- temperature behavior when sensors are absent or unreliable;
- collection interval and chart resolution;
- certificate issuance, rotation, revocation, and recovery;
- central-host backup and restore expectations;
- the schema through which the dashboard exposes only role-appropriate metrics.

The recommended default collection interval is 15–30 seconds, but it should be confirmed alongside health hold times and storage sizing rather than embedded in the stack decision.
