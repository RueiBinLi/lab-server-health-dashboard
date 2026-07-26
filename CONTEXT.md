# Lab Server Health

This context describes how the dashboard represents the operational condition of servers used in the lab.

## Language

**Server Health**:
The operational condition of a server, assessed from reachability, CPU, memory, disk, temperature headroom, required-service operation, and critical errors. It is classified as Healthy, Degraded, or Unavailable.
_Avoid_: Status, uptime

**Resource Usage**:
The current consumption and remaining capacity of a server's CPU, system memory, disk, GPU, and GPU VRAM. GPU utilization and VRAM used versus total are mandatory signals.
_Avoid_: Status, load

**Lab Administrator**:
A person responsible for maintaining the lab servers. A Lab Administrator can inspect detailed metrics, required-service condition, critical errors, alerts, and server configuration.
_Avoid_: Admin, operator

**Lab User**:
A person who uses lab server capacity but does not maintain the servers. A Lab User can inspect summary Server Health and Resource Usage without access to sensitive service details, logs, errors, or configuration.
_Avoid_: User, member

**Critical Alert**:
A notification sent to Lab Administrators by email and Slack when a server becomes Degraded or Unavailable. Repeated notifications are deduplicated, and a recovery notification is sent when the server returns to Healthy.
_Avoid_: Broken notification, warning

**Metric History**:
The most recent 30 days of Server Health and Resource Usage observations retained for comparison, investigation, and trend inspection.
_Avoid_: Logs, archive

**Server Enrollment**:
The Lab Administrator workflow for registering a server, obtaining its collector installation command or configuration, and verifying that monitoring has begun. Enrollment requires no source-code change or dashboard redeployment.
_Avoid_: Adding a server, provisioning
