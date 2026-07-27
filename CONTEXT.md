# Lab Server Health

This context describes how the dashboard represents the operational condition of servers used in the lab.

## Language

**Server Health**:
The operational condition of a server, assessed from reachability, CPU, memory, disk, temperature headroom, required-service operation, and critical errors. The worst active condition wins: it is Healthy when no health rule is active, Degraded when an observable problem is active, and Unavailable only when the server can no longer be observed reliably.
_Avoid_: Status, uptime

**Resource Usage**:
The current consumption and remaining capacity of a server's CPU, system memory, disk, GPU, and GPU VRAM. GPU utilization and VRAM used versus total are mandatory signals; high consumption or utilization alone describes workload activity rather than a Server Health failure.
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

**Server Incident**:
A continuous period in which one server is Degraded or Unavailable, beginning with its transition away from Healthy and ending only when it returns to Healthy. Changing health-rule causes belong to the same Server Incident, while escalation to Unavailable changes its severity.
_Avoid_: Alert, event, outage

**Maintenance Window**:
A declared period of planned server work that annotates current Server Health and suppresses email and Slack notifications without changing the health classification itself.
_Avoid_: Maintenance mode, health override

**Critical Error**:
An allowlisted severe host or GPU event—an out-of-memory kill, storage integrity error, GPU fault or reset, or detected kernel panic or watchdog reset—that makes an observable server Degraded. Generic application or log severity does not make an event a Critical Error.
_Avoid_: Error log, warning

**Metric History**:
The most recent 30 days of Server Health and Resource Usage observations retained for comparison, investigation, and trend inspection.
_Avoid_: Logs, archive

**Server Enrollment**:
The Lab Administrator workflow for registering a server, obtaining its collector installation command or configuration, and verifying first contact. A registered server has no Server Health classification or Critical Alerts until first contact is verified; enrollment requires no source-code change or dashboard redeployment.
_Avoid_: Adding a server, provisioning

**Server ID**:
The immutable identity assigned to a registered server and retained through renaming and re-enrollment. Hostnames, network addresses, and reported machine characteristics are evidence about a server, not its identity.
_Avoid_: Hostname, machine ID

**Awaiting First Contact**:
The Server Enrollment state after registration but before the intended collector first presents its bootstrap credentials. It has no Server Health classification or Critical Alerts.
_Avoid_: Pending Verification, offline server

**Pending Verification**:
The Server Enrollment state after a registered server makes first contact but before a Lab Administrator confirms its identity and reported characteristics. It has no Server Health classification or Critical Alerts.
_Avoid_: Unverified server, inactive server

**Re-enrollment Required**:
The state of an enrolled server whose collector identity has been revoked while its Server Profile, Metric History, and audit record remain. Restoring observation requires new collector credentials and another verified first contact.
_Avoid_: Disabled server, retired server

**Server Retirement**:
The permanent end of observation for an enrolled server, revoking its collector trust and stopping Server Health classification and Critical Alerts while retained history and audit records age out normally. A server returning after retirement receives a new Server ID.
_Avoid_: Deletion, removal, disabling

**Server Profile**:
A named, reusable set of hardware- and workload-specific expectations and health-rule overrides inherited by enrolled servers. Classification semantics and observation timing remain global.
_Avoid_: Per-server exceptions, machine template

**Server Inventory**:
The verified, server-specific record of observed hardware and its stable identifiers, captured during Server Enrollment and checked for later changes. A Server Profile declares reusable capability expectations; Server Inventory records which exact devices satisfy them.
_Avoid_: Server Profile, hardware configuration

**Required Service**:
A system service declared by a Server Profile as necessary for that server's intended lab role. Its failure makes an observable server Degraded rather than Unavailable.
_Avoid_: Process, application
