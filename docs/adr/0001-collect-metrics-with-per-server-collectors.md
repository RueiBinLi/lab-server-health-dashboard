# Collect Metrics with Per-Server Collectors

Run a lightweight collector on every monitored server and have a central dashboard service scrape or receive its metrics. This is preferred over agentless monitoring because local collection can reliably expose required-service condition, GPU utilization, and VRAM usage, while a standard install-and-register workflow lets new servers be added without changing dashboard code; it also requires collector deployment and secure communication on every server.
