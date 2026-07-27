# Authorize with Tailscale Groups

Use Tailscale Serve to supply authenticated identity and Tailscale groups or Grants to distinguish `group:lab-admins` from `group:lab-users`; the dashboard enforces the corresponding Lab Administrator and Lab User permissions and denies identities assigned to neither group. This avoids a custom password system while preserving application-level authorization, at the cost of coupling access management to the tailnet policy.

Application capabilities are the normal and preferred role source. If they are
unavailable in a deployment, a Lab Administrator may explicitly select an
exact-login allowlist mode and configure each recognized identity's application
role. The service never selects this fallback automatically, never derives a
role from identity alone in capability mode, and continues to trust identity
headers only from the loopback-bound Tailscale Serve path.
