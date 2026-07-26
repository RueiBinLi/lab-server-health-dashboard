# Authorize with Tailscale Groups

Use Tailscale Serve to supply authenticated identity and Tailscale groups or Grants to distinguish `group:lab-admins` from `group:lab-users`; the dashboard enforces the corresponding Lab Administrator and Lab User permissions and denies identities assigned to neither group. This avoids a custom password system while preserving application-level authorization, at the cost of coupling access management to the tailnet policy.
