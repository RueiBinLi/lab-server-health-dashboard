# Tailscale-backed identity and role enforcement

Research date: 2026-07-26

## Recommendation

Put Tailscale Serve in front of the dashboard, bind the application itself only to
`127.0.0.1`, and authorize requests from a single custom application capability.
Represent the dashboard role as an opaque capability parameter:

- `{"role": "administrator"}` for `group:lab-admins`
- `{"role": "user"}` for `group:lab-users`

The application must treat a missing, malformed, or unrecognized capability as
**no access**. If an identity is accidentally in both groups, Lab Administrator
takes precedence; keeping the groups mutually exclusive is still preferable.
Require a human identity header as well, so tagged devices cannot become
interactive dashboard users even if a later policy change accidentally grants
them a capability.

This design fits ADR-0003. Tailscale evaluates the source and destination in each
grant, while the application defines and enforces the meaning of custom
capability parameters. Tailscale treats those parameters as opaque JSON rather
than validating the application's role schema
([application capabilities](https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities),
[grants syntax](https://tailscale.com/docs/reference/syntax/grants)).

## Headers supplied by Serve

For a request proxied through Tailscale Serve, the backend receives these user
identity headers:

| Header | Meaning |
| --- | --- |
| `Tailscale-User-Login` | Login name, such as `alice@example.com` |
| `Tailscale-User-Name` | Display name |
| `Tailscale-User-Profile-Pic` | Profile-image URL, when the identity provider supplies one |

Only `Tailscale-User-Login` should be used as the stable application identity.
Name and picture are presentation data. Non-ASCII header values can use RFC 2047
Q encoding, so the HTTP adapter must decode that representation before display
or comparison. Serve strips incoming copies of all three headers before adding
its own, which prevents a remote caller from overriding them
([Serve identity headers](https://tailscale.com/docs/features/tailscale-serve#identity-headers)).

With `--accept-app-caps=<capability>`, Serve also supplies:

```http
Tailscale-App-Capabilities: {"rueibinli.github.io/cap/lab-server-health-dashboard":[{"role":"administrator"}]}
```

The value is serialized JSON containing only the requested capabilities granted
to the connecting peer. Serve also strips an incoming
`Tailscale-App-Capabilities` header before inserting its own. Capability values
with non-ASCII text can likewise be RFC 2047 Q encoded
([Serve app-capabilities header](https://tailscale.com/docs/features/tailscale-serve#app-capabilities-header),
[Serve forwarding example](https://tailscale.com/docs/reference/examples/serve#forward-app-capabilities-to-a-local-service)).

## Tagged devices

Identity headers are populated for users, **not tagged devices**. A tagged
device's Tailscale identity is its set of tags rather than a user, but application
capabilities can be supplied for both user devices and tagged devices
([Tailscale identity](https://tailscale.com/docs/concepts/tailscale-identity),
[tagged devices](https://tailscale.com/docs/features/tags)).

For this human-facing dashboard:

1. grant dashboard access only from the two user groups;
2. do not grant the dashboard capability from any `tag:*` source; and
3. require both an allowed role capability and a non-empty
   `Tailscale-User-Login`.

That makes tagged devices fail closed. Collector authentication should use a
separate endpoint and trust model; it must not reuse this browser authorization.

## Proposed tailnet policy

The custom capability name follows Tailscale's required `{domain}/{path}`
format. `tailscale.com` and `tailscale.io` are reserved, and Tailscale recommends
a domain controlled by the application owner. `rueibinli.github.io` is suitable
only while that GitHub Pages namespace remains controlled by the repository
owner; replace it if the lab has its own domain
([capability naming requirements](https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities#requirements-and-limitations)).

```jsonc
{
  "groups": {
    "group:lab-admins": [
      "administrator@example.edu",
    ],
    "group:lab-users": [
      "member@example.edu",
    ],
  },

  "tagOwners": {
    "tag:lab-dashboard": ["group:lab-admins"],
  },

  "grants": [
    {
      "src": ["group:lab-admins"],
      "dst": ["tag:lab-dashboard"],
      "ip": ["tcp:443"],
      "app": {
        "rueibinli.github.io/cap/lab-server-health-dashboard": [
          {"role": "administrator"},
        ],
      },
    },
    {
      "src": ["group:lab-users"],
      "dst": ["tag:lab-dashboard"],
      "ip": ["tcp:443"],
      "app": {
        "rueibinli.github.io/cap/lab-server-health-dashboard": [
          {"role": "user"},
        ],
      },
    },
  ],
}
```

The explicit `tcp:443` network permission is intentional. An `app` grant does
not itself provide network-layer access when `ip` is omitted; network access
must come from this or another grant. Grants are permissive and the overall
policy is deny-by-default, so no catch-all access rule should also expose the
dashboard node
([grant network capabilities](https://tailscale.com/docs/reference/syntax/grants#network-layer-capabilities),
[grants overview](https://tailscale.com/docs/features/access-control/grants)).

Define policy tests for the network layer before deployment: known members of
each group accept `tag:lab-dashboard:443`, while a representative identity
outside both groups denies it. Tailscale's policy editor supports previewing
permissions and access-control tests
([managing tailnet policies](https://tailscale.com/docs/features/tailnet-policy-file/manage-tailnet-policies)).

## Serve and backend configuration

Run a supported Tailscale release and expose the loopback service through Serve:

```sh
tailscale serve --bg \
  --accept-app-caps=rueibinli.github.io/cap/lab-server-health-dashboard \
  3000
```

The dashboard process must listen on `127.0.0.1:3000`, not `0.0.0.0`, the LAN
address, or the Tailscale address. Serve's reverse proxy targets the local HTTP
service and terminates HTTPS. Tailscale explicitly recommends loopback-only
binding because any client that can call the backend directly can forge these
HTTP headers; loopback limits that residual trust to processes on the Serve
host. Use a dedicated host or container/network namespace if mutually
untrusted local workloads run there
([Serve proxy behavior](https://tailscale.com/docs/reference/tailscale-cli/serve),
[header spoofing guidance](https://tailscale.com/docs/features/tailscale-serve#app-capabilities-header)).

Serve requires HTTPS certificates to be enabled for the tailnet. Do not use
Funnel: Funnel is public and deliberately does not include identity or
application-capability headers
([Serve setup and scope](https://tailscale.com/docs/features/tailscale-serve)).

The application authorization adapter should:

1. reject requests without `Tailscale-User-Login`;
2. RFC 2047-decode, parse, and size-limit `Tailscale-App-Capabilities`;
3. require the exact configured capability key;
4. accept only `role: "administrator"` or `role: "user"`;
5. choose Lab Administrator if both recognized role objects are present;
6. apply the role on every server-side route and data query, not only in the UI;
7. reject missing, empty, malformed, or unknown values; and
8. avoid logging the full header or profile picture URL unnecessarily.

Changing from the LAN-first deployment to header trust is a security boundary:
once this mode is enabled, the backend must no longer be directly reachable on
the LAN. LAN access can go through a separate authenticated reverse proxy before
the Tailscale migration, but it cannot safely share the header-trusting endpoint.

## Version and plan constraints

- The Serve application-capabilities header and `--accept-app-caps` require
  **Tailscale v1.92 or later**. Earlier current-CLI behavior changed in v1.52,
  so operational instructions should target 1.92+ rather than support old Serve
  syntax
  ([Serve app-capabilities header](https://tailscale.com/docs/features/tailscale-serve#app-capabilities-header)).
- Serve needs tailnet HTTPS certificates enabled. Access-control rules apply to
  Serve in the same way as other services
  ([Serve prerequisites](https://tailscale.com/docs/features/tailscale-serve#get-started-with-serve)).
- Custom groups and tags are available on all plans, but the number of groups is
  plan-dependent. As of the research date, Personal permits 3 ACL groups and up
  to 6 users; Standard permits 10 groups and unlimited paid users. The two
  proposed groups fit the Personal group limit, but a lab with more than six
  people does not fit its user limit. Personal is also described as
  non-commercial use
  ([policy group availability](https://tailscale.com/kb/1337/policy-syntax#groups),
  [current pricing and limits](https://tailscale.com/pricing)).
- Current official capability documentation does not state a separate paid-plan
  gate for custom app capabilities. Confirm the chosen plan and limits in the
  tailnet before rollout because pricing can change.
- Directly receiving group-membership data in clients is a different, alpha
  feature requiring v1.97.8+. This design does not depend on it
  ([group visibility on clients](https://tailscale.com/docs/features/group-visibility-clients)).

## Safe fallback without application capabilities

Use a separate, explicit authorization mode based on Serve's identity headers:

```yaml
authorization_mode: tailscale_identity_allowlist
administrators:
  - administrator@example.edu
users:
  - member@example.edu
```

In this mode, map the exact decoded `Tailscale-User-Login` to one role, keep the
same group-scoped `tcp:443` grants, and deny identities not present in either
allowlist. Continue to require Serve and loopback-only backend binding. This is
safe for older clients because Serve's authenticated identity header and header
stripping remain the trust boundary, but membership must be maintained in both
the tailnet policy and application configuration.

The application must never silently fall back merely because
`Tailscale-App-Capabilities` is absent. Select either `tailscale_capability`
(preferred) or `tailscale_identity_allowlist` at startup, validate its complete
configuration, and fail startup otherwise. This prevents a Tailscale upgrade,
Serve flag omission, or policy mistake from turning into a fail-open role
change.

## Decision

Adopt capability-backed authorization for the Tailscale phase with v1.92+,
`group:lab-admins` and `group:lab-users`, `tag:lab-dashboard`, an exact custom
capability, and a loopback-only backend. Keep the explicit identity allowlist as
the supported fallback. Do not derive roles from IP addresses, display names,
tagged devices, or the mere presence of a Tailscale connection.
