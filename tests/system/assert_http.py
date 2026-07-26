from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request


CAPABILITY_NAME = "rueibinli.github.io/cap/lab-server-health"


def get(
    base_url: str, path: str, identity: str | None, role: str | None
) -> tuple[int, dict[str, object]]:
    headers = {}
    if identity is not None:
        headers["Tailscale-User-Login"] = identity
    if role is not None:
        headers["Tailscale-App-Capabilities"] = json.dumps(
            {CAPABILITY_NAME: [{"role": role}]}
        )
    request = urllib.request.Request(base_url + path, headers=headers)
    try:
        response = urllib.request.urlopen(request, timeout=2)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


def main() -> None:
    base_url = sys.argv[1]
    administrator = get(
        base_url, "/api/fleet", "ada@example.com", "lab-administrator"
    )
    lab_user = get(base_url, "/api/fleet", "lin@example.com", "lab-user")
    denied = (
        get(base_url, "/api/fleet", None, None),
        get(base_url, "/api/fleet", "not an identity", "lab-user"),
        get(base_url, "/api/fleet", "unknown@example.com", None),
        get(base_url, "/api/fleet", "roleless@example.com", None),
        get(base_url, "/api/fleet", "tag:build-server", "lab-user"),
    )

    assert administrator == (
        200,
        {
            "viewer": {
                "login": "ada@example.com",
                "role": "lab-administrator",
            },
            "fleet": [],
            "emptyMessage": "No servers have been enrolled.",
        },
    )
    assert lab_user == (
        200,
        {
            "viewer": {"login": "lin@example.com", "role": "lab-user"},
            "fleet": [],
            "emptyMessage": "No servers are available yet.",
        },
    )
    assert denied == ((403, {"error": "access_denied"}),) * 5


if __name__ == "__main__":
    main()
