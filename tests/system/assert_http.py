from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any, cast


CAPABILITY_NAME = "rueibinli.github.io/cap/lab-server-health"


def get(
    base_url: str, path: str, identity: str | None, role: str | None
) -> tuple[int, dict[str, Any]]:
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
        return response.status, cast(dict[str, Any], json.load(response))


def post(
    base_url: str,
    path: str,
    body: Mapping[str, object],
    identity: str,
    role: str,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        base_url + path,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Tailscale-User-Login": identity,
            "Tailscale-App-Capabilities": json.dumps(
                {CAPABILITY_NAME: [{"role": role}]}
            ),
        },
        method="POST",
    )
    try:
        response = urllib.request.urlopen(request, timeout=2)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, cast(dict[str, Any], json.load(response))


def main() -> None:
    base_url = sys.argv[1]
    expected_server_id = sys.argv[2] if len(sys.argv) > 2 else None
    registration_body = {
        "displayName": "System Test Server",
        "scrapeAddress": "https://10.20.30.40:9100/metrics",
        "profileId": "general-linux",
        "reason": "Exercise deployed enrollment boundary",
    }
    administrator = get(
        base_url, "/api/fleet", "ada@example.com", "lab-administrator"
    )
    profiles = get(
        base_url,
        "/api/server-profiles",
        "ada@example.com",
        "lab-administrator",
    )
    if not administrator[1]["fleet"]:
        registration = post(
            base_url,
            "/api/servers",
            registration_body,
            "ada@example.com",
            "lab-administrator",
        )
        assert registration[0] == 201
        administrator = get(
            base_url, "/api/fleet", "ada@example.com", "lab-administrator"
        )
    duplicate = post(
        base_url,
        "/api/servers",
        registration_body,
        "ada@example.com",
        "lab-administrator",
    )
    invalid_address = post(
        base_url,
        "/api/servers",
        {
            **registration_body,
            "displayName": "Invalid Address",
            "scrapeAddress": "https://203.0.113.8:9100/metrics",
        },
        "ada@example.com",
        "lab-administrator",
    )
    unpublished_profile = post(
        base_url,
        "/api/servers",
        {
            **registration_body,
            "displayName": "Unpublished Profile",
            "profileId": "draft-experiment",
        },
        "ada@example.com",
        "lab-administrator",
    )
    lab_user = get(base_url, "/api/fleet", "lin@example.com", "lab-user")
    user_profiles = get(
        base_url, "/api/server-profiles", "lin@example.com", "lab-user"
    )
    user_registration = post(
        base_url,
        "/api/servers",
        registration_body,
        "lin@example.com",
        "lab-user",
    )
    audit = get(
        base_url,
        "/api/audit-events",
        "ada@example.com",
        "lab-administrator",
    )
    denied = (
        get(base_url, "/api/fleet", None, None),
        get(base_url, "/api/fleet", "not an identity", "lab-user"),
        get(base_url, "/api/fleet", "unknown@example.com", None),
        get(base_url, "/api/fleet", "roleless@example.com", None),
        get(base_url, "/api/fleet", "tag:build-server", "lab-user"),
    )

    assert administrator[0] == 200
    administrator_fleet = administrator[1]["fleet"]
    assert len(administrator_fleet) == 1
    server = administrator_fleet[0]
    assert server["displayName"] == "System Test Server"
    assert server["enrollmentState"] == "awaiting-first-contact"
    assert server["serverHealth"] is None
    assert server["metricHistory"] == []
    assert server["criticalAlerts"] == []
    if expected_server_id is not None:
        assert server["serverId"] == expected_server_id
    assert profiles[0] == 200
    assert [
        (profile["name"], profile["state"])
        for profile in profiles[1]["profiles"]
    ] == [
        ("General Linux Server", "published"),
        ("NVIDIA GPU Compute Server", "published"),
    ]
    general, gpu = profiles[1]["profiles"]
    assert general["definition"]["capabilities"]["gpu"] is False
    assert gpu["definition"]["capabilities"]["gpu"] is True
    for profile in (general, gpu):
        assert "reachability" in profile["definition"]["requiredObservations"]
        assert "critical-errors" in profile["definition"]["requiredObservations"]
    assert lab_user == (
        200,
        {
            "viewer": {"login": "lin@example.com", "role": "lab-user"},
            "fleet": [],
            "emptyMessage": "No servers are available yet.",
        },
    )
    assert user_profiles == (403, {"error": "access_denied"})
    assert user_registration == (403, {"error": "access_denied"})
    assert duplicate == (409, {"error": "display_name_conflict"})
    assert invalid_address == (400, {"error": "invalid_registration"})
    assert unpublished_profile == (
        422,
        {"error": "profile_not_published"},
    )
    assert audit[0] == 200
    assert audit[1]["events"][0]["server_id"] == server["serverId"]
    assert audit[1]["events"][0]["result"] == "succeeded"
    audit_results = {event["result"] for event in audit[1]["events"]}
    assert {
        "succeeded",
        "display-name-conflict",
        "invalid-registration",
        "profile-not-published",
    } <= audit_results
    assert denied == ((403, {"error": "access_denied"}),) * 5
    print(server["serverId"])


if __name__ == "__main__":
    main()
