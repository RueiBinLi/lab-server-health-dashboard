import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from test_http import RunningDashboard, collector_inventory, identity_headers
from test_resource_usage import activate_server
from lab_dashboard.health import HealthObservation


ADMINISTRATOR = identity_headers(
    "ada@example.com", "lab-administrator"
)
LAB_USER = identity_headers("lin@example.com", "lab-user")


def general_linux_definition() -> dict[str, object]:
    return {
        "capabilities": {"gpu": False},
        "requiredObservations": [
            "reachability",
            "cpu",
            "memory",
            "root-filesystem",
            "temperature-headroom",
            "critical-errors",
        ],
        "persistentMounts": ["/"],
        "requiredServices": [],
        "temperatureSensors": [],
        "thresholdOverrides": [],
    }


def activation_report(
    configuration_hash: str,
    *,
    extra_observations: tuple[str, ...] = (),
    inventory: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "reportedConfigurationHash": configuration_hash,
        "observations": [
            "reachability",
            "cpu",
            "memory",
            "root-filesystem",
            "temperature-headroom",
            "critical-errors",
            "persistent-mount:/",
            *extra_observations,
        ],
        "inventory": (
            inventory if inventory is not None else collector_inventory()
        ),
    }


class ServerProfileLifecycleTests(unittest.TestCase):
    def test_administrator_clones_edits_and_publishes_complete_profile(
        self,
    ) -> None:
        with RunningDashboard() as dashboard:
            cloned = dashboard.post(
                "/api/server-profiles",
                {
                    "profileId": "storage-linux",
                    "name": "Storage Linux Server",
                    "sourceProfileId": "general-linux",
                    "sourceRevision": 1,
                    "reason": "Create a reusable storage role",
                },
                ADMINISTRATOR,
            )
            invalid = dashboard.post(
                "/api/server-profiles/storage-linux/revisions",
                {
                    "name": "Storage Linux Server",
                    "definition": {
                        **general_linux_definition(),
                        "requiredObservations": ["cpu"],
                        "requiredServices": ["postgres*.service"],
                    },
                    "reason": "Try an unsafe incomplete definition",
                },
                ADMINISTRATOR,
            )
            draft = dashboard.post(
                "/api/server-profiles/storage-linux/revisions",
                {
                    "name": "Storage Linux Server",
                    "definition": {
                        **general_linux_definition(),
                        "persistentMounts": ["/", "/srv/models"],
                        "requiredServices": ["postgresql.service"],
                        "temperatureSensors": [
                            {
                                "logicalName": "cpu-package",
                                "kind": "cpu",
                                "limitSource": "hardware-critical",
                            }
                        ],
                        "thresholdOverrides": [
                            {
                                "key": "memory-available-percent",
                                "fireBelow": 12,
                                "clearAbove": 18,
                                "unit": "percent",
                                "rationale": (
                                    "Storage cache makes lower free memory normal"
                                ),
                            }
                        ],
                    },
                    "reason": "Add the stable data mount and database service",
                },
                ADMINISTRATOR,
            )
            published = dashboard.post(
                "/api/server-profiles/storage-linux/revisions/2/publish",
                {"reason": "Reviewed generated collector requirements"},
                ADMINISTRATOR,
            )
            profiles = dashboard.get(
                "/api/server-profiles?include=all", ADMINISTRATOR
            )
            retired = dashboard.post(
                "/api/server-profiles/storage-linux/revisions/2/retire",
                {"reason": "The storage role is no longer offered"},
                ADMINISTRATOR,
            )
            after_retirement = dashboard.get(
                "/api/server-profiles?include=all", ADMINISTRATOR
            )
            forbidden = dashboard.post(
                "/api/server-profiles",
                {
                    "profileId": "user-profile",
                    "name": "User Profile",
                    "sourceProfileId": "general-linux",
                    "sourceRevision": 1,
                    "reason": "Should not be allowed",
                },
                LAB_USER,
            )

        self.assertEqual(cloned[0], 201)
        self.assertEqual(cloned[1]["profile"]["state"], "draft")
        self.assertEqual(cloned[1]["profile"]["revision"], 1)
        self.assertEqual(
            invalid,
            (
                400,
                {
                    "error": "invalid_profile_definition",
                    "details": [
                        "mandatory required observations cannot be removed",
                        "Required Services must be exact systemd service units",
                    ],
                },
            ),
        )
        self.assertEqual(draft[0], 201)
        self.assertEqual(draft[1]["profile"]["revision"], 2)
        self.assertEqual(published[0], 200)
        self.assertEqual(published[1]["profile"]["state"], "published")
        self.assertEqual(published[1]["affectedServerIds"], [])
        self.assertTrue(published[1]["configurationHash"].startswith("sha256:"))
        self.assertIn(
            {
                "path": "persistentMounts",
                "before": ["/"],
                "after": ["/", "/srv/models"],
            },
            published[1]["effectiveChanges"],
        )
        self.assertEqual(profiles[0], 200)
        self.assertEqual(
            [
                (profile["profileId"], profile["revision"], profile["state"])
                for profile in profiles[1]["profiles"]
                if profile["profileId"] == "storage-linux"
            ],
            [
                ("storage-linux", 1, "draft"),
                ("storage-linux", 2, "published"),
            ],
        )
        self.assertEqual(retired[1]["profile"]["state"], "retired")
        self.assertEqual(
            [
                profile["state"]
                for profile in after_retirement[1]["profiles"]
                if profile["profileId"] == "storage-linux"
            ],
            ["draft", "retired"],
        )
        self.assertEqual(forbidden, (403, {"error": "access_denied"}))

    def test_unsafe_override_and_arbitrary_execution_are_rejected(
        self,
    ) -> None:
        unsafe_documents = [
            {
                **general_linux_definition(),
                "promql": "up == 0",
            },
            {
                **general_linux_definition(),
                "commands": ["systemctl restart sshd"],
            },
            {
                **general_linux_definition(),
                "thresholdOverrides": [
                    {
                        "key": "memory-available-percent",
                        "fireBelow": 20,
                        "clearAbove": 15,
                        "unit": "percent",
                        "rationale": "Overlapping bands are unsafe",
                    }
                ],
            },
            {
                **general_linux_definition(),
                "requiredServices": ["worker@.service"],
            },
            {
                **general_linux_definition(),
                "thresholdOverrides": [
                    {
                        "key": "memory-available-percent",
                        "fireBelow": float("inf"),
                        "clearAbove": float("inf"),
                        "unit": "percent",
                        "rationale": "Non-finite values are ambiguous",
                    }
                ],
            },
            {
                **general_linux_definition(),
                "thresholdOverrides": [
                    {
                        "key": "memory-available-percent",
                        "fireBelow": 5,
                        "clearAbove": 20,
                        "unit": "percent",
                        "rationale": "Weakening mandatory memory coverage",
                    }
                ],
            },
            {
                **general_linux_definition(),
                "thresholdOverrides": [
                    {
                        "key": "primary-telemetry-seconds",
                        "fireBelow": 1,
                        "clearAbove": 2,
                        "unit": "seconds",
                        "rationale": "Global timing must remain mandatory",
                    }
                ],
            },
        ]
        with RunningDashboard() as dashboard:
            dashboard.post(
                "/api/server-profiles",
                {
                    "profileId": "unsafe-profile",
                    "name": "Unsafe Profile",
                    "sourceProfileId": "general-linux",
                    "sourceRevision": 1,
                    "reason": "Prepare validation examples",
                },
                ADMINISTRATOR,
            )
            responses = [
                dashboard.post(
                    "/api/server-profiles/unsafe-profile/revisions",
                    {
                        "name": "Unsafe Profile",
                        "definition": definition,
                        "reason": "Exercise fail-closed validation",
                    },
                    ADMINISTRATOR,
                )
                for definition in unsafe_documents
            ]

        self.assertEqual(
            [response[0] for response in responses],
            [400, 400, 400, 400, 400, 400, 400],
        )
        self.assertTrue(
            all(
                response[1]["error"] == "invalid_profile_definition"
                for response in responses
            )
        )

    def test_publication_waits_for_expected_hash_and_rollback_is_atomic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                server_id = activate_server(dashboard, Path(temporary))
                draft = dashboard.post(
                    "/api/server-profiles/general-linux/revisions",
                    {
                        "name": "General Linux Server",
                        "definition": {
                            **general_linux_definition(),
                            "persistentMounts": ["/", "/srv/models"],
                        },
                        "reason": "Observe the stable model volume",
                    },
                    ADMINISTRATOR,
                )
                published = dashboard.post(
                    "/api/server-profiles/general-linux/revisions/2/publish",
                    {"reason": "Validated profile revision"},
                    ADMINISTRATOR,
                )
                before = dashboard.get(
                    f"/api/servers/{server_id}", ADMINISTRATOR
                )
                unverified_delivery = dashboard.get(
                    f"/api/collectors/{server_id}/profile-configuration"
                )
                delivered = dashboard.get(
                    f"/api/collectors/{server_id}/profile-configuration",
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                mismatched = dashboard.post(
                    f"/api/servers/{server_id}/profile-activations",
                    activation_report("sha256:not-expected"),
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                after_failure = dashboard.get(
                    f"/api/servers/{server_id}", ADMINISTRATOR
                )
                incomplete = dashboard.post(
                    f"/api/servers/{server_id}/profile-activations",
                    activation_report(published[1]["configurationHash"]),
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                replacement_inventory = collector_inventory()
                replacement_inventory["disks"] = [
                    {
                        "stableId": "wwn-approved-replacement",
                        "model": "Replacement Disk",
                        "sizeBytes": 3_840_755_982_336,
                        "mounts": ["/", "/srv/models"],
                    }
                ]
                inventory_acceptance_required = dashboard.post(
                    f"/api/servers/{server_id}/profile-activations",
                    activation_report(
                        published[1]["configurationHash"],
                        extra_observations=(
                            "persistent-mount:/srv/models",
                        ),
                        inventory=replacement_inventory,
                    ),
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                dashboard.post(
                    f"/api/servers/{server_id}/inventory-acceptances",
                    {"reason": "The replacement disk was verified"},
                    ADMINISTRATOR,
                )
                activated = dashboard.post(
                    f"/api/servers/{server_id}/profile-activations",
                    activation_report(
                        published[1]["configurationHash"],
                        extra_observations=(
                            "persistent-mount:/srv/models",
                        ),
                        inventory=replacement_inventory,
                    ),
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                rollback = dashboard.post(
                    f"/api/servers/{server_id}/profile-rollbacks",
                    {
                        "profileId": "general-linux",
                        "revision": 1,
                        "reason": "The new mount is not ready on this host",
                    },
                    ADMINISTRATOR,
                )
                rolled_back = dashboard.post(
                    f"/api/servers/{server_id}/profile-activations",
                    activation_report(
                        rollback[1]["configurationHash"],
                        inventory=replacement_inventory,
                    ),
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                audit = dashboard.get("/api/audit-events", ADMINISTRATOR)

        self.assertEqual(draft[0], 201)
        self.assertEqual(published[1]["affectedServerIds"], [server_id])
        self.assertEqual(before[1]["server"]["profile"]["revision"], 1)
        self.assertEqual(
            unverified_delivery, (403, {"error": "access_denied"})
        )
        self.assertEqual(delivered[0], 200)
        self.assertEqual(
            delivered[1]["configurationHash"],
            published[1]["configurationHash"],
        )
        self.assertEqual(delivered[1]["configuration"]["revision"], 2)
        self.assertEqual(
            before[1]["server"]["pendingProfileConfiguration"],
            {
                "profileId": "general-linux",
                "revision": 2,
                "configurationHash": published[1]["configurationHash"],
                "operation": "publication",
            },
        )
        self.assertEqual(
            mismatched,
            (
                409,
                {
                    "error": "configuration_hash_mismatch",
                    "activeProfileRevision": 1,
                },
            ),
        )
        self.assertEqual(
            after_failure[1]["server"]["profile"]["revision"], 1
        )
        self.assertEqual(
            incomplete,
            (
                422,
                {
                    "error": "profile_requirements_not_verified",
                    "activeProfileRevision": 1,
                },
            ),
        )
        self.assertEqual(
            inventory_acceptance_required,
            (
                422,
                {
                    "error": "profile_requirements_not_verified",
                    "activeProfileRevision": 1,
                },
            ),
        )
        self.assertEqual(activated[0], 200)
        self.assertEqual(activated[1]["server"]["profile"]["revision"], 2)
        self.assertEqual(
            activated[1]["server"]["activeConfigurationHash"],
            published[1]["configurationHash"],
        )
        self.assertNotIn(
            "pendingProfileConfiguration", activated[1]["server"]
        )
        self.assertEqual(rollback[0], 202)
        self.assertEqual(rolled_back[0], 200)
        self.assertEqual(rolled_back[1]["server"]["profile"]["revision"], 1)
        actions = [event["action"] for event in audit[1]["events"]]
        self.assertIn("server-profile-activation-failed", actions)
        self.assertIn("server-profile-activated", actions)
        self.assertIn("server-profile-rollback-staged", actions)

    def test_profile_service_and_temperature_requirements_drive_health(
        self,
    ) -> None:
        now = [datetime(2026, 7, 27, 12, tzinfo=UTC)]
        observation: HealthObservation = {
            "primaryTelemetrySuccessful": True,
            "requiredObservationsComplete": True,
            "cpuUsedPercent": 25.0,
            "normalizedLoad5": 0.5,
            "memoryAvailablePercent": 50.0,
            "filesystems": [
                {
                    "mountpoint": "/",
                    "freePercent": 50.0,
                    "freeBytes": 100 * 1024**3,
                    "exhaustionWithin24Hours": False,
                }
            ],
            "requiredServices": [
                {"service": "postgresql.service", "active": None}
            ],
            "temperatures": [
                {
                    "logicalName": "cpu-package",
                    "headroomCelsius": 20.0,
                    "throttling": False,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                server_id = activate_server(dashboard, Path(temporary))
                bound_inventory = {
                    **collector_inventory(),
                    "temperatureSensorBindings": [
                        {
                            "logicalName": "cpu-package",
                            "sensorId": "hwmon0:temp1",
                            "limitSource": "hardware-critical",
                        }
                    ],
                }
                dashboard.post(
                    f"/api/servers/{server_id}/inventory-observations",
                    {"inventory": bound_inventory},
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                dashboard.post(
                    "/api/server-profiles/general-linux/revisions",
                    {
                        "name": "General Linux Server",
                        "definition": {
                            **general_linux_definition(),
                            "requiredServices": ["postgresql.service"],
                            "temperatureSensors": [
                                {
                                    "logicalName": "cpu-package",
                                    "kind": "cpu",
                                    "limitSource": "hardware-critical",
                                }
                            ],
                        },
                        "reason": "The database is required for this role",
                    },
                    ADMINISTRATOR,
                )
                publication = dashboard.post(
                    "/api/server-profiles/general-linux/revisions/2/publish",
                    {"reason": "Profile configuration validated"},
                    ADMINISTRATOR,
                )
                delivered = dashboard.get(
                    f"/api/collectors/{server_id}/profile-configuration",
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                dashboard.post(
                    f"/api/servers/{server_id}/profile-activations",
                    activation_report(
                        delivered[1]["configurationHash"],
                        extra_observations=(
                            "required-service:postgresql.service",
                            "temperature-sensor:cpu-package",
                        ),
                        inventory=bound_inventory,
                    ),
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                with (
                    patch(
                        "lab_dashboard.app.current_health_observation",
                        side_effect=lambda *_args, **_kwargs: observation,
                    ),
                    patch(
                        "lab_dashboard.app.health_now",
                        side_effect=lambda: now[0],
                    ),
                ):
                    dashboard.get("/api/fleet", ADMINISTRATOR)
                    now[0] += timedelta(minutes=2)
                    service_failed = dashboard.get(
                        "/api/fleet", ADMINISTRATOR
                    )
                    observation["requiredServices"][0]["active"] = True
                    dashboard.get("/api/fleet", ADMINISTRATOR)
                    now[0] += timedelta(minutes=2)
                    service_recovered = dashboard.get(
                        "/api/fleet", ADMINISTRATOR
                    )
                    observation["temperatures"][0][
                        "headroomCelsius"
                    ] = 9.0
                    dashboard.get("/api/fleet", ADMINISTRATOR)
                    now[0] += timedelta(minutes=5)
                    temperature_failed = dashboard.get(
                        "/api/fleet", ADMINISTRATOR
                    )
                    observation["temperatures"][0][
                        "headroomCelsius"
                    ] = 16.0
                    dashboard.get("/api/fleet", ADMINISTRATOR)
                    now[0] += timedelta(minutes=10)
                    temperature_recovered = dashboard.get(
                        "/api/fleet", ADMINISTRATOR
                    )

        self.assertEqual(
            service_failed[1]["fleet"][0]["activeHealthCauses"][0]["rule"],
            "required-service:postgresql.service",
        )
        self.assertEqual(
            (
                service_failed[1]["fleet"][0]["serverIncidents"][0][
                    "profileId"
                ],
                service_failed[1]["fleet"][0]["serverIncidents"][0][
                    "profileRevision"
                ],
            ),
            ("general-linux", 2),
        )
        self.assertEqual(
            service_recovered[1]["fleet"][0]["serverHealth"]["state"],
            "Healthy",
        )
        self.assertEqual(
            temperature_failed[1]["fleet"][0]["activeHealthCauses"][0][
                "rule"
            ],
            "temperature-headroom:cpu-package",
        )
        self.assertEqual(
            temperature_recovered[1]["fleet"][0]["serverHealth"]["state"],
            "Healthy",
        )

    def test_required_inventory_change_latches_until_explicit_acceptance(
        self,
    ) -> None:
        healthy: HealthObservation = {
            "primaryTelemetrySuccessful": True,
            "requiredObservationsComplete": True,
            "cpuUsedPercent": 25.0,
            "normalizedLoad5": 0.5,
            "memoryAvailablePercent": 50.0,
            "filesystems": [
                {
                    "mountpoint": "/",
                    "freePercent": 50.0,
                    "freeBytes": 100 * 1024**3,
                    "exhaustionWithin24Hours": False,
                }
            ],
        }
        changed_inventory = collector_inventory()
        changed_inventory["disks"] = [
            {
                "stableId": "wwn-replacement-device",
                "model": "Replacement Disk",
                "sizeBytes": 3_840_755_982_336,
                "mounts": ["/"],
            }
        ]
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                server_id = activate_server(dashboard, Path(temporary))
                observed = dashboard.post(
                    f"/api/servers/{server_id}/inventory-observations",
                    {
                        "inventory": changed_inventory,
                    },
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                dashboard.post(
                    f"/api/servers/{server_id}/inventory-observations",
                    {
                        "inventory": collector_inventory(),
                    },
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                with patch(
                    "lab_dashboard.app.current_health_observation",
                    return_value=healthy,
                ):
                    degraded = dashboard.get(
                        "/api/fleet", ADMINISTRATOR
                    )
                    accepted = dashboard.post(
                        f"/api/servers/{server_id}/inventory-acceptances",
                        {"reason": "Disk replacement was authorized"},
                        ADMINISTRATOR,
                    )
                    recovered = dashboard.get(
                        "/api/fleet", ADMINISTRATOR
                    )
                audit = dashboard.get("/api/audit-events", ADMINISTRATOR)

        self.assertEqual(observed[0], 202)
        self.assertEqual(
            observed[1]["pendingInventoryChange"]["disks"][0]["stableId"],
            "wwn-replacement-device",
        )
        self.assertEqual(
            degraded[1]["fleet"][0]["activeHealthCauses"][0]["rule"],
            "inventory-change",
        )
        self.assertEqual(accepted[0], 200)
        self.assertEqual(
            recovered[1]["fleet"][0]["serverHealth"]["state"], "Healthy"
        )
        self.assertIn(
            "server-inventory-change-accepted",
            [event["action"] for event in audit[1]["events"]],
        )

    def test_assignment_is_staged_and_retirement_blocks_new_assignments(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                server_id = activate_server(dashboard, Path(temporary))
                dashboard.post(
                    "/api/server-profiles",
                    {
                        "profileId": "compute-linux",
                        "name": "Compute Linux Server",
                        "sourceProfileId": "general-linux",
                        "sourceRevision": 1,
                        "reason": "Create a complete reusable compute role",
                    },
                    ADMINISTRATOR,
                )
                published = dashboard.post(
                    "/api/server-profiles/compute-linux/revisions/1/publish",
                    {"reason": "Generated configuration validated"},
                    ADMINISTRATOR,
                )
                staged = dashboard.post(
                    f"/api/servers/{server_id}/profile-assignments",
                    {
                        "profileId": "compute-linux",
                        "revision": 1,
                        "reason": "Move the host to its intended role",
                    },
                    ADMINISTRATOR,
                )
                before = dashboard.get(
                    f"/api/servers/{server_id}", ADMINISTRATOR
                )
                activated = dashboard.post(
                    f"/api/servers/{server_id}/profile-activations",
                    activation_report(staged[1]["configurationHash"]),
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                retired = dashboard.post(
                    "/api/server-profiles/compute-linux/revisions/1/retire",
                    {"reason": "Stop offering this role to new servers"},
                    ADMINISTRATOR,
                )
                new_assignment_blocked = dashboard.post(
                    f"/api/servers/{server_id}/profile-assignments",
                    {
                        "profileId": "compute-linux",
                        "revision": 1,
                        "reason": "Try to assign a retired revision",
                    },
                    ADMINISTRATOR,
                )

        self.assertEqual(published[0], 200)
        self.assertEqual(staged[0], 202)
        self.assertEqual(staged[1]["operation"], "assignment")
        self.assertEqual(
            before[1]["server"]["profile"]["profileId"], "general-linux"
        )
        self.assertEqual(
            activated[1]["server"]["profile"]["profileId"], "compute-linux"
        )
        self.assertEqual(retired[1]["profile"]["state"], "retired")
        self.assertEqual(
            new_assignment_blocked,
            (422, {"error": "profile_not_published"}),
        )

    def test_activated_threshold_override_changes_health_not_global_timing(
        self,
    ) -> None:
        now = [datetime(2026, 7, 27, 15, tzinfo=UTC)]
        observation: HealthObservation = {
            "primaryTelemetrySuccessful": True,
            "requiredObservationsComplete": True,
            "cpuUsedPercent": 25.0,
            "normalizedLoad5": 0.5,
            "memoryAvailablePercent": 15.0,
            "filesystems": [
                {
                    "mountpoint": "/",
                    "freePercent": 50.0,
                    "freeBytes": 100 * 1024**3,
                    "exhaustionWithin24Hours": False,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            with RunningDashboard() as dashboard:
                server_id = activate_server(dashboard, Path(temporary))
                dashboard.post(
                    "/api/server-profiles/general-linux/revisions",
                    {
                        "name": "General Linux Server",
                        "definition": {
                            **general_linux_definition(),
                            "thresholdOverrides": [
                                {
                                    "key": "memory-available-percent",
                                    "fireBelow": 20,
                                    "clearAbove": 25,
                                    "unit": "percent",
                                    "rationale": (
                                        "This host intentionally uses a large cache"
                                    ),
                                }
                            ],
                        },
                        "reason": "Tune the reusable cache-heavy role",
                    },
                    ADMINISTRATOR,
                )
                publication = dashboard.post(
                    "/api/server-profiles/general-linux/revisions/2/publish",
                    {"reason": "Threshold override reviewed"},
                    ADMINISTRATOR,
                )
                dashboard.post(
                    f"/api/servers/{server_id}/profile-activations",
                    activation_report(
                        publication[1]["configurationHash"]
                    ),
                    {"X-Verified-Collector-Server-ID": server_id},
                )
                with (
                    patch(
                        "lab_dashboard.app.current_health_observation",
                        return_value=observation,
                    ),
                    patch(
                        "lab_dashboard.app.health_now",
                        side_effect=lambda: now[0],
                    ),
                ):
                    dashboard.get("/api/fleet", ADMINISTRATOR)
                    now[0] += timedelta(minutes=4)
                    before_global_hold = dashboard.get(
                        "/api/fleet", ADMINISTRATOR
                    )
                    now[0] += timedelta(minutes=1)
                    overridden_failure = dashboard.get(
                        "/api/fleet", ADMINISTRATOR
                    )
                    observation["memoryAvailablePercent"] = 26.0
                    dashboard.get("/api/fleet", ADMINISTRATOR)
                    now[0] += timedelta(minutes=5)
                    recovered = dashboard.get(
                        "/api/fleet", ADMINISTRATOR
                    )

        self.assertEqual(
            before_global_hold[1]["fleet"][0]["serverHealth"]["state"],
            "Healthy",
        )
        self.assertEqual(
            overridden_failure[1]["fleet"][0]["activeHealthCauses"][0][
                "rule"
            ],
            "memory-pressure",
        )
        self.assertEqual(
            recovered[1]["fleet"][0]["serverHealth"]["state"], "Healthy"
        )


if __name__ == "__main__":
    unittest.main()
