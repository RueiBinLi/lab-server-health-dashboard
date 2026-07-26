from __future__ import annotations

from dataclasses import dataclass

from lab_dashboard.auth import Role


@dataclass(frozen=True)
class EmptyFleetExperience:
    message: str
    guidance: str


def empty_fleet_experience(role: Role) -> EmptyFleetExperience:
    if role is Role.LAB_ADMINISTRATOR:
        return EmptyFleetExperience(
            message="No servers have been enrolled.",
            guidance=(
                "Lab Administrator controls will appear when servers are enrolled."
            ),
        )
    return EmptyFleetExperience(
        message="No servers are available yet.",
        guidance="Server Health and Resource Usage will appear here.",
    )
