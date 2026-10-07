"""Scan configuration and profiles."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ProfileName = Literal["quick", "standard", "deep"]
PROFILES: tuple[str, ...] = ("quick", "standard", "deep")
ProfileRank = {"quick": 0, "standard": 1, "deep": 2}

PROFILE_DEFAULTS: dict[str, dict[str, float]] = {
    "quick": {"max_pages": 15, "max_depth": 2, "rate": 5.0},
    "standard": {"max_pages": 60, "max_depth": 4, "rate": 5.0},
    "deep": {"max_pages": 200, "max_depth": 8, "rate": 4.0},
}


@dataclass
class ScanConfig:
    """Everything one scan run needs to know."""

    url: str
    profile: ProfileName = "standard"
    active: bool = False
    rate: float | None = None
    max_pages: int | None = None
    max_depth: int | None = None
    timeout: float = 15.0
    insecure: bool = False
    respect_robots: bool = False
    cookie: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    roles: dict[str, str] = field(default_factory=dict)
    callback: str | None = None

    def __post_init__(self) -> None:
        defaults = PROFILE_DEFAULTS.get(self.profile, PROFILE_DEFAULTS["standard"])
        if self.rate is None:
            self.rate = defaults["rate"]
        if self.max_pages is None:
            self.max_pages = int(defaults["max_pages"])
        if self.max_depth is None:
            self.max_depth = int(defaults["max_depth"])

    @property
    def rank(self) -> int:
        return ProfileRank.get(self.profile, 1)
