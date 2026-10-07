"""Plugin registry: checks self-register; scanner selects them by profile/mode."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal

from argos.config import ProfileRank, ScanConfig
from argos.engine.allowlist import Allowlist
from argos.engine.crawler import Page
from argos.engine.findings import Finding
from argos.engine.http import HttpClient

Mode = Literal["passive", "active"]
ProgressCb = Callable[[str], Awaitable[None] | None]


@dataclass
class ScanContext:
    """Everything a check needs to do its work."""

    config: ScanConfig
    client: HttpClient
    allowlist: Allowlist
    start_url: str
    pages: list[Page] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # baseline responses per injection point (shared across active checks)
    baselines: dict[str, tuple[int, str]] = field(default_factory=dict)
    # filled by auth modules (phase 4): role name -> cookie header
    role_cookies: dict[str, str] = field(default_factory=dict)

    @property
    def active_allowed(self) -> bool:
        return self.config.active and self.allowlist.allows(self.config.url)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    @property
    def html_pages(self) -> list[Page]:
        return [p for p in self.pages if p.is_html]


class Check(ABC):
    """Base class for all checks.

    mode='passive'  — analyzes already-fetched responses only.
    mode='active'   — sends attack payloads; requires target in argos.allow.
    min_profile     — lowest profile that runs this check.
    """

    name: str = "unnamed"
    mode: Mode = "passive"
    min_profile: str = "standard"
    summary: str = ""

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]:
        ...


_REGISTRY: dict[str, type[Check]] = {}


def register(cls: type[Check]) -> type[Check]:
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(f"duplicate check name: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def all_checks() -> list[Check]:
    return [_REGISTRY[name]() for name in sorted(_REGISTRY)]


def select_checks(config: ScanConfig, active_allowed: bool) -> list[Check]:
    """Checks to run for this scan, in deterministic order."""
    rank = ProfileRank.get(config.profile, 1)
    selected: list[Check] = []
    for name in sorted(_REGISTRY):
        check = _REGISTRY[name]()
        if ProfileRank.get(check.min_profile, 1) > rank:
            continue
        if check.mode == "active" and not active_allowed:
            continue
        selected.append(check)
    return selected


def load_checks() -> None:
    """Import all check modules so @register decorators run."""
    import argos.checks  # noqa: F401
