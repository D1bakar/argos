"""Finding model: severity, CVSS, evidence."""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "cyan",
}


def severity_at_least(sev: Severity, threshold: Severity) -> bool:
    return SEVERITY_RANK[sev] >= SEVERITY_RANK[threshold]


@dataclass
class Finding:
    """A single vulnerability/discovery produced by a check."""

    plugin: str
    title: str
    severity: Severity
    cvss: float
    cwe: str
    url: str
    description: str
    remediation: str
    parameter: str = ""
    evidence_request: str = ""
    evidence_response: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], -f.cvss, f.title))


def truncate(text: str, limit: int = 2000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars]"
