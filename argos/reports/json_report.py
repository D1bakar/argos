"""JSON report writer."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from argos import __version__
from argos.engine.scanner import ScanResult


def to_dict(result: ScanResult) -> dict:
    return {
        "tool": {"name": "argos", "version": __version__},
        "scan": {
            "target": result.target,
            "profile": result.profile,
            "active": result.active,
            "started_at": datetime.fromtimestamp(
                result.started_at, tz=UTC
            ).isoformat(),
            "duration_seconds": round(result.duration, 2),
            "pages_crawled": len(result.pages),
            "requests": result.requests,
            "checks_run": result.checks_run,
            "counts": result.counts(),
        },
        "warnings": result.warnings,
        "findings": [f.to_dict() for f in result.findings],
    }


def write(result: ScanResult, path: Path) -> None:
    path.write_text(json.dumps(to_dict(result), indent=2), encoding="utf-8")
