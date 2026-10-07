"""Scan orchestrator: crawl → run checks → collect findings."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from argos.config import ScanConfig
from argos.engine.allowlist import Allowlist
from argos.engine.crawler import Crawler, Page, RobotsRules
from argos.engine.findings import Finding, sort_findings
from argos.engine.http import HttpClient
from argos.engine.registry import ScanContext, load_checks, select_checks

ProgressCb = Callable[[str], None]


@dataclass
class ScanResult:
    target: str
    profile: str
    active: bool
    started_at: float
    finished_at: float
    pages: list[Page]
    findings: list[Finding]
    warnings: list[str]
    checks_run: list[str]
    requests: int = 0

    @property
    def duration(self) -> float:
        return self.finished_at - self.started_at

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity.value] = out.get(f.severity.value, 0) + 1
        return out

    def highest(self) -> str:
        counts = self.counts()
        for sev in ("critical", "high", "medium", "low", "info"):
            if counts.get(sev):
                return sev
        return "none"


class Scanner:
    def __init__(self, config: ScanConfig, on_progress: ProgressCb | None = None):
        self.config = config
        self.on_progress = on_progress or (lambda msg: None)
        load_checks()

    async def run(self) -> ScanResult:
        cfg = self.config
        started = time.time()
        allowlist = Allowlist.load()

        if cfg.active and not allowlist.allows(cfg.url):
            self.on_progress(
                "active mode requested but target not in argos.allow — "
                "running passive checks only (argos allow add <host> to enable)"
            )

        warnings: list[str] = []
        async with HttpClient(cfg) as client:
            robots = None
            if cfg.respect_robots:
                robots = await RobotsRules.fetch(client, cfg.url)

            self.on_progress(f"scanning {cfg.url} (profile={cfg.profile})")
            crawler = Crawler(
                client,
                max_pages=cfg.max_pages or 60,
                max_depth=cfg.max_depth or 4,
                robots=robots,
                on_progress=self.on_progress,
            )
            pages = await crawler.crawl(cfg.url)
            self.on_progress(f"crawled {len(pages)} page(s), running checks")

            active_allowed = cfg.active and allowlist.allows(cfg.url)
            ctx = ScanContext(
                config=cfg,
                client=client,
                allowlist=allowlist,
                start_url=cfg.url,
                pages=pages,
                warnings=warnings,
            )

            checks = select_checks(cfg, active_allowed)
            checks_run: list[str] = []
            for check in checks:
                try:
                    found = await check.run(ctx)
                except Exception as exc:  # a broken check must not kill the scan
                    ctx.warn(f"check '{check.name}' failed: {exc!r}")
                    continue
                for f in found:
                    ctx.add(f)
                checks_run.append(check.name)
                if found:
                    self.on_progress(f"[{check.mode}] {check.name}: {len(found)} finding(s)")

            finished = time.time()
            return ScanResult(
                target=cfg.url,
                profile=cfg.profile,
                active=cfg.active,
                started_at=started,
                finished_at=finished,
                pages=pages,
                findings=sort_findings(ctx.findings),
                warnings=warnings,
                checks_run=checks_run,
                requests=client.request_count,
            )
