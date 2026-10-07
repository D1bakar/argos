"""Informational: target reachability and fingerprint."""

from __future__ import annotations

from urllib.parse import urlsplit

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.http import snippet
from argos.engine.registry import Check, ScanContext, register


@register
class TargetInfo(Check):
    name = "target-info"
    mode = "passive"
    min_profile = "quick"
    summary = "Target reachability, status, server and tech banners"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.pages:
            return [
                Finding(
                    plugin=self.name,
                    title="Target unreachable",
                    severity=Severity.MEDIUM,
                    cvss=5.3,
                    cwe="N/A",
                    url=ctx.start_url,
                    description="The crawler could not fetch any page from the target.",
                    remediation="Check that the URL is correct and the host is reachable.",
                )
            ]

        page = next((p for p in ctx.pages if p.url == ctx.start_url), ctx.pages[0])
        headers = page.headers
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        host = urlsplit(page.final_url).hostname or ""

        findings: list[Finding] = []
        banner = ", ".join(
            f"{k}={v}" for k, v in (("server", server), ("x-powered-by", powered)) if v
        )
        findings.append(
            Finding(
                plugin=self.name,
                title="Target fingerprint",
                severity=Severity.INFO,
                cvss=0.0,
                cwe="N/A",
                url=page.final_url or page.url,
                description=(
                    f"Fetched {len(ctx.pages)} page(s) on {host}. "
                    + (f"Banners: {banner}." if banner else "No server banners disclosed.")
                ),
                remediation="No action required; informational.",
                evidence_response=truncate(snippet(_RespShim(page)), 800),
            )
        )
        return findings


class _RespShim:
    """Adapt a crawler Page to the snippet() helper (avoids a second fetch)."""

    def __init__(self, page):
        self.status_code = page.status
        self.http_version = "1.1"
        self.headers = page.headers
        self.text = page.html

    @property
    def url(self):  # pragma: no cover
        return ""
