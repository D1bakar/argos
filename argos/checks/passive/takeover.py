"""Subdomain takeover surface: dangling DNS records pointing at hosted services."""

from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlsplit

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

SUBDOMAINS = (
    "www", "api", "app", "dev", "test", "staging", "stage", "admin", "portal",
    "blog", "docs", "mail", "cdn", "static", "assets", "img", "beta", "shop",
    "status", "grafana", "jenkins", "git", "ci",
)

# distinctive "this service is NOT claimed" pages (no generic 404s — FP-safe)
TAKEOVER_FINGERPRINTS = (
    ("GitHub Pages", "There isn't a GitHub Pages site here"),
    ("GitHub Pages (alt)", "is not a GitHub Pages site"),
    ("AWS S3", "NoSuchBucket"),
    ("Heroku", "no-such-app"),
    ("Shopify", "Sorry, this shop is currently unavailable"),
    ("Fastly", "Fastly error: unknown domain"),
    ("WordPress.com", "Do you want to register \""),
    ("Surge.sh", "project not found"),
    ("Bitbucket", "Repository not found"),
    ("Azure Static Web Apps", "404: Not Found"),
)


@register
class SubdomainTakeover(Check):
    name = "subdomain-takeover"
    mode = "passive"
    min_profile = "standard"
    summary = "Dangling subdomain CNAMEs servable by a third party (takeover)"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        host = urlsplit(ctx.start_url).hostname or ""
        if not host or self._is_ip(host) or host in ("localhost",):
            return []  # no DNS zone to enumerate (e.g. local test target)
        labels = host.split(".")
        if len(labels) < 2:
            return []
        base = ".".join(labels[1:])  # naive eTLD+1 (documented limitation)
        scheme = urlsplit(ctx.start_url).scheme or "https"

        findings: list[Finding] = []
        for word in SUBDOMAINS:
            fqdn = f"{word}.{base}"
            if fqdn == host:
                continue
            resolved = await asyncio.to_thread(self._resolve, fqdn)
            if not resolved:
                continue
            try:
                resp = await ctx.client.get(
                    f"{scheme}://{fqdn}/", timeout=8.0, max_redirects=3
                )
            except Exception:
                continue
            body = resp.text[:8000]
            hit = next(
                (svc for svc, sig in TAKEOVER_FINGERPRINTS if sig in body), None
            )
            if hit is None:
                continue
            findings.append(
                Finding(
                    plugin=self.name,
                    title=f"Subdomain takeover possible: {fqdn} → {hit}",
                    severity=Severity.HIGH,
                    cvss=7.5,
                    cwe="CWE-450",
                    url=f"{scheme}://{fqdn}/",
                    parameter=fqdn,
                    description=(
                        f"{fqdn} resolves ({resolved}) and serves {hit}'s "
                        "\"unclaimed\" page — the DNS record dangles at a service "
                        "anyone can register. An attacker claims it and serves "
                        "content under your origin (session cookie theft, OAuth "
                        "redirect abuse, phishing)."
                    ),
                    remediation=(
                        "Remove dangling DNS records; if the service is "
                        "decommissioned, delete the CNAME and the third-party "
                        "resource; for GitHub Pages also delete the repository "
                        "or re-add the custom domain."
                    ),
                    evidence_request=f"GET {scheme}://{fqdn}/",
                    evidence_response=truncate(f"HTTP {resp.status_code}\n{body}", 700),
                )
            )
        return findings

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            socket.inet_aton(host)
            return True
        except OSError:
            return ":" in host  # ipv6 literal

    @staticmethod
    def _resolve(fqdn: str) -> str:
        try:
            infos = socket.getaddrinfo(fqdn, None)
            return str(infos[0][4][0]) if infos else ""
        except OSError:
            return ""
