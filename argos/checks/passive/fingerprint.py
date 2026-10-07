"""Technology fingerprinting and version-banner disclosure (passive)."""

from __future__ import annotations

import re

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

BANNER_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnetmvc-version",
    "x-aspnet-version",
    "x-generator",
]

COOKIE_TECH = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "csrftoken": "Django",
    "laravel_session": "Laravel",
    "_rails_session": "Ruby on Rails",
    "connect.sid": "Express/Connect",
    "express:sess": "Express",
    "xsrf-token": "Laravel/XSRF",
}

VERSION_RE = re.compile(
    r"(?:/|(?<=\s)|\bv)(\d+\.\d+(?:\.\d+)*(?:[-\w.]+)?)"
)

CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri WAF",
    "x-amz-cf-id": "AWS CloudFront",
    "x-cache": "Cache/CDN",
    "x-akamai-transformed": "Akamai",
    "server": None,  # server handled below
}


@register
class TechFingerprint(Check):
    name = "tech-fingerprint"
    mode = "passive"
    min_profile = "standard"
    summary = "Server/framework banners, CDN, framework cookies, version disclosure"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.pages:
            return []
        page = ctx.pages[0]
        headers = {k.lower(): v for k, v in page.headers.items()}

        technologies: list[str] = []
        version_disclosures: list[tuple[str, str]] = []

        for h in BANNER_HEADERS:
            value = headers.get(h)
            if not value:
                continue
            technologies.append(f"{h}: {value}")
            ver = VERSION_RE.search(value)
            if ver:
                version_disclosures.append((h, value))

        for cookie_header in page.cookies:
            name, _, _ = cookie_header.partition("=")
            key = name.strip().lower()
            if key in COOKIE_TECH:
                tech = COOKIE_TECH[key]
                if tech not in technologies:
                    technologies.append(f"cookie '{name}' → {tech}")

        if page.is_html:
            gen = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                page.html,
                re.IGNORECASE,
            )
            if gen:
                technologies.append(f"meta generator: {gen.group(1)}")

        cdns = [label for h, label in CDN_HEADERS.items() if label and h in headers]
        if cdns:
            technologies.append("CDN/WAF: " + ", ".join(sorted(set(cdns))))

        findings: list[Finding] = []

        for header, value in version_disclosures:
            findings.append(
                Finding(
                    plugin=self.name,
                    title=f"Version disclosed in '{header}'",
                    severity=Severity.LOW,
                    cvss=3.7,
                    cwe="CWE-200",
                    url=page.final_url or page.url,
                    parameter=header,
                    description=(
                        f"The response exposes software versions via '{header}: {value}'. "
                        "Attackers use exact versions to target known CVEs."
                    ),
                    remediation=(
                        "Suppress version banners: "
                        "ServerTokens Prod (Apache), server_tokens off (nginx), "
                        "remove X-Powered-By in framework config."
                    ),
                    evidence_response=f"{header}: {value}",
                )
            )

        if technologies:
            findings.append(
                Finding(
                    plugin=self.name,
                    title="Technologies detected",
                    severity=Severity.INFO,
                    cvss=0.0,
                    cwe="N/A",
                    url=page.final_url or page.url,
                    description="Fingerprint: " + "; ".join(truncate(t, 120) for t in technologies),
                    remediation="No action required; informational.",
                )
            )
        return findings
