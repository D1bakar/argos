"""Security response header analysis (passive)."""

from __future__ import annotations

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

_MISSING_LEVELS = [
    # (header, severity, cvss, why it matters, remediation, applies_to_https_only)
    (
        "content-security-policy",
        Severity.MEDIUM,
        5.3,
        "Mitigates XSS and data injection by whitelisting approved sources.",
        "Add a Content-Security-Policy header; start with report-only mode, then enforce.",
        False,
    ),
    (
        "strict-transport-security",
        Severity.MEDIUM,
        5.3,
        "Forces browsers to use HTTPS, preventing downgrade/sslstrip attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        True,
    ),
    (
        "x-frame-options",
        Severity.LOW,
        3.1,
        "Blocks clickjacking via framing (also set via CSP frame-ancestors).",
        "Add: X-Frame-Options: DENY (or SAMEORIGIN) / CSP frame-ancestors 'none'.",
        False,
    ),
    (
        "x-content-type-options",
        Severity.LOW,
        2.6,
        "Stops MIME sniffing that can turn uploads/JSON into executable content.",
        "Add: X-Content-Type-Options: nosniff",
        False,
    ),
    (
        "referrer-policy",
        Severity.LOW,
        2.0,
        "Prevents leakage of URLs (and tokens in them) to third parties.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
        False,
    ),
    (
        "permissions-policy",
        Severity.INFO,
        0.0,
        "Disables powerful browser features (camera, geolocation, USB) on this origin.",
        "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        False,
    ),
]

_CSP_WEAK_RULES = [
    ("unsafe-eval", Severity.MEDIUM, 5.3, "script-src allows eval()"),
    ("*", Severity.MEDIUM, 5.3, "script-src allows any origin"),
    ("unsafe-inline", Severity.LOW, 3.7, "script-src allows inline scripts"),
]


@register
class SecurityHeaders(Check):
    name = "security-headers"
    mode = "passive"
    min_profile = "standard"
    summary = "Missing/weak CSP, HSTS, clickjacking, MIME and referrer protections"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.pages:
            return []
        page = ctx.pages[0]
        headers = {k.lower(): v for k, v in page.headers.items()}
        https = page.final_url.startswith("https://")
        findings: list[Finding] = []
        evidence = truncate(_header_snippet(page), 900)

        for header, sev, score, why, fix, https_only in _MISSING_LEVELS:
            if https_only and not https:
                continue
            if header == "x-frame-options" and "frame-ancestors" in headers.get(
                "content-security-policy", ""
            ):
                continue
            if header not in headers:
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Missing {header} header",
                        severity=sev,
                        cvss=score,
                        cwe="CWE-693",
                        url=page.final_url or page.url,
                        parameter=header,
                        description=f"{header} is not set. {why}",
                        remediation=fix,
                        evidence_response=evidence,
                    )
                )

        csp = headers.get("content-security-policy", "")
        if csp:
            csp_lower = csp.lower()
            script_src = _directive(csp_lower, "script-src") or _directive(
                csp_lower, "default-src"
            )
            for token, sev, score, why in _CSP_WEAK_RULES:
                if not script_src:
                    break
                hit = (
                    "*" in script_src.split() if token == "*" else token in script_src
                )
                if hit:
                    findings.append(
                        Finding(
                            plugin=self.name,
                            title=f"Weak Content-Security-Policy ({token})",
                            severity=sev,
                            cvss=score,
                            cwe="CWE-693",
                            url=page.final_url or page.url,
                            parameter="content-security-policy",
                            description=f"The CSP script-src contains '{token}'. {why}, "
                            "greatly reducing CSP's protection against XSS.",
                            remediation="Remove unsafe directives; use nonces/hashes and "
                            "explicit source allowlists.",
                            evidence_response=evidence,
                        )
                    )
                    break  # one weak-CSP finding is enough
        return findings


def _directive(csp: str, name: str) -> str:
    for part in csp.split(";"):
        parts = part.strip().split(None, 1)
        if parts and parts[0] == name:
            return parts[1] if len(parts) > 1 else ""
    return ""


def _header_snippet(page) -> str:
    lines = [f"HTTP {page.status} {page.url}"]
    for k, v in page.headers.items():
        lines.append(f"{k}: {v}")
    return "\n".join(lines)
