"""Cookie security attribute analysis (passive)."""

from __future__ import annotations

import re

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

SESSION_RE = re.compile(
    r"(session|sess|sid|auth|token|jwt|login|pass|csrf|xsrf|asp\.net|jsessionid|phpsessid)",
    re.IGNORECASE,
)


def _parse_set_cookie(raw: str) -> tuple[str, dict[str, str]]:
    """Return (name, attrs) from a Set-Cookie header value."""
    parts = raw.split(";")
    name, _, value = parts[0].partition("=")
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        key, _, val = part.partition("=")
        attrs[key.strip().lower()] = val.strip()
    return name.strip(), attrs


@register
class CookieFlags(Check):
    name = "cookie-flags"
    mode = "passive"
    min_profile = "standard"
    summary = "Cookie flags: HttpOnly, Secure, SameSite on session cookies"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        https = ctx.start_url.startswith("https://")

        for page in ctx.pages:
            for raw in page.cookies:
                name, attrs = _parse_set_cookie(raw)
                if not name or name in seen:
                    continue
                seen.add(name)
                is_session = bool(SESSION_RE.search(name))
                missing: list[str] = []
                issues: list[tuple[str, Severity, float, str]] = []

                if "httponly" not in attrs:
                    missing.append("HttpOnly")
                    if is_session:
                        issues.append(
                            (
                                "HttpOnly",
                                Severity.MEDIUM,
                                4.3,
                                "JavaScript can read this cookie — any XSS becomes "
                                "full session theft.",
                            )
                        )
                    else:
                        issues.append(
                            ("HttpOnly", Severity.LOW, 2.6, "JavaScript can read this cookie.")
                        )
                if "secure" not in attrs and https:
                    missing.append("Secure")
                    if is_session:
                        issues.append(
                            (
                                "Secure",
                                Severity.MEDIUM,
                                4.3,
                                "Cookie may be sent over plaintext, exposing the session "
                                "to network sniffing.",
                            )
                        )
                    else:
                        issues.append(
                            ("Secure", Severity.LOW, 2.6, "Cookie may be sent over plaintext.")
                        )
                if "samesite" not in attrs:
                    missing.append("SameSite")
                    issues.append(
                        (
                            "SameSite",
                            Severity.LOW if is_session else Severity.INFO,
                            2.6 if is_session else 0.0,
                            "No SameSite policy — cookie is sent on cross-site requests, "
                            "weakening CSRF defenses.",
                        )
                    )

                for flag, sev, score, why in issues:
                    findings.append(
                        Finding(
                            plugin=self.name,
                            title=f"Cookie '{name}' missing {flag}",
                            severity=sev,
                            cvss=score,
                            cwe="CWE-1004",
                            url=page.final_url or page.url,
                            parameter=name,
                            description=(
                                f"Cookie '{name}'"
                                + (" (session-like name)" if is_session else "")
                                + f" lacks {flag}. {why}"
                            ),
                            remediation=(
                                f"Set {flag} on cookie '{name}': "
                                f"{name}=...; HttpOnly; Secure; SameSite=Lax"
                            ),
                            evidence_response=truncate(f"Set-Cookie: {raw}", 500),
                        )
                    )
        return findings
