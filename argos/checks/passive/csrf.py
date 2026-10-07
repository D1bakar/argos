"""CSRF: state-changing forms submitted without an anti-CSRF token."""

from __future__ import annotations

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

TOKEN_HINTS = (
    "csrf",
    "xsrf",
    "token",
    "authenticity",
    "nonce",
    "_token",
    "antiforgery",
    "request-verification",
)


@register
class CSRF(Check):
    name = "csrf"
    mode = "passive"
    min_profile = "quick"
    summary = "State-changing POST forms without an anti-CSRF token"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, tuple[str, ...]]] = set()

        for page in ctx.pages:
            for form in page.forms:
                if form.method != "POST" or not form.inputs:
                    continue
                names = [n.lower() for n in form.inputs]
                # login forms are excluded: login-CSRF is a separate, lower-risk
                # class and would drown the report
                if any("pass" in n or "pwd" in n for n in names):
                    continue
                if any(any(h in n for h in TOKEN_HINTS) for n in names):
                    continue
                key = (form.action, tuple(sorted(names)))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        plugin=self.name,
                        title="State-changing form without CSRF protection",
                        severity=Severity.MEDIUM,
                        cvss=5.4,
                        cwe="CWE-352",
                        url=form.action,
                        parameter=",".join(sorted(form.inputs)),
                        description=(
                            f"The form posting to {form.action} carries no anti-CSRF "
                            "token field. Any site the victim visits can silently "
                            "submit this form with the victim's session, performing "
                            "actions (posts, purchases, settings changes) as them."
                        ),
                        remediation=(
                            "Add a per-session unpredictable token to every "
                            "state-changing form (and API requests via custom "
                            "header), verify it server-side with constant-time "
                            "comparison, and set SameSite=Lax/Strict on session "
                            "cookies as defense in depth."
                        ),
                        evidence_request=f"GET {page.url}\nform action={form.action}",
                        evidence_response=truncate(
                            "fields: " + ", ".join(sorted(form.inputs)), 400
                        ),
                    )
                )
        return findings
