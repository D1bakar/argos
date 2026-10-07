"""HTTP methods: dangerous verbs allowed, TRACE (XST), arbitrary PUT upload."""

from __future__ import annotations

import uuid

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

DANGEROUS = {"PUT", "DELETE", "TRACE"}


@register
class HTTPMethods(Check):
    name = "http-methods"
    mode = "active"
    min_profile = "quick"
    summary = "Dangerous HTTP methods (PUT/DELETE/TRACE), XST, arbitrary file write"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        origin = f"{ctx.config.url.rstrip('/')}"
        pages = ctx.html_pages[:3] or []
        urls = [origin] + [p.url for p in pages]

        # 1) advertised dangerous methods
        allowed: set[str] = set()
        for url in urls:
            resp = await ctx.client.request("OPTIONS", url)
            header = resp.headers.get("allow") or resp.headers.get("public") or ""
            allowed |= {m.strip().upper() for m in header.split(",") if m.strip()}
        bad = sorted(allowed & DANGEROUS)
        if bad:
            findings.append(
                Finding(
                    plugin=self.name,
                    title=f"Dangerous HTTP methods enabled: {', '.join(bad)}",
                    severity=Severity.MEDIUM,
                    cvss=5.3,
                    cwe="CWE-749",
                    url=origin,
                    parameter="",
                    description=(
                        f"OPTIONS advertises {', '.join(bad)} beyond the usual "
                        "safe verbs. Depending on routing this enables state "
                        "changes (PUT/DELETE) or request reflection (TRACE/XST)."
                    ),
                    remediation=(
                        "Disable unused verbs at the framework/reverse-proxy "
                        "level; respond 405 for anything outside the API's "
                        "contract."
                    ),
                    evidence_request=f"OPTIONS {origin}",
                    evidence_response=f"Allow: {', '.join(sorted(allowed))}",
                )
            )

        # 2) TRACE reflection (cross-site tracing)
        canary = f"argos{uuid.uuid4().hex[:10]}"
        resp = await ctx.client.request(
            "TRACE", origin, headers={"X-Argos-Trace": canary}
        )
        if canary in resp.text:
            findings.append(
                Finding(
                    plugin=self.name,
                    title="TRACE enabled — cross-site tracing (XST)",
                    severity=Severity.MEDIUM,
                    cvss=6.1,
                    cwe="CWE-693",
                    url=origin,
                    parameter="",
                    description=(
                        "The server echoes request headers back via TRACE, which "
                        "historically bypassed HttpOnly cookie protections via "
                        "JavaScript-driven tracing."
                    ),
                    remediation="Disable TRACE method server-side and at the proxy.",
                    evidence_request=f"TRACE {origin}\nX-Argos-Trace: {canary}",
                    evidence_response=truncate(resp.text[:500], 600),
                )
            )

        # 3) arbitrary file write via PUT
        name = f"argos-put-{uuid.uuid4().hex[:8]}.txt"
        put_url = f"{origin}/{name}"
        resp = await ctx.client.request("PUT", put_url, content=b"argos-put-probe")
        if resp.status_code in (200, 201, 204):
            cleanup = await ctx.client.request("DELETE", put_url)
            findings.append(
                Finding(
                    plugin=self.name,
                    title="Arbitrary file write via HTTP PUT",
                    severity=Severity.CRITICAL,
                    cvss=9.8,
                    cwe="CWE-434",
                    url=put_url,
                    parameter="request body",
                    description=(
                        f"PUT {put_url} was accepted (HTTP {resp.status_code}) — an "
                        "unauthenticated attacker can upload a web shell or "
                        "overwrite application files. Probe file: /"
                        + name
                        + (
                            " (cleanup DELETE also succeeded)."
                            if cleanup.status_code in (200, 204, 404)
                            else " — cleanup attempt did not succeed; remove manually."
                        )
                    ),
                    remediation=(
                        "Never map PUT to filesystem writes without authentication "
                        "and strict content handling; store uploads outside the web "
                        "root with generated names and serve them as downloads."
                    ),
                    evidence_request=f"PUT {put_url}\n\nargos-put-probe",
                    evidence_response=f"HTTP {resp.status_code}",
                )
            )
        return findings
