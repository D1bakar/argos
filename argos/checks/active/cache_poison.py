"""Web cache poisoning primitives: unkeyed header reflection + routing headers."""

from __future__ import annotations

import uuid

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

UNKEYED_HEADERS = ("X-Forwarded-Host", "X-Host", "X-Forwarded-Server")
ROUTING_HEADERS = ("X-Original-URL", "X-Rewrite-URL", "X-Override-URL")


@register
class CachePoison(Check):
    name = "cache-poisoning"
    mode = "active"
    min_profile = "quick"
    summary = "Unkeyed header reflection (cache poison) + override routing headers"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        url = ctx.start_url

        base = await ctx.client.get(url)

        # --- 1) unkeyed host header reflected into the page -------------------
        for header in UNKEYED_HEADERS:
            canary = f"argoscache{uuid.uuid4().hex[:10]}.example"
            resp = await ctx.client.get(url, headers={header: canary})
            if canary not in resp.text or canary in (base.text or ""):
                continue
            # persistence check: is it still there WITHOUT the header? (cached)
            again = await ctx.client.get(url)
            cached = canary in (again.text or "")
            if cached:
                findings.append(
                    self._finding(
                        url,
                        header,
                        canary,
                        Severity.CRITICAL,
                        9.1,
                        "confirmed cached",
                        (
                            f"The canary injected via {header} persisted in a "
                            "follow-up request without the header — the poisoned "
                            "response is being SERVED FROM CACHE. Visitors now "
                            "load attacker-controlled content (script injection, "
                            "redirection, credential phishing) from your origin."
                        ),
                        resp,
                    )
                )
            else:
                findings.append(
                    self._finding(
                        url,
                        header,
                        canary,
                        Severity.MEDIUM,
                        5.3,
                        "reflected (not cached)",
                        (
                            f"The unkeyed header {header} is reflected into the "
                            "response body but not currently cached. If a cache "
                            "is later placed in front (CDN/proxy) and keys only "
                            "on the URL, this becomes one-request cache poisoning."
                        ),
                        resp,
                    )
                )
            break  # one reflection finding is enough

        # --- 2) override headers that change routing ---------------------------
        for header in ROUTING_HEADERS:
            canary_path = f"/argos-hidden-{uuid.uuid4().hex[:8]}"
            resp = await ctx.client.get(url, headers={header: canary_path})
            same_status = resp.status_code == base.status_code
            from argos.engine.probe import similar

            if same_status and similar(resp.text, base.text):
                continue  # header ignored (correct)
            findings.append(
                Finding(
                    plugin=self.name,
                    title=f"Unkeyed header alters routing: {header}",
                    severity=Severity.HIGH,
                    cvss=7.5,
                    cwe="CWE-444",
                    url=url,
                    parameter=header,
                    description=(
                        f"Sending {header}: {canary_path} changed the response "
                        f"(HTTP {resp.status_code} vs baseline "
                        f"{base.status_code}). Reverse proxies honor this "
                        "header to pick the backend path — an attacker rewrites "
                        "routing to internal/admin locations, bypasses ACLs, or "
                        "confuses cache keys."
                    ),
                    remediation=(
                        f"Strip/override {header} at the edge; never let "
                        "client-supplied values select the upstream path; ensure "
                        "caches key on the normalized, proxy-computed path only."
                    ),
                    evidence_request=f"GET {url}\n{header}: {canary_path}",
                    evidence_response=truncate(
                        f"HTTP {resp.status_code}\n{resp.text[:600]}", 800
                    ),
                )
            )
            break
        return findings

    @staticmethod
    def _finding(
        url: str,
        header: str,
        canary: str,
        sev: Severity,
        score: float,
        state: str,
        why: str,
        resp,
    ) -> Finding:
        return Finding(
            plugin="cache-poisoning",
            title=f"Web cache poisoning primitive ({state}): {header}",
            severity=sev,
            cvss=score,
            cwe="CWE-524",
            url=url,
            parameter=header,
            description=(
                f"With {header}: {canary} the canary appeared in the response "
                f"body. {why}"
            ),
            remediation=(
                "Include the header in the cache key (or reject it), normalize "
                "host headers upstream, and add cache-busting rules for any "
                "unkeyed input that reaches the response."
            ),
            evidence_request=f"GET {url}\n{header}: {canary}",
            evidence_response=truncate(
                f"HTTP {resp.status_code}\n{resp.text[:600]}", 800
            ),
        )
