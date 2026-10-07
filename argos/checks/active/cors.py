"""CORS misconfiguration: reflected Origin / wildcard with credentials."""

from __future__ import annotations

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

CANARY_ORIGIN = "https://argos-origin-canary.example"


@register
class CORS(Check):
    name = "cors-misconfig"
    mode = "active"
    min_profile = "quick"
    summary = "CORS: reflected arbitrary Origin, wildcard, credentials handling"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = [p.url for p in ctx.html_pages[:5]] or [ctx.start_url]
        reported: set[str] = set()

        for url in urls:
            resp = await ctx.client.get(url, headers={"Origin": CANARY_ORIGIN})
            acao = resp.headers.get("access-control-allow-origin", "")
            if not acao:
                continue
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == CANARY_ORIGIN and acac.lower() == "true":
                kind = "with-credentials"
            elif acao == CANARY_ORIGIN:
                kind = "reflected"
            elif acao == "*":
                kind = "wildcard"
            else:
                continue  # fixed allowlist origin — not this check's business
            if kind in reported:
                continue
            reported.add(kind)
            findings.append(self._finding(url, acao, acac, kind))
        return findings

    @staticmethod
    def _finding(url: str, acao: str, acac: str, kind: str) -> Finding:
        if kind == "with-credentials":
            title = "CORS: arbitrary Origin reflected with credentials"
            sev, score = Severity.HIGH, 7.5
            why = (
                "The server echoes any Origin back together with "
                "Access-Control-Allow-Credentials: true — a malicious page can read "
                "this user's authenticated responses (session data, PII, CSRF "
                "tokens) cross-origin."
            )
        elif kind == "reflected":
            title = "CORS: arbitrary Origin reflected"
            sev, score = Severity.MEDIUM, 5.3
            why = (
                "The server reflects any Origin in Access-Control-Allow-Origin. "
                "Without credentials the blast radius is smaller, but any "
                "unauthenticated data on this endpoint becomes readable cross-origin."
            )
        else:
            title = "CORS: wildcard Access-Control-Allow-Origin"
            sev, score = Severity.LOW, 3.1
            why = (
                "The endpoint responds with ACAO: *. Acceptable only for truly "
                "public, unauthenticated data — otherwise it widens cross-origin "
                "exposure."
            )
        return Finding(
            plugin="cors-misconfig",
            title=title,
            severity=sev,
            cvss=score,
            cwe="CWE-942",
            url=url,
            parameter="Origin header",
            description=(
                f"Requesting {url} with 'Origin: {CANARY_ORIGIN}' returned "
                f"Access-Control-Allow-Origin: {acao}"
                + (f" and Access-Control-Allow-Credentials: {acac}" if acac else "")
                + f". {why}"
            ),
            remediation=(
                "Reflect the Origin only after exact-match allowlisting against a "
                "static list of trusted sites, never combine permissive origins "
                "with Allow-Credentials: true, and prefer Vary: Origin caching."
            ),
            evidence_request=f"GET {url}\nOrigin: {CANARY_ORIGIN}",
            evidence_response=truncate(
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {acac or '(absent)'}",
                400,
            ),
        )
