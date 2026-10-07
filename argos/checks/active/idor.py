"""IDOR / broken object-level authorization: enumerate record ids and compare."""

from __future__ import annotations

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.probe import build_points, send, similar, sql_error_in
from argos.engine.registry import Check, ScanContext, register

ID_PARAM_NAMES = {
    "id",
    "uid",
    "user_id",
    "userid",
    "account_id",
    "profile_id",
    "record_id",
    "order",
    "invoice",
    "item_id",
}
TEST_IDS = ("1", "2", "3", "4")


@register
class IDOR(Check):
    name = "idor"
    mode = "active"
    min_profile = "quick"
    summary = "IDOR: enumerate record ids and detect distinct records returned"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        points = [
            p
            for p in build_points(ctx, limit=40)
            if p.method == "GET" and p.param.lower() in ID_PARAM_NAMES
        ]
        findings: list[Finding] = []

        for point in points:
            # normalized body -> first id that produced it. Normalization strips
            # the id itself so an endpoint that merely echoes the id back is
            # NOT flagged — only endpoints returning genuinely different data.
            distinct: dict[str, str] = {}
            for tid in TEST_IDS:
                resp = await send(ctx, point, tid)
                body = resp.text
                if resp.status_code != 200 or not body:
                    continue
                if sql_error_in(body) or "not found" in body.lower():
                    continue
                normalized = body.replace(tid, "#")
                if any(similar(normalized, k) for k in distinct):
                    continue
                distinct[normalized] = tid
            if len(distinct) < 2:
                continue
            ids = list(distinct.values())
            sample = next(iter(distinct))[:500]
            findings.append(
                Finding(
                    plugin=self.name,
                    title="IDOR — direct object reference without authorization check",
                    severity=Severity.HIGH,
                    cvss=7.5,
                    cwe="CWE-639",
                    url=point.endpoint,
                    parameter=point.param,
                    description=(
                        f"Parameter '{point.param}' accepts attacker-chosen record "
                        f"ids: id={ids[0]} and id={ids[1]} returned *different* "
                        "records (bodies differ beyond the id itself). An attacker "
                        "enumerates this parameter to read other users' data. "
                        + (
                            "Authenticated roles were also harvested for this scan."
                            if ctx.role_cookies
                            else "No authentication was required for this access."
                        )
                    ),
                    remediation=(
                        "Enforce authorization on every object access: resolve the "
                        "session user server-side and verify they own (or may read) "
                        "the requested record; never trust ids from the client; prefer "
                        "non-enumerable identifiers (UUIDs) as defense in depth."
                    ),
                    evidence_request=(
                        f"GET {point.endpoint}\n{point.param}={ids[0]}  vs  "
                        f"{point.param}={ids[1]}"
                    ),
                    evidence_response=truncate(sample, 900),
                )
            )
        return findings
