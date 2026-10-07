"""SQL injection: error-based, boolean differential, time-based detection.

Payloads are non-destructive (no DROP/DELETE/UPDATE/UNION data extraction).
"""

from __future__ import annotations

from argos.engine.findings import Finding, Severity
from argos.engine.probe import (
    DEFAULT_POINTS,
    TIME_POINTS,
    baseline,
    build_points,
    send,
    similar,
    sql_error_in,
    timing_hit,
)
from argos.engine.registry import Check, ScanContext, register

ERROR_PAYLOADS = ["'", '"', "1'", "1\"", "' OR '1'='1", "1' OR '1'='1' -- ", "' OR ''='"]

BOOLEAN_PAIRS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1') OR ('1'='1", "1') OR ('1'='2"),
]

TIME_PAYLOADS = [
    "' OR SLEEP({t})-- -",
    "' OR pg_sleep({t})--",
    "'; WAITFOR DELAY '0:0:{t}'--",
    "1' AND SLEEP({t})-- -",
]

SLEEP_SECONDS = 5


@register
class SQLInjection(Check):
    name = "sqli"
    mode = "active"
    min_profile = "quick"
    summary = "SQL injection (error, boolean, time-based) with DBMS fingerprint"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        points = build_points(ctx, limit=DEFAULT_POINTS)
        findings: list[Finding] = []
        time_tests = 0

        for point in points:
            base = await baseline(ctx, point)

            # 1) error-based
            for payload in ERROR_PAYLOADS:
                resp = await send(ctx, point, payload)
                dbms = sql_error_in(resp.text)
                if dbms and not sql_error_in(base.text or ""):
                    findings.append(
                        self._finding(point, payload, resp, Severity.CRITICAL, 9.8,
                                      f"error-based SQL injection ({dbms} error disclosed)",
                                      "The application echoes a database error when the "
                                      "parameter is broken out of its query — the input is "
                                      "embedded in SQL unsafely.")
                    )
                    break
            else:
                # 2) boolean differential
                for true_p, false_p in BOOLEAN_PAIRS:
                    r_true = await send(ctx, point, true_p)
                    r_false = await send(ctx, point, false_p)
                    if (
                        similar(base.text, r_true.text)
                        and not similar(base.text, r_false.text)
                        and not similar(r_true.text, r_false.text)
                    ):
                        findings.append(
                            self._finding(
                                point, true_p, r_true, Severity.CRITICAL, 9.8,
                                "boolean-based blind SQL injection",
                                "True/false SQL conditions produce different pages while "
                                "matching the original — the query logic is attacker-controlled.",
                            )
                        )
                        break
                else:
                    # 3) time-based (limited: sleeps are slow)
                    if time_tests >= TIME_POINTS:
                        continue
                    time_tests += 1
                    for tmpl in TIME_PAYLOADS:
                        payload = tmpl.format(t=SLEEP_SECONDS)
                        if await timing_hit(ctx, point, payload, SLEEP_SECONDS):
                            findings.append(
                                self._finding(
                                    point, payload, None, Severity.CRITICAL, 9.8,
                                    "time-based blind SQL injection",
                                    f"The page response was delayed ~{SLEEP_SECONDS}s by a "
                                    "sleep/WAITFOR payload — the database executes "
                                    "attacker-supplied SQL.",
                                )
                            )
                            break
        return findings

    @staticmethod
    def _finding(point, payload, resp, sev, score, kind, why) -> Finding:
        evidence_req = f"{point.method} {point.endpoint}\n{point.param}={payload}"
        evidence_resp = ""
        if resp is not None:
            evidence_resp = f"HTTP {resp.status_code}\n" + resp.text[:800]
        return Finding(
            plugin="sqli",
            title=f"SQL injection — {kind}",
            severity=sev,
            cvss=score,
            cwe="CWE-89",
            url=point.endpoint,
            parameter=point.param,
            description=(
                f"Parameter '{point.param}' is vulnerable to {kind}. {why}"
            ),
            remediation=(
                "Use parameterized queries / prepared statements for every database "
                "access; never concatenate user input into SQL. Apply least-privilege "
                "DB accounts and input validation as defense in depth."
            ),
            evidence_request=evidence_req,
            evidence_response=evidence_resp,
        )
