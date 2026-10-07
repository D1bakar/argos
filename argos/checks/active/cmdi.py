"""OS command injection: output canary first (fast), then time-based."""

from __future__ import annotations

from argos.engine.findings import Finding, Severity
from argos.engine.probe import (
    TIME_POINTS,
    baseline,
    build_points,
    marker,
    send,
    timing_hit,
)
from argos.engine.registry import Check, ScanContext, register

OUTPUT_TEMPLATES = [
    "; echo {m} #",
    "| echo {m}",
    "& echo {m} &",
    "`echo {m}`",
    "$(echo {m})",
    # NOTE: no bare-newline templates — a reflective endpoint would place the
    # canary on its own line too, defeating output detection.
]

TIME_TEMPLATES = [
    "; sleep {t}",
    "| sleep {t}",
    "& sleep {t}",
    "&& sleep {t}",
    "$(sleep {t})",
    "`sleep {t}`",
    "; ping -n {n} 127.0.0.1 > nul",
    "| ping -n {n} 127.0.0.1",
]

SLEEP_SECONDS = 5


def _canary_on_own_line(body: str, canary: str) -> bool:
    """True when `canary` occupies its own response line.

    Command output (`echo <canary>`) lands on a bare line; a merely-reflective
    endpoint echoes the whole payload, so the canary shares a line with markup
    or the surrounding payload text — which correctly fails this test.
    """
    for line in body.splitlines():
        stripped = line.strip().strip("\r")
        if stripped == canary:
            return True
        # allow html wrapper only if it is *just* the canary
        if stripped in (f"<p>{canary}</p>", f"<pre>{canary}</pre>"):
            return True
    return False


@register
class CommandInjection(Check):
    name = "cmd-injection"
    mode = "active"
    min_profile = "quick"
    summary = "OS command injection (echo canary + sleep/ping timing, Unix & Windows)"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        points = build_points(ctx, limit=10)
        findings: list[Finding] = []
        time_tests = 0

        for point in points:
            await baseline(ctx, point)

            # fast screen: command output echoed by the shell.
            # exact-line match only: a reflective endpoint would echo the payload
            # itself, where the canary sits inside a longer line of markup/echo text.
            for tmpl in OUTPUT_TEMPLATES:
                m = marker("argosCMD")
                payload = tmpl.format(m=m)
                resp = await send(ctx, point, payload)
                if _canary_on_own_line(resp.text, m):
                    findings.append(
                        self._finding(
                            point, payload, resp, "output-based",
                            f"The shell echoed the injected canary {m} back in the "
                            "response — the command executed on the server.",
                        )
                    )
                    break
            else:
                # slow screen: time-based (limited number of points)
                if time_tests >= TIME_POINTS:
                    continue
                time_tests += 1
                for tmpl in TIME_TEMPLATES:
                    payload = tmpl.format(t=SLEEP_SECONDS, n=SLEEP_SECONDS + 1)
                    if await timing_hit(ctx, point, payload, SLEEP_SECONDS):
                        findings.append(
                            self._finding(
                                point, payload, None, "time-based",
                                f"The response was delayed ~{SLEEP_SECONDS}s by a "
                                "sleep/ping payload — the OS executed the injected "
                                "command.",
                            )
                        )
                        break
        return findings

    @staticmethod
    def _finding(point, payload, resp, kind, why) -> Finding:
        evidence_resp = ""
        if resp is not None:
            evidence_resp = f"HTTP {resp.status_code}\n" + resp.text[:800]
        return Finding(
            plugin="cmd-injection",
            title=f"OS command injection ({kind})",
            severity=Severity.CRITICAL,
            cvss=9.8,
            cwe="CWE-78",
            url=point.endpoint,
            parameter=point.param,
            description=(
                f"Parameter '{point.param}' is passed to an OS shell. {why} This is "
                "full remote code execution as the web-server user."
            ),
            remediation=(
                "Never build shell commands from user input. Use language-native APIs "
                "(subprocess with a list argv, no shell=True), strict allowlists for "
                "any required arguments, and least-privilege service accounts."
            ),
            evidence_request=f"{point.method} {point.endpoint}\n{point.param}={payload}",
            evidence_response=evidence_resp,
        )
