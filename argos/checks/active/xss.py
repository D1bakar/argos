"""Reflected XSS: unescaped HTML injection of a unique canary tag."""

from __future__ import annotations

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.probe import DEFAULT_POINTS, baseline, build_points, marker, send
from argos.engine.registry import Check, ScanContext, register

# (payload template, success substrings) — a success substring appearing RAW in
# the response proves unescaped injection; entity-encoded reflections won't match.
PROBES: list[tuple[str, list[str]]] = [
    ('"><{tag}>', ["<{tag}"]),
    ("'><{tag}>", ["<{tag}"]),
    ("</textarea><{tag}>", ["<{tag}"]),
    ("</script><{tag}>", ["<{tag}"]),
    ('"><svg onload=1 argossvg></svg><!--{tag}-->', ["<svg onload=1 argossvg>"]),
]

# attribute-context probe: injected straight into an existing tag
ATTR_PROBE = '" autofocus onfocus=1 argosattr='


@register
class ReflectedXSS(Check):
    name = "xss-reflected"
    mode = "active"
    min_profile = "quick"
    summary = "Reflected XSS: unescaped markup/attribute injection into responses"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        points = build_points(ctx, limit=DEFAULT_POINTS)
        findings: list[Finding] = []

        for point in points:
            await baseline(ctx, point)
            for tmpl, success_markers in PROBES:
                tag = marker("argosx")
                payload = tmpl.format(tag=tag)
                resp = await send(ctx, point, payload)
                if resp.status_code >= 500:
                    continue
                body = resp.text
                hit = next(
                    (m.format(tag=tag) for m in success_markers if m.format(tag= tag) in body),
                    None,
                )
                if hit is None:
                    continue
                findings.append(self._report(point, payload, resp, body, hit))
                break
            else:
                # attribute-context probe: success requires the RAW quote sequence —
                # entity-encoded reflections (&#34; autofocus...) are not exploitable
                tag = marker("argosx")
                payload = ATTR_PROBE + tag
                resp = await send(ctx, point, payload)
                body = resp.text
                raw_seq = ATTR_PROBE + tag
                idx = body.find(raw_seq)
                if idx >= 0 and _inside_tag(body, idx):
                    findings.append(self._report(point, payload, resp, body, tag))
        return findings

    @staticmethod
    def _report(point, payload, resp, body, hit) -> Finding:
        idx = body.find(hit)
        context = body[max(0, idx - 90) : idx + 50] if idx >= 0 else ""
        return Finding(
            plugin="xss-reflected",
            title="Reflected XSS (unescaped HTML injection)",
            severity=Severity.MEDIUM,
            cvss=6.1,
            cwe="CWE-79",
            url=point.endpoint,
            parameter=point.param,
            description=(
                f"Parameter '{point.param}' reflects attacker-controlled markup unencoded "
                f"(observed: {hit!r} rendered raw in the response). A victim opening a "
                "crafted link executes the injected markup in their session."
            ),
            remediation=(
                "Contextually output-encode the parameter (HTML entity, JS, URL or "
                "attribute encoding as appropriate) and set a strict "
                "Content-Security-Policy."
            ),
            evidence_request=f"{point.method} {point.endpoint}\n{point.param}={payload}",
            evidence_response=truncate(f"HTTP {resp.status_code}\n...{context}...", 700),
        )


def _inside_tag(body: str, idx: int) -> bool:
    """True when position idx sits between '<' and '>' (i.e. inside a tag)."""
    last_open = body.rfind("<", 0, idx)
    last_close = body.rfind(">", 0, idx)
    return last_open > last_close
