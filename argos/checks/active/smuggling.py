"""HTTP request smuggling probes (CL.TE / TE.CL) via raw sockets.

Only runs when a proxy/CDN hop is observable — against a bare origin server the
ambiguity probes cannot distinguish desync from normal pipelining, so scanning
there would only produce false positives.
"""

from __future__ import annotations

import asyncio
import ssl
from urllib.parse import urlsplit

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

# headers that betray a proxy/CDN/queue in front of the origin
PROXY_HINTS = (
    "via", "x-cache", "x-served-by", "cf-ray", "cf-cache-status", "x-amz-cf-id",
    "x-fastly-request-id", "x-varnish", "age", "x-cdn", "x-edge-location",
)

CHUNKED_TINY = b"0\r\n\r\n"


def _status_of(raw: bytes) -> int:
    line = raw.split(b"\r\n", 1)[0]
    try:
        return int(line.split()[1])
    except (IndexError, ValueError):
        return 0


async def _raw_request(
    host: str, port: int, use_tls: bool, payload: bytes, timeout: float = 6.0
) -> bytes:
    ssl_ctx = ssl.create_default_context() if use_tls else None
    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
    try:
        writer.write(payload)
        await writer.drain()
        buf = b""
        while len(buf) < 65536:
            try:
                chunk = await asyncio.wait_for(reader.read(8192), timeout)
            except TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
            # first response is enough to judge accept/reject
            if b"\r\n\r\n" in buf:
                break
        return buf
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


def _post(method_line: bytes, host: str, headers: bytes, body: bytes) -> bytes:
    return (
        method_line
        + b"\r\nHost: " + host.encode()
        + b"\r\nConnection: close" + headers + body
    )


@register
class Smuggling(Check):
    name = "http-smuggling"
    mode = "active"
    min_profile = "standard"
    summary = "CL.TE/TE.CL request smuggling (raw sockets; proxy hops only)"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        split = urlsplit(ctx.start_url)
        host = split.hostname or ""
        if not host:
            return []
        port = split.port or (443 if split.scheme == "https" else 80)
        use_tls = split.scheme == "https"
        path = split.path or "/"

        # proxy presence check (response headers of the start URL)
        base = await ctx.client.get(ctx.start_url)
        hop = next((h for h in PROXY_HINTS if h in base.headers), None)
        if hop is None:
            return []  # bare origin — ambiguity probes would be meaningless

        host_hdr = split.netloc
        te_only = _post(
            b"POST " + path.encode() + b" HTTP/1.1",
            host_hdr,
            b"\r\nTransfer-Encoding: chunked",
            CHUNKED_TINY,
    )
        ambiguous = _post(
            b"POST " + path.encode() + b" HTTP/1.1",
            host_hdr,
            b"\r\nContent-Length: 5\r\nTransfer-Encoding: chunked",
            CHUNKED_TINY,
        )

        te_resp = await _raw_request(host, port, use_tls, te_only)
        amb_resp = await _raw_request(host, port, use_tls, ambiguous)
        te_status, amb_status = _status_of(te_resp), _status_of(amb_resp)

        # hard rejections (400/501) mean the hop normalizes — that's safe
        if te_status in (0, 400, 501) or amb_status in (0, 400, 501):
            return []

        findings = [
            Finding(
                plugin=self.name,
                title="Request smuggling: ambiguous CL.TE request accepted",
                severity=Severity.HIGH,
                cvss=7.5,
                cwe="CWE-444",
                url=ctx.start_url,
                parameter="request framing",
                description=(
                    f"A proxy hop ({hop}: {base.headers.get(hop, '')}) fronts "
                    f"this host, and it accepted BOTH a TE-only request (HTTP "
                    f"{te_status}) and a request with conflicting Content-Length "
                    f"and Transfer-Encoding (HTTP {amb_status}) instead of "
                    "responding 400. Front/back framing disagreement is the "
                    "prerequisite for CL.TE/TE.CL desync: an attacker poisons "
                    "the proxy's connection queue to steal or truncate other "
                    "users' requests (session/cookie theft, bypass of WAF/"
                    "auth). Confirm manually with a timing-based smuggle probe."
                ),
                remediation=(
                    "Terminate and normalize requests at one trusted hop; "
                    "reject messages carrying both Content-Length and "
                    "Transfer-Encoding (400), reject TE obfuscations, and "
                    "disable keep-alive between proxy and origin as mitigation "
                    "in depth. Keep proxy/origin versions aligned."
                ),
                evidence_request=(
                    f"POST {path} HTTP/1.1\nHost: {host_hdr}\n"
                    "Content-Length: 5\nTransfer-Encoding: chunked\n\n0\r\n\r\n"
                ),
                evidence_response=truncate(
                    f"TE-only  → {_status_of(te_resp)} "
                    f"{te_resp[:200].decode('latin-1', 'replace')}\n"
                    f"CL.TE    → {_status_of(amb_resp)} "
                    f"{amb_resp[:200].decode('latin-1', 'replace')}",
                    700,
                ),
            )
        ]
        return findings
