"""Known-CVE lookup for detected JS libraries via the OSV.dev API."""

from __future__ import annotations

from argos.checks.deps.js_libs import Lib, detect_libs
from argos.engine.cvss import cvss31_base_score
from argos.engine.findings import Finding, Severity, severity_from_cvss, truncate
from argos.engine.registry import Check, ScanContext, register

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_SEV_FALLBACK = {
    "CRITICAL": (Severity.CRITICAL, 9.0),
    "HIGH": (Severity.HIGH, 7.5),
    "MODERATE": (Severity.MEDIUM, 5.0),
    "MEDIUM": (Severity.MEDIUM, 5.0),
    "LOW": (Severity.LOW, 2.5),
}


def _score_vuln(vuln: dict) -> tuple[Severity, float]:
    sev_text = (vuln.get("database_specific") or {}).get("severity", "").upper()
    if sev_text in _SEV_FALLBACK:
        return _SEV_FALLBACK[sev_text]
    for entry in vuln.get("severity") or []:
        vector = entry.get("score", "")
        if vector.startswith("CVSS"):
            score = cvss31_base_score(vector)
            if score is not None:
                return severity_from_cvss(score), score
    return Severity.MEDIUM, 5.0


@register
class DependencyCVE(Check):
    name = "dependency-cve"
    mode = "passive"
    min_profile = "standard"
    summary = "Known CVEs in JS libraries (jquery, bootstrap, ...) via OSV.dev"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        libs: dict[tuple[str, str], Lib] = {}
        for page in ctx.pages:
            for lib in detect_libs(page.scripts, page.inline_scripts):
                libs.setdefault((lib.name, lib.version), lib)
        if not libs:
            return []

        lib_list = list(libs.values())
        queries = [
            {"package": {"name": lib.name, "ecosystem": "npm"}, "version": lib.version}
            for lib in lib_list
        ]
        try:
            resp = await ctx.client.post(OSV_BATCH_URL, json={"queries": queries})
            resp.raise_for_status()
            results = resp.json().get("results", [])
        except Exception as exc:
            ctx.warn(f"OSV query failed: {exc}")
            return []

        # the batch endpoint returns slim records (id only) — fetch details
        # for severity/summary, capped to keep external traffic bounded
        seen: set[tuple[str, str]] = set()
        pairs: list[tuple[Lib, dict]] = []
        wanted: list[str] = []
        for lib, result in zip(lib_list, results, strict=False):
            for vuln in result.get("vulns") or []:
                vid = vuln.get("id", "")
                if not vid or (lib.name, vid) in seen:
                    continue
                seen.add((lib.name, vid))
                pairs.append((lib, vuln))
                if vid not in wanted and len(wanted) < 40:
                    wanted.append(vid)

        details: dict[str, dict] = {}
        for vid in wanted:
            try:
                dresp = await ctx.client.get(f"https://api.osv.dev/v1/vulns/{vid}")
                if dresp.status_code == 200:
                    details[vid] = dresp.json()
            except Exception:
                continue

        findings: list[Finding] = []
        for lib, slim in pairs:
            vid = slim.get("id", "")
            vuln = details.get(vid, slim)
            score, cvss = _score_vuln(vuln)
            summary = truncate(vuln.get("summary") or vuln.get("details") or "", 300)
            findings.append(
                Finding(
                    plugin=self.name,
                    title=f"{lib.name} {lib.version} — {vid}",
                    severity=score,
                    cvss=cvss,
                    cwe="N/A",
                    url=lib.source,
                    parameter=f"{lib.name}@{lib.version}",
                    description=(
                        f"Detected {lib.name}@{lib.version} ({lib.source}) is affected "
                        f"by {vid}. {summary}"
                    ),
                    remediation=(
                        f"Upgrade {lib.name} to a non-vulnerable version; see "
                        f"https://osv.dev/vulnerability/{vid}"
                    ),
                    evidence_response=truncate(str(vuln), 700),
                )
            )
        return findings
