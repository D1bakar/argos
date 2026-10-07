"""Forced browsing: discover admin interfaces anonymously or with low-priv roles."""

from __future__ import annotations

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.probe import marker, similar
from argos.engine.registry import Check, ScanContext, register

ADMIN_PATHS = (
    "/admin",
    "/administrator",
    "/admin.php",
    "/admin/login",
    "/dashboard",
    "/wp-admin",
    "/console",
    "/manager/html",
    "/phpmyadmin",
    "/adminer.php",
    "/panel",
    "/controlpanel",
    "/cpanel",
    "/webmail",
    "/backend",
    "/manage",
)

# a response only counts as an admin interface when it smells like one
MARKERS = (
    "admin",
    "dashboard",
    "manager",
    "console",
    "phpmyadmin",
    "adminer",
    "control panel",
    "controlpanel",
    "cpanel",
    "webmail",
    "backend",
)


@register
class ForcedBrowse(Check):
    name = "forced-browsing"
    mode = "active"
    min_profile = "quick"
    summary = "Admin interface discovery (anonymous + low-privilege role probing)"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        origin = f"{ctx.config.url.rstrip('/')}"

        # soft-404 baseline: a canary path that does not exist
        canary = marker("argos404")
        resp = await ctx.client.get(f"{origin}/argos-canary-{canary}")
        soft404 = resp.text if resp.status_code == 200 else None

        def is_panel(body: str) -> bool:
            if soft404 and similar(body, soft404):
                return False
            low = body.lower()
            return any(m in low for m in MARKERS)

        for path in ADMIN_PATHS:
            url = f"{origin}{path}"
            resp = await ctx.client.get(url)
            if resp.status_code == 200 and is_panel(resp.text):
                findings.append(self._finding(ctx, url, resp.text, "anonymous", None))
                continue
            # not anonymously visible — probe with each low-privilege role
            if resp.status_code in (301, 302, 303, 401, 403):
                for role, cookie in ctx.role_cookies.items():
                    if "admin" in role.lower():
                        continue  # an admin role seeing the panel is correct
                    r = await ctx.client.get(url, headers={"Cookie": cookie})
                    if r.status_code == 200 and is_panel(r.text):
                        findings.append(self._finding(ctx, url, r.text, "role", role))
                        break
        return findings

    @staticmethod
    def _finding(
        ctx: ScanContext, url: str, body: str, who: str, role: str | None
    ) -> Finding:
        if who == "anonymous":
            title = "Admin interface exposed without authentication"
            why = "The panel was reachable with no session at all."
        else:
            title = f"Admin interface reachable with low-privilege role '{role}'"
            why = (
                "A non-administrator session was accepted for this panel — "
                "privilege checks are missing or client-side only."
            )
        return Finding(
            plugin="forced-browsing",
            title=title,
            severity=Severity.HIGH,
            cvss=7.5,
            cwe="CWE-425",
            url=url,
            parameter="",
            description=(
                f"{why} An attacker brute-forcing common admin paths reaches "
                "management functionality, often as a stepping stone to account "
                "takeover or RCE."
            ),
            remediation=(
                "Require authentication and role checks server-side for all "
                "management routes, return 404 (not 403/redirect) for paths the "
                "caller may not know about, and rate-limit discovery attempts."
            ),
            evidence_request=f"GET {url}",
            evidence_response=truncate(f"HTTP 200\n{body[:700]}", 900),
        )
