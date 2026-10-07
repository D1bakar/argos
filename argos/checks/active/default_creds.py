"""Default/weak credentials: try a small curated list on discovered login forms."""

from __future__ import annotations

from argos.engine.auth import _field_names, find_login_form
from argos.engine.findings import Finding, Severity, truncate
from argos.engine.probe import marker, similar
from argos.engine.registry import Check, ScanContext, register

DEFAULT_PAIRS = (
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "passw0rd"),
    ("admin", "secret"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("test", "test"),
    ("guest", "guest"),
    ("demo", "demo"),
    ("user", "user"),
)

FAIL_MARKERS = ("login failed", "invalid", "incorrect", "wrong password", "denied")


def _looks_like_failure(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in FAIL_MARKERS)


@register
class DefaultCredentials(Check):
    name = "default-credentials"
    mode = "active"
    min_profile = "quick"
    summary = "Default/weak credential spray against discovered login forms"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        form = find_login_form(ctx)
        if form is None:
            return []
        user_field, pass_field = _field_names(form)

        # baseline: random credentials must fail (and must not set a session)
        ctx.client.clear_cookies()
        data = dict(form.inputs)
        data[user_field] = f"argos{marker('')}"
        data[pass_field] = marker("nope")
        base = await ctx.client.post(form.action, data=data, max_redirects=0)
        base_cookie = ctx.client.cookie_header()
        ctx.client.clear_cookies()
        base_redirected = base.status_code in (301, 302, 303, 307, 308)

        for username, password in DEFAULT_PAIRS:
            ctx.client.clear_cookies()
            data = dict(form.inputs)
            data[user_field] = username
            data[pass_field] = password
            resp = await ctx.client.post(form.action, data=data, max_redirects=3)
            cookie = ctx.client.cookie_header()
            ctx.client.clear_cookies()

            success = False
            if resp.status_code in (301, 302, 303, 307, 308) and not base_redirected:
                success = True
            elif cookie and not base_cookie and resp.status_code in (200, 302, 303):
                success = True
            elif (
                resp.status_code == 200
                and base.status_code != 200
                and not _looks_like_failure(resp.text)
            ):
                success = True
            elif (
                resp.status_code == 200
                and _looks_like_failure(base.text)
                and not _looks_like_failure(resp.text)
                and not similar(resp.text, base.text)
            ):
                success = True
            if not success:
                continue

            adminish = "admin" in username.lower() or "root" in username.lower()
            return [
                Finding(
                    plugin=self.name,
                    title=f"Default credentials accepted ({username}:{password})",
                    severity=Severity.CRITICAL if adminish else Severity.HIGH,
                    cvss=9.8 if adminish else 7.5,
                    cwe="CWE-1392",
                    url=form.action,
                    parameter=f"{user_field}/{pass_field}",
                    description=(
                        f"The login form accepted the well-known pair "
                        f"{username}:{password} (baseline random credentials were "
                        f"rejected with HTTP {base.status_code}). Attackers spray "
                        "these lists automatically and take over the account — "
                        "for an administrator this means full system compromise."
                    ),
                    remediation=(
                        "Force credential rotation to unique secrets, disable or "
                        "seed-lock vendor defaults, require multi-factor "
                        "authentication, and rate-limit authentication attempts."
                    ),
                    evidence_request=(
                        f"POST {form.action}\n{user_field}={username}"
                        f"&{pass_field}={password}"
                    ),
                    evidence_response=truncate(
                        f"HTTP {resp.status_code}\n{resp.text[:600]}", 800
                    ),
                )
            ]
        return []
