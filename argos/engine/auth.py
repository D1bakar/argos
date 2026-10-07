"""Role-based login: harvest per-role session cookies for differential checks."""

from __future__ import annotations

from argos.engine.crawler import Form
from argos.engine.registry import ScanContext

USER_FIELD_HINTS = ("user", "login", "email", "account", "name", "id")
PASS_FIELD_HINTS = ("pass", "pwd", "secret")


def find_login_form(ctx: ScanContext) -> Form | None:
    """A POST form with password-like and username-like fields."""
    candidates: list[Form] = []
    for page in ctx.pages:
        for form in page.forms:
            if form.method != "POST" or len(form.inputs) < 2:
                continue
            names = [n.lower() for n in form.inputs]
            has_pass = any(any(h in n for h in PASS_FIELD_HINTS) for n in names)
            has_user = any(any(h in n for h in USER_FIELD_HINTS) for n in names)
            if has_pass and has_user:
                candidates.append(form)
    if not candidates:
        return None
    # prefer forms whose action mentions login
    for form in candidates:
        if "login" in form.action.lower() or "auth" in form.action.lower():
            return form
    return candidates[0]


def _field_names(form: Form) -> tuple[str, str]:
    names = list(form.inputs)
    pass_field = next(
        (n for n in names if any(h in n.lower() for h in PASS_FIELD_HINTS)), names[-1]
    )
    user_field = next(
        (
            n
            for n in names
            if n != pass_field and any(h in n.lower() for h in USER_FIELD_HINTS)
        ),
        names[0],
    )
    return user_field, pass_field


async def harvest_role_cookies(ctx: ScanContext) -> None:
    """Log in once per configured role; store Cookie header strings on ctx."""
    form = find_login_form(ctx)
    if form is None:
        ctx.warn(
            f"--roles given but no login form found on {ctx.start_url}; "
            "role-based checks will be skipped"
        )
        return
    user_field, pass_field = _field_names(form)
    for role, password in ctx.config.roles.items():
        ctx.client.clear_cookies()
        data = dict(form.inputs)
        data[user_field] = role
        data[pass_field] = password
        try:
            await ctx.client.post(form.action, data=data, max_redirects=3)
        except Exception as exc:
            ctx.warn(f"login failed for role '{role}': {exc!r}")
            continue
        cookie = ctx.client.cookie_header()
        ctx.client.clear_cookies()
        if cookie:
            ctx.role_cookies[role] = cookie
            ctx.warn(f"role '{role}' logged in ({form.action})")
        else:
            ctx.warn(f"role '{role}': login produced no session cookie")
