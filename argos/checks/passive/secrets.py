"""Hardcoded secret detection in pages, inline JS, and same-origin JS files."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

# (name, pattern, severity, cvss, cwe, description)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity, float, str, str]] = [
    (
        "AWS access key id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        9.1,
        "CWE-798",
        "An AWS access key id is hardcoded — if the secret key is nearby or "
        "the key is still active, attackers take over the cloud account.",
    ),
    (
        "GitHub token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        Severity.CRITICAL,
        9.1,
        "CWE-798",
        "A GitHub token is hardcoded — repo read/write, package and org access.",
    ),
    (
        "Slack token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        Severity.HIGH,
        7.5,
        "CWE-798",
        "A Slack API token is hardcoded — workspace messages and integrations.",
    ),
    (
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        Severity.HIGH,
        7.5,
        "CWE-798",
        "A Google API key is hardcoded — quota theft or access to enabled APIs.",
    ),
    (
        "Stripe live key",
        re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b"),
        Severity.CRITICAL,
        9.1,
        "CWE-798",
        "A Stripe LIVE secret key is hardcoded — direct payment fraud.",
    ),
    (
        "SendGrid key",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
        Severity.HIGH,
        7.5,
        "CWE-798",
        "A SendGrid API key is hardcoded — email account takeover/phishing.",
    ),
    (
        "PEM private key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        9.1,
        "CWE-321",
        "A PEM private key is embedded — TLS/host/SSH identity compromise.",
    ),
    (
        "hardcoded credential assignment",
        re.compile(
            r"""(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token"""
            r""")\s*[:=]\s*["'][^"'\s]{8,}["']"""
        ),
        Severity.MEDIUM,
        5.3,
        "CWE-798",
        "A credential-looking value is assigned in client-visible code — verify "
        "whether it is real and move it server-side.",
    ),
]

# values that are obviously not real secrets
PLACEHOLDER = re.compile(
    r"(?i)(example|changeme|change_me|placeholder|your[_-]|xxxx|<.*>|\{\{|\$\{|"
    r"dummy|sample|fake|test123|password123!?$|secret123)"
)


def _mask(value: str) -> str:
    if len(value) <= 12:
        return value
    return f"{value[:8]}…{value[-4:]} (len {len(value)})"


def _scan(name: str, pattern: re.Pattern[str], sev: Severity, score: float,
          cwe: str, why: str, text: str, source_url: str) -> Finding | None:
    m = pattern.search(text)
    if not m:
        return None
    value = m.group(0)
    if sev == Severity.MEDIUM and PLACEHOLDER.search(value):
        return None
    # context window for evidence (masked)
    start = max(0, m.start() - 60)
    snippet = text[start : m.end() + 40].replace("\n", " ")
    return Finding(
        plugin="secret-exposure",
        title=f"Hardcoded secret: {name}",
        severity=sev,
        cvss=score,
        cwe=cwe,
        url=source_url,
        parameter="",
        description=(
            f"{name} found in {source_url}: {_mask(value)}. {why}"
        ),
        remediation=(
            "Remove the value from the code/base, rotate the credential, and "
            "load real secrets from environment variables or a secrets manager; "
            "add pre-commit secret scanning to prevent recurrence."
        ),
        evidence_request=f"GET {source_url}",
        evidence_response=truncate(f"...{snippet}...", 500),
    )


@register
class SecretExposure(Check):
    name = "secret-exposure"
    mode = "passive"
    min_profile = "quick"
    summary = "Hardcoded secrets (AWS/GitHub/Slack keys, private keys) in pages & JS"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        # 1) crawled HTML + inline scripts
        texts: list[tuple[str, str]] = []  # (url, text)
        for page in ctx.pages:
            if page.html:
                texts.append((page.final_url or page.url, page.html))
            for inline in page.inline_scripts:
                texts.append((page.final_url or page.url, inline))

        # 2) same-origin JS files referenced by pages (cap to stay polite)
        origin = urlsplit(ctx.start_url)
        js_urls: list[str] = []
        for page in ctx.pages:
            for src in page.scripts:
                s = urlsplit(src)
                if not s.netloc or s.netloc == origin.netloc:
                    full = src if s.netloc else f"{origin.scheme}://{origin.netloc}{src}"
                    if full not in js_urls:
                        js_urls.append(full)
        for url in js_urls[:10]:
            try:
                resp = await ctx.client.get(url)
            except Exception:
                continue
            if resp.status_code == 200:
                texts.append((url, resp.text))

        for source_url, text in texts:
            for name, pattern, sev, score, cwe, why in SECRET_PATTERNS:
                key = (name, source_url)
                if key in seen:
                    continue
                finding = _scan(name, pattern, sev, score, cwe, why, text, source_url)
                if finding:
                    seen.add(key)
                    findings.append(finding)
        return findings
