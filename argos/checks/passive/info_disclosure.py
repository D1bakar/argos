"""Sensitive file/path discovery (passive: plain GETs of common URLs)."""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

Detector = Callable[[bytes, str], bool]
# (path, kind, severity, cvss, title, why-it-matters, detector)
PathEntry = tuple[str, str, Severity, float, str, str, Detector]

# (path, kind, severity, cvss, title, detector)
# detector(body, content_type) -> bool
_GIT_HEAD = re.compile(rb"^ref: refs/", re.M)
_ENV_SECRET = re.compile(
    r"(?i)\b(APP_KEY|DB_PASSWORD|DB_PASS|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|"
    r"SECRET_KEY|PRIVATE_KEY|SMTP_PASSWORD|MAIL_PASSWORD|API_SECRET|DATABASE_URL)\s*="
)
_SQL_DUMP = re.compile(r"(?i)CREATE TABLE|INSERT INTO")


def _is_git(body: bytes, _ct: str) -> bool:
    return bool(_GIT_HEAD.search(body[:200]))


def _is_env(body: bytes, ct: str) -> bool:
    return bool(_ENV_SECRET.search(body.decode("utf-8", "replace")[:8000]))


def _is_env_any(body: bytes, ct: str) -> bool:
    return b"=" in body[:500] and b"\n" in body[:2000] and not body.lstrip().startswith(b"<!D")


def _is_sql(body: bytes, _ct: str) -> bool:
    return bool(_SQL_DUMP.search(body.decode("utf-8", "replace")[:20000]))


def _is_zip(body: bytes, ct: str) -> bool:
    return "zip" in ct or body[:2] == b"PK"


def _is_phpinfo(body: bytes, _ct: str) -> bool:
    text = body.decode("utf-8", "replace")
    return "phpinfo()" in text and "PHP Version" in text


def _is_dirlist(body: bytes, _ct: str) -> bool:
    text = body.decode("utf-8", "replace")[:4000]
    return bool(
        re.search(r"(?i)(Index of /|Directory listing for /)", text)
        or re.search(r"(?i)<h1>\s*(Index of|Directory listing for)", text)
    )


def _is_json(body: bytes, ct: str) -> bool:
    return "json" in ct and body[:1] in (b"{", b"[")


def _is_dsstore(body: bytes, _ct: str) -> bool:
    return body[:4] == b"\x00\x00\x00\x01Bud1" or body[:4] == b"Bud1"


PATHS: list[PathEntry] = [
    ("/.git/HEAD", "git", Severity.HIGH, 7.5, "Exposed Git repository metadata",
     "A live .git directory means the full source tree (and history/secrets) can be "
     "downloaded offline.", _is_git),
    ("/.git/config", "git", Severity.HIGH, 7.5, "Exposed Git config",
     "Git config leaks repository internals; a full dump is likely possible.", _is_git),
    ("/.env", "env", Severity.CRITICAL, 9.1, "Exposed .env file (secrets)",
     "Environment files routinely contain database credentials, API keys and salts.",
     _is_env),
    ("/.env.backup", "env", Severity.CRITICAL, 9.1, "Exposed .env backup",
     "Backed-up environment file with secrets.", _is_env),
    ("/.env.local", "env", Severity.CRITICAL, 9.1, "Exposed .env.local",
     "Local environment file with secrets.", _is_env),
    ("/.env.bak", "env", Severity.CRITICAL, 9.1, "Exposed .env backup",
     "Backed-up environment file with secrets.", _is_env),
    ("/config.php.bak", "backup", Severity.HIGH, 7.5, "Exposed config backup (PHP)",
     "Config backups often contain database passwords in plaintext.", _is_env_any),
    ("/wp-config.php.bak", "backup", Severity.HIGH, 7.5, "Exposed wp-config backup",
     "WordPress config backup contains DB credentials and salts.", _is_env_any),
    ("/config.yml", "backup", Severity.MEDIUM, 5.3, "Exposed config file",
     "Configuration files may contain credentials.", _is_env_any),
    ("/dump.sql", "backup", Severity.HIGH, 7.5, "Exposed SQL dump",
     "A database dump exposes all user data and password hashes.", _is_sql),
    ("/backup.sql", "backup", Severity.HIGH, 7.5, "Exposed SQL dump",
     "A database dump exposes all user data and password hashes.", _is_sql),
    ("/db.sql", "backup", Severity.HIGH, 7.5, "Exposed SQL dump",
     "A database dump exposes all user data and password hashes.", _is_sql),
    ("/backup.zip", "backup", Severity.HIGH, 7.5, "Exposed backup archive",
     "Site backups can contain source code, configs and data.", _is_zip),
    ("/site.zip", "backup", Severity.HIGH, 7.5, "Exposed site archive",
     "Site backups can contain source code, configs and data.", _is_zip),
    ("/www.zip", "backup", Severity.HIGH, 7.5, "Exposed site archive",
     "Site backups can contain source code, configs and data.", _is_zip),
    ("/.DS_Store", "meta", Severity.MEDIUM, 5.3, "Exposed .DS_Store",
     "macOS .DS_Store leaks directory structure and filenames.", _is_dsstore),
    ("/.svn/entries", "meta", Severity.HIGH, 7.5, "Exposed SVN metadata",
     "SVN metadata leaks source paths and revision info.",
     lambda b, c: b"svn" in b[:200].lower() or b"dir" in b[:50]),
    ("/phpinfo.php", "debug", Severity.MEDIUM, 5.3, "phpinfo() exposed",
     "phpinfo() leaks paths, versions, modules and environment variables.",
     _is_phpinfo),
    ("/info.php", "debug", Severity.MEDIUM, 5.3, "phpinfo() exposed",
     "phpinfo() leaks paths, versions, modules and environment variables.",
     _is_phpinfo),
    ("/server-status", "debug", Severity.MEDIUM, 5.3, "Apache server-status exposed",
     "server-status reveals requests, IPs and configuration.",
     lambda b, c: b"Apache Server Status" in b),
    ("/actuator/health", "actuator", Severity.MEDIUM, 5.3, "Spring Actuator endpoint",
     "Actuator endpoints expose health/internal state; /env and /heapdump are critical.",
     _is_json),
    ("/actuator/env", "actuator", Severity.CRITICAL, 9.1, "Spring Actuator /env exposed",
     "Leaks all environment properties including credentials.", _is_json),
    ("/actuator/heapdump", "actuator", Severity.CRITICAL, 9.1,
     "Spring Actuator heapdump exposed", "JVM heap dump contains live secrets in memory.",
     lambda b, c: "java" in c or b[:2] == b"\xfe\xed"),
    ("/console", "debug", Severity.MEDIUM, 5.3, "Debug console exposed",
     "Debug consoles (Django/Flask/Rails) can allow code execution or data access.",
     lambda b, c: b"Traceback" in b or b"Debugger" in b[:3000]),
]

_DEEP_PATHS: list[PathEntry] = [
    ("/.aws/credentials", "cloud", Severity.CRITICAL, 9.1, "AWS credentials file",
     "Cloud credentials allow full account takeover.", _is_env_any),
    ("/id_rsa", "cloud", Severity.CRITICAL, 9.1, "Exposed private key",
     "Leaked SSH private key allows server access.",
     lambda b, c: b"PRIVATE KEY" in b[:200]),
    ("/.docker/env", "cloud", Severity.HIGH, 7.5, "Docker env file",
     "Docker env files often contain registry/app secrets.", _is_env_any),
]


@register
class InfoDisclosure(Check):
    name = "info-disclosure"
    mode = "passive"
    min_profile = "standard"
    summary = "Exposed .git/.env/backups/debug endpoints/directory listings"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        from urllib.parse import urlsplit

        base = ctx.start_url
        parts = urlsplit(base)
        origin = f"{parts.scheme}://{parts.netloc}"

        # soft-404 baseline: fetch a canary path that must not exist
        canary = f"{origin}/.argos-canary-{uuid.uuid4().hex[:10]}"
        try:
            baseline_resp = await ctx.client.get(canary)
            baseline = (baseline_resp.status_code, baseline_resp.text[:300])
        except Exception:
            baseline = (404, "")

        targets = list(PATHS)
        if ctx.config.profile == "deep":
            targets += _DEEP_PATHS

        findings: list[Finding] = []
        for path, kind, sev, score, title, why, detector in targets:
            url = origin + path
            try:
                resp = await ctx.client.get(url)
            except Exception:
                continue
            if resp.status_code in (404, 405):
                continue
            if resp.status_code == 0:
                continue
            # soft-404: server returns 200/403 with the same generic error page
            if resp.status_code == baseline[0] and resp.text[:300] == baseline[1]:
                continue
            if resp.status_code >= 500:
                continue

            body = resp.content
            ct = resp.headers.get("content-type", "")
            found = bool(detector(body, ct))

            if found:
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=title,
                        severity=sev,
                        cvss=score,
                        cwe="CWE-538" if kind in ("git", "meta") else "CWE-200",
                        url=url,
                        parameter=path,
                        description=f"{url} is publicly accessible. {why}",
                        remediation=(
                            f"Block public access to '{path}' at the web server / add it "
                            "to .gitignore-equivalent deny rules, and rotate any "
                            "credentials it contained."
                        ),
                        evidence_response=truncate(
                            f"HTTP {resp.status_code}\n{ct}\n"
                            + body[:600].decode("utf-8", "replace"),
                            800,
                        ),
                    )
                )
            elif resp.status_code == 403 and kind in ("git", "env", "backup", "actuator"):
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Sensitive path exists (403): {path}",
                        severity=Severity.LOW,
                        cvss=3.1,
                        cwe="CWE-538",
                        url=url,
                        parameter=path,
                        description=(
                            f"{url} returned 403 — the resource exists but is blocked. "
                            "Misconfigurations (method tricks, aliases, backups) often "
                            "bypass this."
                        ),
                        remediation=f"Remove '{path}' from the server entirely, don't rely on 403.",
                        evidence_response=f"HTTP {resp.status_code}",
                    )
                )

        # directory listing on any crawled page (e.g. linked folders)
        for page in ctx.pages:
            if not page.is_html or not page.html:
                continue
            if _is_dirlist(page.html.encode("utf-8", "replace"), page.content_type):
                findings.append(
                    Finding(
                        plugin=self.name,
                        title="Directory listing enabled",
                        severity=Severity.MEDIUM,
                        cvss=5.3,
                        cwe="CWE-548",
                        url=page.final_url or page.url,
                        parameter=page.url,
                        description=(
                            "The server lists directory contents, exposing filenames, "
                            "backup files and internal structure."
                        ),
                        remediation=(
                            "Disable autoindex/index listing (Options -Indexes in Apache, "
                            "autoindex off in nginx) and add index files."
                        ),
                        evidence_response=truncate(page.html, 700),
                    )
                )
        return findings
