"""Allowlist: hosts authorized for active (payload-injecting) checks.

Active checks may ONLY target hosts matched by patterns in an `argos.allow` file.
Pattern syntax:
    example.com          exact host
    *.example.com        any subdomain of example.com (apex not included)
    localhost / 127.0.0.1
Comments (#) and blank lines are ignored.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

ALLOW_FILE = "argos.allow"


def _find_allowfile(start: Path | None = None) -> Path | None:
    dirs: list[Path] = []
    if start is not None:
        dirs.append(start if start.is_dir() else start.parent)
    dirs.append(Path.cwd())
    seen: set[Path] = set()
    for base in dirs:
        base = base.resolve()
        for d in [base, *base.parents]:
            if d in seen:
                continue
            seen.add(d)
            candidate = d / ALLOW_FILE
            if candidate.is_file():
                return candidate
    return None


def _host_of(value: str) -> str:
    """Extract lowercase hostname from a URL or bare host."""
    if "://" in value:
        host = urlsplit(value).hostname or ""
    else:
        host = value.split("/")[0]
    host = host.strip().lower()
    if ":" in host:  # strip port (IPv6 in brackets handled by urlsplit above)
        host = host.rsplit(":", 1)[0]
    return host.strip("[]")


class Allowlist:
    def __init__(self, patterns: list[str] | None = None, path: Path | None = None):
        self.path = path
        self.patterns: list[str] = patterns or []

    @classmethod
    def load(cls, start: Path | None = None) -> Allowlist:
        path = _find_allowfile(start)
        if path is None:
            return cls([])
        return cls(_read_patterns(path), path=path)

    @classmethod
    def for_target(cls, url: str) -> Allowlist:
        """Load allowlist, searching next to the target's directory context (cwd)."""
        return cls.load()

    def allows(self, target: str) -> bool:
        host = _host_of(target)
        if not host:
            return False
        return any(_match(host, p) for p in self.patterns)

    def add(self, pattern: str) -> Path:
        pattern = pattern.strip().lower()
        if not pattern:
            raise ValueError("empty pattern")
        path = self.path or (Path.cwd() / ALLOW_FILE)
        if pattern not in self.patterns:
            self.patterns.append(pattern)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(pattern + "\n")
        self.path = path
        return path

    def remove(self, pattern: str) -> bool:
        pattern = pattern.strip().lower()
        if pattern not in self.patterns:
            return False
        self.patterns.remove(pattern)
        if self.path and self.path.is_file():
            _write_patterns(self.path, self.patterns)
        return True


def _match(host: str, pattern: str) -> bool:
    pattern = pattern.strip().lower()
    if not pattern or pattern.startswith("#"):
        return False
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return host == pattern


def _read_patterns(path: Path) -> list[str]:
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _write_patterns(path: Path, patterns: list[str]) -> None:
    header = (
        "# argos allowlist — hosts that active (payload-injecting) checks may target.\n"
        "# Only list domains you own or are authorized to test.\n"
    )
    path.write_text(header + "\n".join(patterns) + "\n", encoding="utf-8")
