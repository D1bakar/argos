"""Client-side library fingerprinting from crawled script URLs."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Lib:
    name: str  # npm ecosystem package name
    version: str
    source: str  # script URL or "inline"


# generic CDN patterns first: cdn.jsdelivr.net/npm/pkg@1.2.3, unpkg.com/pkg@1.2.3,
# cdnjs.cloudflare.com/ajax/libs/pkg/1.2.3/
_CDN_GENERIC = re.compile(
    r"""(?ix)
    (?:cdn\.jsdelivr\.net/npm/|unpkg\.com/)
    (?P<name>[\w.-]+)@(?P<version>\d+\.\d+\.\d+[\w.+-]*)
    |
    cdn\.cdnjs\.cloudflare\.com/ajax/libs/
    (?P<name2>[\w.-]+)/(?P<version2>\d+\.\d+\.\d+[\w.+-]*)
    """
)

# self-hosted / versioned filenames → npm package
# version stops at non-numeric suffix (.min.js etc. must not be swallowed)
_FILE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("jquery", re.compile(r"jquery[.-](?P<v>\d+\.\d+\.\d+(?:-[\w.]+)?)", re.I)),
    ("jquery-ui", re.compile(r"jquery-ui[.-](?P<v>\d+\.\d+\.\d+(?:-[\w.]+)?)", re.I)),
    ("jquery-ui", re.compile(r"jquery-ui/(?P<v>\d+\.\d+\.\d+)", re.I)),
    ("angular", re.compile(r"angularjs[.-/](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("angular", re.compile(r"angular[.-](?P<v>\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("bootstrap", re.compile(r"bootstrap[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("lodash", re.compile(r"lodash[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("moment", re.compile(r"moment[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("react", re.compile(r"react[.-](?P<v>\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("react-dom", re.compile(r"react-dom[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("vue", re.compile(r"vue[.-](?P<v>\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("axios", re.compile(r"axios[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("underscore", re.compile(r"underscore[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("backbone", re.compile(r"backbone[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("handlebars", re.compile(r"handlebars[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("knockout", re.compile(r"knockout[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("mustache", re.compile(r"mustache[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("d3", re.compile(r"d3[.-](?P<v>\d+\.\d+\.\d+)(?:\.min)?\.js", re.I)),
    ("video.js", re.compile(r"video-js[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("tinymce", re.compile(r"tinymce[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("ckeditor", re.compile(r"ckeditor[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("dojo", re.compile(r"dojo[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
    ("marked", re.compile(r"marked[.-](?P<v>\d+\.\d+\.\d+)", re.I)),
]


def _clean(version: str) -> str:
    return version.lstrip("v")


def detect_libs(scripts: list[str], inline: str = "") -> list[Lib]:
    """Find versioned JS libraries in script URLs and inline comments."""
    found: dict[tuple[str, str], Lib] = {}

    for url in scripts:
        m = _CDN_GENERIC.search(url)
        if m:
            name = m.group("name") or m.group("name2")
            version = m.group("version") or m.group("version2")
            found[(name, version)] = Lib(name, _clean(version), url)
            continue
        for name, pattern in _FILE_PATTERNS:
            fm = pattern.search(url)
            if fm:
                version = _clean(fm.group("v"))
                found[(name, version)] = Lib(name, version, url)
                break

    # inline version comments: "jQuery v3.6.0", "AngularJS v1.8.2"
    for name in ("jquery", "angular", "underscore", "backbone", "lodash"):
        im = re.search(
            rf"{name}\s+v?(?P<v>\d+\.\d+\.\d+)", inline, re.IGNORECASE
        )
        if im:
            key = (name, im.group("v"))
            found.setdefault(key, Lib(name, im.group("v"), "inline"))
    return list(found.values())
