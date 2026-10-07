"""Active-probe framework: injection points, safe payload delivery, timing,
response differential analysis.

All active checks share these helpers so payload handling, baselines and
request accounting stay consistent.
"""

from __future__ import annotations

import difflib
import re
import time
import uuid
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from argos.engine.registry import ScanContext


def marker(prefix: str = "argos") -> str:
    """Unique canary string for reflection/output detection."""
    return f"{prefix}{uuid.uuid4().hex[:10]}"


@dataclass
class Point:
    """One injectable parameter (GET query or form field)."""

    method: str  # GET | POST
    endpoint: str  # path+query base for GET / form action for POST
    param: str
    inputs: dict[str, str]  # all params with original values

    @property
    def key(self) -> tuple[str, str, str]:
        path = urlsplit(self.endpoint).path or "/"
        return (self.method, path, self.param)


def build_points(ctx: ScanContext, limit: int = 25) -> list[Point]:
    """Collect deduplicated injection points from crawled pages and forms."""
    points: list[Point] = []
    seen: set[tuple[str, str, str]] = set()

    def add(method: str, endpoint: str, params: dict[str, str]) -> None:
        for name in params:
            p = Point(method=method, endpoint=endpoint, param=name, inputs=dict(params))
            if p.key not in seen:
                seen.add(p.key)
                points.append(p)

    for page in ctx.pages:
        split = urlsplit(page.final_url or page.url)
        query = dict(parse_qsl(split.query, keep_blank_values=True))
        if query:
            base = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
            add("GET", base, query)
        for link in sorted(page.links):
            ls = urlsplit(link)
            lq = dict(parse_qsl(ls.query, keep_blank_values=True))
            if lq:
                base = urlunsplit((ls.scheme, ls.netloc, ls.path, "", ""))
                add("GET", base, lq)
        for form in page.forms:
            if form.method in ("GET", "POST") and form.inputs:
                add(form.method, form.action, form.inputs)
    return points[:limit]


async def send(ctx: ScanContext, point: Point, value: str) -> httpx.Response:
    """Send the point's request with `point.param` replaced by `value`."""
    data = {k: (value if k == point.param else v) for k, v in point.inputs.items()}
    if point.method == "GET":
        split = urlsplit(point.endpoint)
        url = urlunsplit(
            (split.scheme, split.netloc, split.path, urlencode(data), "")
        )
        return await ctx.client.request("GET", url)
    return await ctx.client.request(point.method, point.endpoint, data=data)


async def baseline(ctx: ScanContext, point: Point) -> BaselineResp:
    """Original-value response, cached on the scan context (shared by checks)."""
    key = "|".join(point.key)
    cached = ctx.baselines.get(key)
    if cached is not None:
        return _SyntheticResponse(status=cached[0], text=cached[1])
    resp = await send(ctx, point, point.inputs.get(point.param, ""))
    ctx.baselines[key] = (resp.status_code, resp.text)
    return resp


class BaselineResp(Protocol):
    @property
    def status_code(self) -> int: ...

    @property
    def text(self) -> str: ...


class _SyntheticResponse:
    def __init__(self, status: int, text: str):
        self.status_code = status
        self.text = text


def similar(a: str, b: str) -> bool:
    """True when two response bodies are effectively the same page."""
    if a == b:
        return True
    a, b = a[:5000], b[:5000]
    if not a or not b:
        return False
    return difflib.SequenceMatcher(None, a, b).quick_ratio() > 0.9


async def timed_send(ctx: ScanContext, point: Point, value: str) -> float:
    """Round-trip time (seconds) of an injected request."""
    t0 = time.perf_counter()
    await send(ctx, point, value)
    return time.perf_counter() - t0


async def timing_hit(
    ctx: ScanContext,
    point: Point,
    payload: str,
    sleep_s: float = 5.0,
) -> bool:
    """Screen a time-based payload once, confirm once. Two hits required."""
    base_s, _ = await _timed_full(ctx, point, point.inputs.get(point.param, ""))
    if base_s >= sleep_s * 0.7:
        return False  # baseline already slow; test would be meaningless
    hit_s, _ = await _timed_full(ctx, point, payload)
    if hit_s < base_s + sleep_s * 0.7:
        return False
    confirm_s, _ = await _timed_full(ctx, point, payload)
    return confirm_s >= base_s + sleep_s * 0.7


async def _timed_full(ctx: ScanContext, point: Point, value: str) -> tuple[float, str]:
    t0 = time.perf_counter()
    resp = await send(ctx, point, value)
    return time.perf_counter() - t0, resp.text


# --- SQL error signature detection -----------------------------------------

SQL_ERRORS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"you have an error in your sql syntax", re.I), "MySQL"),
    (re.compile(r"warning:\s*mysql_", re.I), "MySQL"),
    (re.compile(r"mysqli?_", re.I), "MySQL"),
    (re.compile(r"supplied argument is not a valid mysql", re.I), "MySQL"),
    (re.compile(r"pg_query\(\)|pg_exec\(\)|unterminated quoted string", re.I), "PostgreSQL"),
    (re.compile(r"postgresql.*error|psycopg2?\.", re.I), "PostgreSQL"),
    (re.compile(r"unclosed quotation mark after the character string", re.I), "MSSQL"),
    (re.compile(r"microsoft sql server native client|odbc sql server driver", re.I), "MSSQL"),
    (re.compile(r"ora-\d{4,5}|dynamic sql error", re.I), "Oracle"),
    (
        re.compile(r"sqlite[/ ].?(?:exception|error)|unrecognized token", re.I),
        "SQLite",
    ),
    (re.compile(r"sqlstate\[[0-9a-z]+\]|pdoexception", re.I), "Generic SQL"),
    (re.compile(r"you have an error in your sql|syntax error at or near", re.I), "Generic SQL"),
]


def sql_error_in(text: str) -> str | None:
    """Return the DBMS name if an SQL error signature is present."""
    for pattern, dbms in SQL_ERRORS:
        if pattern.search(text):
            return dbms
    return None


# --- point limiting shared by active checks ---------------------------------

DEFAULT_POINTS = 10
TIME_POINTS = 3
