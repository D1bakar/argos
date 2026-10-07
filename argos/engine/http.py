"""Async HTTP client with rate limiting and browser-like defaults."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from typing import Any, Protocol

import httpx

from argos import __version__
from argos.config import ScanConfig

DEFAULT_UA = f"argos/{__version__} (+https://github.com/D1bakar/argos)"

BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}


class RateLimiter:
    """Fixed-interval limiter: at most `rate` requests per second."""

    def __init__(self, rate: float):
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


def parse_cookie_header(cookie: str) -> dict[str, str]:
    """Parse 'a=b; c=d' into a dict."""
    out: dict[str, str] = {}
    for part in cookie.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out


class HttpClient:
    """Thin wrapper over httpx.AsyncClient: rate limiting, auth, consistent UA."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.rate_limiter = RateLimiter(config.rate or 5.0)
        self.request_count = 0
        headers = dict(BROWSER_HEADERS)
        headers["User-Agent"] = DEFAULT_UA
        headers.update(config.headers)
        if config.cookie:
            headers["Cookie"] = config.cookie
        self._client = httpx.AsyncClient(
            http2=True,
            headers=headers,
            timeout=httpx.Timeout(config.timeout),
            verify=not config.insecure,
            follow_redirects=False,
        )

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        max_redirects: int = 0,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send a request, honoring the rate limiter. Follows up to `max_redirects`
        redirects manually so scope checks stay possible at every hop."""
        for _ in range(max_redirects + 1):
            await self.rate_limiter.acquire()
            self.request_count += 1
            resp = await self._client.request(method.upper(), url, **kwargs)
            if max_redirects and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                if not location:
                    return resp
                url = str(resp.url.join(location))
                if resp.status_code in (303,) or (
                    resp.status_code in (301, 302) and method.upper() == "POST"
                ):
                    method = "GET"
                continue
            return resp
        return resp

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    # --- cookie jar management (role logins) ---------------------------------
    def cookie_pairs(self) -> dict[str, str]:
        return {c.name: c.value for c in self._client.cookies.jar if c.value is not None}

    def cookie_header(self) -> str:
        return "; ".join(
            f"{c.name}={c.value}"
            for c in self._client.cookies.jar
            if c.value is not None
        )

    def clear_cookies(self) -> None:
        self._client.cookies.clear()


class ResponseLike(Protocol):
    status_code: int
    http_version: str
    headers: Mapping[str, str]
    text: str


def snippet(resp: ResponseLike, limit: int = 1200) -> str:
    """Response snippet for evidence: status + selected headers + body head."""
    lines = [f"HTTP {resp.status_code} {resp.http_version}"]
    for k, v in resp.headers.items():
        if k.lower() in (
            "server",
            "x-powered-by",
            "content-type",
            "content-length",
            "location",
            "set-cookie",
            "www-authenticate",
            "x-debug",
        ):
            lines.append(f"{k}: {v}")
    body = resp.text[:limit] if "text" in resp.headers.get("content-type", "") or resp.text else ""
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)
