"""Scope-locked breadth-first crawler."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup, Tag

from argos.engine.http import HttpClient

MAX_REDIRECTS = 5


def _attr_str(tag: Tag, name: str) -> str | None:
    """bs4 attribute access as a plain str (handles multi-valued attrs)."""
    value = tag.get(name)
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(str(v) for v in value) if value else None
    return None
ASSET_EXTS = {
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".webp", ".mp4", ".mp3", ".pdf",
    ".zip", ".gz", ".tar",
}


@dataclass
class Form:
    action: str
    method: str
    inputs: dict[str, str]
    page_url: str


@dataclass
class Page:
    url: str
    status: int
    headers: dict[str, str]
    content_type: str = ""
    html: str = ""
    final_url: str = ""
    depth: int = 0
    links: set[str] = field(default_factory=set)
    forms: list[Form] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    inline_scripts: str = ""
    title: str = ""

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type


def same_scope(start_url: str, candidate: str) -> bool:
    """Strict scope: same hostname as the start URL (www. treated as the apex)."""
    a = _host(start_url)
    b = _host(candidate)
    if not a or not b:
        return False
    if a == b:
        return True
    return (a, b) in {("www." + b, b), (b, "www." + b)} or _www(a) == _www(b)


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def normalize(url: str) -> str | None:
    """Canonicalize a URL for dedupe; return None if not crawlable."""
    url, _frag = urldefrag(url.strip())
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return None
    if not parts.hostname:
        return None
    path = parts.path or "/"
    if any(path.lower().endswith(ext) for ext in ASSET_EXTS):
        return None
    return f"{parts.scheme}://{parts.netloc}{path}" + (f"?{parts.query}" if parts.query else "")


class RobotsRules:
    """Minimal robots.txt handling for the `*` user-agent group."""

    def __init__(
        self,
        disallows: list[str] | None = None,
        allows: list[str] | None = None,
    ):
        self.disallows = disallows or []
        self.allows = allows or []

    @classmethod
    async def fetch(cls, client: HttpClient, base_url: str) -> RobotsRules:
        origin = f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}"
        try:
            resp = await client.get(origin + "/robots.txt")
        except httpx.HTTPError:
            return cls()
        if resp.status_code != 200:
            return cls()
        return cls._parse(resp.text)

    @classmethod
    def _parse(cls, text: str) -> RobotsRules:
        disallows: list[str] = []
        allows: list[str] = []
        applies = False
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            field_name, _, value = line.partition(":")
            field_name = field_name.strip().lower()
            value = value.strip()
            if field_name == "user-agent":
                applies = value == "*"
            elif applies and field_name == "disallow" and value:
                disallows.append(value)
            elif applies and field_name == "allow" and value:
                allows.append(value)
        return cls(disallows, allows)

    def allowed(self, url: str) -> bool:
        path = urlsplit(url).path or "/"
        for rule in self.allows:
            if path.startswith(rule):
                return True
        for rule in self.disallows:
            if path.startswith(rule):
                return False
        return True


class Crawler:
    def __init__(
        self,
        client: HttpClient,
        *,
        max_pages: int = 60,
        max_depth: int = 4,
        robots: RobotsRules | None = None,
        on_progress: object = None,
    ):
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.robots = robots
        self.on_progress = on_progress

    async def crawl(self, start_url: str) -> list[Page]:
        start = normalize(start_url)
        if start is None:
            raise ValueError(f"not a crawlable URL: {start_url}")

        pages: list[Page] = []
        seen: set[str] = {start}
        queue: deque[tuple[str, int]] = deque([(start, 0)])

        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()
            if depth > self.max_depth:
                continue
            if self.robots and not self.robots.allowed(url):
                continue

            page = await self._fetch(url, depth)
            if page is None:
                continue
            pages.append(page)
            self._notify(f"crawled {url} ({page.status})")

            if not page.is_html or depth >= self.max_depth:
                continue
            for link in page.links:
                if link in seen:
                    continue
                if not same_scope(start_url, link):
                    continue
                norm = normalize(link)
                if norm and norm not in seen:
                    seen.add(norm)
                    queue.append((norm, depth + 1))
        return pages

    async def _fetch(self, url: str, depth: int) -> Page | None:
        try:
            resp = await self.client.get(url, max_redirects=MAX_REDIRECTS)
        except httpx.HTTPError:
            return None

        # stay in scope across redirects
        if not same_scope(url, str(resp.url)):
            return None

        content_type = resp.headers.get("content-type", "")
        page = Page(
            url=url,
            final_url=str(resp.url),
            status=resp.status_code,
            headers=dict(resp.headers),
            content_type=content_type,
            depth=depth,
        )
        if "html" not in content_type:
            return page

        page.html = resp.text
        page.links, page.forms, page.scripts, page.inline_scripts, page.title = self._parse(
            page.final_url, page.html
        )
        return page

    @staticmethod
    def _parse(
        base_url: str, html: str
    ) -> tuple[set[str], list[Form], list[str], str, str]:
        soup = BeautifulSoup(html, "html.parser")
        links: set[str] = set()
        for tag_name, attr in (("a", "href"), ("link", "href"), ("area", "href")):
            for el in soup.find_all(tag_name):
                href = _attr_str(el, attr)
                if href:
                    links.add(urljoin(base_url, href))
        for el in soup.find_all("script", src=True):
            src = _attr_str(el, "src")
            if src:
                links.add(urljoin(base_url, src))

        forms: list[Form] = []
        for el in soup.find_all("form"):
            action = urljoin(base_url, _attr_str(el, "action") or base_url)
            method = (_attr_str(el, "method") or "GET").upper()
            inputs: dict[str, str] = {}
            for field_el in el.find_all(["input", "textarea", "select"]):
                name = _attr_str(field_el, "name")
                if not name:
                    continue
                value = _attr_str(field_el, "value")
                if value is None and field_el.name == "textarea":
                    value = field_el.text
                inputs[name] = value or ""
            forms.append(Form(action=action, method=method, inputs=inputs, page_url=base_url))

        scripts: list[str] = []
        for s in soup.find_all("script", src=True):
            src = _attr_str(s, "src")
            if src:
                scripts.append(urljoin(base_url, src))
        inline = "\n".join(
            str(s.string) for s in soup.find_all("script") if not s.get("src") and s.string
        )
        title = soup.title.get_text(strip=True) if soup.title else ""
        return links, forms, scripts, inline, title

    def _notify(self, message: str) -> None:
        cb = getattr(self, "on_progress", None)
        if callable(cb):
            cb(message)
