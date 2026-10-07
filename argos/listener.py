"""Out-of-band callback listener: confirm blind SSRF/XXE/command injection.

    argos listen --port 8080
    # then scan with: --callback http://<your-host>:8080
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# payload tokens argos injects into callback URLs (see ssrf/xxe/cmdi checks)
TOKEN_PREFIX = ("argos-oob-", "argos=", "argos")


@dataclass
class Hit:
    seen_at: str
    method: str
    path: str
    client: str
    user_agent: str
    body: str = ""


@dataclass
class ListenerStats:
    hits: list[Hit] = field(default_factory=list)


def _make_handler(stats: ListenerStats, on_hit) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "argos-listener/1.0"

        def log_message(self, fmt: str, *args: object) -> None:  # quiet
            pass

        def _record(self) -> None:
            length = int(self.headers.get("content-length") or 0)
            body = (
                self.rfile.read(min(length, 4096)).decode("utf-8", "replace")
                if length
                else ""
            )
            hit = Hit(
                seen_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                method=self.command,
                path=self.path,
                client=self.client_address[0],
                user_agent=self.headers.get("user-agent", ""),
                body=body,
            )
            stats.hits.append(hit)
            on_hit(hit)
            payload = b"argos: recorded"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            self._record()

        def do_POST(self) -> None:
            self._record()

        def do_PUT(self) -> None:
            self._record()

        def do_HEAD(self) -> None:
            self._record()

        def do_OPTIONS(self) -> None:
            self._record()

    return Handler


def serve(host: str, port: int) -> None:
    """Blocking: print every callback until Ctrl-C."""
    stats = ListenerStats()

    def on_hit(hit: Hit) -> None:
        print(  # noqa: T201 - the listener's whole purpose is printing
            f"[{hit.seen_at}] {hit.method} {hit.path} "
            f"from {hit.client} ua={hit.user_agent!r}",
            flush=True,
        )

    server = ThreadingHTTPServer((host, port), _make_handler(stats, on_hit))
    print(  # noqa: T201
        f"argos listener on http://{host}:{port} — waiting for callbacks (Ctrl-C to stop)\n"
        f"scan with: --callback http://<reachable-host>:{port}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print(f"\nstopped. {len(stats.hits)} callback(s) received.", flush=True)  # noqa: T201
        for h in stats.hits:
            print(  # noqa: T201
                f"  {h.seen_at} {h.method} {h.path} from {h.client}", flush=True
            )
