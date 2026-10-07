"""argos command-line interface."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import cast

import typer
from rich.console import Console
from rich.table import Table

from argos import __version__
from argos.config import PROFILES, ProfileName, ScanConfig
from argos.engine.allowlist import ALLOW_FILE, Allowlist
from argos.engine.findings import Severity, severity_at_least
from argos.engine.registry import load_checks, select_checks
from argos.engine.scanner import Scanner
from argos.reports import html_report, json_report
from argos.reports.console import render


def _force_utf8() -> None:
    """Windows consoles/pipes default to cp1252; reports contain unicode."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass


_force_utf8()

app = typer.Typer(
    name="argos",
    help=(
        "argos — active web vulnerability scanner for AUTHORIZED testing only.\n\n"
        "Active checks run only against hosts listed in argos.allow."
    ),
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
allow_app = typer.Typer(help="manage the active-scan allowlist (argos.allow)")
app.add_typer(allow_app, name="allow")

console = Console()
err_console = Console(stderr=True)


def _fail(message: str) -> None:
    err_console.print(f"[red]error:[/red] {message}")
    raise typer.Exit(code=1)


def _parse_headers(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if ":" not in item:
            _fail(f"invalid --header (want 'Name: value'): {item!r}")
        k, _, v = item.partition(":")
        out[k.strip()] = v.strip()
    return out


def _parse_roles(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if ":" not in item:
            _fail(f"invalid --roles (want name:password): {item!r}")
        k, _, v = item.partition(":")
        out[k.strip()] = v.strip()
    return out


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL, e.g. https://app.example.com"),
    profile: str = typer.Option(
        "standard", "--profile", "-p", help="quick | standard | deep"
    ),
    active: bool = typer.Option(
        False,
        "--active",
        "-a",
        help="Enable payload injection (target must be in argos.allow)",
    ),
    pages: int | None = typer.Option(None, "--pages", help="Max pages to crawl"),
    depth: int | None = typer.Option(None, "--depth", help="Max crawl depth"),
    rate: float | None = typer.Option(None, "--rate", help="Requests per second"),
    timeout: float = typer.Option(15.0, "--timeout", help="Per-request timeout (s)"),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Skip TLS verify"),
    respect_robots: bool = typer.Option(
        False, "--respect-robots", help="Obey robots.txt while crawling"
    ),
    cookie: str | None = typer.Option(
        None, "--cookie", help="Session cookie header value for authenticated scan"
    ),
    header: list[str] = typer.Option(
        [], "--header", "-H", help="Extra request header 'Name: value' (repeatable)"
    ),
    roles: list[str] = typer.Option(
        [], "--roles", help="Scan role 'name:password' (repeatable, e.g. admin:secret)"
    ),
    callback: str | None = typer.Option(
        None, "--callback", help="Out-of-band callback URL you control (SSRF/XXE/blind)"
    ),
    json_out: Path | None = typer.Option(None, "--json", help="Write JSON report"),
    html_out: Path | None = typer.Option(None, "--html", help="Write HTML report"),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit 2 if findings at/above severity (e.g. high)"
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output"),
) -> None:
    """Scan a URL and report vulnerabilities."""
    if profile not in PROFILES:
        _fail(f"unknown profile {profile!r} (choose from {', '.join(PROFILES)})")
    cfg_profile = cast(ProfileName, profile)
    threshold: Severity | None = None
    if fail_on:
        try:
            threshold = Severity(fail_on.lower())
        except ValueError:
            _fail(f"invalid --fail-on {fail_on!r} (critical|high|medium|low|info)")

    if active:
        allowlist = Allowlist.load()
        if not allowlist.allows(url):
            err_console.print(
                f"[yellow]note:[/yellow] {url} is not in {ALLOW_FILE} — "
                "active checks will be skipped. Run: argos allow add <host>"
            )

    config = ScanConfig(
        url=url,
        profile=cfg_profile,
        active=active,
        rate=rate,
        max_pages=pages,
        max_depth=depth,
        timeout=timeout,
        insecure=insecure,
        respect_robots=respect_robots,
        cookie=cookie,
        headers=_parse_headers(header),
        roles=_parse_roles(roles),
        callback=callback,
    )

    progress = (lambda msg: console.print(f"[dim]·[/dim] {msg}")) if not quiet else None

    try:
        result = asyncio.run(Scanner(config, on_progress=progress).run())
    except KeyboardInterrupt:
        _fail("scan interrupted")
    except ValueError as exc:
        _fail(str(exc))

    console.print()
    render(result, console)

    if json_out:
        json_report.write(result, json_out)
        console.print(f"\n[dim]JSON report →[/dim] {json_out}")
    if html_out:
        html_report.write(result, html_out)
        console.print(f"[dim]HTML report →[/dim] {html_out}")

    if threshold and any(severity_at_least(f.severity, threshold) for f in result.findings):
        raise typer.Exit(code=2)


@allow_app.command("add")
def allow_add(pattern: str = typer.Argument(..., help="host or *.host to authorize")):
    """Authorize a host for active scanning."""
    al = Allowlist.load()
    path = al.add(pattern)
    console.print(f"[green]authorized[/green] {pattern}  ([dim]{path}[/dim])")


@allow_app.command("list")
def allow_list():
    """Show authorized hosts."""
    al = Allowlist.load()
    if not al.patterns:
        console.print(f"allowlist empty — create {ALLOW_FILE} or run: argos allow add <host>")
        return
    table = Table(title=f"authorized hosts ({al.path})")
    table.add_column("#", style="dim")
    table.add_column("pattern")
    for i, p in enumerate(al.patterns, 1):
        table.add_row(str(i), p)
    console.print(table)


@allow_app.command("remove")
def allow_remove(pattern: str = typer.Argument(...)):
    """Remove a host from the allowlist."""
    al = Allowlist.load()
    if al.remove(pattern):
        console.print(f"[green]removed[/green] {pattern}")
    else:
        _fail(f"pattern not in allowlist: {pattern}")


@app.command()
def plugins(profile: str = typer.Option("deep", "--profile", "-p")):
    """List available checks for a profile."""
    load_checks()
    table = Table(title=f"checks (profile={profile})")
    table.add_column("name")
    table.add_column("mode")
    table.add_column("min profile")
    table.add_column("summary")
    cfg = ScanConfig(url="placeholder", profile=profile, active=True)  # type: ignore[arg-type]
    for check in select_checks(cfg, active_allowed=True):
        color = "red" if check.mode == "active" else "cyan"
        table.add_row(check.name, f"[{color}]{check.mode}[/]", check.min_profile, check.summary)
    console.print(table)


@app.command()
def listen(
    port: int = typer.Option(8080, "--port", "-p", help="Port to listen on"),
    host: str = typer.Option("0.0.0.0", "--host", help="Bind address"),
) -> None:
    """Listen for out-of-band callbacks (blind SSRF/XXE/injection confirmation).

    Run this where the target can reach you, then scan with
    --callback http://<your-reachable-host>:<port>.
    """
    from argos.listener import serve

    serve(host, port)


@app.command()
def version():
    """Print version."""
    console.print(f"argos {__version__}")


if __name__ == "__main__":
    app()
