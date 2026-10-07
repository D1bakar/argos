"""Rich console report."""

from __future__ import annotations

from datetime import UTC, datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argos.engine.findings import SEVERITY_COLORS, Finding, Severity
from argos.engine.scanner import ScanResult

_SEV_STYLE = {s: SEVERITY_COLORS[s] for s in Severity}


def render(result: ScanResult, console: Console) -> None:
    _header(result, console)
    _summary(result, console)
    if result.findings:
        _finding_index(result, console)
        for f in result.findings:
            _finding_detail(f, console)
    if result.warnings:
        _warnings(result, console)


def _header(result: ScanResult, console: Console) -> None:
    console.rule("[bold]argos scan report")
    started = datetime.fromtimestamp(result.started_at, tz=UTC)
    meta = Table.grid(padding=(0, 2))
    meta.add_row("target", f"[bold]{result.target}[/bold]")
    meta.add_row(
        "profile",
        f"{result.profile}   active={'yes' if result.active else 'no'}",
    )
    meta.add_row(
        "started (UTC)",
        started.strftime("%Y-%m-%d %H:%M:%S"),
    )
    meta.add_row(
        "duration",
        f"{result.duration:.1f}s   pages={len(result.pages)}   "
        f"requests={result.requests}   checks={len(result.checks_run)}",
    )
    console.print(meta)


def _summary(result: ScanResult, console: Console) -> None:
    counts = result.counts()
    parts = []
    for sev in Severity:
        n = counts.get(sev.value, 0)
        if n:
            parts.append(Text(f"{n} {sev.value}", style=_SEV_STYLE[sev]))
    if not parts:
        console.print("[green]no findings[/green]")
        return
    console.print("findings: ", end="")
    for i, p in enumerate(parts):
        console.print(p, end="" if i == len(parts) - 1 else ", ")
    console.print()


def _finding_index(result: ScanResult, console: Console) -> None:
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("#", style="dim", width=3)
    table.add_column("SEV", width=9)
    table.add_column("CVSS", width=4, justify="right")
    table.add_column("CWE", width=12)
    table.add_column("TITLE")
    table.add_column("URL", overflow="fold", max_width=50)
    for i, f in enumerate(result.findings, 1):
        table.add_row(
            str(i),
            Text(f.severity.value.upper(), style=_SEV_STYLE[f.severity]),
            f"{f.cvss:.1f}" if f.cvss else "-",
            f.cwe or "-",
            f.title,
            f.url,
        )
    console.print()
    console.print(table)


def _finding_detail(f: Finding, console: Console) -> None:
    body = Text()
    body.append("What: ", style="bold")
    body.append(f.description + "\n")
    body.append("Where: ", style="bold")
    body.append(f.url)
    if f.parameter:
        body.append(f"  (parameter: {f.parameter})")
    body.append("\n")
    body.append("Fix: ", style="bold")
    body.append(f.remediation + "\n")
    if f.evidence_request or f.evidence_response:
        body.append("\nEvidence\n", style="bold underline")
        if f.evidence_request:
            body.append("REQUEST\n", style="dim")
            body.append(f.evidence_request.rstrip() + "\n")
        if f.evidence_response:
            body.append("RESPONSE\n", style="dim")
            body.append(f.evidence_response.rstrip())
    console.print()
    console.print(
        Panel(
            body,
            title=f"[{_SEV_STYLE[f.severity]}]{f.severity.value.upper()}[/] "
            f"{f.title}  [{f.cwe or 'n/a'}]",
            border_style=_SEV_STYLE[f.severity],
        )
    )


def _warnings(result: ScanResult, console: Console) -> None:
    console.print()
    for w in result.warnings:
        console.print(f"[yellow]warning:[/yellow] {w}")
