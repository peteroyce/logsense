"""
LogSense CLI — terminal-native log intelligence.

Commands
--------
  analyse FILE   Full analysis pipeline with Rich dashboard output.
  stats FILE     Quick stats: line count, error rate, time range.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from logsense import version as __version__
from logsense.parser import detect_format, parse_file
from logsense.clustering import cluster_errors
from logsense.anomaly import detect_anomalies
from logsense.alerts import send_slack_alert

load_dotenv()

console = Console()

_LEVEL_STYLES = {
    "ERROR": "bold red",
    "CRITICAL": "bold bright_red",
    "FATAL": "bold bright_red",
    "WARNING": "bold yellow",
    "WARN": "bold yellow",
    "INFO": "green",
    "DEBUG": "dim cyan",
    "TRACE": "dim",
    "UNKNOWN": "dim white",
}

_SEVERITY_STYLES = {
    "critical": "bold bright_red",
    "warning": "bold yellow",
}


def _level_text(level: str) -> Text:
    style = _LEVEL_STYLES.get(level.upper(), "white")
    return Text(level, style=style)


def _fmt_dt(dt: Optional[datetime]) -> str:
    if dt is None:
        return "[dim]—[/dim]"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _error_rate_colour(rate: float) -> str:
    if rate >= 0.20:
        return "bold red"
    if rate >= 0.05:
        return "yellow"
    return "green"


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="logsense")
def cli() -> None:
    """LogSense — terminal-native log intelligence."""


# ---------------------------------------------------------------------------
# analyse command
# ---------------------------------------------------------------------------

@cli.command("analyse")
@click.argument("file", type=click.Path(exists=True, readable=True, path_type=Path))
@click.option(
    "--format",
    "log_format",
    type=click.Choice(["nginx", "apache", "json", "auto"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Log format (default: auto-detect).",
)
@click.option(
    "--slack-webhook",
    envvar="SLACK_WEBHOOK_URL",
    default=None,
    metavar="URL",
    help="Slack Incoming Webhook URL (or set SLACK_WEBHOOK_URL env var).",
)
@click.option(
    "--window-minutes",
    default=5,
    show_default=True,
    type=click.IntRange(1, 1440),
    help="Size of each anomaly-detection time window (minutes).",
)
def analyse(
    file: Path,
    log_format: str,
    slack_webhook: Optional[str],
    window_minutes: int,
) -> None:
    """Run a full analysis pipeline on FILE and display a Rich dashboard."""

    console.print()
    console.rule(f"[bold cyan]LogSense[/bold cyan] [dim]v{__version__}[/dim]")
    console.print()

    # ---- Parse ----
    with console.status(f"[cyan]Parsing [bold]{file.name}[/bold]…[/cyan]"):
        entries = parse_file(file)

    if not entries:
        console.print(f"[yellow]No log entries found in {file}.[/yellow]")
        sys.exit(0)

    detected = detect_format([e["raw"] for e in entries[:40]])
    actual_format = detected if log_format == "auto" else log_format

    # ---- Aggregate basic stats ----
    total = len(entries)
    error_levels = {"ERROR", "CRITICAL", "FATAL", "WARNING", "WARN"}
    errors = [e for e in entries if e.get("level", "").upper() in error_levels]
    error_count = len(errors)
    error_rate = error_count / total if total else 0.0

    timed = [e for e in entries if isinstance(e.get("timestamp"), datetime)]
    time_min = min(e["timestamp"] for e in timed) if timed else None
    time_max = max(e["timestamp"] for e in timed) if timed else None

    level_counts: dict[str, int] = {}
    for e in entries:
        lvl = e.get("level", "UNKNOWN").upper()
        level_counts[lvl] = level_counts.get(lvl, 0) + 1

    # ---- Cluster errors ----
    with console.status("[cyan]Clustering error patterns…[/cyan]"):
        clusters = cluster_errors(entries)

    # ---- Detect anomalies ----
    with console.status(f"[cyan]Detecting anomalies (window={window_minutes}m)…[/cyan]"):
        anomalies = detect_anomalies(entries, window_minutes=window_minutes)

    # ================================================================
    # Dashboard output
    # ================================================================

    # -- Summary panel --
    rate_style = _error_rate_colour(error_rate)
    summary_lines = [
        f"[bold]File:[/bold]          {file}",
        f"[bold]Format:[/bold]        {actual_format}",
        f"[bold]Total entries:[/bold] {total:,}",
        f"[bold]Error count:[/bold]   [{rate_style}]{error_count:,}[/{rate_style}]",
        f"[bold]Error rate:[/bold]    [{rate_style}]{error_rate:.2%}[/{rate_style}]",
        f"[bold]Time range:[/bold]    {_fmt_dt(time_min)}  →  {_fmt_dt(time_max)}",
        f"[bold]Anomalies:[/bold]     {'[bold red]' + str(len(anomalies)) + '[/bold red]' if anomalies else '[green]None[/green]'}",
    ]
    console.print(
        Panel(
            "\n".join(summary_lines),
            title="[bold cyan]Summary[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )
    console.print()

    # -- Level breakdown table --
    if level_counts:
        lvl_table = Table(
            title="Log Level Breakdown",
            box=box.ROUNDED,
            border_style="dim",
            show_header=True,
            header_style="bold",
        )
        lvl_table.add_column("Level", style="bold", min_width=10)
        lvl_table.add_column("Count", justify="right")
        lvl_table.add_column("Share", justify="right")

        for lvl in sorted(level_counts, key=lambda k: level_counts[k], reverse=True):
            count = level_counts[lvl]
            share = count / total
            style = _LEVEL_STYLES.get(lvl, "white")
            lvl_table.add_row(
                Text(lvl, style=style),
                f"{count:,}",
                f"{share:.1%}",
            )

        console.print(lvl_table)
        console.print()

    # -- Top error patterns table --
    if clusters:
        pat_table = Table(
            title="Top Error Patterns",
            box=box.ROUNDED,
            border_style="dim",
            show_header=True,
            header_style="bold",
        )
        pat_table.add_column("#", justify="right", style="dim", width=3)
        pat_table.add_column("Count", justify="right", min_width=6)
        pat_table.add_column("Pattern", no_wrap=False, min_width=40, max_width=70)
        pat_table.add_column("First seen", min_width=19)
        pat_table.add_column("Last seen", min_width=19)

        for idx, cluster in enumerate(clusters[:15], start=1):
            pat_table.add_row(
                str(idx),
                f"[bold]{cluster['count']:,}[/bold]",
                Text(cluster["pattern"][:200], overflow="fold"),
                _fmt_dt(cluster.get("first_seen")),
                _fmt_dt(cluster.get("last_seen")),
            )

        console.print(pat_table)
        console.print()
    else:
        console.print("[green]No error patterns detected.[/green]\n")

    # -- Anomalies table --
    if anomalies:
        anom_table = Table(
            title=f"[bold red]Anomalous Windows (window={window_minutes}m)[/bold red]",
            box=box.ROUNDED,
            border_style="red",
            show_header=True,
            header_style="bold",
        )
        anom_table.add_column("Window start", min_width=19)
        anom_table.add_column("Window end", min_width=19)
        anom_table.add_column("Total", justify="right")
        anom_table.add_column("Errors", justify="right")
        anom_table.add_column("Rate", justify="right")
        anom_table.add_column("z-score", justify="right")
        anom_table.add_column("Severity", justify="center")

        for anomaly in anomalies:
            sev = anomaly["severity"]
            sev_style = _SEVERITY_STYLES.get(sev, "white")
            rate_val = anomaly["error_rate"]
            anom_table.add_row(
                _fmt_dt(anomaly["window_start"]),
                _fmt_dt(anomaly["window_end"]),
                str(anomaly["total_count"]),
                f"[bold]{anomaly['error_count']}[/bold]",
                f"[{_error_rate_colour(rate_val)}]{rate_val:.1%}[/{_error_rate_colour(rate_val)}]",
                f"{anomaly['z_score']:.1f}σ",
                Text(sev.upper(), style=sev_style),
            )

        console.print(anom_table)
        console.print()

        # -- Slack alert --
        webhook = slack_webhook or os.getenv("SLACK_WEBHOOK_URL", "")
        if webhook:
            top_pattern = clusters[0]["pattern"] if clusters else ""
            summary_payload = {
                "file_path": str(file),
                "total_lines": total,
                "error_count": error_count,
                "error_rate": error_rate,
                "format": actual_format,
                "top_pattern": top_pattern,
            }
            with console.status("[cyan]Sending Slack alert…[/cyan]"):
                ok = send_slack_alert(webhook, anomalies, summary_payload)
            if ok:
                console.print("[green]Slack alert sent.[/green]")
            else:
                console.print("[red]Failed to send Slack alert (check webhook URL / network).[/red]")
        else:
            console.print(
                "[dim]Tip: pass --slack-webhook URL or set SLACK_WEBHOOK_URL to receive Slack alerts.[/dim]"
            )
    else:
        console.print("[green]No anomalies detected.[/green]")

    console.print()
    console.rule("[dim]Done[/dim]")
    console.print()


# ---------------------------------------------------------------------------
# stats command
# ---------------------------------------------------------------------------

@cli.command("stats")
@click.argument("file", type=click.Path(exists=True, readable=True, path_type=Path))
def stats(file: Path) -> None:
    """Display quick statistics for FILE: line count, error rate, and time range."""

    console.print()

    with console.status(f"[cyan]Reading [bold]{file.name}[/bold]…[/cyan]"):
        entries = parse_file(file)

    if not entries:
        console.print(f"[yellow]No log entries found in {file}.[/yellow]")
        sys.exit(0)

    total = len(entries)
    error_levels = {"ERROR", "CRITICAL", "FATAL", "WARNING", "WARN"}
    error_count = sum(1 for e in entries if e.get("level", "").upper() in error_levels)
    error_rate = error_count / total if total else 0.0
    rate_style = _error_rate_colour(error_rate)

    timed = [e for e in entries if isinstance(e.get("timestamp"), datetime)]
    time_min = min(e["timestamp"] for e in timed) if timed else None
    time_max = max(e["timestamp"] for e in timed) if timed else None

    detected = detect_format([e["raw"] for e in entries[:40]])

    # Build stat panels
    panels = [
        Panel(f"[bold]{total:,}[/bold]", title="Total lines", border_style="cyan"),
        Panel(
            f"[{rate_style}]{error_count:,}[/{rate_style}]",
            title="Errors / warnings",
            border_style="cyan",
        ),
        Panel(
            f"[{rate_style}]{error_rate:.2%}[/{rate_style}]",
            title="Error rate",
            border_style="cyan",
        ),
        Panel(
            f"[bold]{detected}[/bold]",
            title="Detected format",
            border_style="cyan",
        ),
    ]

    console.print(Columns(panels, equal=True, expand=True))
    console.print()

    time_range_text = (
        f"[bold]Earliest:[/bold]  {_fmt_dt(time_min)}\n"
        f"[bold]Latest:[/bold]    {_fmt_dt(time_max)}"
    )
    console.print(
        Panel(
            time_range_text,
            title="[bold cyan]Time range[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )
    console.print()


if __name__ == "__main__":
    cli()
