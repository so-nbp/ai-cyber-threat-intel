"""
AI Cyber Threat Intelligence Collector - CLI Entry Point.

Usage:
    python -m src.main collect --all
    python -m src.main collect --source nvd
    python -m src.main schedule
    python -m src.main status
    python -m src.main summary
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .analysis.trends import generate_daily_summary
from .collectors import COLLECTOR_REGISTRY, get_all_collectors, get_collector
from .scheduler import run_collection_cycle, start_scheduler
from .storage.database import ThreatDatabase
from .storage.file_store import FileStore
from .utils.config import load_config
from .utils.logging import get_logger, setup_logging

console = Console()


@click.group()
@click.option("--config", "-c", default=None, help="Path to config YAML file")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool) -> None:
    """AI Cyber Threat Intelligence Collector."""
    ctx.ensure_object(dict)
    cfg = load_config(config)
    if verbose:
        cfg.log_level = "DEBUG"
    setup_logging(cfg.log_level, cfg.log_file)
    ctx.obj["config"] = cfg


@cli.command()
@click.option("--all", "collect_all", is_flag=True, help="Run all collectors")
@click.option("--source", "-s", multiple=True, help="Specific source(s) to collect")
@click.option("--days", "-d", default=7, help="Look back N days (default: 7)")
@click.pass_context
def collect(ctx: click.Context, collect_all: bool, source: tuple, days: int) -> None:
    """Collect threat intelligence from configured sources."""
    cfg = ctx.obj["config"]
    since = datetime.now(timezone.utc) - timedelta(days=days)

    if collect_all:
        console.print(Panel(
            f"[bold green]Starting full collection cycle[/bold green]\n"
            f"Sources: {', '.join(COLLECTOR_REGISTRY.keys())}\n"
            f"Looking back: {days} days",
            title="Collection",
        ))
        result = asyncio.run(run_collection_cycle(cfg))
        _print_collection_result(result)

    elif source:
        for src in source:
            if src not in COLLECTOR_REGISTRY:
                console.print(f"[red]Unknown source: {src}[/red]")
                console.print(f"Available: {', '.join(COLLECTOR_REGISTRY.keys())}")
                continue

            console.print(f"[bold]Collecting from: {src}[/bold]")
            collector_inst = get_collector(src, cfg)

            db = ThreatDatabase(cfg.storage.db_path)
            db.initialize()
            file_store = FileStore(cfg.storage.raw_data_path)

            result_obj, items = asyncio.run(collector_inst.run(since=since))

            if items:
                file_store.store_raw(items, collector_inst.SOURCE_NAME)
                new_count, updated_count = db.store_items(items)
                result_obj.items_new = new_count
                result_obj.items_updated = updated_count

            db.store_collection_run(result_obj)
            db.close()

            _print_single_result(result_obj)
    else:
        console.print("[yellow]Specify --all or --source <name>[/yellow]")
        console.print(f"Available sources: {', '.join(COLLECTOR_REGISTRY.keys())}")


@cli.command()
@click.pass_context
def schedule(ctx: click.Context) -> None:
    """Start the daily collection scheduler."""
    cfg = ctx.obj["config"]
    start_scheduler(cfg)


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show database statistics and recent collection status."""
    cfg = ctx.obj["config"]
    db = ThreatDatabase(cfg.storage.db_path)
    db.initialize()
    stats = db.get_statistics()
    db.close()

    console.print(Panel(
        f"[bold]Total Items:[/bold] {stats['total_items']}\n"
        f"[bold]AI-Related:[/bold] {stats['ai_related_items']}",
        title="Database Status",
    ))

    if stats["by_source"]:
        table = Table(title="Items by Source")
        table.add_column("Source", style="cyan")
        table.add_column("Count", justify="right")
        for src, count in stats["by_source"].items():
            table.add_row(src, str(count))
        console.print(table)

    if stats["by_category"]:
        table = Table(title="Items by Threat Category")
        table.add_column("Category", style="magenta")
        table.add_column("Count", justify="right")
        for cat, count in stats["by_category"].items():
            table.add_row(cat, str(count))
        console.print(table)

    if stats["by_severity"]:
        table = Table(title="Items by Severity")
        table.add_column("Severity", style="red")
        table.add_column("Count", justify="right")
        for sev, count in stats["by_severity"].items():
            table.add_row(sev, str(count))
        console.print(table)

    if stats["recent_runs"]:
        table = Table(title="Recent Collection Runs")
        table.add_column("Source", style="cyan")
        table.add_column("Started", style="dim")
        table.add_column("Collected", justify="right")
        table.add_column("New", justify="right")
        table.add_column("Status")
        for run in stats["recent_runs"][:10]:
            status_str = "[green]OK[/green]" if run["success"] else "[red]FAIL[/red]"
            table.add_row(
                run["source"],
                str(run["started_at"])[:19],
                str(run["items_collected"]),
                str(run["items_new"]),
                status_str,
            )
        console.print(table)


@cli.command()
@click.option("--date", "-d", default=None, help="Date for summary (YYYY-MM-DD)")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
@click.pass_context
def summary(ctx: click.Context, date: Optional[str], json_output: bool) -> None:
    """Generate a daily threat intelligence summary."""
    cfg = ctx.obj["config"]
    target_date = None
    if date:
        target_date = datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc)

    db = ThreatDatabase(cfg.storage.db_path)
    db.initialize()
    result = generate_daily_summary(db, target_date)
    db.close()

    if json_output:
        click.echo(json.dumps(result, indent=2, default=str))
    else:
        _print_summary(result)


@cli.command(name="init")
@click.pass_context
def init_db(ctx: click.Context) -> None:
    """Initialize the database."""
    cfg = ctx.obj["config"]
    db = ThreatDatabase(cfg.storage.db_path)
    db.initialize()
    db.close()
    console.print("[green]Database initialized successfully.[/green]")


@cli.command(name="migrate-sectors")
@click.pass_context
def migrate_sectors(ctx: click.Context) -> None:
    """Classify sectors for existing records that have no sector assigned.

    Runs keyword-based sector classification on all threat items where
    affected_sectors is empty, and updates the database in place.
    """
    cfg = ctx.obj["config"]
    db = ThreatDatabase(cfg.storage.db_path)
    db.initialize()

    console.print("[bold]Running sector migration...[/bold]")
    updated = db.migrate_sector_classification()
    db.close()

    console.print(Panel(
        f"[bold]Updated:[/bold] {updated} records with sector classification",
        title="[green]Sector Migration Complete[/green]",
    ))


@cli.command()
@click.option("--severity", "-sev", default=None,
              type=click.Choice(["critical", "high", "medium", "low", "info", "unknown"]),
              help="Filter by severity")
@click.option("--category", "-cat", default=None,
              type=click.Choice(["ai-as-target", "ai-as-weapon", "ai-enabled", "ai-adjacent", "unknown"]),
              help="Filter by threat category")
@click.option("--source", "-s", default=None, help="Filter by source (nvd, cisa_kev, etc.)")
@click.option("--ai-only", is_flag=True, help="Show only AI-related items")
@click.option("--days", "-d", default=None, type=int, help="Show items from last N days")
@click.option("--limit", "-n", default=20, help="Max items to show (default: 20)")
@click.option("--detail", is_flag=True, help="Show full description for each item")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
@click.pass_context
def show(ctx: click.Context, severity: Optional[str], category: Optional[str],
         source: Optional[str], ai_only: bool, days: Optional[int],
         limit: int, detail: bool, json_output: bool) -> None:
    """Browse and inspect collected threat intelligence items.

    \b
    Examples:
      python -m src.main show --severity critical
      python -m src.main show --severity critical --detail
      python -m src.main show --category ai-as-target --ai-only
      python -m src.main show --source arxiv --days 7
      python -m src.main show --severity high -n 50 -j
    """
    cfg = ctx.obj["config"]
    db = ThreatDatabase(cfg.storage.db_path)
    db.initialize()

    since = None
    if days:
        since = datetime.now(timezone.utc) - timedelta(days=days)

    items = db.get_items(
        source=source,
        threat_category=category,
        severity=severity,
        ai_only=ai_only,
        since=since,
        limit=limit,
    )
    db.close()

    if not items:
        console.print("[yellow]No items found matching the filters.[/yellow]")
        return

    if json_output:
        click.echo(json.dumps(items, indent=2, default=str))
        return

    # ── Summary header ──
    filter_parts = []
    if severity:
        filter_parts.append(f"severity={severity}")
    if category:
        filter_parts.append(f"category={category}")
    if source:
        filter_parts.append(f"source={source}")
    if ai_only:
        filter_parts.append("AI-related only")
    if days:
        filter_parts.append(f"last {days} days")
    filter_str = ", ".join(filter_parts) if filter_parts else "all"

    console.print(Panel(
        f"[bold]Filters:[/bold] {filter_str}\n"
        f"[bold]Results:[/bold] {len(items)} items",
        title="Threat Intelligence Items",
    ))

    if detail:
        # ── Detailed view: one panel per item ──
        _SEVERITY_COLORS = {
            "critical": "bold red", "high": "red", "medium": "yellow",
            "low": "green", "info": "blue", "unknown": "dim",
        }
        for i, item in enumerate(items, 1):
            sev = item.get("severity", "unknown")
            color = _SEVERITY_COLORS.get(sev, "white")

            # Parse tags and CVEs from JSON strings
            tags_raw = item.get("tags", "[]")
            try:
                tags_list = json.loads(tags_raw) if isinstance(tags_raw, str) else tags_raw
            except (json.JSONDecodeError, TypeError):
                tags_list = []

            cves_raw = item.get("cve_ids", "[]")
            try:
                cves_list = json.loads(cves_raw) if isinstance(cves_raw, str) else cves_raw
            except (json.JSONDecodeError, TypeError):
                cves_list = []

            refs_raw = item.get("references_json", "[]")
            try:
                refs_list = json.loads(refs_raw) if isinstance(refs_raw, str) else refs_raw
            except (json.JSONDecodeError, TypeError):
                refs_list = []

            products_raw = item.get("affected_products", "[]")
            try:
                products_list = json.loads(products_raw) if isinstance(products_raw, str) else products_raw
            except (json.JSONDecodeError, TypeError):
                products_list = []

            # Build detail text
            lines = []
            lines.append(f"[bold]Title:[/bold] {item.get('title', 'N/A')}")
            lines.append(f"[{color}]Severity: {sev.upper()}[/{color}]"
                         + (f"  (CVSS: {item.get('cvss_score')})" if item.get("cvss_score") else ""))
            lines.append(f"[bold]Category:[/bold] {item.get('threat_category', 'unknown')}")
            lines.append(f"[bold]Source:[/bold] {item.get('source', '')}  |  "
                         f"[bold]Confidence:[/bold] {item.get('confidence', '')}")
            lines.append(f"[bold]Published:[/bold] {str(item.get('published_at', 'N/A'))[:10]}  |  "
                         f"[bold]Collected:[/bold] {str(item.get('collected_at', ''))[:10]}")

            if item.get("source_url"):
                lines.append(f"[bold]URL:[/bold] {item['source_url']}")

            if cves_list:
                lines.append(f"[bold]CVEs:[/bold] {', '.join(cves_list)}")

            if products_list:
                prod_strs = []
                for p in products_list[:5]:
                    v = p.get("vendor", "")
                    n = p.get("product", "")
                    prod_strs.append(f"{v}/{n}" if v else n)
                lines.append(f"[bold]Affected:[/bold] {', '.join(prod_strs)}")

            if tags_list:
                lines.append(f"[bold]Tags:[/bold] {', '.join(str(t) for t in tags_list[:10])}")

            lines.append("")
            desc = item.get("description", "")
            if desc:
                # Truncate very long descriptions
                if len(desc) > 1000:
                    desc = desc[:1000] + "..."
                lines.append(f"[dim]{desc}[/dim]")

            console.print(Panel(
                "\n".join(lines),
                title=f"[{color}]#{i} — {sev.upper()}[/{color}]",
                border_style=color,
            ))
            console.print()
    else:
        # ── Table view ──
        table = Table(title=f"Results ({len(items)} items)", show_lines=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Category", width=14)
        table.add_column("Source", style="cyan", width=12)
        table.add_column("Title", max_width=60)
        table.add_column("Published", style="dim", width=12)

        _SEV_COLORS = {
            "critical": "bold red", "high": "red", "medium": "yellow",
            "low": "green", "info": "blue", "unknown": "dim",
        }

        for i, item in enumerate(items, 1):
            sev = item.get("severity", "unknown")
            color = _SEV_COLORS.get(sev, "white")
            pub = str(item.get("published_at", "N/A"))[:10]
            title_str = item.get("title", "")
            if len(title_str) > 60:
                title_str = title_str[:57] + "..."

            table.add_row(
                str(i),
                f"[{color}]{sev}[/{color}]",
                item.get("threat_category", ""),
                item.get("source", ""),
                title_str,
                pub,
            )

        console.print(table)
        console.print("\n[dim]Tip: Add --detail to see full descriptions, or -j for JSON output.[/dim]")


@cli.command()
@click.option("--port", "-p", default=8501, help="Port to run the dashboard on (default: 8501)")
def dashboard(port: int) -> None:
    """Launch the Web dashboard (Streamlit)."""
    import subprocess
    import sys
    from pathlib import Path

    app_path = Path(__file__).parent / "dashboard" / "app.py"
    console.print(f"[bold green]Starting dashboard on http://localhost:{port}[/bold green]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(app_path), "--server.port", str(port)],
        check=False,
    )


@cli.command()
def sources() -> None:
    """List available collection sources."""
    table = Table(title="Available Collectors")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    for name, cls in COLLECTOR_REGISTRY.items():
        table.add_row(name, cls.SOURCE_DESCRIPTION)
    console.print(table)


# ── Helpers ──

def _print_collection_result(result: Dict[str, Any]) -> None:
    status_str = "[green]Success[/green]" if result["all_success"] else "[red]Partial Failure[/red]"
    console.print(Panel(
        f"[bold]Cycle:[/bold] {result['cycle_id']}\n"
        f"[bold]Status:[/bold] {status_str}\n"
        f"[bold]Total Collected:[/bold] {result['total_collected']}\n"
        f"[bold]New Items:[/bold] {result['total_new']}",
        title="Collection Complete",
    ))


def _print_single_result(result: Any) -> None:
    status_str = "[green]OK[/green]" if result.success else "[red]FAIL[/red]"
    console.print(
        f"  {status_str} {result.source}: "
        f"collected={result.items_collected}, "
        f"new={result.items_new}, "
        f"updated={result.items_updated}, "
        f"duration={result.duration_seconds:.1f}s"
    )
    if result.errors:
        for err in result.errors:
            console.print(f"    [red]Error: {err}[/red]")


def _print_summary(result: Dict[str, Any]) -> None:
    console.print(Panel(
        f"[bold]Date:[/bold] {result['date']}\n"
        f"[bold]Total Items:[/bold] {result['total_items']}\n"
        f"[bold]AI-Related:[/bold] {result.get('ai_related_items', 'N/A')}",
        title="Daily Summary",
    ))
    if "top_items" in result:
        table = Table(title="Top Items by Severity")
        table.add_column("Severity", style="red")
        table.add_column("Category", style="magenta")
        table.add_column("Title")
        table.add_column("Source", style="cyan")
        for item in result["top_items"]:
            table.add_row(item["severity"], item["category"], item["title"][:80], item["source"])
        console.print(table)


if __name__ == "__main__":
    cli()
