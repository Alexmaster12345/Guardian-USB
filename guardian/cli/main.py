"""Guardian USB Typer CLI."""
from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from guardian.core.config import get_settings
from guardian.database.engine import init_db, session_scope

app = typer.Typer(help="Guardian USB — Vulnerability Management Platform", no_args_is_help=True)
jobs_app = typer.Typer(help="Manage scheduled jobs")
app.add_typer(jobs_app, name="jobs")
console = Console()


@app.callback()
def _init() -> None:
    """Ensure the database schema exists before any command."""
    init_db()


@app.command()
def discover(
    range_: str = typer.Option(..., "--range", "-r", help="CIDR or host, e.g. 192.168.1.0/24"),
):
    """Run asset discovery across a network range."""
    from guardian.automation.tasks import scan_task

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        progress.add_task(f"Discovering assets in {range_}...", total=None)
        result = scan_task(target_range=range_, scan_type="Discovery")
    console.print(Panel.fit(
        f"[green]Discovery complete[/green]\n"
        f"Assets: {result['assets']}  Findings: {result['findings']}  Scan ID: {result['scan_id']}",
        title="Discovery"))


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="CIDR/IP range to scan"),
    type_: str = typer.Option("full", "--type", help="Discovery|Vulnerability|Compliance|Full"),
):
    """Run a vulnerability scan against a target."""
    from guardian.automation.tasks import scan_task

    scan_type = type_.capitalize()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        progress.add_task(f"Scanning {target} ({scan_type})...", total=None)
        result = scan_task(target_range=target, scan_type=scan_type)

    table = Table(title="Scan Result")
    table.add_column("Metric"); table.add_column("Value", justify="right")
    table.add_row("Scan ID", str(result["scan_id"]))
    table.add_row("Assets discovered", str(result["assets"]))
    table.add_row("Findings", str(result["findings"]))
    console.print(table)


@app.command()
def report(
    format_: str = typer.Option("html", "--format", "-f", help="html|json|csv"),
    output: str = typer.Option("./report.html", "--output", "-o", help="Output file path"),
):
    """Generate a vulnerability report."""
    from guardian.reporting import ReportGenerator

    ReportGenerator().generate(fmt=format_, output_path=output)
    console.print(f"[green]Report written to[/green] {output}")


@app.command()
def update(
    online: bool = typer.Option(False, "--online", help="Fetch latest CVEs from NVD"),
    offline: bool = typer.Option(False, "--offline", help="Import from a local JSON file"),
    file: str = typer.Option(None, "--file", help="Path to offline CVE JSON file"),
    max_records: int = typer.Option(500, "--max", help="Max records for online sync"),
):
    """Update the vulnerability database (online NVD sync or offline import)."""
    if online:
        from guardian.updates import NVDSync
        with console.status("Syncing CVEs from NVD..."):
            count = NVDSync().sync(max_records=max_records)
        console.print(f"[green]Synced {count} CVEs from NVD[/green]")
    elif offline:
        from guardian.updates import OfflineImporter
        path = file or str(get_settings().vuln_db_dir / "sample_cves.json")
        count = OfflineImporter().import_file(path)
        console.print(f"[green]Imported {count} CVEs from[/green] {path}")
    else:
        console.print("[yellow]Specify --online or --offline[/yellow]")
        raise typer.Exit(1)


@app.command()
def serve(
    host: str = typer.Option(None, "--host", help="Bind host"),
    port: int = typer.Option(None, "--port", "-p", help="Bind port"),
):
    """Start the Guardian REST API server."""
    import uvicorn

    settings = get_settings()
    console.print(Panel.fit("[bold cyan]Guardian USB API[/bold cyan] starting...", title="serve"))
    uvicorn.run("guardian.api.app:app", host=host or settings.host, port=port or settings.port)


@jobs_app.command("list")
def jobs_list():
    """List scheduled jobs."""
    from guardian.automation import GuardianScheduler

    jobs = GuardianScheduler().list_jobs()
    table = Table(title="Scheduled Jobs")
    for col in ("Name", "Type", "Cron", "Target", "Enabled"):
        table.add_column(col)
    for j in jobs:
        table.add_row(j.name, j.job_type, j.cron_expression, j.target or "-", str(j.enabled))
    console.print(table if jobs else "[yellow]No scheduled jobs[/yellow]")


@jobs_app.command("add")
def jobs_add(
    name: str = typer.Argument(...),
    type_: str = typer.Option(..., "--type", help="scan|report|alert|update"),
    cron: str = typer.Option(..., "--cron", help="Cron expression, e.g. '0 2 * * *'"),
    target: str = typer.Option(None, "--target", help="Target range for scan jobs"),
):
    """Add a scheduled job."""
    from guardian.automation import GuardianScheduler

    GuardianScheduler().add_job(name=name, job_type=type_, cron_expression=cron, target=target)
    console.print(f"[green]Added job[/green] {name} ({type_}) [{cron}]")


@jobs_app.command("remove")
def jobs_remove(name: str = typer.Argument(...)):
    """Remove a scheduled job by name."""
    from guardian.automation import GuardianScheduler

    ok = GuardianScheduler().remove_job(name)
    console.print(f"[green]Removed[/green] {name}" if ok else f"[yellow]Not found:[/yellow] {name}")


@app.command()
def assets():
    """List discovered assets."""
    from guardian.database.repositories.asset_repository import AssetRepository

    with session_scope() as session:
        items = AssetRepository(session).list(limit=200)
        table = Table(title="Assets")
        for col in ("ID", "Hostname", "IP", "OS", "Type", "Criticality"):
            table.add_column(col)
        for a in items:
            table.add_row(str(a.id), a.hostname or "-", a.ip_address or "-",
                          a.os_name or "-", a.asset_type or "-",
                          a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality))
    console.print(table if items else "[yellow]No assets[/yellow]")


if __name__ == "__main__":
    app()
