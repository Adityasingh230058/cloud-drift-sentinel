"""
Command Line Interface for Cloud Drift Sentinel using Typer and Rich.
"""

import json
import os
import sys
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich import box

# Force UTF-8 on Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from .core.models import ScanResult, DriftType
from .core.engine import SentinelEngine
from .core.baseline import BaselineManager
from .providers.aws import AWSCloudProvider
from .providers.mock_provider import MockCloudProvider
from .reports.console import ConsoleReporter
from .reports.html_report import HTMLReporter
from .remediation.generator import RemediationGenerator
from .rules.base import RuleRegistry
import cloud_drift_sentinel.rules  # Load all registered rules

app = typer.Typer(
    name="cloud-drift-sentinel",
    help="Cloud Drift Sentinel: Automated Cloud Security Posture Management & Drift Engine",
    add_completion=False,
)
console = Console(highlight=False)


@app.command()
def scan(
    mock: bool = typer.Option(False, "--mock", "-m", help="Run offline simulation using realistic mock cloud telemetry."),
    region: str = typer.Option("us-east-1", "--region", "-r", help="AWS region to scan."),
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="AWS named profile."),
    baseline: Optional[str] = typer.Option(None, "--baseline", "-b", help="Path to golden baseline JSON to detect drift."),
    html: Optional[str] = typer.Option(None, "--html", help="Path to save interactive HTML dashboard report."),
    json_out: Optional[str] = typer.Option(None, "--json", help="Path to export raw scan result as JSON."),
    remediate: Optional[str] = typer.Option(None, "--remediate", help="Directory to generate remediation playbooks (Bash & Python)."),
):
    """
    Execute a comprehensive security posture and compliance scan.
    """
    provider = MockCloudProvider() if mock else AWSCloudProvider(region_name=region, profile_name=profile)
    engine = SentinelEngine(provider=provider)

    with console.status("[bold cyan]Scanning cloud infrastructure & evaluating CIS benchmarks...[/bold cyan]"):
        result = engine.run_scan(baseline_file=baseline)

    # Console Output
    reporter = ConsoleReporter()
    reporter.print_scan_result(result)

    # HTML Report
    if html:
        path = HTMLReporter.generate_html_report(result, html)
        console.print(f"[bold green][OK] Interactive HTML report generated:[/bold green] [underline cyan]{path}[/underline cyan]")

    # JSON Export
    if json_out:
        os.makedirs(os.path.dirname(os.path.abspath(json_out)), exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[bold green][OK] JSON result exported:[/bold green] [underline cyan]{json_out}[/underline cyan]")

    # Remediation Playbooks
    if remediate:
        scripts = RemediationGenerator.generate_remediation_suite(result.findings, remediate)
        console.print(f"[bold green][OK] Generated {len(scripts)} remediation scripts in:[/bold green] [underline cyan]{remediate}[/underline cyan]")


@app.command()
def drift(
    baseline: str = typer.Option(..., "--baseline", "-b", help="Path to golden baseline JSON file."),
    mock: bool = typer.Option(False, "--mock", "-m", help="Use mock cloud state for testing."),
    region: str = typer.Option("us-east-1", "--region", "-r", help="AWS region."),
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="AWS CLI profile."),
):
    """
    Compare current cloud state against a golden baseline snapshot to detect infrastructure drift.
    """
    if not os.path.exists(baseline):
        console.print(f"[bold red]Error:[/bold red] Baseline file '{baseline}' not found.")
        raise typer.Exit(1)

    provider = MockCloudProvider() if mock else AWSCloudProvider(region_name=region, profile_name=profile)
    with console.status("[bold yellow]Collecting live state and calculating configuration drift...[/bold yellow]"):
        current_resources = provider.collect_resources()
        baseline_resources = BaselineManager.load_baseline(baseline)
        drift_records = BaselineManager.compare_drift(baseline_resources, current_resources)

    if not drift_records:
        console.print("[bold green][OK] Zero drift detected! Cloud infrastructure perfectly matches the baseline.[/bold green]")
        return

    table = Table(title="[bold yellow][DRIFT] Infrastructure Drift Detected[/bold yellow]", box=box.ROUNDED)
    table.add_column("Drift Type", justify="center", style="bold")
    table.add_column("Resource Name / ID", style="white")
    table.add_column("Type", style="dim")
    table.add_column("Details", style="cyan")

    for d in drift_records:
        color = "green" if d.drift_type.value == "ADDED" else ("red" if d.drift_type.value == "REMOVED" else "yellow")
        table.add_row(
            f"[{color}]{d.drift_type.value}[/{color}]",
            f"{d.resource_name}\n[dim]{d.resource_id}[/dim]",
            d.resource_type.value,
            json.dumps(d.differences, indent=2) if d.drift_type == DriftType.MODIFIED else str(d.differences.get("status", "")),
        )

    console.print(table)
    console.print(f"\n[bold red]Alert:[/bold red] Found [bold]{len(drift_records)}[/bold] infrastructure drift deviations from baseline.")


@app.command()
def baseline(
    output: str = typer.Option("baseline.json", "--output", "-o", help="Filepath to save the exported baseline snapshot."),
    mock: bool = typer.Option(False, "--mock", "-m", help="Use mock cloud state."),
    region: str = typer.Option("us-east-1", "--region", "-r", help="AWS region."),
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="AWS CLI profile."),
):
    """
    Snapshot current cloud infrastructure state into a Golden Baseline configuration.
    """
    provider = MockCloudProvider() if mock else AWSCloudProvider(region_name=region, profile_name=profile)
    with console.status("[bold cyan]Gathering cloud resources for baseline snapshot...[/bold cyan]"):
        resources = provider.collect_resources()
        BaselineManager.export_baseline(resources, output)

    console.print(f"[bold green][OK] Golden State Baseline successfully exported:[/bold green] [underline cyan]{output}[/underline cyan]")
    console.print(f"[dim]Total resources indexed: {len(resources)}[/dim]")


@app.command()
def rules():
    """
    List all available CIS AWS Foundations Benchmark compliance rules.
    """
    all_rules = RuleRegistry.get_all_rules()
    table = Table(title="[bold cyan]Registered Security & Compliance Rules[/bold cyan]", box=box.ROUNDED)
    table.add_column("Rule ID", style="cyan", justify="center")
    table.add_column("Severity", justify="center", style="bold")
    table.add_column("Resource Type", style="white")
    table.add_column("Rule Name", style="bold white")
    table.add_column("Benchmark", style="dim")

    for r in sorted(all_rules, key=lambda x: x.rule_id):
        sev_color = {
            "CRITICAL": "red",
            "HIGH": "bright_red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
        }.get(r.severity.value, "white")

        table.add_row(
            r.rule_id,
            f"[{sev_color}]{r.severity.value}[/{sev_color}]",
            r.resource_type.value,
            r.rule_name,
            r.benchmark_reference,
        )

    console.print(table)
    console.print(f"\n[dim]Total active rules in registry: {len(all_rules)}[/dim]")


def main():
    app()


if __name__ == "__main__":
    main()
