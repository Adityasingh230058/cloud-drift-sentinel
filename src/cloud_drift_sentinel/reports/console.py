"""
Rich Console Reporter: Formats security posture and drift results for terminal viewing.
"""

import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from ..core.models import ScanResult, Severity, DriftType

# Force UTF-8 on Windows streams if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


class ConsoleReporter:
    """
    Renders security posture findings, drift comparisons, and summary statistics to terminal.
    """

    def __init__(self):
        self.console = Console(highlight=False)

    def print_scan_result(self, result: ScanResult) -> None:
        summary = result.summary

        # Title Header
        self.console.print()
        self.console.print(
            Panel(
                Text.from_markup(
                    f"[bold white]CLOUD DRIFT SENTINEL[/bold white] [cyan]v1.0.0[/cyan]\n"
                    f"[dim]Automated Cloud Security Posture & Infrastructure Drift Engine[/dim]\n\n"
                    f"Provider: [bold yellow]{result.provider.upper()}[/bold yellow] | "
                    f"Scan Time: [dim]{result.scan_time}[/dim] | "
                    f"Resources Scanned: [bold cyan]{summary.total_resources}[/bold cyan]"
                ),
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

        # Compliance Score Panel
        score_color = "green" if summary.compliance_score >= 80 else ("yellow" if summary.compliance_score >= 50 else "red")
        score_text = Text()
        score_text.append(f"Security Compliance Score: {summary.compliance_score}%\n", style=f"bold {score_color}")
        score_text.append(
            f"Findings Breakdown: {summary.critical_count} Critical, "
            f"{summary.high_count} High, {summary.medium_count} Medium, "
            f"{summary.low_count} Low\n",
            style="dim"
        )
        score_text.append(
            f"Rules Evaluated: {summary.passed_rules} Passed, {summary.failed_rules} Failed",
            style="bold white"
        )
        self.console.print(Panel(score_text, title="[bold]Compliance Health[/bold]", border_style=score_color, box=box.ROUNDED))

        # Findings Table
        if result.findings:
            table = Table(title="[bold red]Security Posture Findings[/bold red]", box=box.SIMPLE_HEAVY)
            table.add_column("Severity", justify="center", style="bold")
            table.add_column("Rule ID", style="cyan")
            table.add_column("Resource", style="white")
            table.add_column("Description", style="dim")
            table.add_column("Benchmark", style="italic")

            for f in result.findings:
                sev_style = {
                    Severity.CRITICAL: "bold white on red",
                    Severity.HIGH: "bold red",
                    Severity.MEDIUM: "bold yellow",
                    Severity.LOW: "bold cyan",
                    Severity.INFO: "bold blue",
                }.get(f.severity, "white")

                table.add_row(
                    Text(f.severity.value, style=sev_style),
                    f.rule_id,
                    f.resource_id.split(":")[-1] if len(f.resource_id) > 40 else f.resource_id,
                    f.description,
                    f.benchmark_reference,
                )

            self.console.print(table)
        else:
            self.console.print("[bold green][OK] No security misconfigurations detected![/bold green]")

        # Drift Records Table
        if result.drift_records:
            self.console.print()
            drift_table = Table(title="[bold yellow][DRIFT] Infrastructure Drift Detected[/bold yellow]", box=box.SIMPLE_HEAVY)
            drift_table.add_column("Drift Type", justify="center", style="bold")
            drift_table.add_column("Resource ID", style="white")
            drift_table.add_column("Type", style="dim")
            drift_table.add_column("Difference / Reason", style="yellow")

            for d in result.drift_records:
                dtype_style = {
                    DriftType.ADDED: "bold green",
                    DriftType.REMOVED: "bold red",
                    DriftType.MODIFIED: "bold yellow",
                }.get(d.drift_type, "white")

                drift_table.add_row(
                    Text(d.drift_type.value, style=dtype_style),
                    d.resource_id,
                    d.resource_type.value,
                    str(list(d.differences.keys())) if d.drift_type == DriftType.MODIFIED else str(d.differences.get("status", "")),
                )
            self.console.print(drift_table)

        self.console.print()
