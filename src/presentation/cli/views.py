from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from src.domain.models.audit import AuditReport

console = Console()

def print_banner():
    banner = """
    [bold cyan]
    ███╗   ██╗███████╗████████╗███████╗██╗  ██╗██╗███████╗██████╗ 
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██║██╔════╝██╔══██╗
    ██╔██╗ ██║█████╗     ██║   ███████╗███████║██║█████╗  ██║  ██║
    ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══██║██║██╔══╝  ██║  ██║
    ██║ ╚████║███████╗   ██║   ███████║██║  ██║██║███████╗██████╔╝
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═════╝ 
    [/bold cyan]
    [bold white]Core Engine - Network Security Auditing[/bold white]
    """
    console.print(banner)

def print_audit_report(report: AuditReport, summary: dict):
    table = Table(title=f"Audit Results - {summary['device']}", show_header=True, header_style="bold magenta")
    table.add_column("Rule ID", style="dim", width=10)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Rule Name", width=30)
    table.add_column("Details", width=50)
    
    for result in report.results:
        status_text = "[green]PASS[/green]" if result.passed else "[red]FAIL[/red]"
        table.add_row(
            result.rule.rule_id,
            status_text,
            result.rule.name,
            result.details
        )
        
    console.print(table)
    
    # Summary panel
    color = "green" if summary["status"] == "SECURE" else "red"
    summary_text = (
        f"Score: [bold {color}]{summary['score']:.2f}%[/bold {color}]\n"
        f"Passed: {summary['passed']} | Failed: {summary['failed']}\n"
        f"Overall Status: [bold {color}]{summary['status']}[/bold {color}]"
    )
    console.print(Panel(summary_text, title="Audit Summary", expand=False))
