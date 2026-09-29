import argparse
import sys
import uuid
from rich.console import Console
from src.presentation.cli.views import print_banner, print_audit_report
from src.domain.models.audit import Device
from src.service.audit_service import AuditService
from src.service.report_service import ReportService
from src.data.supabase.repositories.supabase_audit_repo import SupabaseAuditRepository
from src.data.supabase.repositories.supabase_device_repo import SupabaseDeviceRepository

console = Console()

def run_cli():
    parser = argparse.ArgumentParser(description="NetShield Core - Network Security Auditing CLI")
    parser.add_argument("--config", "-c", required=True, help="Path to the Cisco config file (.cfg)")
    parser.add_argument("--hostname", "-n", required=True, help="Device hostname")
    parser.add_argument("--ip", "-i", required=True, help="Device IP address")
    parser.add_argument("--os", "-o", required=True, help="Device OS version")
    
    args = parser.parse_args()
    
    print_banner()
    
    try:
        device = Device(
            device_id=str(uuid.uuid4()),
            hostname=args.hostname,
            ip_address=args.ip,
            os_version=args.os
        )
        
        console.print(f"[cyan]Initiating audit for device {device.hostname} ({device.ip_address})...[/cyan]\n")
        
        audit_repo = SupabaseAuditRepository()
        device_repo = SupabaseDeviceRepository()
        service = AuditService(audit_repo, device_repo)
        
        report = service.run_audit(args.config, device)
        summary = ReportService.generate_summary(report)
        
        print_audit_report(report, summary)
        
    except Exception as e:
        console.print(f"[bold red]Error during audit: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    run_cli()
