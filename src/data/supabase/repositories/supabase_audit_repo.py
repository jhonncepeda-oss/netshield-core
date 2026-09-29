from typing import Optional, List
from src.domain.repositories.audit_repository import AuditRepository
from src.domain.models.audit import AuditReport, AuditResult, Device, Rule, Severity
from src.data.supabase.client import supabase_client
import logging

logger = logging.getLogger(__name__)

class SupabaseAuditRepository(AuditRepository):
    def save_report(self, report: AuditReport) -> None:
        if not supabase_client:
            logger.warning("Supabase client not initialized. Skipping save.")
            return

        try:
            # Insert report
            report_data = {
                "report_id": report.report_id,
                "device_id": report.device.device_id,
                "overall_score": report.overall_score,
                "timestamp": report.timestamp.isoformat()
            }
            supabase_client.table("audit_reports").insert(report_data).execute()

            # Insert results
            results_data = [
                {
                    "report_id": report.report_id,
                    "rule_id": result.rule.rule_id,
                    "passed": result.passed,
                    "details": result.details,
                    "remediation": result.remediation
                } for result in report.results
            ]
            if results_data:
                supabase_client.table("audit_results").insert(results_data).execute()
                
        except Exception as e:
            logger.error(f"Error saving report to Supabase: {e}")

    def get_report(self, report_id: str) -> Optional[AuditReport]:
        # Implementation for retrieving report
        pass

    def list_reports_by_device(self, device_id: str) -> List[AuditReport]:
        # Implementation for listing reports
        return []
