from src.domain.models.audit import AuditReport

class ReportService:
    @staticmethod
    def generate_summary(report: AuditReport) -> dict:
        passed = sum(1 for r in report.results if r.passed)
        failed = len(report.results) - passed
        
        return {
            "report_id": report.report_id,
            "device": report.device.hostname,
            "score": report.overall_score,
            "total_rules": len(report.results),
            "passed": passed,
            "failed": failed,
            "status": "SECURE" if report.overall_score >= 80 else "VULNERABLE",
            "timestamp": report.timestamp.isoformat()
        }
