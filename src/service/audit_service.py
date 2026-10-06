from typing import List
from datetime import datetime
import uuid
from src.domain.models.audit import AuditReport, AuditResult, Device
from src.domain.rules.cisco_ios import get_all_cisco_rules
from src.data.parsers.cisco_parser import CiscoParser
from src.domain.repositories.audit_repository import AuditRepository
from src.domain.repositories.device_repository import DeviceRepository

class AuditService:
    def __init__(self, audit_repo: AuditRepository, device_repo: DeviceRepository):
        self.audit_repo = audit_repo
        self.device_repo = device_repo
        self.rules = get_all_cisco_rules()

    def run_audit(self, filepath: str, device: Device, user_id: str = None) -> AuditReport:
        # Parse and redact
        config_lines = CiscoParser.parse_from_file(filepath)
        
        # Evaluate rules
        results: List[AuditResult] = []
        for rule in self.rules:
            result = rule.evaluate(config_lines)
            results.append(result)
            
        # Generate report
        report = AuditReport(
            report_id=str(uuid.uuid4()),
            device=device,
            timestamp=datetime.now(),
            results=results
        )
        if user_id:
            report.user_id = user_id
        report.calculate_score()
        
        # Save to database
        self.device_repo.save_device(device)
        self.audit_repo.save_report(report)
        
        return report
