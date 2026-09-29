from abc import ABC, abstractmethod
from typing import Optional, List
from src.domain.models.audit import AuditReport

class AuditRepository(ABC):
    @abstractmethod
    def save_report(self, report: AuditReport) -> None:
        pass

    @abstractmethod
    def get_report(self, report_id: str) -> Optional[AuditReport]:
        pass

    @abstractmethod
    def list_reports_by_device(self, device_id: str) -> List[AuditReport]:
        pass
