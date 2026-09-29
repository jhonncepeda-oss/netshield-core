from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from enum import Enum


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Rule:
    rule_id: str
    name: str
    description: str
    severity: Severity


@dataclass
class AuditResult:
    rule: Rule
    passed: bool
    details: str
    remediation: Optional[str] = None


@dataclass
class Device:
    device_id: str
    hostname: str
    ip_address: str
    os_version: str
    device_type: str = "cisco_ios"


@dataclass
class AuditReport:
    report_id: str
    device: Device
    timestamp: datetime
    results: List[AuditResult]
    overall_score: float = 0.0

    def calculate_score(self) -> float:
        if not self.results:
            return 100.0
        
        passed_count = sum(1 for r in self.results if r.passed)
        self.overall_score = (passed_count / len(self.results)) * 100
        return self.overall_score
