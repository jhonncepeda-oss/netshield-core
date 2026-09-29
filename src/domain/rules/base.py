from abc import ABC, abstractmethod
from typing import Dict, Any
from src.domain.models.audit import Rule, AuditResult


class BaseRule(ABC):
    """Abstract base class for all security hardening rules."""
    
    @property
    @abstractmethod
    def rule_definition(self) -> Rule:
        pass

    @abstractmethod
    def evaluate(self, config_lines: list[str]) -> AuditResult:
        """
        Evaluates the rule against the parsed configuration.
        
        :param config_lines: List of configuration lines from the device.
        :return: AuditResult indicating pass/fail and details.
        """
        pass
