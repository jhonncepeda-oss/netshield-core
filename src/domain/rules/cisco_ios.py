from src.domain.rules.base import BaseRule
from src.domain.models.audit import Rule, AuditResult, Severity

class SEC01_PasswordEncryption(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-01",
            name="Password Encryption Enabled",
            description="Ensures 'service password-encryption' is configured to prevent plaintext passwords in config.",
            severity=Severity.HIGH
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("service password-encryption" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "Password encryption is enabled.")
        return AuditResult(
            self.rule_definition, False, "Password encryption is disabled.",
            remediation="Run 'service password-encryption' in global configuration mode."
        )

class SEC02_NoTelnet(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-02",
            name="Telnet Disabled",
            description="Ensures SSH is used instead of Telnet for VTY lines.",
            severity=Severity.CRITICAL
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        # Simplistic check for demo purposes: look for transport input ssh
        # In a real scenario, we'd parse VTY blocks specifically.
        passed = any("transport input ssh" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "SSH is configured on VTY lines.")
        return AuditResult(
            self.rule_definition, False, "SSH might not be enforced on VTY lines (Telnet could be active).",
            remediation="Configure 'transport input ssh' under 'line vty 0 4'."
        )

class SEC03_ExecTimeout(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-03",
            name="EXEC Timeout Configured",
            description="Ensures VTY and Console lines have an idle timeout configured.",
            severity=Severity.MEDIUM
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("exec-timeout" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "EXEC timeout is configured.")
        return AuditResult(
            self.rule_definition, False, "EXEC timeout is missing.",
            remediation="Configure 'exec-timeout 5 0' (5 minutes) under line configurations."
        )

class SEC04_NoIPHttpServer(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-04",
            name="HTTP Server Disabled",
            description="Ensures the unencrypted HTTP management server is disabled.",
            severity=Severity.HIGH
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("no ip http server" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "HTTP server is disabled.")
        return AuditResult(
            self.rule_definition, False, "HTTP server is enabled or not explicitly disabled.",
            remediation="Run 'no ip http server'."
        )

class SEC05_LoggingEnabled(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-05",
            name="Syslog Configured",
            description="Ensures the device is configured to send logs to a central server.",
            severity=Severity.MEDIUM
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any(line.strip().startswith("logging host") or line.strip().startswith("logging ") and not line.strip() == "logging buffered" for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "External logging is configured.")
        return AuditResult(
            self.rule_definition, False, "No external syslog server configured.",
            remediation="Configure 'logging host <IP>'."
        )

def get_all_cisco_rules() -> list[BaseRule]:
    return [
        SEC01_PasswordEncryption(),
        SEC02_NoTelnet(),
        SEC03_ExecTimeout(),
        SEC04_NoIPHttpServer(),
        SEC05_LoggingEnabled()
    ]
