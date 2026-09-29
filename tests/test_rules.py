from src.domain.rules.cisco_ios import (
    SEC01_PasswordEncryption,
    SEC02_NoTelnet,
    SEC03_ExecTimeout,
    SEC04_NoIPHttpServer,
    SEC05_LoggingEnabled
)

def test_password_encryption_rule():
    rule = SEC01_PasswordEncryption()
    assert rule.evaluate(["service password-encryption"]).passed is True
    assert rule.evaluate(["hostname Router"]).passed is False

def test_no_telnet_rule():
    rule = SEC02_NoTelnet()
    assert rule.evaluate(["line vty 0 4", " transport input ssh"]).passed is True
    assert rule.evaluate(["line vty 0 4", " login"]).passed is False

def test_exec_timeout_rule():
    rule = SEC03_ExecTimeout()
    assert rule.evaluate(["line vty 0 4", " exec-timeout 5 0"]).passed is True
    assert rule.evaluate(["line vty 0 4"]).passed is False

def test_http_server_rule():
    rule = SEC04_NoIPHttpServer()
    assert rule.evaluate(["no ip http server"]).passed is True
    assert rule.evaluate(["ip http server"]).passed is False

def test_logging_rule():
    rule = SEC05_LoggingEnabled()
    assert rule.evaluate(["logging host 10.0.0.1"]).passed is True
    assert rule.evaluate(["logging buffered 16000"]).passed is False
