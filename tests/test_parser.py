from src.data.parsers.cisco_parser import CiscoParser

def test_redact_enable_secret():
    lines = ["enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0", "hostname Router"]
    redacted = CiscoParser.redact_secrets(lines)
    assert redacted[0] == "enable secret 5 <REDACTED>"
    assert redacted[1] == "hostname Router"

def test_redact_username_password():
    lines = ["username admin password 0 admin123", "username user secret 5 hash"]
    redacted = CiscoParser.redact_secrets(lines)
    # The regex in parser might need tweaking if format varies, but based on what we wrote:
    # re.compile(r'(username \S+ (?:password|secret) \d )([^\s]+)')
    assert redacted[0] == "username admin password 0 <REDACTED>"
    assert redacted[1] == "username user secret 5 <REDACTED>"

def test_redact_snmp_community():
    lines = ["snmp-server community public RO", "snmp-server community secret RW"]
    redacted = CiscoParser.redact_secrets(lines)
    assert redacted[0] == "snmp-server community <REDACTED> RO"
    assert redacted[1] == "snmp-server community <REDACTED> RW"
