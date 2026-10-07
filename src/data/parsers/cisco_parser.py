import re

class CiscoParser:
    """
    Parses Cisco iOS configuration files and redacts sensitive information.
    """
    
    # Regex patterns for sensitive data
    PASSWORD_PATTERNS = [
        re.compile(r'(enable secret 5 )([^\s]+)'),
        re.compile(r'(password 7 )([^\s]+)'),
        re.compile(r'(username \S+ (?:password|secret) \d )([^\s]+)')
    ]
    
    COMMUNITY_STRING_PATTERN = re.compile(r'(snmp-server community )([^\s]+)(.*)')

    @classmethod
    def redact_secrets(cls, config_lines: list[str]) -> list[str]:
        """
        Takes a list of config lines, redacts passwords, hashes, and SNMP strings.
        """
        redacted_lines = []
        for line in config_lines:
            redacted_line = line
            
            # Redact passwords
            for pattern in cls.PASSWORD_PATTERNS:
                redacted_line = pattern.sub(r'\1<REDACTED>', redacted_line)
                
            # Redact SNMP Community Strings
            redacted_line = cls.COMMUNITY_STRING_PATTERN.sub(r'\1<REDACTED>\3', redacted_line)
            
            redacted_lines.append(redacted_line)
            
        return redacted_lines

    @classmethod
    def parse_from_file(cls, filepath: str) -> list[str]:
        """
        Reads a config file and returns redacted lines.
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        
        return cls.redact_secrets(lines)

    @classmethod
    def extract_os_version(cls, config_lines: list[str]) -> str | None:
        """
        Extracts the Cisco IOS version.
        """
        version_pattern = re.compile(r'^version\s+(\d+\.\d+)')
        for line in config_lines:
            match = version_pattern.match(line.strip())
            if match:
                return match.group(1)
        return None

    @classmethod
    def extract_inferred_ports(cls, config_lines: list[str]) -> list[int]:
        """
        Infers exposed logic ports based on active services.
        """
        ports = set()
        for line in config_lines:
            line_str = line.strip().lower()
            if line_str.startswith("ip http server"):
                ports.add(80)
            elif line_str.startswith("ip http secure-server"):
                ports.add(443)
            elif "transport input telnet" in line_str or "transport input all" in line_str:
                ports.add(23)
            elif "snmp-server community" in line_str:
                ports.add(161)
            elif "ip ssh version" in line_str or "transport input ssh" in line_str:
                ports.add(22)
            elif "ntp server" in line_str:
                ports.add(123)
        return list(ports)
