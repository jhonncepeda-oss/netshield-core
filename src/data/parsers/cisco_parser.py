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
