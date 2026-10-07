import json
import os

CVE_DB = {
    "15.2": [
        {"cve": "CVE-2018-0171", "type": "Smart Install Remote Code Execution", "severity": "CRITICAL", "requires_port": None},
        {"cve": "CVE-2017-3881", "type": "Cisco CMP Telnet RCE", "severity": "CRITICAL", "requires_port": 23},
        {"cve": "CVE-2019-12648", "type": "REST API Authentication Bypass", "severity": "HIGH", "requires_port": 443}
    ],
    "12.4": [
        {"cve": "CVE-2017-3881", "type": "Cisco CMP Telnet RCE", "severity": "CRITICAL", "requires_port": 23},
        {"cve": "CVE-2008-0960", "type": "SNMP Message Processing Denial of Service", "severity": "HIGH", "requires_port": 161}
    ],
    "15.0": [
        {"cve": "CVE-2018-0171", "type": "Smart Install Remote Code Execution", "severity": "CRITICAL", "requires_port": None},
        {"cve": "CVE-2016-1409", "type": "IPv6 ND Crafted Packet Denial of Service", "severity": "HIGH", "requires_port": None}
    ],
    "15.1": [
        {"cve": "CVE-2018-0171", "type": "Smart Install Remote Code Execution", "severity": "CRITICAL", "requires_port": None},
        {"cve": "CVE-2016-1372", "type": "IKEv2 Fragmentation Denial of Service", "severity": "HIGH", "requires_port": 500}
    ]
}

class CVEDatabase:
    @classmethod
    def get_cves_for_version_and_ports(cls, version: str, active_ports: list[int]) -> list[dict]:
        """
        Cross-references the OS version and inferred active ports with known CVEs.
        If requires_port is None, the vulnerability is inherent to the OS logic (no specific port).
        """
        if not version:
            return []
            
        # Try exact match or base match (e.g. 15.2(4)M -> 15.2)
        matched_cves = []
        base_version = version.split('(')[0] if '(' in version else version
        
        # We only map the first two digits for simplistic match (e.g., 15.2)
        base_version_short = ".".join(base_version.split('.')[:2])
        
        cves = CVE_DB.get(base_version_short, [])
        for cve_record in cves:
            req_port = cve_record.get("requires_port")
            if req_port is None or req_port in active_ports:
                matched_cves.append(cve_record)
                
        return matched_cves
