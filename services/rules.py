"""
Rule Registry
-------------
Contains all threshold-based detection rules used by the
Rule-Based Detection Engine.

Each rule defines:
- Rule ID
- Input field
- Threshold
- Threat details
- Severity
- Threat score
"""

from services.rules_config import *

RULES = [

    {
        "id": RB001,
        "field": "failed_logins",
        "limit": FAILED_LOGIN_LIMIT,
        "category": AUTHENTICATION,
        "threat": "Brute Force",
        "severity": HIGH,
        "score": BRUTE_FORCE_SCORE,
        "description": "Failed login threshold exceeded.",
    },

    {
        "id": RB002,
        "field": "failed_ssh_logins",
        "limit": PASSWORD_SPRAY_LIMIT,
        "category": AUTHENTICATION,
        "threat": "Password Spraying",
        "severity": HIGH,
        "score": PASSWORD_SPRAY_SCORE,
        "description": "Multiple failed SSH logins detected.",
    },

    {
        "id": RB003,
        "field": "ports_accessed",
        "limit": PORT_SCAN_LIMIT,
        "category": NETWORK_RECON,
        "threat": "Port Scan",
        "severity": HIGH,
        "score": PORT_SCAN_SCORE,
        "description": "Large number of ports accessed.",
    },

    {
        "id": RB004,
        "field": "syn_packets",
        "limit": SYN_FLOOD_LIMIT,
        "category": DOS,
        "threat": "SYN Flood",
        "severity": HIGH,
        "score": SYN_FLOOD_SCORE,
        "description": "Excessive SYN packets detected.",
    },

    {
        "id": RB005,
        "field": "udp_packets",
        "limit": UDP_FLOOD_LIMIT,
        "category": DOS,
        "threat": "UDP Flood",
        "severity": HIGH,
        "score": UDP_FLOOD_SCORE,
        "description": "High UDP traffic detected.",
    },

    {
        "id": RB006,
        "field": "icmp_packets",
        "limit": ICMP_FLOOD_LIMIT,
        "category": DOS,
        "threat": "ICMP Flood",
        "severity": HIGH,
        "score": ICMP_FLOOD_SCORE,
        "description": "High ICMP traffic detected.",
    },

    {
        "id": RB007,
        "field": "dns_queries",
        "limit": DNS_QUERY_LIMIT,
        "category": DNS,
        "threat": "DNS Tunneling",
        "severity": HIGH,
        "score": DNS_TUNNEL_SCORE,
        "description": "Large number of DNS queries detected.",
    },

    {
        "id": RB011,
        "field": "bytes_sent",
        "limit": DATA_EXFIL_LIMIT,
        "category": DATA_SECURITY,
        "threat": "Data Exfiltration",
        "severity": CRITICAL,
        "score": DATA_EXFIL_SCORE,
        "description": "Outbound traffic exceeded threshold.",
    },

    {
        "id": RB013,
        "field": "encrypted_files",
        "limit": ENCRYPTED_FILE_LIMIT,
        "category": ENDPOINT,
        "threat": "Ransomware Behaviour",
        "severity": CRITICAL,
        "score": RANSOMWARE_SCORE,
        "description": "Mass file encryption detected.",
    },

    {
        "id": RB014,
        "field": "privilege_changes",
        "limit": PRIVILEGE_CHANGE_LIMIT,
        "category": HOST_SECURITY,
        "threat": "Privilege Escalation",
        "severity": CRITICAL,
        "score": PRIVILEGE_ESCALATION_SCORE,
        "description": "Privilege escalation behaviour detected.",
    },

]