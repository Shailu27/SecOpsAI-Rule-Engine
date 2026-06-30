"""
Detection Request Schema
------------------------
Defines the input expected by the Rule-Based Detection Engine.
"""
from dataclasses import dataclass


@dataclass(slots=True)
class DetectionRequest:

    # Network
    source_ip: str
    destination_ip: str
    protocol: str = "TCP"
    packet_size: int = 0

    # Authentication
    failed_logins: int = 0
    failed_ssh_logins: int = 0

    # Network
    ports_accessed: int = 0

    # DoS
    syn_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0

    # DNS
    dns_queries: int = 0

    # Data
    bytes_sent: int = 0

    # Endpoint
    encrypted_files: int = 0
    malware_signature: bool = False

    # Host
    privilege_changes: int = 0

    # Web
    payload: str = ""

    # C2
    connection_interval: int = 0

    # HTTP
    user_agent: str = ""