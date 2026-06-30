"""
Rule Engine Test Suite
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pprint import pprint

from schemas.detection import DetectionRequest
from services.rule_engine import run_rule_engine


def run_test(title, request):

    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    result = run_rule_engine(request)

    pprint(result)


####################################################
# TEST 1 : Normal Traffic
####################################################

run_test(
    "TEST 1 : NORMAL TRAFFIC",
    DetectionRequest(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
    ),
)

####################################################
# TEST 2 : Brute Force
####################################################

run_test(
    "TEST 2 : BRUTE FORCE",
    DetectionRequest(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        failed_logins=10,
    ),
)

####################################################
# TEST 3 : Password Spraying
####################################################

run_test(
    "TEST 3 : PASSWORD SPRAYING",
    DetectionRequest(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        failed_ssh_logins=15,
    ),
)

####################################################
# TEST 4 : Port Scan
####################################################

run_test(
    "TEST 4 : PORT SCAN",
    DetectionRequest(
        source_ip="172.16.1.1",
        destination_ip="172.16.1.2",
        ports_accessed=35,
    ),
)

####################################################
# TEST 5 : SYN Flood
####################################################

run_test(
    "TEST 5 : SYN FLOOD",
    DetectionRequest(
        source_ip="8.8.8.8",
        destination_ip="192.168.1.5",
        syn_packets=2500,
    ),
)

####################################################
# TEST 6 : UDP Flood
####################################################

run_test(
    "TEST 6 : UDP FLOOD",
    DetectionRequest(
        source_ip="8.8.8.8",
        destination_ip="192.168.1.5",
        udp_packets=2500,
    ),
)

####################################################
# TEST 7 : ICMP Flood
####################################################

run_test(
    "TEST 7 : ICMP FLOOD",
    DetectionRequest(
        source_ip="8.8.8.8",
        destination_ip="192.168.1.5",
        icmp_packets=2500,
    ),
)

####################################################
# TEST 8 : DNS Tunneling
####################################################

run_test(
    "TEST 8 : DNS TUNNELING",
    DetectionRequest(
        source_ip="192.168.1.1",
        destination_ip="8.8.8.8",
        dns_queries=1000,
    ),
)

####################################################
# TEST 9 : SQL Injection
####################################################

run_test(
    "TEST 9 : SQL INJECTION",
    DetectionRequest(
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        payload="' OR 1=1 -- UNION SELECT password FROM users",
    ),
)

####################################################
# TEST 10 : XSS
####################################################

run_test(
    "TEST 10 : XSS",
    DetectionRequest(
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        payload="<script>alert('xss')</script>",
    ),
)

####################################################
# TEST 11 : Command Injection
####################################################

run_test(
    "TEST 11 : COMMAND INJECTION",
    DetectionRequest(
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        payload="whoami && cat /etc/passwd",
    ),
)

####################################################
# TEST 12 : Data Exfiltration
####################################################

run_test(
    "TEST 12 : DATA EXFILTRATION",
    DetectionRequest(
        source_ip="192.168.1.10",
        destination_ip="10.10.10.10",
        bytes_sent=5000000,
    ),
)

####################################################
# TEST 13 : Malware
####################################################

run_test(
    "TEST 13 : MALWARE",
    DetectionRequest(
        source_ip="192.168.1.10",
        destination_ip="10.10.10.10",
        malware_signature=True,
    ),
)

####################################################
# TEST 14 : Ransomware
####################################################

run_test(
    "TEST 14 : RANSOMWARE",
    DetectionRequest(
        source_ip="192.168.1.10",
        destination_ip="10.10.10.10",
        encrypted_files=1200,
    ),
)

####################################################
# TEST 15 : Privilege Escalation
####################################################

run_test(
    "TEST 15 : PRIVILEGE ESCALATION",
    DetectionRequest(
        source_ip="192.168.1.10",
        destination_ip="10.10.10.10",
        privilege_changes=10,
    ),
)

####################################################
# TEST 16 : Beaconing
####################################################

run_test(
    "TEST 16 : BEACONING",
    DetectionRequest(
        source_ip="192.168.1.10",
        destination_ip="10.10.10.10",
        connection_interval=30,
    ),
)

####################################################
# TEST 17 : Suspicious User Agent
####################################################

run_test(
    "TEST 17 : SUSPICIOUS USER AGENT",
    DetectionRequest(
        source_ip="192.168.1.10",
        destination_ip="10.10.10.10",
        user_agent="sqlmap/1.8",
    ),
)

####################################################
# TEST 18 : Multiple Threats
####################################################

run_test(
    "TEST 18 : MULTIPLE THREATS",
    DetectionRequest(
        source_ip="10.0.0.5",
        destination_ip="8.8.8.8",
        failed_logins=15,
        failed_ssh_logins=20,
        ports_accessed=50,
        syn_packets=3000,
        udp_packets=3000,
        icmp_packets=3000,
        dns_queries=800,
        bytes_sent=5000000,
        encrypted_files=1200,
        malware_signature=True,
        privilege_changes=5,
        connection_interval=20,
        payload="<script>alert(1)</script> UNION SELECT * FROM users",
        user_agent="sqlmap",
    ),
)

print("\nAll Rule Engine tests completed successfully.")