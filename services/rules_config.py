"""
Rule Configuration
------------------
Centralized configuration for the Rule-Based Detection Engine.

Contains:
- Detection thresholds
- Threat scores
- Severity levels
- Alert categories
- Rule identifiers
"""

# Thresholds

FAILED_LOGIN_LIMIT = 5
PASSWORD_SPRAY_LIMIT = 10

PORT_SCAN_LIMIT = 20

SYN_FLOOD_LIMIT = 1000
UDP_FLOOD_LIMIT = 1000
ICMP_FLOOD_LIMIT = 1000

DNS_QUERY_LIMIT = 500

DATA_EXFIL_LIMIT = 1_000_000

ENCRYPTED_FILE_LIMIT = 500

PRIVILEGE_CHANGE_LIMIT = 3

BEACON_INTERVAL = 60

# Scores

BRUTE_FORCE_SCORE = 90
PASSWORD_SPRAY_SCORE = 88
PORT_SCAN_SCORE = 85
SYN_FLOOD_SCORE = 90
UDP_FLOOD_SCORE = 88
ICMP_FLOOD_SCORE = 88
DNS_TUNNEL_SCORE = 92
SQLI_SCORE = 98
XSS_SCORE = 95
COMMAND_INJECTION_SCORE = 97
DATA_EXFIL_SCORE = 95
MALWARE_SCORE = 99
RANSOMWARE_SCORE = 100
PRIVILEGE_ESCALATION_SCORE = 96
BEACON_SCORE = 90
USER_AGENT_SCORE = 75

# Severity

LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

# Categories

AUTHENTICATION = "Authentication"
NETWORK_RECON = "Network Reconnaissance"
DOS = "Denial of Service"
WEB_SECURITY = "Web Security"
DNS = "DNS"
DATA_SECURITY = "Data Security"
ENDPOINT = "Endpoint Security"
HOST_SECURITY = "Host Security"
COMMAND_CONTROL = "Command & Control"

RULE_ENGINE_SOURCE = "RULE_ENGINE"

# Authentication
RB001 = "RB001"   # Brute Force
RB002 = "RB002"   # Password Spraying

# Network Reconnaissance
RB003 = "RB003"   # Port Scan

# Denial of Service
RB004 = "RB004"   # SYN Flood
RB005 = "RB005"   # UDP Flood
RB006 = "RB006"   # ICMP Flood

# DNS
RB007 = "RB007"   # DNS Tunneling

# Web
RB008 = "RB008"   # SQL Injection
RB009 = "RB009"   # Cross Site Scripting
RB010 = "RB010"   # Command Injection

# Data
RB011 = "RB011"   # Data Exfiltration

# Endpoint
RB012 = "RB012"   # Malware Activity
RB013 = "RB013"   # Ransomware Behaviour

# Host
RB014 = "RB014"   # Privilege Escalation

# Command & Control
RB015 = "RB015"   # Beaconing

# HTTP
RB016 = "RB016"   # Suspicious User Agent