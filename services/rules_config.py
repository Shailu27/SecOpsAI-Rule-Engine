"""
Rule Configuration
------------------
Centralized configuration for all Rule-Based Detection thresholds.
"""

# =====================================================
# Rule Thresholds
# =====================================================

# Authentication
FAILED_LOGIN_LIMIT = 5

# Network Reconnaissance
PORT_SCAN_LIMIT = 20

# Data Exfiltration
DATA_EXFIL_LIMIT = 1_000_000


# =====================================================
# Threat Scores
# =====================================================

BRUTE_FORCE_SCORE = 90
PORT_SCAN_SCORE = 85
DATA_EXFIL_SCORE = 95


# =====================================================
# Severity Levels
# =====================================================

LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"


# =====================================================
# Alert Categories
# =====================================================

AUTHENTICATION = "Authentication"
NETWORK_RECON = "Network Reconnaissance"
DATA_SECURITY = "Data Security"


# =====================================================
# Alert Source
# =====================================================

RULE_ENGINE_SOURCE = "RULE_ENGINE"


# =====================================================
# Rule IDs
# =====================================================

RB001 = "RB001"
RB002 = "RB002"
RB003 = "RB003"