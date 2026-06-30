"""
Rule Engine Test Suite
"""

from pprint import pprint

from schemas.detection import DetectionRequest
from services.rule_engine import run_rule_engine


def run_test(title: str, request: DetectionRequest):

    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    result = run_rule_engine(request)

    pprint(result)


# =====================================================
# Test 1 : Normal Traffic
# =====================================================

run_test(
    "TEST 1 : NORMAL TRAFFIC",
    DetectionRequest(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        failed_logins=2,
        ports_accessed=4,
        bytes_sent=5000,
    ),
)

# =====================================================
# Test 2 : Brute Force
# =====================================================

run_test(
    "TEST 2 : BRUTE FORCE",
    DetectionRequest(
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        failed_logins=10,
        ports_accessed=2,
        bytes_sent=3000,
    ),
)

# =====================================================
# Test 3 : Port Scan
# =====================================================

run_test(
    "TEST 3 : PORT SCAN",
    DetectionRequest(
        source_ip="172.16.1.2",
        destination_ip="172.16.1.3",
        failed_logins=1,
        ports_accessed=35,
        bytes_sent=10000,
    ),
)

# =====================================================
# Test 4 : Data Exfiltration
# =====================================================

run_test(
    "TEST 4 : DATA EXFILTRATION",
    DetectionRequest(
        source_ip="192.168.100.1",
        destination_ip="8.8.8.8",
        failed_logins=0,
        ports_accessed=3,
        bytes_sent=2_500_000,
    ),
)

# =====================================================
# Test 5 : Multiple Threats
# =====================================================

run_test(
    "TEST 5 : MULTIPLE THREATS",
    DetectionRequest(
        source_ip="192.168.0.100",
        destination_ip="8.8.4.4",
        failed_logins=12,
        ports_accessed=40,
        bytes_sent=5_000_000,
    ),
)

print("\nAll Rule Engine tests completed successfully.")