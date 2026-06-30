"""
Rule-Based Detection Engine
---------------------------
Performs baseline rule-based threat detection before
Machine Learning based detection.
"""

from datetime import datetime
from typing import Any
import logging

from schemas.alert import Alert
from schemas.detection import DetectionRequest

from services.rules_config import (
    FAILED_LOGIN_LIMIT,
    PORT_SCAN_LIMIT,
    DATA_EXFIL_LIMIT,
    BRUTE_FORCE_SCORE,
    PORT_SCAN_SCORE,
    DATA_EXFIL_SCORE,
    AUTHENTICATION,
    NETWORK_RECON,
    DATA_SECURITY,
    RULE_ENGINE_SOURCE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
    RB001,
    RB002,
    RB003,
)

logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Baseline Rule-Based Detection Engine.
    """

    def __init__(self):
        self.rules = (
            self.detect_bruteforce,
            self.detect_portscan,
            self.detect_data_exfiltration,
        )

    # =====================================================
    # Utility
    # =====================================================

    def _create_alert(
        self,
        rule_id: str,
        category: str,
        threat: str,
        severity: str,
        score: int,
        description: str,
        timestamp: str,
    ) -> Alert:

        return Alert(
            rule_id=rule_id,
            category=category,
            source=RULE_ENGINE_SOURCE,
            threat=threat,
            severity=severity,
            threat_score=score,
            description=description,
            timestamp=timestamp,
        )

    # =====================================================
    # RB001 - Brute Force
    # =====================================================

    def detect_bruteforce(
        self,
        request: DetectionRequest,
        timestamp: str,
    ):

        if request.failed_logins <= FAILED_LOGIN_LIMIT:
            return None

        logger.warning("%s triggered - Brute Force detected", RB001)

        return self._create_alert(
            rule_id=RB001,
            category=AUTHENTICATION,
            threat="Brute Force",
            severity=HIGH,
            score=BRUTE_FORCE_SCORE,
            description="Failed login attempts exceeded configured threshold.",
            timestamp=timestamp,
        )

    # =====================================================
    # RB002 - Port Scan
    # =====================================================

    def detect_portscan(
        self,
        request: DetectionRequest,
        timestamp: str,
    ):

        if request.ports_accessed <= PORT_SCAN_LIMIT:
            return None

        logger.warning("%s triggered - Port Scan detected", RB002)

        return self._create_alert(
            rule_id=RB002,
            category=NETWORK_RECON,
            threat="Port Scan",
            severity=HIGH,
            score=PORT_SCAN_SCORE,
            description="Number of accessed ports exceeded configured threshold.",
            timestamp=timestamp,
        )

    # =====================================================
    # RB003 - Data Exfiltration
    # =====================================================

    def detect_data_exfiltration(
        self,
        request: DetectionRequest,
        timestamp: str,
    ):

        if request.bytes_sent <= DATA_EXFIL_LIMIT:
            return None

        logger.warning("%s triggered - Data Exfiltration detected", RB003)

        return self._create_alert(
            rule_id=RB003,
            category=DATA_SECURITY,
            threat="Data Exfiltration",
            severity=CRITICAL,
            score=DATA_EXFIL_SCORE,
            description="Outbound data transfer exceeded configured threshold.",
            timestamp=timestamp,
        )

    # =====================================================
    # Helpers
    # =====================================================

    def _overall_severity(self, alerts):

        if not alerts:
            return LOW

        ranking = {
            LOW: 1,
            MEDIUM: 2,
            HIGH: 3,
            CRITICAL: 4,
        }

        return max(
            alerts,
            key=lambda a: ranking[a.severity]
        ).severity

    def _threat_score(self, alerts):

        if not alerts:
            return 0

        return max(
            alert.threat_score
            for alert in alerts
        )

    # =====================================================
    # Execute Rule Engine
    # =====================================================

    def run(
        self,
        request: DetectionRequest,
    ) -> dict:

        timestamp = datetime.utcnow().isoformat()

        alerts = []

        for rule in self.rules:

            alert = rule(
                request,
                timestamp,
            )

            if alert:
                alerts.append(alert)

        return {

            "matched": bool(alerts),

            "alert_count": len(alerts),

            "overall_severity":
                self._overall_severity(alerts),

            "threat_score":
                self._threat_score(alerts),

            "alerts": [
                alert.to_dict()
                for alert in alerts
            ],
        }


_engine = RuleEngine()


def run_rule_engine(
    request: DetectionRequest,
) -> dict:
    """
    Public API for the Rule Engine.
    """

    return _engine.run(request)