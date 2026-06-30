"""
Rule-Based Detection Engine
---------------------------
Registry-based Rule Engine for SecOpsAI.
Threshold-based rules are loaded from services.rules.
Custom rules are implemented as dedicated methods.
"""

from datetime import datetime
import logging

from schemas.alert import Alert
from schemas.detection import DetectionRequest

from services.rules import RULES
from services.rules_config import *

logger = logging.getLogger(__name__)


class RuleEngine:

    ####################################################
    # Alert Builder
    ####################################################

    def _create_alert(
        self,
        rule_id,
        category,
        threat,
        severity,
        score,
        description,
        timestamp,
    ):

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

    ####################################################
    # Registry Rules
    ####################################################

    def run_threshold_rules(self, request, timestamp):

        alerts = []

        for rule in RULES:

            value = getattr(request, rule["field"], 0)

            if value > rule["limit"]:

                logger.warning("%s triggered", rule["id"])

                alerts.append(

                    self._create_alert(

                        rule["id"],

                        rule["category"],

                        rule["threat"],

                        rule["severity"],

                        rule["score"],

                        rule["description"],

                        timestamp,

                    )

                )

        return alerts
    ####################################################
    # RB008 - SQL Injection
    ####################################################

    def detect_sql_injection(self, request, timestamp):

        payload = request.payload.lower()

        keywords = [
            "union select",
            "drop table",
            "insert into",
            "delete from",
            "update ",
            "or 1=1",
            "'--",
            "information_schema",
        ]

        if not any(keyword in payload for keyword in keywords):
            return None

        logger.warning("%s triggered", RB008)

        return self._create_alert(
            RB008,
            WEB_SECURITY,
            "SQL Injection",
            CRITICAL,
            SQLI_SCORE,
            "Possible SQL Injection payload detected.",
            timestamp,
        )

    ####################################################
    # RB009 - Cross Site Scripting
    ####################################################

    def detect_xss(self, request, timestamp):

        payload = request.payload.lower()

        patterns = [
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "onmouseover=",
            "<iframe",
        ]

        if not any(pattern in payload for pattern in patterns):
            return None

        logger.warning("%s triggered", RB009)

        return self._create_alert(
            RB009,
            WEB_SECURITY,
            "Cross Site Scripting",
            HIGH,
            XSS_SCORE,
            "Potential XSS payload detected.",
            timestamp,
        )

    ####################################################
    # RB010 - Command Injection
    ####################################################

    def detect_command_injection(self, request, timestamp):

        payload = request.payload.lower()

        patterns = [
            ";",
            "&&",
            "||",
            "$(",
            "`",
        ]

        if not any(pattern in payload for pattern in patterns):
            return None

        logger.warning("%s triggered", RB010)

        return self._create_alert(
            RB010,
            WEB_SECURITY,
            "Command Injection",
            CRITICAL,
            COMMAND_INJECTION_SCORE,
            "Possible command injection payload detected.",
            timestamp,
        )
        ####################################################
    # RB012 - Malware Activity
    ####################################################

    def detect_malware(self, request, timestamp):

        if not request.malware_signature:
            return None

        logger.warning("%s triggered", RB012)

        return self._create_alert(
            RB012,
            ENDPOINT,
            "Malware Activity",
            CRITICAL,
            MALWARE_SCORE,
            "Known malware signature detected.",
            timestamp,
        )

    ####################################################
    # RB015 - Beaconing
    ####################################################

    def detect_beaconing(self, request, timestamp):

        if request.connection_interval > BEACON_INTERVAL:
            return None

        logger.warning("%s triggered", RB015)

        return self._create_alert(
            RB015,
            COMMAND_CONTROL,
            "Beaconing",
            HIGH,
            BEACON_SCORE,
            "Periodic outbound communication detected.",
            timestamp,
        )

    ####################################################
    # RB016 - Suspicious User Agent
    ####################################################

    def detect_suspicious_user_agent(self, request, timestamp):

        user_agent = request.user_agent.lower()

        suspicious_agents = [
            "curl",
            "wget",
            "python",
            "sqlmap",
            "nikto",
            "masscan",
            "nmap",
            "zgrab",
            "nessus",
            "acunetix",
        ]

        if not any(agent in user_agent for agent in suspicious_agents):
            return None

        logger.warning("%s triggered", RB016)

        return self._create_alert(
            RB016,
            WEB_SECURITY,
            "Suspicious User Agent",
            MEDIUM,
            USER_AGENT_SCORE,
            "Known security tool or scanner detected.",
            timestamp,
        )

    ####################################################
    # Helper Methods
    ####################################################

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
            key=lambda alert: ranking[alert.severity],
        ).severity

    def _threat_score(self, alerts):

        return max(
            (alert.threat_score for alert in alerts),
            default=0,
        )
    ####################################################
    # Execute Rule Engine
    ####################################################

    def run(self, request: DetectionRequest):

        timestamp = datetime.utcnow().isoformat()

        alerts = []

        # Run all threshold-based rules
        alerts.extend(
            self.run_threshold_rules(
                request,
                timestamp,
            )
        )

        # Run all custom detection rules
        custom_rules = (
            self.detect_sql_injection,
            self.detect_xss,
            self.detect_command_injection,
            self.detect_malware,
            self.detect_beaconing,
            self.detect_suspicious_user_agent,
        )

        for rule in custom_rules:

            alert = rule(
                request,
                timestamp,
            )

            if alert:
                alerts.append(alert)

        return {
            "matched": bool(alerts),
            "alert_count": len(alerts),
            "overall_severity": self._overall_severity(alerts),
            "threat_score": self._threat_score(alerts),
            "alerts": [
                alert.to_dict()
                for alert in alerts
            ],
        }


####################################################
# Singleton Instance
####################################################

_engine = RuleEngine()


####################################################
# Public API
####################################################

def run_rule_engine(request: DetectionRequest):

    return _engine.run(request)