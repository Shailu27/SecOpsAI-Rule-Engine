"""
Detection Request Schema
------------------------
Defines the input format expected by the Rule-Based Detection Engine.
"""

from dataclasses import dataclass


@dataclass(slots=True)
class DetectionRequest:
    """
    Input data for the Rule Engine.
    """

    source_ip: str
    destination_ip: str

    failed_logins: int
    ports_accessed: int
    bytes_sent: int