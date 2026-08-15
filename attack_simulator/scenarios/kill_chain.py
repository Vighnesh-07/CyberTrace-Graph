"""
Multi-Stage Lateral Movement Kill Chain Scenario.

Simulates a 4-stage attack:
  Stage 1: Brute Force (External IP failing logins to Target Host)
  Stage 2: Compromise (Successful login to Target Host)
  Stage 3: Lateral Movement (Target Host scanning/connecting to Internal DB)
  Stage 4: Exfiltration (Internal DB tunneling data via DNS)
"""

import random
import string
import base64
from datetime import datetime, timezone, timedelta
from typing import List

from junction_nodes.common.models.events import (
    DNSEvent, AuthEvent, NetworkEvent, EventType, SeverityLevel, SecurityEvent
)

class KillChainScenario:
    def __init__(
        self,
        sensor_id: str = "sim-multi-01",
        c2_domain: str = "c2.evil-corp.net",
    ):
        self.sensor_id = sensor_id
        self.c2_domain = c2_domain
        self.attacker_ip = "203.0.113.42"
        self.compromised_host = "192.168.1.50"
        self.internal_db = "10.0.0.5"

    def _generate_encoded_payload(self, size: int = 30) -> str:
        raw = "".join(random.choices(string.ascii_letters + string.digits, k=size))
        return base64.b64encode(raw.encode()).decode().rstrip("=")

    def generate_events(
        self,
        duration_seconds: int = 300,
    ) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        base_time = datetime.now(timezone.utc)
        current_time = 0.0

        # ── Stage 1: Brute Force (0-30s) ──
        while current_time < min(30, duration_seconds):
            t = base_time + timedelta(seconds=current_time)
            events.append(AuthEvent(
                sensor_id=self.sensor_id,
                sensor_type="AUTH",
                event_type=EventType.AUTH_FAILURE,
                timestamp=t,
                severity=SeverityLevel.LOW,
                source_ip=self.attacker_ip,
                target_host=self.compromised_host,
                username="admin",
                auth_method="SSH",
                success=False,
                failure_reason="Invalid credentials",
                mitre_tactic="TA0006",
                mitre_technique="T1110",
                confidence_score=0.8,
            ))
            current_time += 1.0

        # ── Stage 2: Compromise (30s) ──
        if duration_seconds >= 30:
            t = base_time + timedelta(seconds=30)
            events.append(AuthEvent(
                sensor_id=self.sensor_id,
                sensor_type="AUTH",
                event_type=EventType.AUTH_LOGIN,
                timestamp=t,
                severity=SeverityLevel.CRITICAL,
                source_ip=self.attacker_ip,
                target_host=self.compromised_host,
                username="admin",
                auth_method="SSH",
                success=True,
                privilege_level="root",
                mitre_tactic="TA0006",
                mitre_technique="T1078.003",
                confidence_score=0.9,
            ))
            current_time = 35.0

        # ── Stage 3: Lateral Movement (35-90s) ──
        while current_time < min(90, duration_seconds):
            t = base_time + timedelta(seconds=current_time)
            events.append(NetworkEvent(
                sensor_id=self.sensor_id,
                sensor_type="NETWORK",
                event_type=EventType.NETWORK_CONNECTION,
                timestamp=t,
                severity=SeverityLevel.MEDIUM,
                source_ip=self.compromised_host,
                destination_ip=self.internal_db,
                destination_port=3306,
                protocol="TCP",
                bytes_sent=random.randint(100, 500),
                bytes_received=random.randint(500, 5000),
                mitre_tactic="TA0008",
                mitre_technique="T1021.002",
                confidence_score=0.7,
            ))
            current_time += 5.0

        # ── Stage 4: Exfiltration from DB (90s+) ──
        current_time = 90.0
        while current_time < duration_seconds:
            t = base_time + timedelta(seconds=current_time)
            payload = self._generate_encoded_payload(60)
            events.append(DNSEvent(
                sensor_id=self.sensor_id,
                sensor_type="DNS",
                event_type=EventType.DNS_QUERY,
                timestamp=t,
                severity=SeverityLevel.HIGH,
                source_ip=self.internal_db,
                destination_ip="8.8.8.8",
                query_name=f"{payload}.{self.c2_domain}",
                query_type="TXT",
                mitre_tactic="TA0010",
                mitre_technique="T1048.003",
                confidence_score=0.9,
            ))
            current_time += 3.0

        return events
