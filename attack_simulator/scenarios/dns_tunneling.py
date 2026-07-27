"""
DNS Tunneling Attack Scenario Simulator.

Simulates a realistic DNS tunneling attack that exfiltrates data
via encoded DNS queries to a C2 server, progressing through 3 phases:
  Phase 1 (0-60s):   Initial C2 domain resolution (reconnaissance)
  Phase 2 (60-180s): Begin data exfiltration via encoded subdomains
  Phase 3 (180+s):   Accelerated exfiltration with larger payloads

Normal DNS traffic is mixed in throughout to make detection harder.
"""

import random
import string
import base64
from datetime import datetime, timezone, timedelta
from typing import List

from junction_nodes.common.models.events import DNSEvent, EventType, SeverityLevel


class DNSTunnelingScenario:
    """Simulates a DNS tunneling exfiltration attack.
    
    Args:
        sensor_id: Sensor ID to stamp events with.
        c2_domain: The attacker's C2 domain for DNS tunneling.
    """

    def __init__(
        self,
        sensor_id: str = "sim-dns-01",
        c2_domain: str = "data.evil-c2-server.xyz",
    ):
        self.sensor_id = sensor_id
        self.c2_domain = c2_domain
        self.attacker_ip = "192.168.1.50"

    def _generate_encoded_payload(self, size: int = 30) -> str:
        """Generate a random base64-like string to simulate encoded exfil data."""
        raw = "".join(random.choices(string.ascii_letters + string.digits, k=size))
        return base64.b64encode(raw.encode()).decode().rstrip("=")

    def _generate_normal_traffic(self, base_time: datetime) -> DNSEvent:
        """Generate a benign-looking DNS query."""
        normal_domains = [
            "google.com", "office365.com", "github.com",
            "microsoft.com", "cdn.cloudflare.com", "slack.com",
        ]
        return DNSEvent(
            sensor_id=self.sensor_id,
            sensor_type="DNS",
            event_type=EventType.DNS_QUERY,
            timestamp=base_time,
            severity=SeverityLevel.LOW,
            confidence_score=0.05,
            source_ip=f"192.168.1.{random.randint(10, 200)}",
            destination_ip="8.8.8.8",
            destination_port=53,
            query_name=random.choice(normal_domains),
            query_type="A",
            response_code="NOERROR",
        )

    def generate_events(
        self,
        duration_seconds: int = 300,
        beacon_interval: float = 5.0,
    ) -> List[DNSEvent]:
        """Generate a complete DNS tunneling attack scenario.
        
        Args:
            duration_seconds: Total duration of the simulation in seconds.
            beacon_interval: Time between beacon queries in seconds.
            
        Returns:
            List of DNSEvent objects representing the attack + cover traffic.
        """
        events: List[DNSEvent] = []
        base_time = datetime.now(timezone.utc)
        current_time = 0.0

        # ── Phase 1: Initial reconnaissance (0–60s) ──
        while current_time < min(60, duration_seconds):
            t = base_time + timedelta(seconds=current_time)
            # Normal cover traffic
            events.append(self._generate_normal_traffic(t))
            # Occasional C2 domain lookups (low suspicion)
            if random.random() < 0.15:
                events.append(DNSEvent(
                    sensor_id=self.sensor_id,
                    sensor_type="DNS",
                    event_type=EventType.DNS_QUERY,
                    timestamp=t,
                    severity=SeverityLevel.LOW,
                    confidence_score=0.3,
                    source_ip=self.attacker_ip,
                    destination_ip="8.8.8.8",
                    destination_port=53,
                    query_name=self.c2_domain,
                    query_type="A",
                    response_code="NOERROR",
                    mitre_tactic="TA0011",       # Command and Control
                    mitre_technique="T1071.004",  # DNS
                    tags=["c2_recon"],
                ))
            current_time += beacon_interval

        # ── Phase 2: Data exfiltration begins (60–180s) ──
        while current_time < min(180, duration_seconds):
            t = base_time + timedelta(seconds=current_time)
            events.append(self._generate_normal_traffic(t))
            # Encoded data as DNS subdomain queries
            payload = self._generate_encoded_payload(30)
            events.append(DNSEvent(
                sensor_id=self.sensor_id,
                sensor_type="DNS",
                event_type=EventType.DNS_QUERY,
                timestamp=t,
                severity=SeverityLevel.HIGH,
                confidence_score=0.8,
                source_ip=self.attacker_ip,
                destination_ip="8.8.8.8",
                destination_port=53,
                query_name=f"{payload}.{self.c2_domain}",
                query_type="TXT",
                response_code="NOERROR",
                mitre_tactic="TA0010",       # Exfiltration
                mitre_technique="T1048.003",  # Exfil Over Alternative Protocol: DNS
                tags=["dns_tunneling", "exfiltration"],
            ))
            current_time += beacon_interval

        # ── Phase 3: Accelerated exfiltration (180s+) ──
        while current_time < duration_seconds:
            t = base_time + timedelta(seconds=current_time)
            events.append(self._generate_normal_traffic(t))
            # Larger payloads, faster rate
            payload = self._generate_encoded_payload(60)
            events.append(DNSEvent(
                sensor_id=self.sensor_id,
                sensor_type="DNS",
                event_type=EventType.DNS_QUERY,
                timestamp=t,
                severity=SeverityLevel.CRITICAL,
                confidence_score=0.95,
                source_ip=self.attacker_ip,
                destination_ip="8.8.8.8",
                destination_port=53,
                query_name=f"{payload}.{self.c2_domain}",
                query_type="TXT",
                response_code="NOERROR",
                mitre_tactic="TA0010",
                mitre_technique="T1048.003",
                tags=["dns_tunneling", "exfiltration", "high_rate"],
            ))
            current_time += beacon_interval / 2  # Double the rate

        return events
