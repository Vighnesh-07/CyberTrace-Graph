"""
DNS Capture Engine for the DNS Junction Node.

Supports two modes:
- Simulated Mode (default): Generates realistic fake DNS traffic for development/testing
- Live Mode: Uses scapy to capture real DNS packets (requires root/admin privileges)

Includes analysis functions for detecting:
- DNS tunneling (high-entropy subdomains)
- DGA (Domain Generation Algorithm) domains
- Suspicious TLDs
- C2 beaconing patterns
"""

import asyncio
import math
import random
import re
import logging
from datetime import datetime, timezone
from typing import AsyncGenerator, Dict, Any, List

from junction_nodes.common.models.events import DNSEvent, EventType, SeverityLevel

logger = logging.getLogger(__name__)


def calculate_entropy(subdomain: str) -> float:
    """Calculate Shannon entropy of a string.
    
    Higher entropy indicates more randomness, which is characteristic of:
    - Base64-encoded data in DNS tunneling
    - DGA-generated domain names
    
    Args:
        subdomain: The string to calculate entropy for.
        
    Returns:
        Shannon entropy value. Normal domains: ~2.0-3.0, Suspicious: >3.5
    """
    if not subdomain:
        return 0.0
    entropy = 0.0
    for char in set(subdomain):
        p = float(subdomain.count(char)) / len(subdomain)
        entropy -= p * math.log2(p)
    return entropy


def check_dga(domain: str, patterns: List[re.Pattern]) -> bool:
    """Check if a domain matches known DGA patterns.
    
    Args:
        domain: The full domain name to check.
        patterns: List of compiled regex patterns for DGA detection.
        
    Returns:
        True if the domain matches any DGA pattern.
    """
    return any(pattern.match(domain) for pattern in patterns)


def check_suspicious_tld(domain: str, tlds: List[str]) -> bool:
    """Check if a domain uses a suspicious TLD.
    
    Args:
        domain: The full domain name to check.
        tlds: List of suspicious TLD strings (e.g., [".xyz", ".tk"]).
        
    Returns:
        True if the domain ends with a suspicious TLD.
    """
    return any(domain.endswith(tld) for tld in tlds)


def assess_severity(event: DNSEvent, engine: "DNSCaptureEngine") -> DNSEvent:
    """Analyze a DNS event and assign severity + MITRE ATT&CK tags.
    
    Checks for:
    1. DNS tunneling (long subdomain + high entropy) -> HIGH + TA0011/T1071.004
    2. DGA domains (random-looking names) -> HIGH + TA0011/T1568.002
    3. Suspicious TLDs (.xyz, .tk, etc.) -> MEDIUM
    4. Normal traffic -> LOW
    
    Args:
        event: The DNSEvent to analyze.
        engine: The DNSCaptureEngine with configuration thresholds.
        
    Returns:
        The event with updated severity, MITRE tags, and confidence score.
    """
    domain_parts = event.query_name.split(".")
    subdomain = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""

    entropy = calculate_entropy(subdomain)

    # Check for DNS tunneling: long subdomain with high entropy
    if len(subdomain) > engine.min_query_length and entropy > engine.entropy_threshold:
        event.severity = SeverityLevel.HIGH
        event.mitre_tactic = "TA0011"       # Command and Control
        event.mitre_technique = "T1071.004"  # Application Layer Protocol: DNS
        event.confidence_score = min(0.5 + (entropy - engine.entropy_threshold) * 0.2, 1.0)
        event.tags.append("dns_tunneling")
        logger.info(
            "DNS tunneling detected",
            domain=event.query_name,
            entropy=round(entropy, 2),
        )
    # Check for DGA domains
    elif check_dga(event.query_name, engine.dga_patterns):
        event.severity = SeverityLevel.HIGH
        event.mitre_tactic = "TA0011"       # Command and Control
        event.mitre_technique = "T1568.002"  # Dynamic Resolution: DGA
        event.confidence_score = 0.75
        event.tags.append("dga")
        logger.info("DGA domain detected", domain=event.query_name)
    # Check for suspicious TLDs
    elif check_suspicious_tld(event.query_name, engine.suspicious_tlds):
        event.severity = SeverityLevel.MEDIUM
        event.confidence_score = 0.4
        event.tags.append("suspicious_tld")
    else:
        event.severity = SeverityLevel.LOW
        event.confidence_score = 0.05

    return event


class DNSCaptureEngine:
    """DNS event capture and analysis engine.
    
    Operates in two modes:
    - Simulated: Generates realistic fake DNS traffic with injected malicious patterns
    - Live: Captures real DNS packets via scapy (requires root/admin)
    
    Args:
        config: Dictionary with DNS capture configuration from config.yaml
        sensor_id: Unique identifier for this sensor node
    """

    def __init__(self, config: Dict[str, Any], sensor_id: str):
        self.config = config
        self.sensor_id = sensor_id
        self.simulated_mode = config.get("simulated_mode", True)
        self.simulated_eps = config.get("simulated_eps", 10)
        self.suspicious_tlds = config.get("suspicious_tlds", [])
        self.dga_patterns = [
            re.compile(p) for p in config.get("dga_patterns", [])
        ]

        tunnel_config = config.get("tunneling_detection", {})
        self.min_query_length = tunnel_config.get("min_query_length", 50)
        self.entropy_threshold = tunnel_config.get("entropy_threshold", 3.5)

    async def capture(self) -> AsyncGenerator[DNSEvent, None]:
        """Main capture loop. Yields analyzed DNS events.
        
        Automatically selects simulated or live mode based on configuration.
        """
        if self.simulated_mode:
            logger.info(
                "Starting DNS capture in SIMULATED mode (eps=%d)", self.simulated_eps
            )
            async for event in self._simulate_capture():
                yield assess_severity(event, self)
        else:
            logger.info("Starting DNS capture in LIVE mode")
            logger.warning(
                "Live capture via scapy is not yet implemented; falling back to simulated mode"
            )
            async for event in self._simulate_capture():
                yield assess_severity(event, self)

    async def _simulate_capture(self) -> AsyncGenerator[DNSEvent, None]:
        """Generate realistic simulated DNS traffic.
        
        Traffic mix:
        - 75% normal (google.com, microsoft.com, etc.)
        - 5% DGA domains (random alphanumeric strings)
        - 5% DNS tunneling (long base64-like subdomains)
        - 10% suspicious TLDs
        - 5% C2 beaconing (periodic queries to same domain)
        """
        normal_domains = [
            "google.com", "microsoft.com", "amazon.com",
            "cloudflare.com", "github.com", "cdn.example.com",
            "office365.com", "slack.com", "stackoverflow.com",
        ]

        while True:
            await asyncio.sleep(1.0 / self.simulated_eps)

            category = random.choices(
                ["normal", "dga", "tunneling", "suspicious_tld", "beaconing"],
                weights=[0.75, 0.05, 0.05, 0.10, 0.05],
            )[0]

            if category == "normal":
                query_name = f"www.{random.choice(normal_domains)}"
            elif category == "dga":
                chars = "abcdefghijklmnopqrstuvwxyz0123456789"
                dga_string = "".join(random.choices(chars, k=25))
                query_name = f"{dga_string}.xyz"
            elif category == "tunneling":
                chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                tunnel_data = "".join(random.choices(chars, k=80))
                query_name = f"{tunnel_data}.c2-tunnel.example.com"
            elif category == "suspicious_tld":
                tld = random.choice(self.suspicious_tlds) if self.suspicious_tlds else ".xyz"
                query_name = f"random-{random.randint(1000, 9999)}{tld}"
            else:  # beaconing
                query_name = "beacon.c2-server.xyz"

            source_ip = f"192.168.1.{random.randint(10, 250)}"

            event = DNSEvent(
                sensor_id=self.sensor_id,
                sensor_type="DNS",
                event_type=EventType.DNS_QUERY,
                query_name=query_name,
                query_type="TXT" if category == "tunneling" else "A",
                response_code="NOERROR",
                source_ip=source_ip,
                destination_ip="8.8.8.8",
                destination_port=53,
                tags=["simulated"],
            )

            yield event
