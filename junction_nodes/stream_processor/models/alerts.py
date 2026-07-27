from enum import Enum
from typing import Optional
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field

from junction_nodes.common.models.events import SeverityLevel

class AlertType(str, Enum):
    DNS_TUNNELING = "DNS_TUNNELING"
    DGA_DOMAIN = "DGA_DOMAIN"
    C2_BEACONING = "C2_BEACONING"
    BRUTE_FORCE = "BRUTE_FORCE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    ANOMALY = "ANOMALY"

class ThreatIntelMatch(BaseModel):
    """Result of a threat intelligence feed lookup."""
    indicator: str              # The matched IOC (IP, domain, hash)
    indicator_type: str         # ip, domain, hash
    feed_name: str              # Feed source name
    threat_type: str            # malware, c2, phishing, etc.
    confidence: float = 0.0     # 0.0 to 1.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    reference_url: Optional[str] = None

class GeoIPInfo(BaseModel):
    """GeoIP enrichment data."""
    ip: str
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    as_org: Optional[str] = None
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False

class EnrichedEvent(BaseModel):
    """A SecurityEvent enriched with threat intel and GeoIP data."""
    original_event: dict           # The raw SecurityEvent as dict
    event_id: str
    event_type: str
    timestamp: datetime
    sensor_id: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    severity: str
    tags: list[str] = Field(default_factory=list)
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence_score: float = 0.0
    # Enrichment fields
    source_geo: Optional[GeoIPInfo] = None
    destination_geo: Optional[GeoIPInfo] = None
    threat_intel_matches: list[ThreatIntelMatch] = Field(default_factory=list)
    is_internal_ip: bool = False
    enrichment_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_kafka_value(self) -> bytes:
        return self.model_dump_json().encode('utf-8')

    def to_kafka_key(self) -> bytes:
        return (self.source_ip or self.sensor_id).encode('utf-8')

class AlertEvent(BaseModel):
    """An alert produced by the detection pipeline."""
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    alert_type: AlertType
    title: str
    description: str
    severity: SeverityLevel
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    related_event_ids: list[str] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)  # Supporting data for the alert
    tags: list[str] = Field(default_factory=list)
    status: str = "OPEN"  # OPEN, ACKNOWLEDGED, INVESTIGATING, CLOSED

    def to_kafka_value(self) -> bytes:
        return self.model_dump_json().encode('utf-8')

    def to_kafka_key(self) -> bytes:
        return (self.source_ip or self.alert_id).encode('utf-8')
