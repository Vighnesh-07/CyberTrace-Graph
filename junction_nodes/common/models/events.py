from enum import Enum
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
from uuid import uuid4
from typing import Optional

def utcnow():
    return datetime.now(timezone.utc)

class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EventType(str, Enum):
    DNS_QUERY = "DNS_QUERY"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    PROCESS_CREATION = "PROCESS_CREATION"
    FILE_ACCESS = "FILE_ACCESS"
    AUTH_LOGIN = "AUTH_LOGIN"
    AUTH_FAILURE = "AUTH_FAILURE"
    REGISTRY_CHANGE = "REGISTRY_CHANGE"
    CLOUD_API_CALL = "CLOUD_API_CALL"
    HEARTBEAT = "HEARTBEAT"

class SecurityEvent(BaseModel):
    """Base event that all sensor events inherit from."""
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: EventType
    timestamp: datetime = Field(default_factory=utcnow)
    sensor_id: str
    sensor_type: str
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    hostname: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.LOW
    raw_data: dict = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    mitre_tactic: Optional[str] = None  # e.g., "TA0011" (C2)
    mitre_technique: Optional[str] = None  # e.g., "T1071.004" (DNS)
    confidence_score: float = Field(0.0, description="0.0 to 1.0 confidence score", ge=0.0, le=1.0)

    def to_kafka_value(self) -> bytes:
        return self.model_dump_json().encode('utf-8')

    def to_kafka_key(self) -> bytes:
        return (self.source_ip or self.sensor_id).encode('utf-8')

class DNSEvent(SecurityEvent):
    """DNS query/response event."""
    event_type: EventType = EventType.DNS_QUERY
    query_name: str
    query_type: str = "A"
    response_code: Optional[str] = None
    response_ips: list[str] = Field(default_factory=list)
    query_size: int = 0
    response_size: int = 0
    is_recursive: bool = True
    dns_server: Optional[str] = None

class NetworkEvent(SecurityEvent):
    """Network connection event."""
    event_type: EventType = EventType.NETWORK_CONNECTION
    protocol: str = "TCP"
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    connection_state: Optional[str] = None
    duration_ms: int = 0

class AuthEvent(SecurityEvent):
    """Authentication event."""
    event_type: EventType = EventType.AUTH_LOGIN
    username: str = ""
    auth_method: str = ""
    success: bool = True
    failure_reason: Optional[str] = None
    target_host: Optional[str] = None
    privilege_level: Optional[str] = None

class ProcessEvent(SecurityEvent):
    """Process creation/execution event."""
    event_type: EventType = EventType.PROCESS_CREATION
    process_name: str = ""
    process_id: int = 0
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    user: Optional[str] = None

class HeartbeatEvent(SecurityEvent):
    """Junction Node health check."""
    event_type: EventType = EventType.HEARTBEAT
    uptime_seconds: float = 0.0
    events_processed: int = 0
    events_dropped: int = 0
    buffer_usage_percent: float = 0.0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
