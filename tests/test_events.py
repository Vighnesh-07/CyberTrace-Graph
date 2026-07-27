"""Unit tests for event models (SecurityEvent, DNSEvent, etc.)."""

import json
from uuid import UUID
from datetime import datetime

import pytest
from pydantic import ValidationError

from junction_nodes.common.models.events import (
    SecurityEvent, DNSEvent, EventType, SeverityLevel,
)


def test_dns_event_creation(sample_dns_event):
    """DNSEvent should be created with correct field values."""
    assert sample_dns_event.sensor_id == "test-sensor"
    assert sample_dns_event.event_type == EventType.DNS_QUERY
    assert sample_dns_event.query_name == "google.com"
    assert sample_dns_event.severity == SeverityLevel.LOW


def test_confidence_score_must_be_between_0_and_1():
    """confidence_score > 1.0 or < 0.0 should raise ValidationError."""
    with pytest.raises(ValidationError):
        DNSEvent(
            sensor_id="test",
            sensor_type="DNS",
            event_type=EventType.DNS_QUERY,
            confidence_score=1.5,  # Too high
            query_name="test.com",
        )
    with pytest.raises(ValidationError):
        DNSEvent(
            sensor_id="test",
            sensor_type="DNS",
            event_type=EventType.DNS_QUERY,
            confidence_score=-0.1,  # Too low
            query_name="test.com",
        )


def test_event_id_is_auto_generated_uuid(sample_dns_event):
    """event_id should be a valid UUID string, auto-generated."""
    assert sample_dns_event.event_id is not None
    assert isinstance(sample_dns_event.event_id, str)
    # Should parse as a valid UUID
    UUID(sample_dns_event.event_id)


def test_timestamp_is_auto_set(sample_dns_event):
    """timestamp should be auto-set to a datetime."""
    assert sample_dns_event.timestamp is not None
    assert isinstance(sample_dns_event.timestamp, datetime)


def test_enum_values():
    """EventType and SeverityLevel enum values should match their string definitions."""
    assert EventType.DNS_QUERY.value == "DNS_QUERY"
    assert EventType.HEARTBEAT.value == "HEARTBEAT"
    assert SeverityLevel.CRITICAL.value == "CRITICAL"
    assert SeverityLevel.LOW.value == "LOW"


def test_to_kafka_value_serialization(sample_dns_event):
    """to_kafka_value() should return valid JSON bytes."""
    kafka_val = sample_dns_event.to_kafka_value()
    assert isinstance(kafka_val, bytes)
    parsed = json.loads(kafka_val.decode("utf-8"))
    assert parsed["sensor_id"] == "test-sensor"
    assert parsed["query_name"] == "google.com"


def test_to_kafka_key(sample_dns_event):
    """to_kafka_key() should use source_ip as partition key."""
    key = sample_dns_event.to_kafka_key()
    assert key == b"192.168.1.100"


def test_to_kafka_key_falls_back_to_sensor_id():
    """When source_ip is None, to_kafka_key() should use sensor_id."""
    event = DNSEvent(
        sensor_id="fallback-sensor",
        sensor_type="DNS",
        event_type=EventType.DNS_QUERY,
        query_name="test.com",
        # No source_ip set
    )
    assert event.to_kafka_key() == b"fallback-sensor"


def test_model_dump_json_roundtrip(sample_dns_event):
    """model_dump_json() output should be valid JSON that deserializes back."""
    json_str = sample_dns_event.model_dump_json()
    parsed = json.loads(json_str)
    assert parsed["sensor_id"] == "test-sensor"
    assert parsed["event_type"] == "DNS_QUERY"
    assert "event_id" in parsed
    assert "timestamp" in parsed


def test_dns_event_inherits_security_event(sample_dns_event):
    """DNSEvent should be a subclass of SecurityEvent."""
    assert isinstance(sample_dns_event, SecurityEvent)
