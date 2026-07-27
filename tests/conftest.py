"""Shared pytest fixtures for the CyberTrace-Graph test suite."""

import pytest
from junction_nodes.common.models.events import (
    DNSEvent, NetworkEvent, AuthEvent,
    EventType, SeverityLevel,
)
from junction_nodes.common.config import KafkaConfig


@pytest.fixture
def sample_dns_event():
    """A normal, benign DNS event."""
    return DNSEvent(
        sensor_id="test-sensor",
        sensor_type="DNS",
        event_type=EventType.DNS_QUERY,
        severity=SeverityLevel.LOW,
        confidence_score=0.05,
        source_ip="192.168.1.100",
        destination_ip="8.8.8.8",
        destination_port=53,
        query_name="google.com",
        query_type="A",
        response_code="NOERROR",
    )


@pytest.fixture
def sample_network_event():
    """A normal network connection event."""
    return NetworkEvent(
        sensor_id="test-sensor",
        sensor_type="NETWORK",
        event_type=EventType.NETWORK_CONNECTION,
        severity=SeverityLevel.LOW,
        confidence_score=0.05,
        source_ip="192.168.1.100",
        source_port=12345,
        destination_ip="8.8.8.8",
        destination_port=443,
        protocol="TCP",
        bytes_sent=1024,
        bytes_received=2048,
    )


@pytest.fixture
def sample_auth_event():
    """A successful SSH authentication event."""
    return AuthEvent(
        sensor_id="test-sensor",
        sensor_type="AUTH",
        event_type=EventType.AUTH_LOGIN,
        severity=SeverityLevel.LOW,
        confidence_score=0.05,
        username="admin",
        source_ip="192.168.1.100",
        destination_ip="192.168.1.10",
        auth_method="ssh",
        success=True,
    )


@pytest.fixture
def suspicious_dns_event():
    """A DNS event with a high-entropy subdomain (potential tunneling)."""
    return DNSEvent(
        sensor_id="test-sensor",
        sensor_type="DNS",
        event_type=EventType.DNS_QUERY,
        severity=SeverityLevel.HIGH,
        confidence_score=0.8,
        source_ip="192.168.1.100",
        destination_ip="8.8.8.8",
        destination_port=53,
        query_name="aGVsbG8gd29ybGQ.evil.xyz",
        query_type="TXT",
        response_code="NOERROR",
        mitre_tactic="TA0010",
        mitre_technique="T1048.003",
    )


@pytest.fixture
def kafka_config():
    """A KafkaConfig pointing to localhost for testing."""
    return KafkaConfig(bootstrap_servers="localhost:9092")
