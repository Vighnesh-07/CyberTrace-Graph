"""Unit tests for DNS capture analysis functions."""

import re
import pytest
from junction_nodes.dns_sensor.dns_capture import (
    calculate_entropy,
    check_dga,
    check_suspicious_tld,
    assess_severity,
    DNSCaptureEngine,
)
from junction_nodes.common.models.events import DNSEvent, EventType, SeverityLevel


class TestCalculateEntropy:
    def test_low_entropy_repeated_chars(self):
        """Repeated characters should have very low entropy."""
        assert calculate_entropy("aaaa") < 1.0

    def test_high_entropy_random_string(self):
        """Base64-like strings should have high entropy (> 3.5)."""
        assert calculate_entropy("aGVsbG8gd29ybGQ") > 3.0

    def test_empty_string_returns_zero(self):
        assert calculate_entropy("") == 0.0

    def test_single_char_returns_zero(self):
        assert calculate_entropy("a") == 0.0

    def test_two_unique_chars_balanced(self):
        """'abababab' has exactly 1 bit of entropy."""
        entropy = calculate_entropy("abababab")
        assert abs(entropy - 1.0) < 0.01


class TestCheckDGA:
    def test_dga_domain_matches(self):
        patterns = [re.compile(r"^[a-z]{15,}\.(com|net|org)$")]
        assert check_dga("abcdefghijklmnopqrstuvwxyz.com", patterns) is True

    def test_normal_domain_does_not_match(self):
        patterns = [re.compile(r"^[a-z]{15,}\.(com|net|org)$")]
        assert check_dga("google.com", patterns) is False

    def test_empty_patterns(self):
        assert check_dga("anything.com", []) is False


class TestCheckSuspiciousTLD:
    def test_suspicious_tld_detected(self):
        assert check_suspicious_tld("evil.xyz", [".xyz", ".tk"]) is True
        assert check_suspicious_tld("malware.tk", [".xyz", ".tk"]) is True

    def test_normal_tld_not_flagged(self):
        assert check_suspicious_tld("google.com", [".xyz", ".tk"]) is False
        assert check_suspicious_tld("github.org", [".xyz", ".tk"]) is False


class TestAssessSeverity:
    @pytest.fixture
    def engine(self):
        config = {
            "simulated_mode": True,
            "simulated_eps": 10,
            "suspicious_tlds": [".xyz", ".tk"],
            "dga_patterns": [r"^[a-z]{15,}\.(com|net|org)$"],
            "tunneling_detection": {
                "min_query_length": 50,
                "entropy_threshold": 3.5,
            },
        }
        return DNSCaptureEngine(config, "test-sensor")

    def test_normal_domain_is_low(self, engine):
        event = DNSEvent(
            sensor_id="test", sensor_type="DNS",
            query_name="www.google.com",
        )
        result = assess_severity(event, engine)
        assert result.severity == SeverityLevel.LOW

    def test_suspicious_tld_is_medium(self, engine):
        event = DNSEvent(
            sensor_id="test", sensor_type="DNS",
            query_name="random-1234.xyz",
        )
        result = assess_severity(event, engine)
        assert result.severity == SeverityLevel.MEDIUM
        assert "suspicious_tld" in result.tags

    def test_tunneling_is_high(self, engine):
        # Create a long, high-entropy subdomain
        long_subdomain = "aGVsbG93b3JsZHRoaXNpc2F0ZXN0b2ZkbnN0dW5uZWxpbmc" + "x" * 20
        event = DNSEvent(
            sensor_id="test", sensor_type="DNS",
            query_name=f"{long_subdomain}.c2.example.com",
        )
        result = assess_severity(event, engine)
        assert result.severity == SeverityLevel.HIGH
        assert result.mitre_tactic == "TA0011"
        assert "dns_tunneling" in result.tags
