"""Unit tests for the DNS Tunneling attack scenario simulator."""

import pytest
from junction_nodes.common.models.events import SeverityLevel
from junction_nodes.dns_sensor.dns_capture import calculate_entropy
from attack_simulator.scenarios.dns_tunneling import DNSTunnelingScenario


class TestDNSTunnelingScenario:
    @pytest.fixture
    def scenario(self):
        return DNSTunnelingScenario(
            sensor_id="test-sim",
            c2_domain="data.evil-c2-server.xyz",
        )

    def test_generates_events(self, scenario):
        """Should generate a non-empty list of events."""
        events = scenario.generate_events(duration_seconds=60, beacon_interval=5.0)
        assert len(events) > 0

    def test_contains_both_normal_and_malicious(self, scenario):
        """Events should be a mix of normal and malicious traffic."""
        events = scenario.generate_events(duration_seconds=300)
        severities = {e.severity for e in events}
        # Should have at least LOW (normal) and something higher (malicious)
        assert SeverityLevel.LOW in severities
        assert len(severities) > 1  # Not all the same severity

    def test_malicious_events_have_mitre_tags(self, scenario):
        """Malicious events should have MITRE ATT&CK tactic/technique set."""
        events = scenario.generate_events(duration_seconds=300)
        malicious = [e for e in events if e.severity != SeverityLevel.LOW]
        assert len(malicious) > 0
        for event in malicious:
            assert event.mitre_tactic is not None
            assert event.mitre_technique is not None

    def test_exfil_payloads_have_high_entropy(self, scenario):
        """Encoded payloads in tunneling queries should have entropy > 3.5."""
        events = scenario.generate_events(duration_seconds=300)
        tunneling_events = [
            e for e in events if "dns_tunneling" in (e.tags or [])
        ]
        assert len(tunneling_events) > 0
        for event in tunneling_events:
            # Extract the subdomain (everything before the C2 domain)
            subdomain = event.query_name.replace(f".{scenario.c2_domain}", "")
            entropy = calculate_entropy(subdomain)
            assert entropy > 3.0, f"Expected high entropy for '{subdomain}', got {entropy}"

    def test_event_count_scales_with_duration(self, scenario):
        """Longer duration should produce more events."""
        short = scenario.generate_events(duration_seconds=60, beacon_interval=5.0)
        long = scenario.generate_events(duration_seconds=300, beacon_interval=5.0)
        assert len(long) > len(short)

    def test_phase3_has_higher_severity(self, scenario):
        """Phase 3 events (accelerated exfil) should have CRITICAL severity."""
        events = scenario.generate_events(duration_seconds=300, beacon_interval=5.0)
        critical_events = [e for e in events if e.severity == SeverityLevel.CRITICAL]
        assert len(critical_events) > 0
