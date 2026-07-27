import pytest
from junction_nodes.stream_processor.enrichment import GeoIPService, ThreatIntelService

class TestGeoIPService:
    def test_internal_ip_detection(self):
        svc = GeoIPService()
        assert svc.is_internal("192.168.1.100") is True
        assert svc.is_internal("10.0.0.1") is True
        assert svc.is_internal("8.8.8.8") is False
    
    def test_known_ip_lookup(self):
        svc = GeoIPService()
        result = svc.lookup("8.8.8.8")
        assert result is not None
        assert result.country_code == "US"
        assert result.as_org == "Google LLC"
    
    def test_unknown_ip_returns_generated_data(self):
        svc = GeoIPService()
        result = svc.lookup("203.0.113.50")
        assert result is not None
        assert result.ip == "203.0.113.50"
    
    def test_internal_ip_returns_none(self):
        svc = GeoIPService()
        result = svc.lookup("192.168.1.100")
        assert result is None  # Internal IPs don't have GeoIP

class TestThreatIntelService:
    def test_known_bad_domain(self):
        svc = ThreatIntelService()
        result = svc.check_domain("evil-c2-server.xyz")
        assert result is not None
        assert result.threat_type in ["c2", "malware", "C2", "Malware"]
    
    def test_clean_domain(self):
        svc = ThreatIntelService()
        result = svc.check_domain("google.com")
        assert result is None
    
    def test_subdomain_matching(self):
        """Should match parent domain even when subdomain is queried."""
        svc = ThreatIntelService()
        result = svc.check_domain("data.evil-c2-server.xyz")
        assert result is not None
    
    def test_check_event_with_dns_query(self):
        svc = ThreatIntelService()
        event = {
            "event_type": "DNS_QUERY",
            "source_ip": "192.168.1.100",
            "destination_ip": "8.8.8.8",
            "query_name": "beacon.c2-server.xyz",
        }
        matches = svc.check_event(event)
        # Should match the domain
        assert len(matches) >= 1
