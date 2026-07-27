import pytest
from junction_nodes.stream_processor.pipeline import ProcessingPipeline
from junction_nodes.common.config import KafkaConfig

class TestProcessingPipeline:
    @pytest.fixture
    def pipeline(self):
        """Create a pipeline for testing (won't connect to Kafka in enrichment-only tests)."""
        config = KafkaConfig()
        processor_config = {
            "processor": {"group_id": "test-group"},
            "input_topics": ["apt.events.dns"],
            "output_topics": {"alerts": "apt.alerts.raw", "enriched": "apt.events.enriched"},
            "detectors": {
                "beaconing": {"window_seconds": 60, "min_samples": 5, "cv_threshold": 0.3},
                "dns_anomaly": {"window_seconds": 60, "max_unique_domains": 50, "max_query_rate": 100},
            },
        }
        return ProcessingPipeline(config, processor_config)
    
    def test_enrich_adds_geoip(self, pipeline):
        event = {
            "event_id": "test-123",
            "event_type": "DNS_QUERY",
            "timestamp": "2024-01-01T00:00:00Z",
            "sensor_id": "dns-sensor-01",
            "source_ip": "192.168.1.100",
            "destination_ip": "8.8.8.8",
            "severity": "LOW",
            "tags": [],
            "confidence_score": 0.1,
            "query_name": "google.com",
        }
        enriched = pipeline.enrich_event(event)
        assert enriched.is_internal_ip is True
        assert enriched.destination_geo is not None
        assert enriched.destination_geo.country_code == "US"
    
    def test_enrich_adds_threat_intel(self, pipeline):
        event = {
            "event_id": "test-456",
            "event_type": "DNS_QUERY",
            "timestamp": "2024-01-01T00:00:00Z",
            "sensor_id": "dns-sensor-01",
            "source_ip": "192.168.1.50",
            "destination_ip": "8.8.8.8",
            "severity": "LOW",
            "tags": [],
            "confidence_score": 0.1,
            "query_name": "evil-c2-server.xyz",
        }
        enriched = pipeline.enrich_event(event)
        assert len(enriched.threat_intel_matches) > 0
    
    def test_detect_returns_alerts_for_suspicious_dns(self, pipeline):
        """Run many suspicious DNS events to trigger detection."""
        import time
        base_time = time.time()
        alerts = []
        for i in range(60):
            event = {
                "event_type": "DNS_QUERY",
                "source_ip": "192.168.1.50",
                "query_name": f"query{i}.evil.xyz",
                "query_type": "TXT",
                "response_code": "NOERROR",
                "timestamp": base_time + i,
            }
            result = pipeline.detect(event)
            alerts.extend(result)
        assert len(alerts) > 0
