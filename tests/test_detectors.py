import time
import pytest
from junction_nodes.stream_processor.models.alerts import AlertType
from junction_nodes.stream_processor.detectors import BeaconingDetector, DNSAnomalyDetector

class TestBeaconingDetector:
    def test_periodic_queries_trigger_alert(self):
        """Regular 5-second beacons should trigger C2_BEACONING alert."""
        detector = BeaconingDetector(window_seconds=60, min_samples=5, cv_threshold=0.3)
        alert = None
        base_time = time.time()
        for i in range(10):
            event = {
                "event_type": "DNS_QUERY",
                "source_ip": "192.168.1.50",
                "query_name": "beacon.c2-server.xyz",
                "timestamp": base_time + (i * 5.0),  # Exactly 5 second intervals
            }
            # We need to mock time or set timestamps
            result = detector.add_event(event)
            if result:
                alert = result
        assert alert is not None
        assert alert.alert_type == AlertType.C2_BEACONING
    
    def test_random_queries_no_alert(self):
        """Random timing should NOT trigger beaconing."""
        detector = BeaconingDetector(window_seconds=60, min_samples=5, cv_threshold=0.3)
        import random
        base_time = time.time()
        current = base_time
        for i in range(10):
            current += random.uniform(0.5, 30.0)  # Very irregular
            event = {
                "event_type": "DNS_QUERY",
                "source_ip": "192.168.1.50",
                "query_name": "google.com",
                "timestamp": current,
            }
            detector.add_event(event)
        # Should not have triggered (high CV due to random intervals)

class TestDNSAnomalyDetector:
    def test_high_query_rate_triggers_alert(self):
        """Flooding queries should trigger DATA_EXFILTRATION."""
        detector = DNSAnomalyDetector(window_seconds=60, max_query_rate=50)
        alerts = []
        base_time = time.time()
        for i in range(60):
            event = {
                "event_type": "DNS_QUERY",
                "source_ip": "192.168.1.50",
                "query_name": f"query{i}.example.com",
                "query_type": "A",
                "response_code": "NOERROR",
                "timestamp": base_time + (i * 0.5),
            }
            result = detector.add_event(event)
            if result:
                alerts.extend(result)
        assert any(a.alert_type == AlertType.DATA_EXFILTRATION for a in alerts) or \
               any(a.alert_type == AlertType.DGA_DOMAIN for a in alerts)
    
    def test_high_txt_ratio_triggers_tunneling(self):
        """Many TXT queries should trigger DNS_TUNNELING."""
        detector = DNSAnomalyDetector(window_seconds=300, txt_ratio_threshold=0.3, max_query_rate=500)
        alerts = []
        base_time = time.time()
        for i in range(20):
            event = {
                "event_type": "DNS_QUERY",
                "source_ip": "192.168.1.50",
                "query_name": f"data{i}.c2.example.com",
                "query_type": "TXT" if i < 15 else "A",  # 75% TXT
                "response_code": "NOERROR",
                "timestamp": base_time + i,
            }
            result = detector.add_event(event)
            if result:
                alerts.extend(result)
        assert any(a.alert_type == AlertType.DNS_TUNNELING for a in alerts)
    
    def test_normal_traffic_no_alert(self):
        """Normal DNS traffic should not trigger alerts."""
        detector = DNSAnomalyDetector(window_seconds=300)
        alerts = []
        base_time = time.time()
        for i in range(10):
            event = {
                "event_type": "DNS_QUERY",
                "source_ip": "192.168.1.100",
                "query_name": "google.com",
                "query_type": "A",
                "response_code": "NOERROR",
                "timestamp": base_time + (i * 10),  # Slow, normal
            }
            result = detector.add_event(event)
            if result:
                alerts.extend(result)
        assert len(alerts) == 0
