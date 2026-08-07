import pytest
from neo4j import GraphDatabase
from junction_nodes.common.config import Neo4jConfig
from junction_nodes.correlation_engine.graph_service import GraphService
from junction_nodes.correlation_engine.detectors import GraphDetector

def is_neo4j_available():
    try:
        config = Neo4jConfig()
        driver = GraphDatabase.driver(config.uri, auth=(config.user, config.password))
        driver.verify_connectivity()
        driver.close()
        return True
    except Exception:
        return False

pytestmark = pytest.mark.skipif(not is_neo4j_available(), reason="Neo4j not available")

@pytest.fixture(scope="class")
def detector_env():
    """Set up a graph with a known attack scenario."""
    config = Neo4jConfig()
    gs = GraphService(config)
    gs.initialize_schema()
    # Clear
    with gs._driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
    gs.initialize_schema()
    
    # ── Seed a simulated attack ──
    # Two internal IPs querying a suspicious DGA domain
    gs.upsert_ip("192.168.1.10", is_internal=True)
    gs.upsert_ip("192.168.1.20", is_internal=True)
    gs.upsert_domain("xjk3mq9z.evil.com", entropy=4.5, is_dga=True)
    gs.upsert_domain("abc123xyz.evil.com", entropy=4.2, is_dga=True)
    gs.upsert_domain("qwerty789.evil.com", entropy=4.0, is_dga=True)
    gs.upsert_domain("rnd999abc.evil.com", entropy=4.1, is_dga=True)
    gs.upsert_domain("zzzyyy888.evil.com", entropy=4.3, is_dga=True)
    
    # IP 1 queries all DGA domains
    for domain in ["xjk3mq9z.evil.com", "abc123xyz.evil.com", "qwerty789.evil.com", "rnd999abc.evil.com", "zzzyyy888.evil.com"]:
        gs.create_relationship("IPAddress", "ip", "192.168.1.10", "Domain", "name", domain, "QUERIED", {"query_type": "TXT"})
    # IP 2 queries some of them
    for domain in ["xjk3mq9z.evil.com", "abc123xyz.evil.com"]:
        gs.create_relationship("IPAddress", "ip", "192.168.1.20", "Domain", "name", domain, "QUERIED", {"query_type": "A"})
    
    # Alerts for both IPs
    gs.ingest_alert({
        "alert_id": "det-alert-001", "alert_type": "DGA_DOMAIN", "severity": "HIGH",
        "confidence_score": 0.9, "title": "DGA detected", "description": "...",
        "timestamp": "2024-01-01T01:00:00Z", "source_ip": "192.168.1.10",
        "mitre_technique": "T1568", "status": "OPEN", "evidence": {"domain": "xjk3mq9z.evil.com"}
    })
    gs.ingest_alert({
        "alert_id": "det-alert-002", "alert_type": "C2_BEACONING", "severity": "HIGH",
        "confidence_score": 0.95, "title": "Beaconing", "description": "...",
        "timestamp": "2024-01-01T01:05:00Z", "source_ip": "192.168.1.10",
        "mitre_technique": "T1071", "status": "OPEN", "evidence": {"domain": "xjk3mq9z.evil.com"}
    })
    gs.ingest_alert({
        "alert_id": "det-alert-003", "alert_type": "DNS_TUNNELING", "severity": "HIGH",
        "confidence_score": 0.85, "title": "DNS Tunneling", "description": "...",
        "timestamp": "2024-01-01T02:00:00Z", "source_ip": "192.168.1.20",
        "mitre_technique": "T1071.004", "status": "OPEN", "evidence": {"domain": "abc123xyz.evil.com"}
    })
    
    # Lateral movement: a user authenticating to multiple hosts
    gs.upsert_user("admin_user", privilege_level="admin")
    gs.upsert_host("server-web-01")
    gs.upsert_host("server-db-01")
    gs.upsert_host("server-dc-01")
    gs.create_relationship("User", "username", "admin_user", "Host", "hostname", "server-web-01", "AUTHENTICATED_TO", {"success": True, "auth_method": "ssh"})
    gs.create_relationship("User", "username", "admin_user", "Host", "hostname", "server-db-01", "AUTHENTICATED_TO", {"success": True, "auth_method": "rdp"})
    gs.create_relationship("User", "username", "admin_user", "Host", "hostname", "server-dc-01", "AUTHENTICATED_TO", {"success": False, "auth_method": "ssh"})
    
    detector = GraphDetector(gs)
    yield detector, gs
    gs.close()

class TestGraphDetector:
    def test_detect_kill_chains(self, detector_env):
        detector, gs = detector_env
        results = detector.detect_kill_chains()
        assert len(results) >= 1
        ips = [r["source_ip"] for r in results]
        assert "192.168.1.10" in ips  # Has DGA queries + 2 alerts
    
    def test_detect_c2_infrastructure(self, detector_env):
        detector, gs = detector_env
        results = detector.detect_c2_infrastructure()
        assert len(results) >= 1
        domains = [r["domain"] for r in results]
        # xjk3mq9z.evil.com is queried by both IPs
        assert "xjk3mq9z.evil.com" in domains
    
    def test_detect_dga_clusters(self, detector_env):
        detector, gs = detector_env
        results = detector.detect_dga_clusters()
        assert len(results) >= 1
        # 192.168.1.10 queries 5 DGA domains
        ips = [r["source_ip"] for r in results]
        assert "192.168.1.10" in ips
    
    def test_detect_lateral_movement(self, detector_env):
        detector, gs = detector_env
        results = detector.detect_lateral_movement()
        assert len(results) >= 1
        users = [r["username"] for r in results]
        assert "admin_user" in users
    
    def test_get_attack_timeline(self, detector_env):
        detector, gs = detector_env
        timeline = detector.get_attack_timeline("192.168.1.10")
        assert len(timeline) >= 1  # Should have QUERIED and TRIGGERED relationships
    
    def test_run_all_detections(self, detector_env):
        detector, gs = detector_env
        results = detector.run_all_detections()
        assert "kill_chains" in results
        assert "lateral_movement" in results
        assert "c2_infrastructure" in results
        assert "dga_clusters" in results
