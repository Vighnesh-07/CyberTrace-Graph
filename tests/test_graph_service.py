import pytest
from neo4j import GraphDatabase
from junction_nodes.common.config import Neo4jConfig
from junction_nodes.correlation_engine.graph_service import GraphService

# Skip all tests if Neo4j is not available
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
def graph_service():
    config = Neo4jConfig()
    gs = GraphService(config)
    gs.initialize_schema()
    # Clear the graph before tests
    with gs._driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
    gs.initialize_schema()  # Re-seed MITRE nodes
    yield gs
    gs.close()

class TestGraphService:
    def test_initialize_schema_creates_constraints(self, graph_service):
        """Schema initialization should create constraints."""
        with graph_service._driver.session() as session:
            result = session.run("SHOW CONSTRAINTS")
            constraints = [dict(r) for r in result]
        assert len(constraints) >= 5  # At least our 6 constraints
    
    def test_upsert_ip_creates_node(self, graph_service):
        graph_service.upsert_ip("192.168.1.100", is_internal=True)
        with graph_service._driver.session() as session:
            result = session.run("MATCH (n:IPAddress {ip: '192.168.1.100'}) RETURN n")
            records = list(result)
        assert len(records) == 1
        assert records[0]["n"]["is_internal"] == True
    
    def test_upsert_ip_is_idempotent(self, graph_service):
        """Upserting the same IP twice should not create duplicates."""
        graph_service.upsert_ip("10.0.0.1", is_internal=True)
        graph_service.upsert_ip("10.0.0.1", is_internal=True)
        with graph_service._driver.session() as session:
            result = session.run("MATCH (n:IPAddress {ip: '10.0.0.1'}) RETURN count(n) AS c")
            count = result.single()["c"]
        assert count == 1
    
    def test_upsert_domain_creates_node(self, graph_service):
        graph_service.upsert_domain("evil-c2.xyz", entropy=4.2, is_dga=True)
        with graph_service._driver.session() as session:
            result = session.run("MATCH (n:Domain {name: 'evil-c2.xyz'}) RETURN n")
            records = list(result)
        assert len(records) == 1
        assert records[0]["n"]["is_dga"] == True
    
    def test_create_relationship(self, graph_service):
        graph_service.upsert_ip("192.168.1.50")
        graph_service.upsert_domain("test-domain.com")
        graph_service.create_relationship(
            "IPAddress", "ip", "192.168.1.50",
            "Domain", "name", "test-domain.com",
            "QUERIED",
            {"query_type": "A"}
        )
        with graph_service._driver.session() as session:
            result = session.run(
                "MATCH (ip:IPAddress {ip: '192.168.1.50'})-[r:QUERIED]->(d:Domain {name: 'test-domain.com'}) RETURN r"
            )
            records = list(result)
        assert len(records) >= 1
    
    def test_ingest_enriched_dns_event(self, graph_service):
        event = {
            "event_type": "DNS_QUERY",
            "event_id": "test-evt-001",
            "source_ip": "192.168.1.200",
            "destination_ip": "8.8.8.8",
            "sensor_id": "dns-sensor-01",
            "timestamp": "2024-01-01T00:00:00Z",
            "severity": "LOW",
            "is_internal_ip": True,
            "source_geo": {"country_code": "LOCAL"},
            "destination_geo": {"country_code": "US", "as_org": "Google LLC"},
            "threat_intel_matches": [],
            "original_event": {
                "query_name": "suspicious-domain.xyz",
                "query_type": "TXT",
                "response_code": "NOERROR",
                "response_ips": ["1.2.3.4"],
            }
        }
        graph_service.ingest_enriched_event(event)
        
        # Should have created: source IP, dest IP, domain, QUERIED relationship, RESOLVED_TO
        with graph_service._driver.session() as session:
            # Check IP nodes
            result = session.run("MATCH (n:IPAddress {ip: '192.168.1.200'}) RETURN n")
            assert len(list(result)) == 1
            
            # Check domain node
            result = session.run("MATCH (n:Domain {name: 'suspicious-domain.xyz'}) RETURN n")
            assert len(list(result)) == 1
            
            # Check QUERIED relationship
            result = session.run(
                "MATCH (:IPAddress {ip: '192.168.1.200'})-[:QUERIED]->(:Domain {name: 'suspicious-domain.xyz'}) RETURN count(*) AS c"
            )
            assert result.single()["c"] >= 1
    
    def test_ingest_alert_creates_node_and_relationships(self, graph_service):
        alert = {
            "alert_id": "alert-test-001",
            "alert_type": "C2_BEACONING",
            "severity": "HIGH",
            "confidence_score": 0.95,
            "title": "Beaconing Detected",
            "description": "Periodic connections to evil domain",
            "timestamp": "2024-01-01T00:05:00Z",
            "source_ip": "192.168.1.200",
            "mitre_technique": "T1071",
            "status": "OPEN",
            "evidence": {"domain": "suspicious-domain.xyz", "cv": 0.05},
            "tags": ["beaconing"]
        }
        graph_service.ingest_alert(alert)
        
        with graph_service._driver.session() as session:
            # Alert node exists
            result = session.run("MATCH (a:Alert {alert_id: 'alert-test-001'}) RETURN a")
            records = list(result)
            assert len(records) == 1
            assert records[0]["a"]["alert_type"] == "C2_BEACONING"
            
            # TRIGGERED relationship exists
            result = session.run(
                "MATCH (:IPAddress {ip: '192.168.1.200'})-[:TRIGGERED]->(:Alert {alert_id: 'alert-test-001'}) RETURN count(*) AS c"
            )
            assert result.single()["c"] >= 1
            
            # MAPS_TO MITRE relationship exists
            result = session.run(
                "MATCH (:Alert {alert_id: 'alert-test-001'})-[:MAPS_TO]->(:MitreAttack {technique_id: 'T1071'}) RETURN count(*) AS c"
            )
            assert result.single()["c"] >= 1
    
    def test_get_stats(self, graph_service):
        stats = graph_service.get_stats()
        assert "nodes" in stats
        assert "relationships" in stats
        assert "internal_stats" in stats
