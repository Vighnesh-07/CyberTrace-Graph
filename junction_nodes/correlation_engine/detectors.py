import logging
from typing import Optional

from junction_nodes.correlation_engine.graph_service import GraphService
from junction_nodes.correlation_engine.cypher_queries import CypherQueries

logger = logging.getLogger(__name__)

class GraphDetector:
    """Runs Cypher detection queries against the attack graph."""
    
    def __init__(self, graph_service: GraphService):
        self.graph = graph_service
    
    def _run_query(self, query: str, params: dict = None) -> list[dict]:
        """Execute a Cypher query and return results as list of dicts."""
        with self.graph._driver.session() as session:
            result = session.run(query, **(params or {}))
            return [dict(record) for record in result]
    
    def detect_kill_chains(self) -> list[dict]:
        """Find internal IPs showing kill chain patterns."""
        results = self._run_query(CypherQueries.KILL_CHAIN_DETECTION)
        if results:
            logger.warning(f"🔴 Kill chain patterns detected: {len(results)} IPs")
        return results
    
    def detect_lateral_movement(self) -> list[dict]:
        """Find users authenticating to multiple hosts."""
        results = self._run_query(CypherQueries.LATERAL_MOVEMENT)
        if results:
            logger.warning(f"🟠 Lateral movement detected: {len(results)} users")
        return results
    
    def detect_c2_infrastructure(self) -> list[dict]:
        """Find domains used as C2 by multiple internal IPs."""
        results = self._run_query(CypherQueries.C2_INFRASTRUCTURE)
        if results:
            logger.warning(f"🔴 C2 infrastructure detected: {len(results)} domains")
        return results
    
    def detect_dga_clusters(self) -> list[dict]:
        """Find IPs querying clusters of DGA-like domains."""
        results = self._run_query(CypherQueries.DGA_CLUSTER_DETECTION)
        if results:
            logger.warning(f"🟡 DGA clusters detected: {len(results)} IPs")
        return results
    
    def get_attack_timeline(self, ip: str) -> list[dict]:
        """Get the full attack timeline for a specific IP."""
        return self._run_query(CypherQueries.ATTACK_TIMELINE, {"target_ip": ip})
    
    def run_all_detections(self) -> dict:
        """Run all detection queries and return combined results."""
        logger.info("Running all graph-based detections...")
        results = {
            "kill_chains": self.detect_kill_chains(),
            "lateral_movement": self.detect_lateral_movement(),
            "c2_infrastructure": self.detect_c2_infrastructure(),
            "dga_clusters": self.detect_dga_clusters(),
        }
        total = sum(len(v) for v in results.values())
        logger.info(f"Detection complete. {total} total findings.")
        return results
