"""
Neo4j client for the CyberTrace-Graph Dashboard API.

Provides query methods for the dashboard to fetch graph data,
alerts, detections, and topology information from Neo4j.
"""

import logging
from typing import Optional
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


class Neo4jClient:
    def __init__(self, uri: str = "bolt://localhost:7687", user: str = "neo4j", password: str = "apthunter2024"):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        logger.info(f"Neo4j client connected to {uri}")

    def close(self):
        self._driver.close()

    def _run_query(self, query: str, params: dict = None) -> list[dict]:
        with self._driver.session() as session:
            result = session.run(query, **(params or {}))
            return [dict(record) for record in result]

    def get_stats(self) -> dict:
        """Get node and relationship counts."""
        nodes = self._run_query("MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC")
        rels = self._run_query("MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS count ORDER BY count DESC")
        return {
            "nodes": {r["label"]: r["count"] for r in nodes},
            "relationships": {r["type"]: r["count"] for r in rels},
        }

    def get_alerts(self, limit: int = 50, severity: str = None, status: str = None) -> list[dict]:
        """Fetch alert nodes from the graph."""
        query = "MATCH (a:Alert) "
        conditions = []
        params = {"limit": limit}
        if severity:
            conditions.append("a.severity = $severity")
            params["severity"] = severity
        if status:
            conditions.append("a.status = $status")
            params["status"] = status
        if conditions:
            query += "WHERE " + " AND ".join(conditions) + " "
        query += "RETURN a ORDER BY a.timestamp DESC LIMIT $limit"
        results = self._run_query(query, params)
        return [dict(r["a"]) for r in results]

    def get_alert_by_id(self, alert_id: str) -> Optional[dict]:
        """Get a single alert with its relationships."""
        results = self._run_query(
            "MATCH (a:Alert {alert_id: $aid}) "
            "OPTIONAL MATCH (a)-[r]->(target) "
            "RETURN a, collect({type: type(r), target: labels(target)[0], props: properties(target)}) AS related",
            {"aid": alert_id},
        )
        if not results:
            return None
        row = results[0]
        alert = dict(row["a"])
        alert["related_entities"] = [r for r in row["related"] if r["target"] is not None]
        return alert

    def update_alert_status(self, alert_id: str, new_status: str) -> bool:
        """Update the status of an alert node."""
        results = self._run_query(
            "MATCH (a:Alert {alert_id: $aid}) SET a.status = $status RETURN a",
            {"aid": alert_id, "status": new_status},
        )
        return len(results) > 0

    def get_topology(self, limit: int = 200) -> dict:
        """Get a lightweight node/edge list for graph visualization."""
        results = self._run_query(
            "MATCH (a)-[r]->(b) "
            "WHERE (a:IPAddress OR a:Domain OR a:Alert) AND (b:IPAddress OR b:Domain OR b:Alert) "
            "RETURN elementId(a) AS source, labels(a)[0] AS source_label, properties(a) AS source_props, "
            "       elementId(b) AS target, labels(b)[0] AS target_label, properties(b) AS target_props, "
            "       type(r) AS type LIMIT $limit",
            {"limit": limit},
        )
        
        nodes_dict = {}
        edges = []
        
        for row in results:
            if row["source"] not in nodes_dict:
                nodes_dict[row["source"]] = {"id": row["source"], "label": row["source_label"], **self._safe_props(row["source_props"])}
            if row["target"] not in nodes_dict:
                nodes_dict[row["target"]] = {"id": row["target"], "label": row["target_label"], **self._safe_props(row["target_props"])}
            edges.append({"source": row["source"], "target": row["target"], "type": row["type"]})
            
        return {
            "nodes": list(nodes_dict.values()),
            "edges": edges,
        }

    def _safe_props(self, props: dict) -> dict:
        """Extract safe, serializable properties for the frontend."""
        safe = {}
        for k, v in props.items():
            if k in ("ip", "address", "domain", "name", "alert_id", "alert_type",
                     "severity", "status", "confidence_score", "title", "country_code",
                     "is_internal", "first_seen", "last_seen"):
                safe[k] = v
        return safe

    def get_timeline(self, ip: str) -> list[dict]:
        """Get attack timeline for a specific IP."""
        return self._run_query(
            "MATCH (ip:IPAddress {ip: $ip})-[r]->(target) "
            "RETURN type(r) AS action, labels(target)[0] AS target_type, "
            "properties(target) AS target_props, r.timestamp AS timestamp "
            "ORDER BY r.timestamp DESC LIMIT 100",
            {"ip": ip},
        )

    def run_detections(self) -> dict:
        """Run graph-based detection queries."""
        kill_chains = self._run_query(
            "MATCH (ip:IPAddress)-[:QUERIED]->(d:Domain), "
            "(ip)-[:TRIGGERED]->(a:Alert) "
            "WHERE a.severity IN ['HIGH', 'CRITICAL'] "
            "RETURN ip.ip AS ip, collect(DISTINCT d.name) AS domains, "
            "collect(DISTINCT a.alert_type) AS alert_types, count(a) AS alert_count "
            "ORDER BY alert_count DESC LIMIT 20"
        )
        return {
            "kill_chains": kill_chains,
            "total_findings": len(kill_chains),
        }

    def health_check(self) -> bool:
        """Check if Neo4j is reachable."""
        try:
            self._run_query("RETURN 1")
            return True
        except Exception:
            return False

    def get_severity_distribution(self) -> list[dict]:
        """Get counts of alerts grouped by severity."""
        return self._run_query(
            "MATCH (a:Alert) RETURN a.severity AS severity, count(a) AS count"
        )

    def get_alert_timeline(self) -> list[dict]:
        """Get alert volume over time (hourly buckets) for the last 24 hours."""
        return self._run_query(
            "MATCH (a:Alert) "
            "WITH a, datetime(a.timestamp) AS dt "
            "WITH date(dt) AS d, dt.hour AS h, count(a) AS count "
            "RETURN toString(d) + ' ' + toString(h) + ':00' AS time, count "
            "ORDER BY time DESC LIMIT 24"
        )

    def get_top_mitre_techniques(self, limit: int = 5) -> list[dict]:
        """Get the most frequently detected MITRE ATT&CK techniques."""
        return self._run_query(
            "MATCH (a:Alert)-[:MAPS_TO]->(m:MitreAttack) "
            "RETURN m.technique_id AS technique, count(a) AS count "
            "ORDER BY count DESC LIMIT $limit",
            {"limit": limit}
        )
