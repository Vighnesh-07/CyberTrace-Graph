import logging
import math
from datetime import datetime, timezone
from typing import Optional, Any

from neo4j import GraphDatabase

from junction_nodes.common.config import Neo4jConfig
from junction_nodes.correlation_engine.schema import initialize_schema

logger = logging.getLogger(__name__)

class GraphService:
    """Manages Neo4j connection and provides CRUD for the attack graph.
    
    All writes use MERGE for idempotency — ingesting the same event
    twice will not create duplicates.
    """
    
    def __init__(self, config: Neo4jConfig):
        self._driver = GraphDatabase.driver(config.uri, auth=(config.user, config.password))
        self._stats = {"nodes_created": 0, "relationships_created": 0, "events_ingested": 0}
        logger.info(f"Connected to Neo4j at {config.uri}")
    
    def close(self):
        self._driver.close()
    
    def initialize_schema(self):
        initialize_schema(self._driver)
    
    def get_stats(self) -> dict:
        """Get graph statistics."""
        with self._driver.session() as session:
            result = session.run(
                "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC"
            )
            node_counts = {record["label"]: record["count"] for record in result}
            result = session.run(
                "MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS count ORDER BY count DESC"
            )
            rel_counts = {record["type"]: record["count"] for record in result}
        return {"nodes": node_counts, "relationships": rel_counts, "internal_stats": self._stats}
    
    # ── Node upsert methods ─────────────────────────────────────────
    
    def upsert_ip(self, ip: str, is_internal: bool = False, 
                  country_code: str = None, country_name: str = None,
                  city: str = None, asn: int = None, as_org: str = None,
                  is_vpn: bool = False, is_tor: bool = False) -> None:
        """MERGE an IPAddress node."""
        with self._driver.session() as session:
            session.run(
                "MERGE (n:IPAddress {ip: $ip}) "
                "ON CREATE SET n.first_seen = datetime(), n.is_internal = $is_internal, "
                "n.country_code = $cc, n.country_name = $cn, n.city = $city, "
                "n.asn = $asn, n.as_org = $as_org, n.is_vpn = $is_vpn, n.is_tor = $is_tor "
                "ON MATCH SET n.last_seen = datetime()",
                ip=ip, is_internal=is_internal, cc=country_code, cn=country_name,
                city=city, asn=asn, as_org=as_org, is_vpn=is_vpn, is_tor=is_tor
            )
    
    def upsert_domain(self, name: str, entropy: float = 0.0, is_dga: bool = False) -> None:
        """MERGE a Domain node."""
        with self._driver.session() as session:
            session.run(
                "MERGE (n:Domain {name: $name}) "
                "ON CREATE SET n.first_seen = datetime(), n.entropy = $entropy, n.is_dga = $is_dga "
                "ON MATCH SET n.last_seen = datetime()",
                name=name, entropy=entropy, is_dga=is_dga
            )
    
    def upsert_host(self, hostname: str, sensor_id: str = None) -> None:
        """MERGE a Host node."""
        with self._driver.session() as session:
            session.run(
                "MERGE (n:Host {hostname: $hostname}) "
                "ON CREATE SET n.first_seen = datetime(), n.sensor_id = $sensor_id "
                "ON MATCH SET n.last_seen = datetime()",
                hostname=hostname, sensor_id=sensor_id
            )
    
    def upsert_user(self, username: str, privilege_level: str = None) -> None:
        """MERGE a User node."""
        with self._driver.session() as session:
            session.run(
                "MERGE (n:User {username: $username}) "
                "ON CREATE SET n.first_seen = datetime(), n.privilege_level = $privilege_level "
                "ON MATCH SET n.last_seen = datetime()",
                username=username, privilege_level=privilege_level
            )
    
    def upsert_alert(self, alert_dict: dict) -> None:
        """Create an Alert node from an AlertEvent dict."""
        with self._driver.session() as session:
            session.run(
                "MERGE (a:Alert {alert_id: $alert_id}) "
                "ON CREATE SET a.alert_type = $alert_type, a.severity = $severity, "
                "a.confidence_score = $confidence, a.title = $title, a.description = $description, "
                "a.timestamp = datetime($ts), a.status = $status, a.source_ip = $source_ip",
                alert_id=alert_dict.get("alert_id", ""),
                alert_type=alert_dict.get("alert_type", ""),
                severity=alert_dict.get("severity", ""),
                confidence=alert_dict.get("confidence_score", 0.0),
                title=alert_dict.get("title", ""),
                description=alert_dict.get("description", ""),
                ts=alert_dict.get("timestamp", datetime.now(timezone.utc).isoformat()),
                status=alert_dict.get("status", "OPEN"),
                source_ip=alert_dict.get("source_ip", "")
            )
            self._stats["nodes_created"] += 1
    
    # ── Relationship creation ───────────────────────────────────────
    
    def create_relationship(self, from_label: str, from_key_field: str, from_key_value: str,
                          to_label: str, to_key_field: str, to_key_value: str,
                          rel_type: str, properties: dict = None) -> None:
        """Create a relationship between two existing nodes."""
        props_str = ""
        params = {"from_val": from_key_value, "to_val": to_key_value}
        if properties:
            prop_parts = []
            for k, v in properties.items():
                params[f"p_{k}"] = v
                prop_parts.append(f"r.{k} = $p_{k}")
            props_str = "SET " + ", ".join(prop_parts)
        
        query = (
            f"MATCH (a:{from_label} {{{from_key_field}: $from_val}}), "
            f"(b:{to_label} {{{to_key_field}: $to_val}}) "
            f"CREATE (a)-[r:{rel_type}]->(b) {props_str}"
        )
        with self._driver.session() as session:
            session.run(query, **params)
            self._stats["relationships_created"] += 1
    
    # ── High-level event ingestion ──────────────────────────────────
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)
    
    def ingest_enriched_event(self, event_dict: dict) -> None:
        """Ingest a full enriched event into the graph.
        
        Creates nodes for IPs, domains, hosts and appropriate relationships
        based on the event type.
        """
        event_type = event_dict.get("event_type", "")
        source_ip = event_dict.get("source_ip")
        dest_ip = event_dict.get("destination_ip")
        timestamp = event_dict.get("timestamp", datetime.now(timezone.utc).isoformat())
        
        # Get the original event data (may contain extra fields like query_name)
        original = event_dict.get("original_event", event_dict)
        
        # GeoIP data from enrichment
        source_geo = event_dict.get("source_geo") or {}
        dest_geo = event_dict.get("destination_geo") or {}
        is_internal = event_dict.get("is_internal_ip", False)
        
        # Upsert source IP node
        if source_ip:
            self.upsert_ip(
                ip=source_ip, is_internal=is_internal,
                country_code=source_geo.get("country_code"),
                country_name=source_geo.get("country_name"),
                city=source_geo.get("city"),
                asn=source_geo.get("asn"),
                as_org=source_geo.get("as_org"),
                is_vpn=source_geo.get("is_vpn", False),
                is_tor=source_geo.get("is_tor", False),
            )
        
        # Upsert destination IP node
        if dest_ip:
            self.upsert_ip(
                ip=dest_ip, is_internal=False,
                country_code=dest_geo.get("country_code"),
                country_name=dest_geo.get("country_name"),
                city=dest_geo.get("city"),
                asn=dest_geo.get("asn"),
                as_org=dest_geo.get("as_org"),
                is_vpn=dest_geo.get("is_vpn", False),
                is_tor=dest_geo.get("is_tor", False),
            )
        
        # Upsert host if present
        hostname = original.get("hostname")
        sensor_id = event_dict.get("sensor_id", "")
        if hostname:
            self.upsert_host(hostname, sensor_id)
        
        # ── Event-type-specific graph operations ────────────────────
        
        if event_type == "DNS_QUERY":
            query_name = original.get("query_name", "")
            query_type = original.get("query_type", "A")
            response_code = original.get("response_code", "")
            response_ips = original.get("response_ips", [])
            
            if query_name:
                entropy = self._calculate_entropy(query_name.split('.')[0])
                is_dga = entropy > 3.5 and len(query_name.split('.')[0]) > 10
                self.upsert_domain(query_name, entropy=entropy, is_dga=is_dga)
                
                # source_ip QUERIED domain
                if source_ip:
                    self.create_relationship(
                        "IPAddress", "ip", source_ip,
                        "Domain", "name", query_name,
                        "QUERIED",
                        {"timestamp": timestamp, "query_type": query_type, "response_code": response_code}
                    )
                
                # domain RESOLVED_TO response IPs
                for rip in response_ips:
                    self.upsert_ip(rip)
                    self.create_relationship(
                        "Domain", "name", query_name,
                        "IPAddress", "ip", rip,
                        "RESOLVED_TO",
                        {"timestamp": timestamp, "query_type": query_type}
                    )
        
        elif event_type == "NETWORK_CONNECTION":
            if source_ip and dest_ip:
                protocol = original.get("protocol", "TCP")
                dest_port = original.get("destination_port")
                bytes_sent = original.get("bytes_sent", 0)
                self.create_relationship(
                    "IPAddress", "ip", source_ip,
                    "IPAddress", "ip", dest_ip,
                    "CONNECTED_TO",
                    {"timestamp": timestamp, "protocol": protocol, "port": dest_port, "bytes_sent": bytes_sent}
                )
        
        elif event_type in ("AUTH_LOGIN", "AUTH_FAILURE"):
            username = original.get("username", "")
            auth_method = original.get("auth_method", "")
            success = original.get("success", False)
            target_host = original.get("target_host", "")
            
            if username:
                self.upsert_user(username, original.get("privilege_level"))
                if target_host:
                    self.upsert_host(target_host)
                    self.create_relationship(
                        "User", "username", username,
                        "Host", "hostname", target_host,
                        "AUTHENTICATED_TO",
                        {"timestamp": timestamp, "auth_method": auth_method, "success": success}
                    )
        
        elif event_type == "PROCESS_CREATION":
            process_name = original.get("process_name", "")
            username = original.get("user", "")
            if process_name and username:
                self.upsert_user(username)
                # We create Process nodes inline since they need pid for uniqueness
                with self._driver.session() as session:
                    session.run(
                        "MERGE (p:Process {name: $name, pid: $pid}) "
                        "ON CREATE SET p.command_line = $cmd, p.file_hash = $hash, p.first_seen = datetime()",
                        name=process_name, pid=original.get("process_id", 0),
                        cmd=original.get("command_line", ""), hash=original.get("file_hash_sha256", "")
                    )
                self.create_relationship(
                    "User", "username", username,
                    "Process", "name", process_name,
                    "EXECUTED",
                    {"timestamp": timestamp, "hostname": hostname or ""}
                )
                # Parent process relationship
                parent_name = original.get("parent_process_name")
                if parent_name:
                    with self._driver.session() as session:
                        session.run(
                            "MERGE (p:Process {name: $name, pid: $pid}) ON CREATE SET p.first_seen = datetime()",
                            name=parent_name, pid=original.get("parent_process_id", 0)
                        )
                    self.create_relationship(
                        "Process", "name", parent_name,
                        "Process", "name", process_name,
                        "SPAWNED",
                        {"timestamp": timestamp}
                    )
        
        self._stats["events_ingested"] += 1
        
        if self._stats["events_ingested"] % 100 == 0:
            logger.info(f"Graph stats: {self._stats}")
    
    def ingest_alert(self, alert_dict: dict) -> None:
        """Ingest an alert into the graph.
        
        Creates the Alert node and links it to:
        - Source IP (TRIGGERED relationship)
        - MITRE ATT&CK technique (MAPS_TO relationship)
        """
        self.upsert_alert(alert_dict)
        alert_id = alert_dict.get("alert_id", "")
        
        # Link to source IP
        source_ip = alert_dict.get("source_ip")
        if source_ip:
            self.upsert_ip(source_ip)
            self.create_relationship(
                "IPAddress", "ip", source_ip,
                "Alert", "alert_id", alert_id,
                "TRIGGERED",
                {"timestamp": alert_dict.get("timestamp", datetime.now(timezone.utc).isoformat())}
            )
        
        # Link to MITRE technique
        mitre_technique = alert_dict.get("mitre_technique")
        if mitre_technique:
            # Ensure the MitreAttack node exists
            with self._driver.session() as session:
                session.run(
                    "MERGE (m:MitreAttack {technique_id: $tech_id})",
                    tech_id=mitre_technique
                )
            self.create_relationship(
                "Alert", "alert_id", alert_id,
                "MitreAttack", "technique_id", mitre_technique,
                "MAPS_TO"
            )
        
        # Link alert to domain if evidence contains one
        evidence = alert_dict.get("evidence", {})
        domain = evidence.get("domain")
        if domain:
            self.upsert_domain(domain)
            self.create_relationship(
                "Alert", "alert_id", alert_id,
                "Domain", "name", domain,
                "TARGETS",
                {"timestamp": alert_dict.get("timestamp", "")}
            )
        
        self._stats["nodes_created"] += 1
