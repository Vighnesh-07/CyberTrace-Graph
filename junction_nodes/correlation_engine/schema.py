"""Neo4j Attack Graph Schema for CyberTrace-Graph.

Node Labels:
- IPAddress: ip (key), is_internal, country_code, country_name, city, asn, as_org, is_vpn, is_tor, first_seen, last_seen
- Domain: name (key), entropy, is_dga, first_seen, last_seen
- Host: hostname (key), sensor_id, os_type, first_seen
- User: username (key), privilege_level, first_seen
- Process: name, pid, command_line, file_hash, first_seen
- Alert: alert_id (key), alert_type, severity, confidence_score, title, description, timestamp
- MitreAttack: technique_id (key), tactic_id, technique_name, tactic_name

Relationship Types:
- RESOLVED_TO: Domain -> IPAddress (timestamp, query_type)
- CONNECTED_TO: IPAddress -> IPAddress (timestamp, port, protocol, bytes_sent)
- QUERIED: IPAddress -> Domain (timestamp, query_type, response_code)
- AUTHENTICATED_TO: User -> Host (timestamp, auth_method, success)
- EXECUTED: User -> Process (timestamp, hostname)
- SPAWNED: Process -> Process (timestamp)
- TRIGGERED: IPAddress -> Alert (timestamp)
- TARGETS: Alert -> Domain (timestamp)
- MAPS_TO: Alert -> MitreAttack ()
"""

import logging
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

# Constraint creation queries
SCHEMA_CONSTRAINTS = [
    "CREATE CONSTRAINT ip_address_unique IF NOT EXISTS FOR (n:IPAddress) REQUIRE n.ip IS UNIQUE",
    "CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (n:Domain) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT host_unique IF NOT EXISTS FOR (n:Host) REQUIRE n.hostname IS UNIQUE",
    "CREATE CONSTRAINT user_unique IF NOT EXISTS FOR (n:User) REQUIRE n.username IS UNIQUE",
    "CREATE CONSTRAINT alert_unique IF NOT EXISTS FOR (n:Alert) REQUIRE n.alert_id IS UNIQUE",
    "CREATE CONSTRAINT mitre_unique IF NOT EXISTS FOR (n:MitreAttack) REQUIRE n.technique_id IS UNIQUE",
]

# Index creation for faster lookups
SCHEMA_INDEXES = [
    "CREATE INDEX ip_country IF NOT EXISTS FOR (n:IPAddress) ON (n.country_code)",
    "CREATE INDEX domain_dga IF NOT EXISTS FOR (n:Domain) ON (n.is_dga)",
    "CREATE INDEX alert_type_idx IF NOT EXISTS FOR (n:Alert) ON (n.alert_type)",
    "CREATE INDEX alert_severity_idx IF NOT EXISTS FOR (n:Alert) ON (n.severity)",
    "CREATE INDEX mitre_tactic IF NOT EXISTS FOR (n:MitreAttack) ON (n.tactic_id)",
]

# MITRE ATT&CK reference data (the techniques we use in our detectors)
MITRE_TECHNIQUES = {
    "T1071": {"tactic_id": "TA0011", "tactic_name": "Command and Control", "technique_name": "Application Layer Protocol"},
    "T1071.004": {"tactic_id": "TA0011", "tactic_name": "Command and Control", "technique_name": "DNS"},
    "T1048": {"tactic_id": "TA0010", "tactic_name": "Exfiltration", "technique_name": "Exfiltration Over Alternative Protocol"},
    "T1568": {"tactic_id": "TA0011", "tactic_name": "Command and Control", "technique_name": "Dynamic Resolution"},
    "T1110": {"tactic_id": "TA0006", "tactic_name": "Credential Access", "technique_name": "Brute Force"},
    "T1021": {"tactic_id": "TA0008", "tactic_name": "Lateral Movement", "technique_name": "Remote Services"},
    "T1059": {"tactic_id": "TA0002", "tactic_name": "Execution", "technique_name": "Command and Scripting Interpreter"},
}

def initialize_schema(driver) -> None:
    """Create constraints, indexes, and seed MITRE data in Neo4j."""
    with driver.session() as session:
        for constraint in SCHEMA_CONSTRAINTS:
            session.run(constraint)
            logger.info(f"Created constraint: {constraint[:60]}...")
        for index in SCHEMA_INDEXES:
            session.run(index)
            logger.info(f"Created index: {index[:60]}...")
        # Seed MITRE ATT&CK nodes
        for tech_id, data in MITRE_TECHNIQUES.items():
            session.run(
                "MERGE (m:MitreAttack {technique_id: $tech_id}) "
                "SET m.tactic_id = $tactic_id, m.tactic_name = $tactic_name, m.technique_name = $tech_name",
                tech_id=tech_id, tactic_id=data["tactic_id"],
                tactic_name=data["tactic_name"], tech_name=data["technique_name"]
            )
        logger.info(f"Seeded {len(MITRE_TECHNIQUES)} MITRE ATT&CK technique nodes.")
