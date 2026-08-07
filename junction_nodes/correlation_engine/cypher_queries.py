"""Cypher query library for CyberTrace-Graph attack detection."""

class CypherQueries:
    """Library of Cypher queries for attack pattern detection."""
    
    # ── Kill Chain Detection ────────────────────────────────────────
    # Find internal IPs that: queried suspicious domains AND triggered alerts
    KILL_CHAIN_DETECTION = """
    MATCH (ip:IPAddress {is_internal: true})-[:QUERIED]->(d:Domain)
    MATCH (ip)-[:TRIGGERED]->(a:Alert)
    WHERE d.is_dga = true OR d.entropy > 3.5
    WITH ip, collect(DISTINCT d.name) AS domains, 
         collect(DISTINCT a.alert_type) AS alert_types,
         count(DISTINCT a) AS alert_count
    WHERE alert_count >= 2
    RETURN ip.ip AS source_ip, domains, alert_types, alert_count
    ORDER BY alert_count DESC
    LIMIT 20
    """
    
    # ── Lateral Movement ────────────────────────────────────────────
    # Find users authenticating to multiple hosts
    LATERAL_MOVEMENT = """
    MATCH (u:User)-[auth:AUTHENTICATED_TO]->(h:Host)
    WITH u, collect(DISTINCT h.hostname) AS hosts, count(DISTINCT h) AS host_count,
         collect(auth.success) AS successes
    WHERE host_count >= 2
    RETURN u.username AS username, hosts, host_count,
           size([s IN successes WHERE s = true]) AS successful_auths,
           size([s IN successes WHERE s = false]) AS failed_auths
    ORDER BY host_count DESC
    LIMIT 20
    """
    
    # ── C2 Infrastructure Detection ─────────────────────────────────
    # Find domains queried by multiple internal IPs that have alerts
    C2_INFRASTRUCTURE = """
    MATCH (ip:IPAddress {is_internal: true})-[:QUERIED]->(d:Domain)
    OPTIONAL MATCH (ip)-[:TRIGGERED]->(a:Alert)
    WITH d, collect(DISTINCT ip.ip) AS querying_ips, 
         count(DISTINCT ip) AS ip_count,
         collect(DISTINCT a.alert_type) AS alert_types
    WHERE ip_count >= 2
    RETURN d.name AS domain, d.entropy AS entropy, d.is_dga AS is_dga,
           querying_ips, ip_count, alert_types
    ORDER BY ip_count DESC
    LIMIT 20
    """
    
    # ── DGA Cluster Detection ───────────────────────────────────────
    # Find IPs querying many high-entropy, likely DGA domains
    DGA_CLUSTER_DETECTION = """
    MATCH (ip:IPAddress)-[:QUERIED]->(d:Domain)
    WHERE d.entropy > 3.5
    WITH ip, collect(DISTINCT d.name) AS dga_domains, 
         count(DISTINCT d) AS dga_count,
         avg(d.entropy) AS avg_entropy
    WHERE dga_count >= 5
    RETURN ip.ip AS source_ip, ip.is_internal AS is_internal,
           dga_count, avg_entropy, dga_domains[..10] AS sample_domains
    ORDER BY dga_count DESC
    LIMIT 20
    """
    
    # ── Attack Timeline ─────────────────────────────────────────────
    # Get full chronological event chain for a specific IP
    ATTACK_TIMELINE = """
    MATCH (ip:IPAddress {ip: $target_ip})-[r]->(n)
    RETURN type(r) AS relationship, labels(n)[0] AS target_type,
           CASE
             WHEN 'Domain' IN labels(n) THEN n.name
             WHEN 'IPAddress' IN labels(n) THEN n.ip
             WHEN 'Alert' IN labels(n) THEN n.title
             WHEN 'Host' IN labels(n) THEN n.hostname
             ELSE toString(id(n))
           END AS target,
           r.timestamp AS timestamp
    ORDER BY r.timestamp
    LIMIT 100
    """
    
    # ── Graph Summary ───────────────────────────────────────────────
    GRAPH_SUMMARY = """
    CALL {
        MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count
    }
    RETURN label, count ORDER BY count DESC
    """
    
    RELATIONSHIP_SUMMARY = """
    CALL {
        MATCH ()-[r]->() RETURN type(r) AS rel_type, count(r) AS count
    }
    RETURN rel_type, count ORDER BY count DESC
    """
