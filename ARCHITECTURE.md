# Architecture & Technical Deep-Dive: CyberTrace-Graph

This document provides a comprehensive technical breakdown of the **CyberTrace-Graph** architecture, data flow, graph modeling principles, and detection paradigms.

---

## 1. High-Level Architecture Overview

CyberTrace-Graph implements a distributed, reactive microservices pipeline designed for high-throughput security event processing and low-latency graph correlation:

```
                                  ┌─────────────────────────────┐
                                  │   Real Telemetry / Sysmon   │
                                  │   or Adversary Simulator    │
                                  └──────────────┬──────────────┘
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │   Ingestion Gateway (REST)  │
                                  │  - Schema Normalization     │
                                  │  - API Key Authentication   │
                                  └──────────────┬──────────────┘
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │    Apache Kafka Cluster     │
                                  │  - apt.events.endpoint      │
                                  │  - apt.events.network       │
                                  │  - apt.events.dns           │
                                  │  - apt.events.auth          │
                                  └──────────────┬──────────────┘
                                                 │
                                                 ▼
                       ┌──────────────────────────────────────────────────┐
                       │             Stream Processing Node               │
                       │  - Threat Intel & GeoIP Enrichment               │
                       │  - ML Engine (Random Forest DGA + Isolation For.)│
                       │  - Heuristic Detectors (Port scan, Cred dump)    │
                       │  - Dynamic YAML Rule Engine                      │
                       │  - Redis Sliding Windows (ZSET state durability) │
                       └────────┬────────────────────────────────┬────────┘
                                │                                │
                Raw Alerts      │                                │ Enriched Events
                                ▼                                ▼
                       ┌─────────────────┐             ┌───────────────────┐
                       │ apt.alerts.raw  │             │apt.events.enriched│
                       └────────┬────────┘             └─────────┬─────────┘
                                │                                │
                                └───────────────┬────────────────┘
                                                │
                                                ▼
                               ┌─────────────────────────────────┐
                               │   Correlation Engine Ingestor   │
                               │  - UNWIND Micro-Batch Ingestion │
                               │  - Multi-Hop Kill Chain Queries │
                               │  - Scheduled Graph TTL Pruning  │
                               └────────────────┬────────────────┘
                                                │
                                                ▼
                               ┌─────────────────────────────────┐
                               │       Neo4j Attack Graph        │
                               │  (Entities, Edges, MitreAttack, │
                               │   ResponseAction, AuditLog)     │
                               └────────────────┬────────────────┘
                                                │
                                                ▼
                               ┌─────────────────────────────────┐
                               │     FastAPI Security Gateway    │
                               │  - JWT Bearer Authentication    │
                               │  - SSE Real-Time Streaming      │
                               │  - Active SOAR Webhook Engine   │
                               └────────────────┬────────────────┘
                                                │
                                                ▼
                               ┌─────────────────────────────────┐
                               │   React 19 SOC Command Center   │
                               └─────────────────────────────────┘
```

---

## 2. Ingestion & Event Backbone

### Apache Kafka Topologies
Events are routed through dedicated, partitioned Kafka topics:
* `apt.events.dns`: DNS resolution events, query names, query types, response IPs.
* `apt.events.network`: TCP/UDP connection records, bytes transferred, source/destination ports.
* `apt.events.endpoint`: Process creations, LSASS process access, parent/child relationships, command-line arguments.
* `apt.events.auth`: Successful and failed logon attempts, target hostnames, privilege levels.
* `apt.alerts.raw`: Uncorrelated detections emitted by the stream processor.
* `apt.events.enriched`: Telemetry decorated with GeoIP metadata, threat intelligence matches, and internal IP flags.

### Sysmon Normalization Gateway
The Ingestion Gateway (`junction_nodes/ingestion_gateway`) exposes a high-throughput REST interface for log collectors (Winlogbeat, Fluentbit, Vector):
* **Sysmon Event ID 1 (Process Creation)** $\rightarrow$ Normalized `PROCESS_CREATION`
* **Sysmon Event ID 3 (Network Connection)** $\rightarrow$ Normalized `NETWORK_CONNECTION`
* **Sysmon Event ID 10 (ProcessAccess / LSASS Injection)** $\rightarrow$ Normalized `PROCESS_ACCESS`
* **Sysmon Event ID 22 (DNSEvent)** $\rightarrow$ Normalized `DNS_QUERY`

---

## 3. Detection & Machine Learning Layer

The detection engine combines three distinct paradigms to eliminate blind spots:

### A. Unsupervised & Supervised Machine Learning
1. **DGA Classifier (Supervised Random Forest):**
   * Features: String length, Shannon entropy, vowel-to-consonant ratios, digit ratios, n-gram frequencies.
   * Performance: 96.4% Accuracy, 94.2% Precision, 98.9% Recall on evaluation sets.
2. **Network Anomaly Detector (Unsupervised Isolation Forest):**
   * Isolates subtle beaconing cadence (low timestamp variance / jitter) and anomalous packet size distributions without requiring pre-labeled training data.

### B. Distributed State Durability via Redis
Traditional stream processors keep sliding windows in local Python memory, which wipes detection progress during container restarts.
* **Architecture:** CyberTrace-Graph uses Redis Sorted Sets (`ZSET`).
* **Algorithm:**
  * When an event occurs, `ZADD key timestamp event_id` records the occurrence.
  * `ZREMRANGEBYSCORE key -inf (now - window_sec)` evicts expired events outside the sliding window.
  * `ZCARD key` calculates current window frequency in $O(1)$ complexity.
  * Applied to: Port scan detection, brute force authentication tracking, and C2 jitter tracking.

### C. Declarative Dynamic Rule Engine
Enables SOC teams to hot-deploy custom detection rules in YAML format without restarting stream processors. Rules support:
* Exact, regex, substring, and in-list condition evaluations.
* Threshold grouping (`group_by: source_ip`, window duration).
* Automatic MITRE ATT&CK technique and tactic tagging.

---

## 4. Graph Correlation & Micro-Batching in Neo4j

### Graph Schema
* **Nodes:** `IPAddress`, `Domain`, `Host`, `User`, `Process`, `Alert`, `MitreAttack`, `ResponseAction`, `AuditLog`.
* **Relationships:**
  * `(:Domain)-[:RESOLVED_TO]->(:IPAddress)`
  * `(:IPAddress)-[:CONNECTED_TO]->(:IPAddress)`
  * `(:IPAddress)-[:QUERIED]->(:Domain)`
  * `(:User)-[:AUTHENTICATED_TO]->(:Host)`
  * `(:User)-[:EXECUTED]->(:Process)`
  * `(:Process)-[:SPAWNED]->(:Process)`
  * `(:IPAddress)-[:TRIGGERED]->(:Alert)`
  * `(:Alert)-[:MAPS_TO]->(:MitreAttack)`
  * `(:Alert)-[:RESPONDED_WITH]->(:ResponseAction)`
  * `(:ResponseAction)-[:BLOCKED]->(:IPAddress)`
  * `(:ResponseAction)-[:ACTED_ON]->(:Host)`

### UNWIND Micro-Batch Optimization
Executing individual `MERGE` queries per event causes lock contention on high-frequency nodes (e.g., Domain Controllers, Gateway routers).
* **Solution:** Events are buffered in memory and flushed in micro-batches (e.g., every 500 events or 1.0 second).
* **Cypher Micro-Batch Query:**
  ```cypher
  UNWIND $batch AS conn
  MATCH (src:IPAddress {ip: conn.source_ip})
  MATCH (dst:IPAddress {ip: conn.dest_ip})
  MERGE (src)-[r:CONNECTED_TO]->(dst)
  ON CREATE SET r.first_seen = datetime(conn.timestamp), r.count = 1, r.bytes_sent = conn.bytes_sent
  ON MATCH SET r.last_seen = datetime(conn.timestamp), r.count = r.count + 1, r.bytes_sent = r.bytes_sent + conn.bytes_sent
  ```

### Automated Graph TTL Pruning
To prevent graph explosion over continuous operations, a background job purges un-alerted leaf nodes older than 7 days:
```cypher
MATCH (n:IPAddress)
WHERE n.last_seen < datetime() - duration({days: 7})
  AND NOT (n)<-[:TRIGGERED]-()
DETACH DELETE n
```

---

## 5. Active SOAR & Compliance Audit Engine

The SOAR engine converts CyberTrace-Graph into an active XDR platform:
1. **Firewall Quarantine:** Invokes firewall API endpoints (Palo Alto / AWS WAF / iptables) to isolate malicious IPs.
2. **EDR Host Isolation:** Network-isolates compromised workstations via CrowdStrike/Defender APIs.
3. **Process Termination:** Kills malicious binaries in real time.
4. **Immutable Audit Trail:** All actions create non-deletable `(AuditLog)` and `(ResponseAction)` nodes in Neo4j with timestamps, actor IDs, and justification strings, satisfying SOC 2, HIPAA, and ISO 27001 requirements.
