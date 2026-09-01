# Architecture: CyberTrace-Graph

CyberTrace-Graph implements a highly distributed, microservices-oriented architecture designed to handle large volumes of telemetry data for real-time Advanced Persistent Threat (APT) detection.

## High-Level System Design

The architecture is divided into three primary tiers: **Ingestion**, **Processing & Storage**, and **Correlation & Analytics**.

### 1. Ingestion Tier (Junction Nodes)
Junction nodes act as distributed sensors deployed across the network, endpoints, and cloud environments.
- **DNS Sensor:** Captures and analyzes DNS requests for tunneling, DGA domains, and suspicious TLDs.
- **Fault Tolerance:** Each sensor utilizes a local ring-buffer (`collections.deque`). If the central Kafka cluster becomes unreachable, events are buffered locally and flushed automatically upon reconnection.
- **Event Models:** All telemetry is strictly validated using Pydantic V2 models (`SecurityEvent`, `DNSEvent`, etc.) to guarantee schema consistency.

### 2. Processing & Storage Tier (Event Backbone)
- **Apache Kafka:** The central nervous system of the platform. Telemetry is partitioned by source IP to ensure ordered processing of events originating from the same host.
- **Topics:**
  - `apt.events.dns`, `apt.events.network`, `apt.events.endpoint` (Raw Telemetry)
  - `apt.alerts.raw`, `apt.alerts.correlated` (Detections)
  - `apt.system.heartbeat` (Node Health)

### 3. Correlation & Analytics Tier
- **Stream Processing (Apache Flink/Faust):** Consumes raw events from Kafka, performs stateless enrichments (e.g., GeoIP), and stateful windowed aggregations (e.g., detecting C2 beaconing over a 5-minute tumbling window).
- **Graph Database (Neo4j):** Stores the relational mapping of the network. IPs, Domains, Users, and Processes are represented as nodes. Edges represent interactions (e.g., `USER` -> `LOGGED_IN_TO` -> `HOST`). This schema allows complex Cypher queries to detect lateral movement and complete attack chains.
- **Caching (Redis):** Used by the stream processors for fast lookups of threat intelligence feeds and deduplication of alerts.

## Attack Simulator
To validate the architecture, the platform includes an `attack_simulator`. It utilizes adversarial emulation (e.g., DNS Tunneling) mixed with baseline normal traffic to test detection efficacy and system throughput safely.

## Future Enhancements
- Kubernetes (Helm) deployments for production-scale resilience.
- Machine Learning models (Isolation Forests) for unsupervised anomaly detection.
- React-based SOC dashboard utilizing D3.js for visual graph exploration.
