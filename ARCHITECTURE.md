# Architecture: CyberTrace-Graph

CyberTrace-Graph implements a highly distributed, microservices-oriented architecture designed to handle large volumes of telemetry data for real-time Advanced Persistent Threat (APT) detection. 

Unlike traditional SIEMs that treat logs as flat text, CyberTrace-Graph maps telemetry into a **highly connected graph**, exposing lateral movement and complex, multi-stage attack patterns that relational databases miss.

---

## 🏗️ High-Level System Design

The architecture is divided into four primary tiers:

### 1. Ingestion Tier (Junction Nodes)
Junction nodes act as distributed, lightweight sensors deployed across the network and endpoints.
- **Sensor Types:** DNS, Network, Endpoint, and Cloud.
- **Fault Tolerance:** Each sensor utilizes a local ring-buffer (`collections.deque`). If the central Kafka cluster becomes unreachable, events are buffered locally and flushed automatically upon reconnection.
- **Data Integrity:** All telemetry is strictly validated using Pydantic V2 models to guarantee schema consistency before entering the pipeline.

### 2. Processing & Storage Tier (Event Backbone)
- **Apache Kafka:** The central nervous system. Telemetry is partitioned by source IP to ensure ordered processing of events originating from the same host.
- **Neo4j Graph Database:** Stores the relational mapping of the network. IPs, Domains, Users, and Processes are represented as nodes. Edges represent interactions (e.g., `USER` -> `LOGGED_IN_TO` -> `HOST`). 
- **Redis Cache:** Used by the stream processors for fast lookups of threat intelligence feeds and deduplication of real-time alerts.

### 3. Correlation & Analytics Tier
The Python-based Stream Processor consumes raw events from Kafka and runs them through a sophisticated multi-stage pipeline:
- **Heuristic Detectors:** Identifies rapid Port Scans (T1046) and OS Credential Dumping via LSASS (T1003.001) using sliding time windows and command-line keyword heuristics.
- **Statistical / ML Detectors:** 
  - Detects **Ransomware (T1486)** by tracking file operation ratios and calculating Shannon entropy on file extensions.
  - Identifies **DNS Tunneling / DGA (T1568)** using an `IsolationForest` ML model and tracking TXT query ratios.
  - Detects **C2 Beaconing (T1132)** using coefficient of variation calculations on connection intervals.

### 4. Presentation Tier (SOC Dashboard)
- **FastAPI Backend:** Provides a high-performance REST API and Server-Sent Events (SSE) for real-time alert streaming to the UI.
- **React Frontend:** A modern, widget-driven SOC dashboard. Utilizes Vis.js/D3 for interactive graph topology exploration, allowing analysts to visually track an attacker's lateral movement.

---

## 🛡️ Security Posture

As an industry-grade security tool, CyberTrace-Graph secures its own infrastructure:
- **Authentication:** The FastAPI backend utilizes OAuth2 with JWT (JSON Web Tokens). All endpoints, including the real-time SSE streams, require cryptographic validation. The React frontend is fully integrated with this JWT flow.
- **Network Isolation:** Internal data stores (Kafka, Neo4j, Zookeeper, Redis) are strictly bound to the Docker local bridge network and `127.0.0.1`. They are not exposed to the external network adapter.
- **Secret Management:** Hardcoded credentials are fundamentally rejected. The system relies entirely on `.env` variable injection.

---

## ⚔️ Attack Simulator

To validate detection efficacy, the platform includes a powerful adversarial emulation framework (`simulate_apt.py`). 

It generates synthetic baseline traffic intermixed with highly targeted attack telemetry:
- **`port-scan`**: Simulates rapid SYN scans across multiple destination ports.
- **`cred-dump`**: Simulates `procdump` accessing the `lsass.exe` process.
- **`ransomware`**: Simulates high-frequency file modifications and entropy spikes.
- **`apt-scenario`**: Simulates a complete kill-chain (Phishing -> Execution -> Lateral Movement -> Exfiltration).
