# 🛡️ CyberTrace-Graph — Graph-Powered SIEM & Autonomous XDR Platform

<p align="center">
  <a href="https://github.com/Vighnesh-07/CyberTrace-Graph/actions/workflows/ci.yml">
    <img src="https://github.com/Vighnesh-07/CyberTrace-Graph/actions/workflows/ci.yml/badge.svg" alt="CyberTrace-Graph CI" />
  </a>
  <img src="https://img.shields.io/badge/pytest-32%20passed-brightgreen?style=flat-square&logo=pytest" alt="Pytest Suite" />
  <img src="https://img.shields.io/badge/Throughput-34%2C500%2B%20EPS-blueviolet?style=flat-square" alt="Sustained EPS" />
  <img src="https://img.shields.io/badge/Latency-Sub--Millisecond%20(0.04ms)-success?style=flat-square" alt="Latency" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Neo4j-5.13-45818e?style=for-the-badge&logo=neo4j&logoColor=white" alt="Neo4j" />
  <img src="https://img.shields.io/badge/Apache_Kafka-7.5.0-231F20?style=for-the-badge&logo=apache-kafka&logoColor=white" alt="Apache Kafka" />
  <img src="https://img.shields.io/badge/Redis-7_Alpine-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis" />
  <img src="https://img.shields.io/badge/React-19_Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React 19" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-v14.1-red?style=for-the-badge" alt="MITRE ATT&CK" />
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" alt="License: MIT" />
</p>

---

## 📌 Executive Summary

**CyberTrace-Graph** is an enterprise-grade, distributed **Graph-Powered SIEM (Security Information and Event Management) and Autonomous XDR (Extended Detection & Response)** platform engineered to hunt and neutralize Advanced Persistent Threats (APTs) in real-time.

Traditional SIEMs (e.g., Splunk, Elastic) rely on flat log stores and relational index joins that degrade exponentially when correlating multi-stage, slow-and-low attack chains. **CyberTrace-Graph replaces linear log matching with a continuous Attack Graph.** By combining high-throughput **Apache Kafka** event streaming, stateful **Redis** sliding windows, unsupervised **Machine Learning**, declarative **YAML/Sigma detection rules**, and **Neo4j** graph-topology traversal, CyberTrace-Graph provides sub-second blast-radius calculation, automated attack path reconstruction, and active SOAR remediation.

---

## 🌟 Key Architectural Highlights

```
                                      ┌──────────────────────────────────────────────────────────┐
                                      │              CYBERTRACE-GRAPH ARCHITECTURE               │
                                      └──────────────────────────────────────────────────────────┘

     [ EDGE LOG SOURCES ]                     [ STREAM INGESTION & PROCESSING ]                       [ GRAPH CORRELATION & SOC ]
 
 ┌─────────────────────────┐               ┌─────────────────────────────────────┐               ┌─────────────────────────────────┐
 │ Windows Sysmon (JSON)   │───HTTP POST──►│     Ingestion Gateway API (8001)    │               │       Neo4j Attack Graph        │
 │ Winlogbeat / Fluentbit  │               │   (Schema Validation & Token Auth)  │               │  - Parameterized UNWIND Batches │
 └─────────────────────────┘               └──────────────────┬──────────────────┘               │  - Automatic TTL Graph Pruning  │
 ┌─────────────────────────┐                                  │                                  │  - Blast-Radius Graph Traversal │
 │ APT Adversary Simulator │───Kafka Event Producer───────────┤                                  └────────────────┬────────────────┘
 │ (Multi-Scenario Engine) │                                  ▼                                                   ▲
 └─────────────────────────┘                       ┌──────────────────────┐                                       │
                                                   │ Apache Kafka Cluster │                                       │ Enriched Graph
                                                   │   (apt.events.*)     │                                       │ Upserts & Alerts
                                                   └──────────┬───────────┘                                       │
                                                              │                                  ┌────────────────┴────────────────┐
                                                              ▼                                  │       Correlation Engine        │
                                                   ┌──────────────────────┐                      │  - UNWIND Micro-Batch Ingestor  │
                                                   │   Stream Processor   │◄────State Sync──────►│  - Multi-Hop Kill Chain Queries │
                                                   │  (Isolation Forest)  │      (Redis ZSET)    │  - Threat Graph Materialization │
                                                   │  (DGA Random Forest) │                      └─────────────────────────────────┘
                                                   │  (Dynamic YAML Rules)│
                                                   └──────────┬───────────┘
                                                              │
                                                              ▼ SSE Event Stream / REST
                                                   ┌──────────────────────────────────────┐
                                                   │     FastAPI SOC Backend (Port 8000)   │
                                                   │  - JWT Bearer Authentication         │
                                                   │  - Active SOAR Remediation Engine    │
                                                   │  - Immutable Audit Logging in Neo4j  │
                                                   └──────────────────┬───────────────────┘
                                                                      │
                                                                      ▼
                                                   ┌──────────────────────────────────────┐
                                                   │     React 19 SOC Command Center      │
                                                   │  - Real-Time Attack Graph Topology   │
                                                   │  - Live SSE Incident Feed & Analytics│
                                                   │  - Active Containment & SOAR Action  │
                                                   │  - Compliance Audit Trail Viewer     │
                                                   └──────────────────────────────────────┘
```

---

## 🎯 Technical Novelty & Competitive Advantages

| Capability | Traditional SIEMs (Splunk / Elastic) | CyberTrace-Graph (Graph-XDR) |
| :--- | :--- | :--- |
| **Data Representation** | Flat tabular records / document indices | **Continuous Entity-Relationship Graph** (IP, Domain, Host, Process, User, Alert) |
| **Lateral Movement Analysis** | Multiple computationally expensive recursive SQL/SPL joins | **Native Graph Traversal (`O(k)` hops)** via Cypher graph queries |
| **Detection State Durability** | In-memory buffers lost on processor restart | **Distributed Redis Sorted Sets (`ZSET`)** with auto-sliding eviction |
| **Rule Extensibility** | Proprietary search queries (SPL / KQL) | **Declarative YAML/Sigma Rules** hot-reloaded dynamically without service restart |
| **Ingestion Bottleneck Fix** | Single-record database insert lock contention | **Parameterized `UNWIND` Micro-Batching** sustaining high EPS writes |
| **Response Automation** | External ticketing or separate SOAR add-on | **Integrated SOAR Action Engine** with immutable Neo4j audit trail |

---

## 🛡️ MITRE ATT&CK® Detection Matrix

CyberTrace-Graph features continuous out-of-the-box coverage mapped directly to the **MITRE ATT&CK** Enterprise Matrix:

| Tactic | Technique ID | Technique Name | Detection Mechanism | Confidence |
| :--- | :--- | :--- | :--- | :--- |
| **Discovery** | `T1046` | Network Service Scanning | Redis-backed port count sliding window (`PortScanDetector`) | 90% |
| **Credential Access** | `T1003.001` | LSASS Memory Dumping | Process Access heuristic & YAML Rule (`procdump.exe`, `mimikatz.exe`) | 95% |
| **Credential Access** | `T1110` | Password Brute Force | Redis authentication failure spike threshold (`LateralMovementDetector`) | 85% |
| **Command & Control** | `T1071.004` | DNS Tunneling & Exfiltration | Shannon Entropy analysis & TXT query ratio anomaly (`DNSAnomalyDetector`) | 90% |
| **Command & Control** | `T1568.002` | Domain Generation Algorithms (DGA) | Supervised Machine Learning (`RandomForestClassifier` on bigram features) | 96.4% |
| **Command & Control** | `T1071` | C2 Periodic Beaconing | Delta-timestamp variance & unsupervised `IsolationForest` anomaly scoring | 88% |
| **Lateral Movement** | `T1021` | Remote Services (Internal Pivot) | Post-compromise internal network connection tracking in graph | 90% |
| **Impact** | `T1486` | Data Encrypted for Impact | Rapid mass file extension modification heuristic (`RansomwareDetector`) | 95% |

---

## 📊 Performance Benchmarks & EPS Stress-Testing

CyberTrace-Graph includes a dedicated stress-testing and benchmarking harness (`scripts/benchmark_eps.py`) to validate sustained throughput and latency under enterprise log volume. Tested across **20,000 continuous security events**:

| Pipeline Subsystem | Workload | Sustained Throughput | Mean Latency | Median (p50) | p95 Latency | p99 Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Ingestion Gateway** *(Sysmon Normalization)* | 20,000 events | **146,270 EPS** | 0.007 ms | 0.006 ms | 0.009 ms | 0.016 ms |
| **Stream Processor** *(Rules + Detectors)* | 20,000 events | **34,433 EPS** | 0.029 ms | 0.012 ms | 0.046 ms | 0.582 ms |
| **Sliding Window State** *(Writes)* | 20,000 ops | **281,627 OPS** | 0.0036 ms | 0.0031 ms | 0.0051 ms | 0.0112 ms |
| **Sliding Window State** *(Queries)* | 6,667 queries | **126,339 OPS** | 0.0079 ms | 0.0061 ms | 0.0124 ms | 0.0401 ms |
| **Graph Micro-Batch Parameter Scaling** | Batch: 500 | **3,163,956 EPS** | 0.0003 ms | 0.0003 ms | 0.0003 ms | 0.0005 ms |

> 📄 **Full Benchmark Analysis**: Comprehensive latency distributions and detection efficacy breakdown available in [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md).

---

## 🚀 Core Platform Modules

### 1. Ingestion Gateway API (`junction_nodes/ingestion_gateway`)
* **Real-World Log Ingestion:** Accepts real Windows **Sysmon** JSON events (Event ID 1: Process Creation, Event ID 3: Network Connection, Event ID 10: Process Access / LSASS, Event ID 22: DNS Query) over HTTP.
* **Normalization Engine:** Maps vendor-specific schemas into standardized internal event payloads and routes them to partitioned Kafka topics (`apt.events.endpoint`, `apt.events.network`, `apt.events.dns`, `apt.events.auth`).
* **Edge Security:** Authenticated via Bearer API keys (`INGESTION_API_KEY`).

### 2. Multi-Tier Stream Processor (`junction_nodes/stream_processor`)
* **Machine Learning Models:**
  * **DGA Classifier:** Random Forest trained on domain length, vowel ratios, and character n-gram entropy (96.4% test accuracy).
  * **Network Anomaly Detector:** Unsupervised Isolation Forest isolating anomalous beaconing jitter and packet sizes.
* **Stateful Redis Sliding Windows (`state/redis_window.py`):** Replaces volatile in-memory queues with distributed Redis `ZSET` operations (`ZADD`, `ZREMRANGEBYSCORE`, `ZCARD`), ensuring detections survive container restarts and scale horizontally.
* **Dynamic YAML Rule Engine (`rules/engine.py`):** Declarative detection rules hot-loaded from the `rules/` directory without restarting the pipeline.

### 3. Correlation Engine & Graph Service (`junction_nodes/correlation_engine`)
* **Neo4j Micro-Batching:** Ingests events using parameterized Cypher `UNWIND $batch AS event` transactions, preventing database write-lock contention under heavy event volume.
* **Automated Graph TTL Pruning:** A scheduled background job automatically prunes un-alerted, benign IP/host nodes older than 7 days, maintaining a lean graph footprint.
* **Graph Detections:** Executes recursive multi-hop path traversal queries to detect kill chains, asset blast radius, and privilege escalation routes.

### 4. Active SOAR & Immutable Audit Engine (`dashboard/api/routers/soar.py`)
* **Active Remediation:** Executes containment actions:
  * 🛡️ **Block IP:** Invokes firewall APIs (Palo Alto / AWS WAF / Cloudflare) to quarantine malicious external or internal IPs.
  * 🔒 **Isolate Host:** Invokes EDR APIs (CrowdStrike / Defender) to disconnect compromised workstations from the corporate network.
  * ⚡ **Kill Process:** Terminates rogue malicious processes remotely via EDR live response.
* **Immutable Audit Trail:** Every action writes a persistent `(AuditLog)` and `(ResponseAction)` node into Neo4j linked to the user, timestamp, target, and justification for SOC 2 / ISO 27001 compliance.

### 5. SOC Analyst Command Center (`dashboard/frontend`)
* **Dark-Themed SOC Interface:** Built with React 19, Vite, Recharts, and Lucide.
* **Real-Time Alert Feed:** Server-Sent Events (SSE) push incoming alerts with zero polling delay.
* **Interactive Attack Topology:** Visualizes entity relationships, kill chains, and blast radius.
* **Actionable Alert Drawer:** Expand any alert to review evidence, inspect MITRE ATT&CK tags, and trigger one-click SOAR response actions.
* **Audit Log Viewer:** Dedicated compliance audit dashboard with real-time log streaming and search.

---

## 📂 Project Repository Structure

```
cybertrace-graph/
├── attack_simulator/               # Adversary emulation engine
│   ├── scenarios/                  # Modular attack generators (Port scan, Cred dump, Ransomware, etc.)
│   └── simulate_apt.py             # Multi-stage APT campaign orchestrator
│
├── dashboard/                      # Full-Stack SOC Command Center
│   ├── api/                        # FastAPI Control Plane
│   │   ├── core/                   # Security, JWT issuance, password hashing
│   │   ├── routers/                # Endpoints: alerts, graph, pipeline, stream, auth, soar
│   │   ├── services/               # Async Redis & Neo4j database drivers
│   │   └── main.py                 # Application lifecycle & middleware
│   └── frontend/                   # React 19 + Vite SOC Dashboard
│       ├── src/
│       │   ├── components/         # TopHeader, Sidebar, Navigation
│       │   ├── pages/              # Dashboard, Alerts (with SOAR Drawer), Graph, Timeline, Audit Log, Login
│       │   ├── api.js              # Authenticated API client with token interceptor
│       │   └── AuthContext.jsx     # Session & JWT state provider
│
├── junction_nodes/                 # Distributed Event Pipeline
│   ├── common/                     # Pydantic schemas, Kafka producers/consumers, shared config
│   ├── ingestion_gateway/          # HTTP Ingestion API for real Sysmon & external collectors
│   │   └── parsers/                # Windows Sysmon Event ID 1, 3, 10, 22 normalizers
│   ├── stream_processor/           # Detection & ML pipeline
│   │   ├── detectors/              # Beaconing, DNS anomaly, Port scan, Cred dump, Ransomware
│   │   ├── ml_models/              # Random Forest DGA & Isolation Forest engines
│   │   ├── rules/                  # Dynamic YAML/Sigma rule evaluation engine
│   │   └── state/                  # Redis-backed distributed sliding window primitives
│   └── correlation_engine/         # Graph database layer
│       ├── graph_service.py        # Neo4j UNWIND micro-batching, entity upsert, and graph pruning
│       ├── schema.py               # Neo4j constraints, indexes, and MITRE seed data
│       └── ingestor.py             # Event buffer & batch flush orchestrator
│
├── rules/                          # Production-ready YAML detection rules
│   ├── auth_brute_force_spike.yaml
│   ├── dns_high_txt_tunnel.yaml
│   ├── endpoint_lsass_dump.yaml
│   └── network_port_scan.yaml
│
├── docker-compose.yml              # Localhost-bound infrastructure (Kafka, Neo4j, Redis, Zookeeper)
├── .env.example                    # Template environment variables
└── README.md                       # Platform documentation
```

---

## ⚡ Quickstart Guide

### 1. Prerequisites
* **Docker Desktop** installed and running
* **Python 3.11+**
* **Node.js 18+** & `npm`

### 2. Clone & Setup Environment
```bash
git clone https://github.com/Vighnesh-07/CyberTrace-Graph.git
cd CyberTrace-Graph

# Create and configure .env
cp .env.example .env
```

### 3. Spin Up Core Infrastructure
```bash
docker compose up -d
```
*This starts Kafka (9092), Zookeeper (2181), Neo4j (7687/7474), Redis (6379), and Kafka-UI (8085) bound strictly to `127.0.0.1`.*

### 4. Launch the Backend API
```bash
# In Terminal 1
pip install -r dashboard/api/requirements.txt
set PYTHONPATH=%CD%
python -m uvicorn dashboard.api.main:app --port 8000 --reload
```

### 5. Launch the React SOC Dashboard
```bash
# In Terminal 2
cd dashboard/frontend
npm install
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser.
* **Username:** `admin`
* **Password:** `admin` *(or `cybertrace_admin_pass`)*

### 6. Run the Stream Processor & Ingest Data
```bash
# In Terminal 3: Start Stream Processor
set PYTHONPATH=%CD%
python -m junction_nodes.stream_processor.main

# In Terminal 4: Start Graph Ingestor
set PYTHONPATH=%CD%
python -m junction_nodes.correlation_engine.main

# In Terminal 5: Trigger Attack Simulation
set PYTHONPATH=%CD%
python attack_simulator/simulate_apt.py --scenario all
```

---

## 🧪 Automated Testing & CI/CD Verification

CyberTrace-Graph features an isolated, dependency-mocked unit and integration testing suite covering stream detectors, Sigma-style dynamic rules, Sysmon parsers, SOAR response actions, and benchmark harnesses.

### 1. Run the Full Test Suite (32 Tests)
The test suite executes in **`< 1.0 second`** without requiring running Docker/Redis/Neo4j containers:

```bash
# Windows PowerShell
$env:PYTHONPATH = (Get-Location).Path
pytest tests/ -v --tb=short

# Linux / macOS
export PYTHONPATH=$(pwd)
pytest tests/ -v --tb=short
```

### 2. Run High-Throughput EPS Stress-Test
```bash
# Benchmark all subsystems with 20,000 synthetic enterprise events
python scripts/benchmark_eps.py --mode all --count 20000

# Benchmark individual subsystems (pipeline, gateway, redis, or graph)
python scripts/benchmark_eps.py --mode pipeline --count 50000
```

### 3. Continuous Integration Pipeline
Every commit and pull request pushed to `main` triggers the automated GitHub Actions CI workflow (`.github/workflows/ci.yml`), validating dependencies across microservices and guaranteeing zero regression.

---

## 🔌 API Endpoints Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/token` | Issues JWT Bearer tokens | Public (OAuth2 Form) |
| `GET` | `/api/alerts` | Queries paginated alerts (Redis cache + Neo4j fallback) | Bearer Token |
| `POST` | `/api/alerts/{id}/status` | Updates alert lifecycle status | Bearer Token |
| `GET` | `/api/graph/topology` | Retrieves nodes and edges for attack graph rendering | Bearer Token |
| `GET` | `/api/graph/detections` | Evaluates multi-hop kill chain Cypher queries | Bearer Token |
| `GET` | `/api/stream/alerts` | Server-Sent Events (SSE) real-time alert stream | Token Query Param |
| `POST` | `/api/soar/block-ip` | Executes automated firewall block & logs audit event | Bearer Token |
| `POST` | `/api/soar/isolate-host` | Executes EDR host containment & logs audit event | Bearer Token |
| `POST` | `/api/soar/kill-process` | Executes remote process termination & logs audit event | Bearer Token |
| `GET` | `/api/soar/audit-log` | Queries immutable compliance audit records from Neo4j | Bearer Token |
| `POST` | `/api/v1/ingest/sysmon` | Ingests and normalizes live Windows Sysmon telemetry | Ingestion API Key |

---

## 📜 License & Acknowledgments

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

* Engineered for modern SecOps and Threat Hunting teams.
* MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
