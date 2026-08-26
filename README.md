<div align="center">

# CyberTrace-Graph

**Industry-Grade Distributed SIEM & XDR Threat Hunting Platform**

Real-time telemetry ingestion, machine-learning anomaly detection, and graph-based correlation. Detect advanced persistent threats (APTs) and lateral movement as they happen.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![React](https://img.shields.io/badge/React-18.2-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Neo4j](https://img.shields.io/badge/Neo4j-5.13-418BCA?style=for-the-badge&logo=neo4j&logoColor=white)](https://neo4j.com/)
[![Kafka](https://img.shields.io/badge/Kafka-7.5-black?style=for-the-badge&logo=apachekafka&logoColor=white)](https://kafka.apache.org/)

---

> *"Standard SIEMs treat logs as flat text. CyberTrace-Graph treats your network as a highly connected battlefield, automatically mapping out lateral movement and multi-stage attacks."*

</div>

---

## The Problem

Modern SOCs are drowning in alert fatigue. Legacy Security Information and Event Management (SIEM) tools struggle because they evaluate events in isolation. They are blind to:

- **Lateral Movement:** An attacker using stolen credentials to hop between internal machines.
- **Low and Slow Beaconing:** Command and Control (C2) traffic that blends in with normal network noise over days.
- **Multi-Stage APTs:** The connection between a phishing email (Initial Access) and a massive database dump (Exfiltration) a week later.

CyberTrace-Graph was built to close that gap by unifying streaming analytics with graph database technology.

---

## How It Works

The platform runs incoming telemetry through a sophisticated pipeline, transforming raw logs into a connected graph of malicious behavior.

```mermaid
flowchart TB
    subgraph INPUT["INPUT: Edge Sensors"]
        direction LR
        A["DNS Sensor"]
        B["Network Sensor"]
        C["Endpoint Sensor"]
    end

    subgraph PHASE_1["PHASE 1 -- HIGH-THROUGHPUT STREAMING"]
        direction TB
        D["1 -- Kafka Broker<br>Partitioned by IP"]
        E["2 -- Local Ring-Buffer<br>Partition tolerance"]
    end

    subgraph PHASE_2["PHASE 2 -- CORRELATION & DETECTION"]
        direction TB
        F["3 -- Stream Processor<br>Python/Faust"]
        G["4 -- ML Anomaly Engine<br>Isolation Forests"]
        H["5 -- Heuristic Detectors<br>Sliding Windows"]
        I["6 -- Graph Correlation<br>Neo4j Cypher Injection"]
    end

    subgraph OUTPUT["OUTPUT: SOC DASHBOARD"]
        J["FastAPI Backend<br>JWT Secured"]
        K["React UI<br>Vis.js Topology"]
        L["Real-Time Alerts<br>Server-Sent Events"]
    end

    A --> D
    B --> D
    C --> D
    D <--> E
    D --> F
    F --> G --> I
    F --> H --> I
    I --> J
    J --> K
    J --> L

    style INPUT fill:#1e293b,stroke:#475569,color:#f8fafc
    style PHASE_1 fill:#0f172a,stroke:#3b82f6,color:#93c5fd
    style PHASE_2 fill:#0f172a,stroke:#f59e0b,color:#fcd34d
    style OUTPUT fill:#1e293b,stroke:#22c55e,color:#86efac
```

---

## Pipeline Stages

### Phase 1: High-Throughput Streaming

| Stage | Name | Description |
|:-----:|------|-------------|
| **1** | **Kafka Backbone** | All telemetry is streamed through Apache Kafka. Events are partitioned by source IP address to guarantee ordered processing for stateful windowed analytics. |
| **2** | **Resilient Edge Nodes** | Python-based junction nodes deployed on edge devices use a local `collections.deque` ring-buffer to survive network partitions, automatically flushing to Kafka upon reconnection. |

### Phase 2: Correlation & Detection

| Stage | Name | Description |
|:-----:|------|-------------|
| **3** | **Graph DB Ingestion** | Uses Neo4j to store relational mappings. IPs, Domains, Users, and Processes are mapped as nodes. Edges represent interactions (`USER -> LOGGED_IN_TO -> HOST`). |
| **4** | **ML Anomaly Engine** | Deploys Scikit-Learn **Isolation Forests** to detect Domain Generation Algorithms (DGA) and DNS Tunneling by evaluating TXT query ratios and unique domain counts in real-time. |
| **5** | **Heuristic Engine** | Detects rapid Port Scans (T1046) and OS Credential Dumping via LSASS (T1003.001) using sliding time windows and command-line keyword matching. |
| **6** | **Ransomware Detection** | Evaluates file extensions and calculates **Shannon Entropy** spikes in file systems to detect active ransomware encryption (T1486) before critical data is lost. |

---

## Comparison with Industry Tools

> CyberTrace-Graph provides the graph-based lateral movement detection of advanced XDRs with the streaming capabilities of modern SIEMs.

| Capability | CyberTrace-Graph | Splunk Enterprise | Microsoft Sentinel | CrowdStrike Falcon |
|:-----------|:---------------------:|:-----:|:----:|:----------:|
| Real-Time Event Streaming | Yes | Yes | Yes | Yes |
| Native Graph Database (Neo4j) | **Yes** | No | No | Yes (Threat Graph) |
| Built-in ML Anomaly Detection | **Yes** | Paid Add-on | Yes | Yes |
| Visual Attack Path Topology | **Yes** | Requires App | Partial | Yes |
| Edge Node Partition Tolerance | **Yes** | No | No | Yes |
| Built-in Adversary Simulator | **Yes** | No | No | No |
| Shannon Entropy Ransomware Checks | **Yes** | No | Custom Queries | Yes |
| Free / Open Source | **Yes** | Enterprise Pricing | Pay-as-you-go | Enterprise Pricing |

---

## 🛡️ Military-Grade Security Architecture

Unlike many open-source prototypes, CyberTrace-Graph secures its own infrastructure:
- **Zero Hardcoded Secrets:** All credentials (Neo4j, JWT salts) are strictly injected via `.env`.
- **Network Isolation:** Internal data stores (Kafka, Neo4j, Redis, Zookeeper) are strictly bound to `127.0.0.1` and the internal Docker bridge network. They are invisible to external network adapters.
- **Cryptographic Auth:** The FastAPI backend utilizes OAuth2 with JWT (JSON Web Tokens). All API endpoints and Server-Sent Event (SSE) streams require strict Bearer token validation.

---

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.11+
- Node.js (for Dashboard)

### 1. Initialize Configuration
```bash
cp .env.example .env
# Edit .env with your secure passwords!
```

### 2. Start the Secure Infrastructure
```bash
docker-compose up -d
```

### 3. Launch the Stream Processor
```bash
# Windows
$env:PYTHONPATH="."
$env:PYTHONUTF8="1"
python -m junction_nodes.stream_processor.main
```

### 4. Start the SOC Dashboard
```bash
# Terminal 1: Backend API
python -m uvicorn dashboard.api.main:app --reload --port 8000

# Terminal 2: React Frontend
cd dashboard/frontend
npm install
npm run dev
```

### 5. Run an Attack Simulation
```bash
# Test the ML and Heuristic engines!
python -m attack_simulator.simulate_apt ransomware --output kafka
python -m attack_simulator.simulate_apt cred-dump --output kafka
python -m attack_simulator.simulate_apt port-scan --output kafka
```

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
