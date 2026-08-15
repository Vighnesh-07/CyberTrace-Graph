<div align="center">
  
# 🛡️ CyberTrace-Graph
**Next-Generation Distributed SOC Analytics & XDR Platform**

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/react-18.0%2B-blueviolet.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Neo4j](https://img.shields.io/badge/Neo4j-Graph_DB-4285F4.svg)](https://neo4j.com/)
[![Kafka](https://img.shields.io/badge/Apache_Kafka-Streaming-231F20.svg)](https://kafka.apache.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CyberTrace-Graph is an industry-grade, distributed cybersecurity threat hunting platform designed to identify Advanced Persistent Threats (APTs) in real-time. By combining high-throughput event streaming, machine learning-driven anomaly detection, and graph-based correlation, CyberTrace-Graph empowers modern Security Operations Center (SOC) teams to visualize and mitigate complex, multi-stage attacks.

[Features](#-key-features) • [Architecture](#-architecture) • [Getting Started](#-quick-start) • [Attack Simulation](#-attack-simulation)

---
</div>

## 🌟 Key Features

*   **Real-Time Stream Processing**: Ingests high-volume security telemetry (DNS, Network, Auth) via **Apache Kafka** with sub-millisecond latency.
*   **Machine Learning Detection**: Built-in `IsolationForest` models and heuristic detectors automatically flag anomalies such as Beaconing, DGA domains, and Brute Force lateral movement.
*   **Graph-Based Correlation**: Attack paths are dynamically modeled in **Neo4j**, transforming isolated alerts into a cohesive, visual "Kill Chain".
*   **Modern SOC Dashboard**: A beautiful, premium **React (Recharts)** frontend providing analysts with real-time severity distributions, MITRE ATT&CK technique rankings, and volume time-series charts.
*   **Role-Based Access Control (RBAC)**: Secure Mock JWT implementation separating `Admin` and `Analyst` capabilities for alert investigation and resolution.

## 🏗️ Architecture

CyberTrace-Graph utilizes a highly decoupled microservices architecture:

1.  **Junction Nodes (Sensors)**: Edge nodes that capture and forward network events to Kafka topics (`apt.events.dns`, `apt.events.network`, etc.).
2.  **Stream Processor & ML Engine**: Consumes from Kafka, runs data through Machine Learning models (Isolation Forest) and deterministic rules, and publishes findings to Redis.
3.  **Correlation Engine**: Consumes alerts, maps relationships (IPs, Domains, Users), and persists the attack graph into Neo4j.
4.  **Backend API**: A blazing-fast **FastAPI** service that provides complex Cypher query aggregations.
5.  **Frontend Dashboard**: A **Vite + React** Single Page Application designed for SOC Analysts.

## 🚀 Quick Start

### Prerequisites
*   Docker and Docker Compose
*   Python 3.11+
*   Node.js v18+ & npm
*   `make` utility (Optional, but recommended)

### 1. Spin up the Infrastructure
Start the core distributed systems (Kafka, Zookeeper, Neo4j, Redis):
```bash
docker-compose up -d
```

### 2. Initialize the Python Backend
Install dependencies and create the required Kafka topics:
```bash
pip install -r dashboard/api/requirements.txt
pip install -r junction_nodes/stream_processor/requirements.txt

# Create Kafka topics
python scripts/create_topics.py
```

### 3. Start the Engines
You'll need a few terminal windows for this to replicate the microservices environment:

**Terminal 1 (Backend API)**
```bash
cd dashboard/api
uvicorn main:app --reload --port 8000
```

**Terminal 2 (Stream Processor)**
```bash
export PYTHONPATH=$(pwd)
python -m junction_nodes.correlation_engine.main
```

**Terminal 3 (Frontend Dashboard)**
```bash
cd dashboard/frontend
npm install
npm run dev
```

The SOC Dashboard will now be live at `http://localhost:5173`. 
*(Demo credentials: `admin:admin` or `analyst:analyst`)*

## 🎯 Attack Simulation

To see the platform in action, you can generate synthetic APT traffic that will flow through the entire system and appear on your dashboard.

**Simulate a Multi-Stage Kill Chain (Brute Force ➔ Lateral Movement ➔ Exfiltration):**
```bash
export PYTHONPATH=$(pwd)
python attack_simulator/simulate_apt.py kill-chain --output kafka
```

**Simulate a Low-and-Slow DNS Tunneling Attack:**
```bash
export PYTHONPATH=$(pwd)
python attack_simulator/simulate_apt.py dns-tunnel --duration 300 --output kafka
```

## 📁 Project Structure

```text
cybertrace-graph/
├── attack_simulator/      # Scenario-based APT traffic simulation
├── dashboard/             
│   ├── api/               # FastAPI Backend (Neo4j/Redis interfaces)
│   └── frontend/          # React/Vite SOC Dashboard
├── junction_nodes/        # Distributed Processors
│   ├── common/            # Shared Kafka models
│   ├── correlation_engine/# Neo4j Graph ingestion
│   └── stream_processor/  # ML Models (Isolation Forest, DGA detection)
├── scripts/               # Infrastructure setup scripts
├── tests/                 # Unit testing
└── docker-compose.yml     # Infrastructure definitions
```

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
