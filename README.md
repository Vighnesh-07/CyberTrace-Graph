# CyberTrace-Graph

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)

CyberTrace-Graph is a distributed cybersecurity threat hunting platform designed to identify Advanced Persistent Threats (APTs) in real-time. By leveraging Kafka for high-throughput event streaming, Apache Flink for real-time correlation, and Neo4j for attack graph modeling, CyberTrace-Graph provides a robust and scalable architecture for modern SOC teams.

## 🌟 Key Features
- **Distributed Junction Nodes:** Scalable sensors (DNS, Network, Endpoint, Cloud) that feed high-volume security telemetry into Kafka.
- **Resilient Delivery:** Built-in ring-buffer fault tolerance for edge nodes during network partitions.
- **Graph-based Correlation:** Attack paths are modeled in Neo4j to visualize lateral movement and complex multi-stage attacks.
- **Real-time Stream Processing:** Stateful windowed analytics to detect beaconing, data exfiltration, and DGA anomalies.

## 📖 Documentation
- [Architecture Guide](ARCHITECTURE.md) - Deep dive into the system design and data flow.
- [Contributing](CONTRIBUTING.md) - Guidelines for contributing to the repository.
- [Code of Conduct](CODE_OF_CONDUCT.md) - Community rules.
- [Security Policy](SECURITY.md) - Reporting vulnerabilities.

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.11+
- `make` utility

### Local Environment Setup

1. **Start the Infrastructure**
   ```bash
   make up
   ```
   *This starts Kafka, Zookeeper, Neo4j, Redis, and Kafka-UI.*

2. **Initialize Kafka Topics**
   ```bash
   pip install confluent-kafka
   make create-topics
   ```

3. **Run a Sensor Node (e.g., DNS)**
   ```bash
   pip install -r junction_nodes/dns_sensor/requirements.txt
   make run-dns-sensor
   ```

4. **Run the Attack Simulator**
   ```bash
   make run-simulator
   ```

## 🏗️ Project Structure

```text
cybertrace-graph/
├── attack_simulator/      # Scenario-based APT traffic simulation
├── junction_nodes/        # Sensor implementations
│   ├── common/            # Shared models and Kafka configurations
│   ├── dns_sensor/        # DNS capture and anomaly detection
├── scripts/               # Utility scripts for infrastructure management
├── tests/                 # Pytest suites
├── docker-compose.yml     # Container orchestration
├── Makefile               # Task automation
└── README.md
```

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
