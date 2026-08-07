"""CyberTrace-Graph Correlation Engine — Entry Point."""

import argparse
import logging
import signal
import sys
from pathlib import Path
import yaml

from junction_nodes.common.config import KafkaConfig, Neo4jConfig
from junction_nodes.correlation_engine.ingestor import GraphIngestor

BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║     ____            _                                    ║
║    / ___|___  _ __ | |_ _ __ __ _  ___ ___               ║
║   | |   / _ \| '_ \| __| '__/ _` |/ __/ _ \              ║
║   | |__| (_) | | | | |_| | | (_| | (_|  __/              ║
║    \____\___/|_| |_|\__|_|  \__,_|\___\___|              ║
║                                                          ║
║     CyberTrace-Graph — Correlation Engine Node           ║
╚══════════════════════════════════════════════════════════╝
"""

ingestor = None

def handle_signal(sig, frame):
    logging.info(f"Received signal {sig}. Stopping ingestor...")
    if ingestor:
        ingestor.stop()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Correlation Engine Node")
    parser.add_argument("--config", type=str, default="junction_nodes/correlation_engine/config.yaml")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Config file not found at {config_path}")
        sys.exit(1)

    with open(config_path, "r") as f:
        config_dict = yaml.safe_load(f)

    log_level = config_dict.get("processor", {}).get("log_level", "INFO")
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger(__name__)

    print(BANNER)
    logger.info("Initializing Correlation Engine...")

    kafka_cfg = config_dict.get("kafka", {})
    kafka_config = KafkaConfig(bootstrap_servers=kafka_cfg.get("bootstrap_servers", "localhost:9092"))

    neo4j_cfg = config_dict.get("neo4j", {})
    neo4j_config = Neo4jConfig(
        uri=neo4j_cfg.get("uri", "bolt://localhost:7687"),
        user=neo4j_cfg.get("user", "neo4j"),
        password=neo4j_cfg.get("password", "apthunter2024")
    )

    group_id = config_dict.get("processor", {}).get("group_id", "cybertrace-graph-ingestor-01")
    input_topics = config_dict.get("input_topics", ["apt.events.enriched", "apt.alerts.raw"])
    detection_interval = config_dict.get("processor", {}).get("detection_interval", 300)

    global ingestor
    ingestor = GraphIngestor(
        kafka_config=kafka_config,
        neo4j_config=neo4j_config,
        group_id=group_id,
        input_topics=input_topics,
        detection_interval=detection_interval
    )

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        ingestor.run()
    except Exception as e:
        logger.error(f"Ingestor crashed: {e}")
        if ingestor:
            ingestor.stop()
        sys.exit(1)

if __name__ == "__main__":
    main()
