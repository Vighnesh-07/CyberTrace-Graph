"""CyberTrace-Graph Stream Processor — Entry Point."""

import argparse
import logging
import signal
import sys
from pathlib import Path
import yaml

from junction_nodes.common.config import KafkaConfig
from junction_nodes.stream_processor.pipeline import ProcessingPipeline

BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║     ____            _                                    ║
║    / ___|___  _ __ | |_ _ __ __ _  ___ ___               ║
║   | |   / _ \| '_ \| __| '__/ _` |/ __/ _ \              ║
║   | |__| (_) | | | | |_| | | (_| | (_|  __/              ║
║    \____\___/|_| |_|\__|_|  \__,_|\___\___|              ║
║                                                          ║
║       CyberTrace-Graph — Stream Processor Node           ║
╚══════════════════════════════════════════════════════════╝
"""

pipeline = None

def handle_signal(sig, frame):
    logging.info(f"Received signal {sig}. Stopping pipeline...")
    if pipeline:
        pipeline.stop()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Stream Processor Node")
    parser.add_argument("--config", type=str, default="junction_nodes/stream_processor/config.yaml", help="Path to YAML config file")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Config file not found at {config_path}")
        sys.exit(1)

    with open(config_path, "r") as f:
        config_dict = yaml.safe_load(f)

    log_level_str = config_dict.get("processor", {}).get("log_level", "INFO")
    logging.basicConfig(level=getattr(logging, log_level_str.upper(), logging.INFO),
                        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    
    logger = logging.getLogger(__name__)
    
    print(BANNER)
    logger.info("Initializing Stream Processor...")

    kafka_config_dict = config_dict.get("kafka", {})
    kafka_config = KafkaConfig(
        bootstrap_servers=kafka_config_dict.get("bootstrap_servers", "localhost:9092"),
    )

    global pipeline
    pipeline = ProcessingPipeline(kafka_config=kafka_config, processor_config=config_dict)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        pipeline.run()
    except Exception as e:
        logger.error(f"Pipeline crashed: {e}")
        if pipeline:
            pipeline.stop()
        sys.exit(1)

if __name__ == "__main__":
    main()
