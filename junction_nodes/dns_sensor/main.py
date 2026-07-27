"""
DNS Sensor Junction Node — Entry Point.

Starts the DNS capture engine, connects to Kafka, and streams
DNS events to the `apt.events.dns` topic in real-time.

Usage:
    python main.py --config config.yaml
"""

import argparse
import asyncio
import logging
import sys
import time
from pathlib import Path

import yaml

from junction_nodes.common.config import KafkaConfig, SensorConfig, AppConfig
from junction_nodes.common.kafka_producer import KafkaEventProducer
from junction_nodes.common.models.events import HeartbeatEvent, EventType
from junction_nodes.dns_sensor.dns_capture import DNSCaptureEngine

logger = logging.getLogger(__name__)

BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║       ____  _   _ ____    ____                           ║
║      |  _ \| \ | / ___|  / ___|  ___ _ __  ___  ___  _ __║
║      | | | |  \| \___ \  \___ \ / _ \ '_ \/ __|/ _ \| '__|
║      | |_| | |\  |___) |  ___) |  __/ | | \__ \ (_) | |  ║
║      |____/|_| \_|____/  |____/ \___|_| |_|___/\___/|_|  ║
║                                                          ║
║         CyberTrace-Graph - DNS Junction Node       ║
╚══════════════════════════════════════════════════════════╝
"""


def load_yaml_config(config_path: str) -> dict:
    """Load configuration from YAML file."""
    path = Path(config_path)
    if not path.exists():
        logger.warning("Config file not found: %s. Using defaults.", config_path)
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def setup_logging(level: str = "INFO"):
    """Configure structured logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def heartbeat_loop(
    producer: KafkaEventProducer,
    sensor_id: str,
    interval: int,
    start_time: float,
    stats: dict,
):
    """Periodically send heartbeat events to Kafka."""
    while True:
        try:
            await asyncio.sleep(interval)
            heartbeat = HeartbeatEvent(
                sensor_id=sensor_id,
                sensor_type="DNS",
                event_type=EventType.HEARTBEAT,
                uptime_seconds=time.time() - start_time,
                events_processed=stats.get("events_sent", 0),
                events_dropped=stats.get("events_dropped", 0),
                buffer_usage_percent=(
                    len(producer.buffer) / producer.buffer.maxlen * 100
                    if producer.buffer.maxlen
                    else 0.0
                ),
            )
            producer.produce("apt.system.heartbeat", heartbeat)
            logger.debug("Heartbeat sent (uptime=%.0fs)", heartbeat.uptime_seconds)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Heartbeat error: %s", e)


async def main():
    parser = argparse.ArgumentParser(description="DNS Sensor Junction Node")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to sensor configuration file (default: config.yaml)",
    )
    args = parser.parse_args()

    # Load configuration
    config_dict = load_yaml_config(args.config)
    sensor_cfg = config_dict.get("sensor", {})
    kafka_cfg = config_dict.get("kafka", {})
    dns_cfg = config_dict.get("dns_capture", {})

    setup_logging(sensor_cfg.get("log_level", "INFO"))

    print(BANNER)

    sensor_id = sensor_cfg.get("sensor_id", "dns-sensor-01")
    mode = "Simulated" if dns_cfg.get("simulated_mode", True) else "Live"

    logger.info("=" * 50)
    logger.info("Sensor ID   : %s", sensor_id)
    logger.info("Mode        : %s", mode)
    logger.info("Kafka       : %s", kafka_cfg.get("bootstrap_servers", "localhost:9092"))
    logger.info("EPS Target  : %d", dns_cfg.get("simulated_eps", 10))
    logger.info("=" * 50)

    # Initialize Kafka producer
    kafka_config = KafkaConfig(**kafka_cfg)
    producer = KafkaEventProducer(
        config=kafka_config,
        max_buffer_size=sensor_cfg.get("buffer_max_size", 10000),
    )

    # Check Kafka connectivity
    if producer.health_check():
        logger.info("✅ Kafka connection established")
    else:
        logger.warning("⚠️  Kafka not reachable. Events will be buffered locally.")

    # Initialize DNS capture engine
    engine = DNSCaptureEngine(dns_cfg, sensor_id)

    # Start heartbeat in background
    start_time = time.time()
    stats = {"events_sent": 0, "events_dropped": 0}
    heartbeat_task = asyncio.create_task(
        heartbeat_loop(
            producer,
            sensor_id,
            sensor_cfg.get("heartbeat_interval_sec", 30),
            start_time,
            stats,
        )
    )

    # Main capture loop
    try:
        async for event in engine.capture():
            try:
                producer.produce("apt.events.dns", event)
                stats["events_sent"] += 1

                if stats["events_sent"] % 100 == 0:
                    logger.info(
                        "📊 DNS events sent: %d | Failed: %d | Buffered: %d",
                        stats["events_sent"],
                        producer.events_failed,
                        len(producer.buffer),
                    )
            except Exception as e:
                logger.error("Failed to produce event: %s", e)
                stats["events_dropped"] += 1

    except KeyboardInterrupt:
        logger.info("🛑 Keyboard interrupt received")
    except Exception as e:
        logger.error("Capture loop error: %s", e)
    finally:
        heartbeat_task.cancel()
        producer.flush(timeout=5.0)
        producer.close()
        elapsed = time.time() - start_time
        logger.info("=" * 50)
        logger.info("Shutdown complete.")
        logger.info("  Total events sent   : %d", stats["events_sent"])
        logger.info("  Total events dropped: %d", stats["events_dropped"])
        logger.info("  Uptime              : %.1f seconds", elapsed)
        logger.info("=" * 50)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
