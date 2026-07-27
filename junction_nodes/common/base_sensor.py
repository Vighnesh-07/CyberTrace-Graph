import asyncio
import signal
import logging
import time
import psutil
from abc import ABC, abstractmethod
from typing import AsyncGenerator

from .config import SensorConfig
from .kafka_producer import KafkaEventProducer
from .models.events import SecurityEvent, HeartbeatEvent

logger = logging.getLogger(__name__)

class BaseSensor(ABC):
    def __init__(self, config: SensorConfig, producer: KafkaEventProducer):
        self.config = config
        self.producer = producer
        self.is_running = False
        self.start_time = time.time()
        self.events_processed = 0
        self.events_dropped = 0
        self._setup_signal_handlers()

    @abstractmethod
    async def capture(self) -> AsyncGenerator[SecurityEvent, None]:
        """Yields security events from the data source."""
        yield  # type: ignore

    def _setup_signal_handlers(self):
        def handle_signal(sig, frame):
            logger.info(f"Received signal {sig}. Shutting down gracefully...")
            self.is_running = False

        try:
            signal.signal(signal.SIGINT, handle_signal)
            signal.signal(signal.SIGTERM, handle_signal)
        except ValueError:
            # Signals might not work in some non-main threads or on Windows without proper handling
            pass

    async def _send_heartbeat(self):
        while self.is_running:
            try:
                await asyncio.sleep(self.config.heartbeat_interval_sec)
                
                process = psutil.Process()
                uptime = time.time() - self.start_time
                cpu_percent = process.cpu_percent()
                memory_mb = process.memory_info().rss / (1024 * 1024)
                
                buffer_usage = 0.0
                if self.producer.buffer.maxlen:
                    buffer_usage = (len(self.producer.buffer) / self.producer.buffer.maxlen) * 100

                heartbeat = HeartbeatEvent(
                    sensor_id=self.config.sensor_id,
                    sensor_type=self.config.sensor_type.value,
                    uptime_seconds=uptime,
                    events_processed=self.events_processed,
                    events_dropped=self.events_dropped,
                    buffer_usage_percent=buffer_usage,
                    cpu_percent=cpu_percent,
                    memory_mb=memory_mb
                )
                
                self.producer.produce("apt.system.heartbeat", heartbeat)
                logger.debug(f"Heartbeat sent for {self.config.sensor_id}")
            except Exception as e:
                logger.error(f"Error sending heartbeat: {e}")

    async def run(self):
        self.is_running = True
        logger.info(f"Starting {self.config.sensor_type.value} sensor: {self.config.sensor_id}")
        
        heartbeat_task = asyncio.create_task(self._send_heartbeat())
        
        try:
            async for event in self.capture():
                if not self.is_running:
                    break
                try:
                    self.producer.produce("security-events", event)
                    self.events_processed += 1
                except Exception as e:
                    logger.error(f"Failed to process event: {e}")
                    self.events_dropped += 1
        except Exception as e:
            logger.error(f"Capture loop error: {e}")
        finally:
            self.is_running = False
            heartbeat_task.cancel()
            self.producer.close()
            logger.info("Sensor shutdown complete.")
