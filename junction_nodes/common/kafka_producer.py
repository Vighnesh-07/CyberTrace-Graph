import logging
from collections import deque
from confluent_kafka import Producer, KafkaError
from typing import Optional
from .config import KafkaConfig
from .models.events import SecurityEvent

logger = logging.getLogger(__name__)

class KafkaEventProducer:
    def __init__(self, config: KafkaConfig, max_buffer_size: int = 10000):
        self.config = config
        self.producer = Producer({
            'bootstrap.servers': config.bootstrap_servers,
            'client.id': config.client_id,
            'compression.type': config.compression_type,
            'batch.size': config.batch_size,
            'linger.ms': config.linger_ms,
            'acks': config.acks
        })
        self.buffer = deque(maxlen=max_buffer_size)
        self.events_sent = 0
        self.events_failed = 0
        self.events_buffered = 0

    def delivery_callback(self, err, msg):
        if err is not None:
            logger.error(f"Failed to deliver message: {err}")
            self.events_failed += 1
        else:
            self.events_sent += 1
            logger.debug(f"Message delivered to {msg.topic()} [{msg.partition()}]")

    def produce(self, topic: str, event: SecurityEvent):
        try:
            self._drain_buffer(topic)
            self.producer.produce(
                topic,
                key=event.to_kafka_key(),
                value=event.to_kafka_value(),
                callback=self.delivery_callback
            )
            self.producer.poll(0)
        except BufferError:
            logger.warning("Local Kafka producer queue is full, buffering locally.")
            self.buffer.append(event)
            self.events_buffered += 1
        except Exception as e:
            logger.error(f"Error producing event: {e}")
            self.buffer.append(event)
            self.events_buffered += 1

    def _drain_buffer(self, topic: str):
        while self.buffer:
            event = self.buffer[0]
            try:
                self.producer.produce(
                    topic,
                    key=event.to_kafka_key(),
                    value=event.to_kafka_value(),
                    callback=self.delivery_callback
                )
                self.buffer.popleft()
                self.events_buffered -= 1
            except BufferError:
                break
            except Exception as e:
                logger.error(f"Error draining buffer: {e}")
                break

    def flush(self, timeout: float = 5.0):
        logger.info(f"Flushing Kafka producer. Timeout: {timeout}s")
        self.producer.flush(timeout)

    def close(self):
        logger.info("Closing Kafka producer.")
        self.flush()

    def health_check(self) -> bool:
        try:
            # list_topics is a blocking call to get cluster metadata
            self.producer.list_topics(timeout=3.0)
            return True
        except Exception as e:
            logger.error(f"Kafka health check failed: {e}")
            return False
