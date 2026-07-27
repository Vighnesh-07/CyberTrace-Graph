import json
import logging
from typing import Optional, List, Dict, Any

from confluent_kafka import Consumer, KafkaError, KafkaException
from junction_nodes.common.config import KafkaConfig

logger = logging.getLogger(__name__)

class KafkaEventConsumer:
    """Consumes SecurityEvents from Kafka topics.
    
    Uses confluent_kafka.Consumer with consumer group for
    scalable, fault-tolerant event consumption.
    """
    
    def __init__(self, config: KafkaConfig, group_id: str, topics: List[str]):
        self.config = config
        self.consumer = Consumer({
            'bootstrap.servers': config.bootstrap_servers,
            'group.id': group_id,
            'auto.offset.reset': 'latest',
            'enable.auto.commit': True,
            'auto.commit.interval.ms': 5000,
        })
        self.consumer.subscribe(topics)
        self._running = True
        self.events_consumed = 0
        self.events_errors = 0
    
    def consume(self, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """Poll for the next event. Returns parsed event dict or None."""
        try:
            msg = self.consumer.poll(timeout)
            if msg is None:
                return None
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    logger.debug(f"Reached end of partition: {msg.topic()} [{msg.partition()}] at offset {msg.offset()}")
                else:
                    self.events_errors += 1
                    logger.error(f"Kafka error: {msg.error()}")
                return None
            
            value = msg.value()
            if value:
                parsed_value = json.loads(value.decode('utf-8'))
                self.events_consumed += 1
                return parsed_value
            return None
        except Exception as e:
            self.events_errors += 1
            logger.error(f"Error consuming message: {e}")
            return None
    
    def consume_batch(self, max_messages: int = 100, timeout: float = 1.0) -> List[Dict[str, Any]]:
        """Consume up to max_messages events."""
        events = []
        for _ in range(max_messages):
            event = self.consume(timeout=timeout / max_messages)
            if event:
                events.append(event)
            else:
                break
        return events
    
    def close(self):
        """Close consumer connection."""
        self._running = False
        self.consumer.close()
