import logging
import time
import threading
from junction_nodes.common.config import KafkaConfig, Neo4jConfig
from junction_nodes.stream_processor.consumer import KafkaEventConsumer
from junction_nodes.correlation_engine.graph_service import GraphService
from junction_nodes.correlation_engine.detectors import GraphDetector

logger = logging.getLogger(__name__)

class GraphIngestor:
    """Consumes enriched events and alerts from Kafka and writes them to Neo4j.
    
    Also periodically runs graph-based detection queries.
    """
    
    def __init__(self, kafka_config: KafkaConfig, neo4j_config: Neo4jConfig,
                 group_id: str = "cybertrace-graph-ingestor-01",
                 input_topics: list = None,
                 detection_interval: int = 300,
                 batch_size: int = 500,
                 batch_timeout: float = 1.0):
        self.input_topics = input_topics or ["apt.events.enriched", "apt.alerts.raw"]
        self.consumer = KafkaEventConsumer(kafka_config, group_id, self.input_topics)
        self.graph_service = GraphService(neo4j_config)
        self.graph_service.initialize_schema()
        self.detector = GraphDetector(self.graph_service)
        self.detection_interval = detection_interval
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        
        self.event_buffer = []
        self._last_flush_time = time.time()
        self._last_prune_time = time.time()
        
        self._running = False
        self._stats = {
            "events_ingested": 0,
            "alerts_ingested": 0,
            "errors": 0,
            "detections_run": 0,
        }
        self._last_detection_time = 0.0
    
    def _is_alert(self, event_dict: dict) -> bool:
        """Determine if an event is an alert or an enriched event."""
        return "alert_id" in event_dict or "alert_type" in event_dict
    
    def _maybe_run_detections(self):
        """Run graph detections periodically."""
        now = time.time()
        if now - self._last_detection_time >= self.detection_interval:
            self._last_detection_time = now
            self._stats["detections_run"] += 1
            try:
                results = self.detector.run_all_detections()
                total_findings = sum(len(v) for v in results.values())
                if total_findings > 0:
                    logger.warning(f"🚨 Graph detection found {total_findings} findings!")
                    for category, findings in results.items():
                        if findings:
                            logger.warning(f"  {category}: {len(findings)} findings")
                            for f in findings[:3]:  # Log first 3
                                logger.warning(f"    → {f}")
            except Exception as e:
                logger.error(f"Error running graph detections: {e}")
                
        # Also maybe prune graph every 1 hour
        if now - self._last_prune_time >= 3600:
            self._last_prune_time = now
            try:
                self.graph_service.prune_stale_graph(days=7)
            except Exception as e:
                logger.error(f"Error pruning graph: {e}")

    def _flush_buffer(self):
        """Flush buffered events to Neo4j in a batch."""
        if not self.event_buffer:
            return
            
        try:
            self.graph_service.batch_upsert_events(self.event_buffer)
            self._stats["events_ingested"] += len(self.event_buffer)
        except Exception as e:
            logger.error(f"Error during batch upsert: {e}")
            self._stats["errors"] += 1
            
        self.event_buffer.clear()
        self._last_flush_time = time.time()

    def run(self):
        """Main ingestor loop."""
        self._running = True
        self._last_detection_time = time.time()
        logger.info(f"Graph Ingestor started. Consuming from: {self.input_topics}")
        logger.info(f"Detection interval: {self.detection_interval}s")
        
        while self._running:
            event = self.consumer.consume(timeout=self.batch_timeout)
            now = time.time()
            
            if event:
                try:
                    if self._is_alert(event):
                        self.graph_service.ingest_alert(event)
                        self._stats["alerts_ingested"] += 1
                    else:
                        self.event_buffer.append(event)
                except Exception as e:
                    logger.error(f"Error processing event: {e}")
                    self._stats["errors"] += 1
            
            if len(self.event_buffer) >= self.batch_size or (now - self._last_flush_time) >= self.batch_timeout:
                self._flush_buffer()
            
            self._maybe_run_detections()
            
            total = self._stats["events_ingested"] + self._stats["alerts_ingested"]
            if total > 0 and total % 500 == 0:
                logger.info(f"📊 Ingestor stats: {self._stats}")
                graph_stats = self.graph_service.get_stats()
                logger.info(f"📊 Graph stats: {graph_stats}")
    
    def stop(self):
        """Gracefully stop the ingestor."""
        self._running = False
        self._flush_buffer()
        self.consumer.close()
        self.graph_service.close()
        logger.info(f"Graph Ingestor stopped. Final stats: {self._stats}")
