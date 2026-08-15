"""
Main stream processing pipeline for CyberTrace-Graph.

Consumes raw security events from Kafka, enriches them with
GeoIP and threat intel data, runs detection algorithms (including
ML-powered models), and produces alerts to output topics.

Pipeline stages:
1. Consume raw events from apt.events.* topics
2. Enrich with GeoIP data
3. Match against threat intelligence feeds
4. Run through detection algorithms (beaconing, DNS anomaly, ML models)
5. Produce enriched events to downstream topics
6. Produce alerts to apt.alerts.raw topic
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

from junction_nodes.common.config import KafkaConfig
from junction_nodes.common.kafka_producer import KafkaEventProducer
from junction_nodes.stream_processor.consumer import KafkaEventConsumer
from junction_nodes.stream_processor.models.alerts import EnrichedEvent, AlertEvent
from junction_nodes.stream_processor.enrichment.geoip import GeoIPService
from junction_nodes.stream_processor.enrichment.threat_intel import ThreatIntelService
from junction_nodes.stream_processor.detectors.beaconing import BeaconingDetector
from junction_nodes.stream_processor.detectors.dns_anomaly import DNSAnomalyDetector

from junction_nodes.stream_processor.detectors.brute_force import LateralMovementDetector

logger = logging.getLogger(__name__)


class ProcessingPipeline:
    """Main stream processing pipeline.

    Consumes raw security events from Kafka, enriches them with
    GeoIP and threat intel data, runs ML-powered detection algorithms,
    and produces alerts to output topics.
    """

    def __init__(self, kafka_config: KafkaConfig, processor_config: dict):
        group_id = processor_config.get("processor", {}).get(
            "group_id", "cybertrace-processor-01"
        )
        input_topics = processor_config.get(
            "input_topics",
            ["apt.events.dns", "apt.events.network", "apt.events.endpoint", "apt.events.auth"],
        )
        self.output_topics = processor_config.get(
            "output_topics",
            {"alerts": "apt.alerts.raw", "enriched": "apt.events.enriched"},
        )

        # Kafka I/O
        self.consumer = KafkaEventConsumer(kafka_config, group_id, input_topics)
        self.producer = KafkaEventProducer(kafka_config)

        # Enrichment services
        self.geoip_service = GeoIPService()
        self.threat_intel_service = ThreatIntelService()

        # ── ML Models ───────────────────────────────────────────────────
        self.dga_classifier = None
        self.anomaly_detector = None
        self._init_ml_models(processor_config)

        # ── Detection engines ───────────────────────────────────────────
        detector_cfg = processor_config.get("detectors", {})

        beacon_cfg = detector_cfg.get("beaconing", {})
        self.beaconing_detector = BeaconingDetector(
            window_seconds=beacon_cfg.get("window_seconds", 300),
            min_samples=beacon_cfg.get("min_samples", 5),
            cv_threshold=beacon_cfg.get("cv_threshold", 0.3),
            anomaly_detector=self.anomaly_detector,
        )

        dns_cfg = detector_cfg.get("dns_anomaly", {})
        self.dns_detector = DNSAnomalyDetector(
            window_seconds=dns_cfg.get("window_seconds", 300),
            max_unique_domains=dns_cfg.get("max_unique_domains", 100),
            max_query_rate=dns_cfg.get("max_query_rate", 200),
            txt_ratio_threshold=dns_cfg.get("txt_ratio_threshold", 0.3),
            nxdomain_ratio_threshold=dns_cfg.get("nxdomain_ratio_threshold", 0.5),
            dga_classifier=self.dga_classifier,
        )
        
        self.lateral_detector = LateralMovementDetector()

        self._running = False
        self._stats = {
            "events_processed": 0,
            "events_enriched": 0,
            "alerts_generated": 0,
            "ml_dga_detections": 0,
            "ml_anomaly_detections": 0,
            "errors": 0,
        }
        self.stats_interval = processor_config.get("processor", {}).get("stats_interval", 50)
        
        # Redis for dashboard stats
        try:
            import redis
            import json
            self.redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
            self.redis_client.ping()
            logger.info("Connected to Redis for stats publishing.")
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}")
            self.redis_client = None

    # ── ML Initialization ───────────────────────────────────────────────

    def _init_ml_models(self, processor_config: dict):
        """Initialize and train ML models at startup using synthetic data."""
        ml_cfg = processor_config.get("ml_models", {})
        enable_ml = ml_cfg.get("enabled", True)

        if not enable_ml:
            logger.info("🤖 ML models disabled by configuration.")
            return

        logger.info("🤖 Initializing ML models...")

        # 1. DGA Classifier (Random Forest)
        try:
            from junction_nodes.stream_processor.ml_models.dga_classifier import DGAClassifier

            self.dga_classifier = DGAClassifier()
            dga_cfg = ml_cfg.get("dga_classifier", {})
            metrics = self.dga_classifier.train(
                n_benign=dga_cfg.get("n_benign", 8000),
                n_dga=dga_cfg.get("n_dga", 8000),
            )
            logger.info(
                "✅ DGA Classifier trained — Accuracy: %.3f | Precision: %.3f | Recall: %.3f | F1: %.3f",
                metrics["accuracy"],
                metrics["precision"],
                metrics["recall"],
                metrics["f1"],
            )
        except Exception as e:
            logger.error("❌ Failed to initialize DGA Classifier: %s", e, exc_info=True)
            self.dga_classifier = None

        # 2. Network Anomaly Detector (Isolation Forest)
        try:
            from junction_nodes.stream_processor.ml_models.isolation_forest import NetworkAnomalyDetector

            self.anomaly_detector = NetworkAnomalyDetector()
            iso_cfg = ml_cfg.get("isolation_forest", {})
            train_result = self.anomaly_detector.train(
                n_normal=iso_cfg.get("n_normal", 10000),
                contamination=iso_cfg.get("contamination", 0.05),
            )
            logger.info(
                "✅ Isolation Forest trained — Samples: %d | Contamination: %.2f | Features: %s",
                train_result["samples_trained"],
                train_result["contamination"],
                train_result["features"],
            )
        except Exception as e:
            logger.error("❌ Failed to initialize Isolation Forest: %s", e, exc_info=True)
            self.anomaly_detector = None

    # ── Stage 2-3: Enrichment ───────────────────────────────────────────

    def enrich_event(self, event_dict: Dict[str, Any]) -> EnrichedEvent:
        """Enrich a raw event with GeoIP data and threat intel matches."""
        source_ip = event_dict.get("source_ip")
        dest_ip = event_dict.get("destination_ip")

        # GeoIP lookups (returns None for internal/unknown IPs)
        source_geo = self.geoip_service.lookup(source_ip) if source_ip else None
        dest_geo = self.geoip_service.lookup(dest_ip) if dest_ip else None

        # Threat intelligence matching (check all IOC fields at once)
        threat_intel_matches = self.threat_intel_service.check_event(event_dict)

        # Check if source is an internal IP
        is_internal = self.geoip_service.is_internal(source_ip) if source_ip else False

        # Determine severity — boost if threat intel matched
        severity = event_dict.get("severity", "LOW")
        tags = list(event_dict.get("tags", []))
        confidence = event_dict.get("confidence_score", 0.0)

        if threat_intel_matches:
            severity = "HIGH"
            tags.append("threat_intel_match")
            # Boost confidence to the max match confidence
            max_ti_confidence = max(m.confidence for m in threat_intel_matches)
            confidence = max(confidence, max_ti_confidence)

        # Build the EnrichedEvent using the correct field names
        enriched = EnrichedEvent(
            original_event=event_dict,
            event_id=event_dict.get("event_id", ""),
            event_type=event_dict.get("event_type", ""),
            timestamp=event_dict.get("timestamp", datetime.now(timezone.utc)),
            sensor_id=event_dict.get("sensor_id", ""),
            source_ip=source_ip,
            destination_ip=dest_ip,
            severity=severity,
            tags=tags,
            mitre_tactic=event_dict.get("mitre_tactic"),
            mitre_technique=event_dict.get("mitre_technique"),
            confidence_score=confidence,
            source_geo=source_geo,
            destination_geo=dest_geo,
            threat_intel_matches=threat_intel_matches,
            is_internal_ip=is_internal,
        )

        self._stats["events_enriched"] += 1
        return enriched

    # ── Stage 4: Detection ──────────────────────────────────────────────

    def detect(self, event_dict: Dict[str, Any]) -> List[AlertEvent]:
        """Run detection algorithms on an event."""
        alerts: List[AlertEvent] = []
        event_type = event_dict.get("event_type", "")

        # DNS events → DNS anomaly detector + beaconing detector
        if event_type == "DNS_QUERY":
            dns_alerts = self.dns_detector.add_event(event_dict)
            if dns_alerts:
                alerts.extend(dns_alerts)
                # Track ML-specific detections for stats
                for alert in dns_alerts:
                    if "ml_detection" in alert.tags:
                        self._stats["ml_dga_detections"] += 1
            beacon_alert = self.beaconing_detector.add_event(event_dict)
            if beacon_alert:
                alerts.append(beacon_alert)
                if "ml_correlated" in beacon_alert.tags:
                    self._stats["ml_anomaly_detections"] += 1

        # Network events → beaconing detector + lateral movement
        elif event_type == "NETWORK_CONNECTION":
            beacon_alert = self.beaconing_detector.add_event(event_dict)
            if beacon_alert:
                alerts.append(beacon_alert)
                if "ml_correlated" in beacon_alert.tags:
                    self._stats["ml_anomaly_detections"] += 1
            
            lm_alerts = self.lateral_detector.add_event(event_dict)
            if lm_alerts:
                alerts.extend(lm_alerts)
                
        # Auth events → lateral movement / brute force
        elif event_type in ["AUTH_LOGIN", "AUTH_FAILURE"]:
            lm_alerts = self.lateral_detector.add_event(event_dict)
            if lm_alerts:
                alerts.extend(lm_alerts)

        return alerts

    # ── Full Pipeline ───────────────────────────────────────────────────

    def process_event(self, event_dict: Dict[str, Any]):
        """Process a single event through the full pipeline."""
        self._stats["events_processed"] += 1

        # 1. Enrich
        enriched_event = self.enrich_event(event_dict)

        # 2. Detect
        alerts = self.detect(event_dict)

        # 3. Produce enriched event to downstream topic
        self.producer.produce(
            self.output_topics.get("enriched", "apt.events.enriched"),
            enriched_event,
        )

        # 4. Produce alerts
        for alert in alerts:
            self.producer.produce(
                self.output_topics.get("alerts", "apt.alerts.raw"),
                alert,
            )
            self._stats["alerts_generated"] += 1
            logger.warning(
                "🚨 ALERT: %s | %s → %s | Confidence: %.2f",
                alert.alert_type.value,
                alert.source_ip,
                alert.title,
                alert.confidence_score,
            )

    def run(self):
        """Main processing loop. Runs until stopped."""
        self._running = True
        logger.info("Pipeline started. Consuming from topics...")
        while self._running:
            event = self.consumer.consume(timeout=1.0)
            if event:
                try:
                    self.process_event(event)
                except Exception as e:
                    logger.error("Error processing event: %s", e, exc_info=True)
                    self._stats["errors"] += 1

            if (
                self._stats["events_processed"] % self.stats_interval == 0
                and self._stats["events_processed"] > 0
            ):
                logger.info("📊 Pipeline stats: %s", self._stats)
                if getattr(self, 'redis_client', None):
                    import json
                    try:
                        self.redis_client.set("pipeline:stats", json.dumps(self._stats), ex=60)
                    except Exception as e:
                        logger.error(f"Failed to push stats to Redis: {e}")

    def stop(self):
        """Gracefully stop the pipeline."""
        self._running = False
        self.consumer.close()
        self.producer.flush(timeout=5.0)
        self.producer.close()
        logger.info("Pipeline stopped. Final stats: %s", self._stats)
