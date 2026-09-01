import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

from junction_nodes.stream_processor.models.alerts import AlertEvent, AlertType, SeverityLevel
from junction_nodes.stream_processor.state.redis_window import RedisSlidingWindow

logger = logging.getLogger(__name__)

class PortScanDetector:
    def __init__(self, port_threshold: int = 15, window_seconds: int = 10, redis_url: str = "redis://localhost:6379/0"):
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        
        # State tracking via Redis
        self.window = RedisSlidingWindow(redis_url=redis_url, namespace="portscan")

    def _parse_timestamp(self, ts) -> datetime:
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        return datetime.now(timezone.utc)

    def add_event(self, event_dict: Dict[str, Any]) -> List[AlertEvent]:
        alerts = []
        event_type = event_dict.get("event_type", "")
        source_ip = event_dict.get("source_ip")
        ts = self._parse_timestamp(event_dict.get("timestamp"))

        if not source_ip or event_type != "NETWORK_CONNECTION":
            return alerts
            
        target_ip = event_dict.get("destination_ip")
        target_port = event_dict.get("destination_port")
        event_id = event_dict.get("event_id", f"{ts.timestamp()}-{target_port}")
        
        if target_ip and target_port:
            # Key identifies the source and target pair
            key = f"{source_ip}:{target_ip}"
            
            # Store the port as part of the event identifier to ensure uniqueness for ports
            # We want to count unique ports. If we just store event_ids, we might count the same port twice.
            # So we use target_port as the 'member' in the sorted set, because multiple connections 
            # to the SAME port will just update the score (timestamp) and keep unique members = unique ports.
            
            self.window.add_event(key, str(target_port), ts.timestamp(), ttl_seconds=self.window_seconds * 2)
            
            # Count unique ports
            unique_ports_count = self.window.count_events(key, self.window_seconds)
            
            if unique_ports_count >= self.port_threshold:
                alerts.append(AlertEvent(
                    alert_type=AlertType.PORT_SCAN,
                    severity=SeverityLevel.MEDIUM,
                    confidence_score=0.9,
                    title="Port Scan Detected",
                    description=f"Source {source_ip} rapidly connected to {unique_ports_count} unique ports on {target_ip}.",
                    source_ip=source_ip,
                    mitre_tactic="TA0007",  # Discovery
                    mitre_technique="T1046", # Network Service Discovery
                    tags=["port_scan", "network_discovery"],
                    evidence={"unique_ports_scanned": unique_ports_count, "target_ip": target_ip}
                ))
                # Clear history for this pair to avoid alert spamming
                self.window.clear(key)
                
        return alerts
