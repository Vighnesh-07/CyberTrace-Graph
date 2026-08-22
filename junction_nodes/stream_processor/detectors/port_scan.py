import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

from junction_nodes.stream_processor.models.alerts import AlertEvent, AlertType, SeverityLevel

logger = logging.getLogger(__name__)

class PortScanDetector:
    def __init__(self, port_threshold: int = 15, window_seconds: int = 10):
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        
        # State tracking
        # {source_ip: {target_ip: [ (timestamp, port) ] }}
        self.scan_history = defaultdict(lambda: defaultdict(list))

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

    def _cleanup_old_events(self, current_time: datetime):
        cutoff = current_time - timedelta(seconds=self.window_seconds)
        for src in list(self.scan_history.keys()):
            for dst in list(self.scan_history[src].keys()):
                self.scan_history[src][dst] = [
                    (t, p) for (t, p) in self.scan_history[src][dst] if t > cutoff
                ]
                if not self.scan_history[src][dst]:
                    del self.scan_history[src][dst]
            if not self.scan_history[src]:
                del self.scan_history[src]

    def add_event(self, event_dict: Dict[str, Any]) -> List[AlertEvent]:
        alerts = []
        event_type = event_dict.get("event_type", "")
        source_ip = event_dict.get("source_ip")
        ts = self._parse_timestamp(event_dict.get("timestamp"))

        if not source_ip or event_type != "NETWORK_CONNECTION":
            return alerts
            
        self._cleanup_old_events(ts)

        target_ip = event_dict.get("destination_ip")
        target_port = event_dict.get("destination_port")
        
        if target_ip and target_port:
            self.scan_history[source_ip][target_ip].append((ts, target_port))
            
            # Count unique ports
            unique_ports = set(p for t, p in self.scan_history[source_ip][target_ip])
            
            if len(unique_ports) >= self.port_threshold:
                alerts.append(AlertEvent(
                    alert_type=AlertType.PORT_SCAN,
                    severity=SeverityLevel.MEDIUM,
                    confidence_score=0.9,
                    title="Port Scan Detected",
                    description=f"Source {source_ip} rapidly connected to {len(unique_ports)} unique ports on {target_ip}.",
                    source_ip=source_ip,
                    mitre_tactic="TA0007",  # Discovery
                    mitre_technique="T1046", # Network Service Discovery
                    tags=["port_scan", "network_discovery"],
                    evidence={"unique_ports_scanned": len(unique_ports), "target_ip": target_ip}
                ))
                # Clear history for this pair to avoid alert spamming
                del self.scan_history[source_ip][target_ip]
                
        return alerts
