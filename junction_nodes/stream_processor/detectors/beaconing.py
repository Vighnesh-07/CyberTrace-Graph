import time
import statistics
from typing import Optional
from junction_nodes.stream_processor.models.alerts import AlertEvent, AlertType
from junction_nodes.common.models.events import SeverityLevel

class BeaconingDetector:
    """Detects C2 beaconing by analyzing periodicity of connections.
    
    Beaconing = regular, periodic callbacks to a C2 server.
    Detection method: Track timestamps per (source_ip, destination_domain) pair.
    When enough samples exist, calculate the coefficient of variation (CV)
    of the inter-arrival times. Low CV = highly periodic = likely beaconing.
    """
    
    def __init__(self, window_seconds: int = 300, min_samples: int = 5, cv_threshold: float = 0.3):
        # window_seconds: How long to retain timestamps
        # min_samples: Minimum beacons to trigger detection
        # cv_threshold: Max coefficient of variation to consider as beaconing
        self.window_seconds = window_seconds
        self.min_samples = min_samples
        self.cv_threshold = cv_threshold
        self._timestamps: dict[str, list[float]] = {}  # key -> list of epoch timestamps
    
    def _make_key(self, source_ip: str, domain: str) -> str:
        return f"{source_ip}:{domain}"
    
    def add_event(self, event_dict: dict) -> Optional[AlertEvent]:
        """Process an event. Returns an AlertEvent if beaconing is detected.
        
        For DNS events: use source_ip + query_name
        For network events: use source_ip + destination_ip
        """
        source_ip = event_dict.get('source_ip')
        if not source_ip:
            return None
            
        domain = None
        if event_dict.get('event_type') == 'DNS_QUERY':
            domain = event_dict.get('query_name')
        elif event_dict.get('event_type') == 'NETWORK_CONNECTION':
            domain = event_dict.get('destination_ip')
            
        if not domain:
            return None
            
        key = self._make_key(source_ip, domain)
        
        # Use the event's timestamp if available, otherwise fall back to wall clock
        event_ts = event_dict.get('timestamp')
        if isinstance(event_ts, (int, float)):
            current_time = float(event_ts)
        elif isinstance(event_ts, str):
            try:
                from datetime import datetime
                current_time = datetime.fromisoformat(event_ts.replace('Z', '+00:00')).timestamp()
            except (ValueError, TypeError):
                current_time = time.time()
        else:
            current_time = time.time()
        
        if key not in self._timestamps:
            self._timestamps[key] = []
            
        self._timestamps[key].append(current_time)
        self._cleanup(key, current_time)
        
        timestamps = self._timestamps[key]
        if len(timestamps) >= self.min_samples:
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            if not intervals:
                return None
                
            mean_interval = statistics.mean(intervals)
            
            # Avoid division by zero
            if mean_interval == 0:
                mean_interval = 0.001
                
            if len(intervals) > 1:
                std_interval = statistics.stdev(intervals)
            else:
                std_interval = 0.0
                
            cv = std_interval / mean_interval
            
            if cv < self.cv_threshold:
                # Beaconing detected
                return AlertEvent(
                    alert_type=AlertType.C2_BEACONING,
                    title="Potential C2 Beaconing Detected",
                    description=f"Periodic connection detected from {source_ip} to {domain}.",
                    severity=SeverityLevel.HIGH,
                    confidence_score=1.0 - cv,
                    source_ip=source_ip,
                    destination_ip=domain if event_dict.get('event_type') == 'NETWORK_CONNECTION' else None,
                    mitre_tactic="TA0011",
                    mitre_technique="T1071",
                    related_event_ids=[event_dict.get('event_id', '')],
                    evidence={
                        "mean_interval": mean_interval,
                        "cv": cv,
                        "sample_count": len(timestamps),
                        "domain": domain
                    }
                )
        return None
    
    def _cleanup(self, key: str, current_time: float):
        """Remove timestamps outside the window."""
        cutoff_time = current_time - self.window_seconds
        self._timestamps[key] = [t for t in self._timestamps[key] if t >= cutoff_time]
        if not self._timestamps[key]:
            del self._timestamps[key]

