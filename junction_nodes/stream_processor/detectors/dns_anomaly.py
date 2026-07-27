import math
import time
from dataclasses import dataclass, field
from junction_nodes.stream_processor.models.alerts import AlertEvent, AlertType
from junction_nodes.common.models.events import SeverityLevel

@dataclass
class SourceWindow:
    queries: list[dict] = field(default_factory=list)  # list of {timestamp, domain, query_type, response_code, entropy}
    start_time: float = field(default_factory=time.time)

class DNSAnomalyDetector:
    """Detects DNS anomalies using windowed aggregation.
    
    Tracks per-source-IP statistics in a sliding window:
    - Total query count
    - Unique domain count
    - Average query entropy
    - TXT query ratio
    - NXDOMAIN ratio
    
    Fires alerts when thresholds are exceeded.
    """
    
    def __init__(self, window_seconds: int = 300, 
                 max_unique_domains: int = 100,
                 max_query_rate: int = 200,
                 txt_ratio_threshold: float = 0.3,
                 nxdomain_ratio_threshold: float = 0.5):
        self.window_seconds = window_seconds
        self.max_unique_domains = max_unique_domains
        self.max_query_rate = max_query_rate
        self.txt_ratio_threshold = txt_ratio_threshold
        self.nxdomain_ratio_threshold = nxdomain_ratio_threshold
        self._windows: dict[str, SourceWindow] = {}  # source_ip -> window data
    
    def add_event(self, event_dict: dict) -> list[AlertEvent]:
        """Process a DNS event. Returns list of AlertEvents if anomalies detected.
        
        Checks performed:
        1. High query rate (> max_query_rate per window) -> DATA_EXFILTRATION
        2. Too many unique domains (> max_unique_domains) -> DGA_DOMAIN
        3. High TXT query ratio (> txt_ratio_threshold) -> DNS_TUNNELING
        4. High NXDOMAIN ratio (> nxdomain_ratio_threshold) -> DGA_DOMAIN
        """
        if event_dict.get('event_type') != 'DNS_QUERY':
            return []
            
        source_ip = event_dict.get('source_ip')
        if not source_ip:
            return []
            
        domain = event_dict.get('query_name', '')
        query_type = event_dict.get('query_type', '')
        response_code = event_dict.get('response_code', '')
        
        window = self._get_or_create_window(source_ip)
        
        # Use the event's timestamp if available, otherwise fall back to wall clock
        event_ts = event_dict.get('timestamp')
        if isinstance(event_ts, (int, float)):
            current_time = float(event_ts)
        else:
            current_time = time.time()
        
        entropy = self._calculate_entropy(domain)
        window.queries.append({
            'timestamp': current_time,
            'domain': domain,
            'query_type': query_type,
            'response_code': response_code,
            'entropy': entropy
        })
        
        self._prune_window(window, current_time)
        
        alerts = []
        num_queries = len(window.queries)
        if num_queries == 0:
            return []
            
        unique_domains = set(q['domain'] for q in window.queries)
        txt_queries = sum(1 for q in window.queries if q['query_type'] == 'TXT')
        nxdomains = sum(1 for q in window.queries if q['response_code'] == 'NXDOMAIN')
        
        # 1. High query rate -> DATA_EXFILTRATION
        if num_queries > self.max_query_rate:
            alerts.append(AlertEvent(
                alert_type=AlertType.DATA_EXFILTRATION,
                title="High DNS Query Rate",
                description=f"Source {source_ip} exceeded max DNS query rate.",
                severity=SeverityLevel.HIGH,
                confidence_score=0.8,
                source_ip=source_ip,
                mitre_tactic="TA0010",
                mitre_technique="T1048",
                evidence={"query_count": num_queries, "window_seconds": self.window_seconds}
            ))
            
        # 2. Too many unique domains -> DGA_DOMAIN
        if len(unique_domains) > self.max_unique_domains:
            alerts.append(AlertEvent(
                alert_type=AlertType.DGA_DOMAIN,
                title="High Number of Unique Domains",
                description=f"Source {source_ip} queried excessive unique domains.",
                severity=SeverityLevel.MEDIUM,
                confidence_score=0.7,
                source_ip=source_ip,
                mitre_tactic="TA0011",
                mitre_technique="T1568",
                evidence={"unique_domains": len(unique_domains)}
            ))
            
        # 3. High TXT query ratio -> DNS_TUNNELING
        txt_ratio = txt_queries / num_queries
        if txt_ratio > self.txt_ratio_threshold and num_queries > 10:
            alerts.append(AlertEvent(
                alert_type=AlertType.DNS_TUNNELING,
                title="High TXT Query Ratio",
                description=f"Source {source_ip} has a high ratio of TXT queries.",
                severity=SeverityLevel.HIGH,
                confidence_score=0.9,
                source_ip=source_ip,
                mitre_tactic="TA0011",
                mitre_technique="T1071.004",
                evidence={"txt_ratio": txt_ratio, "txt_queries": txt_queries, "total_queries": num_queries}
            ))
            
        # 4. High NXDOMAIN ratio -> DGA_DOMAIN
        nxdomain_ratio = nxdomains / num_queries
        if nxdomain_ratio > self.nxdomain_ratio_threshold and num_queries > 10:
            alerts.append(AlertEvent(
                alert_type=AlertType.DGA_DOMAIN,
                title="High NXDOMAIN Ratio",
                description=f"Source {source_ip} has a high ratio of NXDOMAIN responses.",
                severity=SeverityLevel.MEDIUM,
                confidence_score=0.75,
                source_ip=source_ip,
                mitre_tactic="TA0011",
                mitre_technique="T1568",
                evidence={"nxdomain_ratio": nxdomain_ratio, "nxdomains": nxdomains, "total_queries": num_queries}
            ))
            
        return alerts
    
    def _get_or_create_window(self, source_ip: str) -> SourceWindow:
        if source_ip not in self._windows:
            self._windows[source_ip] = SourceWindow()
        return self._windows[source_ip]
        
    def _prune_window(self, window: SourceWindow, current_time: float):
        cutoff_time = current_time - self.window_seconds
        window.queries = [q for q in window.queries if q['timestamp'] >= cutoff_time]
        
    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        entropy = 0
        for x in set(text):
            p_x = float(text.count(x)) / len(text)
            entropy += - p_x * math.log(p_x, 2)
        return entropy
