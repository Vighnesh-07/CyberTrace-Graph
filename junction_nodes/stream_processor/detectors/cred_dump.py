import logging
from typing import Dict, Any, List

from junction_nodes.stream_processor.models.alerts import AlertEvent, AlertType, SeverityLevel

logger = logging.getLogger(__name__)

class CredDumpDetector:
    def __init__(self):
        # Known indicators of LSASS credential dumping
        self.suspicious_commands = ["procdump", "lsass", "mimikatz", "comsvcs.dll", "MiniDump"]

    def add_event(self, event_dict: Dict[str, Any]) -> List[AlertEvent]:
        alerts = []
        event_type = event_dict.get("event_type", "")
        
        if event_type == "PROCESS_CREATION":
            command_line = event_dict.get("command_line", "").lower()
            process_name = event_dict.get("process_name", "").lower()
            
            # Check for matches
            matched_keywords = [kw for kw in self.suspicious_commands if kw.lower() in command_line or kw.lower() in process_name]
            
            # If we see multiple keywords (like procdump + lsass), it's highly suspicious
            if len(matched_keywords) >= 2 or "mimikatz" in matched_keywords:
                source_ip = event_dict.get("source_ip") or event_dict.get("hostname")
                alerts.append(AlertEvent(
                    alert_type=AlertType.CREDENTIAL_DUMPING,
                    severity=SeverityLevel.CRITICAL,
                    confidence_score=0.95,
                    title="LSASS Credential Dumping",
                    description=f"Highly suspicious process execution detected indicating credential dumping: {command_line}",
                    source_ip=source_ip,
                    mitre_tactic="TA0006", # Credential Access
                    mitre_technique="T1003.001", # OS Credential Dumping: LSASS Memory
                    tags=["cred_dump", "lsass"],
                    evidence={"command_line": command_line, "matched_keywords": matched_keywords}
                ))
                
        return alerts
