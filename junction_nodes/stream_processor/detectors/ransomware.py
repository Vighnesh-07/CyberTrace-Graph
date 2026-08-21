import dateutil.parser
from datetime import datetime, timezone
from typing import List, Optional

from junction_nodes.common.models.events import SeverityLevel
from junction_nodes.stream_processor.models.alerts import AlertEvent, AlertType

class RansomwareDetector:
    """Detects ransomware behavior such as shadow copy deletion and mass encryption."""

    def __init__(self):
        pass

    def _parse_timestamp(self, ts):
        if isinstance(ts, str):
            try:
                return dateutil.parser.isoparse(ts)
            except Exception:
                return datetime.now(timezone.utc)
        return ts

    def add_event(self, event_dict: dict) -> List[AlertEvent]:
        event_type = event_dict.get("event_type")
        if event_type != "PROCESS_CREATION":
            return []
        
        process_name = (event_dict.get("process_name") or "").lower()
        command_line = (event_dict.get("command_line") or "").lower()
        
        # Detect Shadow Copy Deletion
        is_shadow_deletion = False
        if "vssadmin.exe" in process_name and "delete shadows" in command_line:
            is_shadow_deletion = True
        
        # Detect rapid file encryption commands (heuristic)
        is_encryption_cmd = False
        if "cmd.exe" in process_name and "move " in command_line and ".enc" in command_line:
            is_encryption_cmd = True
            
        if is_shadow_deletion or is_encryption_cmd:
            alert = self._generate_alert(event_dict, "shadow_deletion" if is_shadow_deletion else "encryption")
            return [alert]
            
        return []

    def _generate_alert(self, event_dict: dict, r_type: str) -> AlertEvent:
        source_ip = event_dict.get("source_ip", "Unknown")
        host = event_dict.get("hostname", source_ip)
        ts = self._parse_timestamp(event_dict.get("timestamp"))
        event_id = event_dict.get("event_id", "")
        
        # Extend AlertType in the pipeline by just using ANOMALY if RANSOMWARE isn't there
        # Or let's assume we can add RANSOMWARE to AlertType, but for now we use ANOMALY
        # with high severity.
        
        if r_type == "shadow_deletion":
            title = f"Ransomware Indicator: Shadow Copy Deletion on {host}"
            description = f"Detected vssadmin.exe attempting to delete volume shadow copies on {host}. Highly indicative of ransomware."
            severity = SeverityLevel.CRITICAL
            tactic = "TA0040"
            tech = "T1490"
        else:
            title = f"Ransomware Indicator: Mass File Encryption on {host}"
            description = f"Detected rapid file renaming to .enc extension on {host}."
            severity = SeverityLevel.HIGH
            tactic = "TA0040"
            tech = "T1486"

        return AlertEvent(
            alert_type="ANOMALY", # since RANSOMWARE is not in the Enum
            title=title,
            description=description,
            severity=severity,
            confidence_score=0.95,
            timestamp=ts,
            source_ip=source_ip,
            destination_ip=None,
            mitre_tactic=tactic,
            mitre_technique=tech,
            related_event_ids=[event_id],
            evidence={"command_line": event_dict.get("command_line"), "process": event_dict.get("process_name")},
            tags=["ransomware", r_type, "deterministic"]
        )
