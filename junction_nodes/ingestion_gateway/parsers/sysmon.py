from typing import Tuple, Dict, Any, Optional
import uuid
from datetime import datetime, timezone

def parse_sysmon_event(event: dict) -> Tuple[Optional[Dict[str, Any]], str]:
    """
    Parses a Windows Sysmon JSON event (e.g., from Winlogbeat) and maps it 
    to the CyberTrace-Graph internal schema.
    Returns: (parsed_event_dict, kafka_topic_suffix)
    """
    system = event.get("System", {})
    event_data = event.get("EventData", {})
    event_id = system.get("EventID")
    
    if not event_id:
        return None, ""
        
    ts = system.get("TimeCreated", {}).get("SystemTime", datetime.now(timezone.utc).isoformat())
    computer = system.get("Computer", "unknown_host")
    
    internal_event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts,
        "sensor_id": f"sysmon-{computer}",
        "host": computer
    }
    
    if event_id == 1: # Process Creation
        internal_event.update({
            "event_type": "PROCESS_CREATION",
            "process_name": event_data.get("Image", "").split("\\")[-1],
            "process_path": event_data.get("Image"),
            "command_line": event_data.get("CommandLine"),
            "user": event_data.get("User"),
            "parent_process": event_data.get("ParentImage", "").split("\\")[-1]
        })
        return internal_event, "endpoint"
        
    elif event_id == 3: # Network Connection
        internal_event.update({
            "event_type": "NETWORK_CONNECTION",
            "source_ip": event_data.get("SourceIp"),
            "source_port": event_data.get("SourcePort"),
            "destination_ip": event_data.get("DestinationIp"),
            "destination_port": event_data.get("DestinationPort"),
            "protocol": event_data.get("Protocol"),
            "process_name": event_data.get("Image", "").split("\\")[-1]
        })
        return internal_event, "network"
        
    elif event_id == 10: # Process Access (e.g. LSASS dump)
        internal_event.update({
            "event_type": "PROCESS_ACCESS",
            "source_process": event_data.get("SourceImage", "").split("\\")[-1],
            "target_process": event_data.get("TargetImage", "").split("\\")[-1],
            "granted_access": event_data.get("GrantedAccess")
        })
        return internal_event, "endpoint"
        
    elif event_id == 22: # DNS Query
        internal_event.update({
            "event_type": "DNS_QUERY",
            "query": event_data.get("QueryName"),
            "query_type": "A", # Sysmon doesn't always provide this cleanly
            "process_name": event_data.get("Image", "").split("\\")[-1]
        })
        return internal_event, "dns"
        
    # Unsupported event ID
    return None, ""
