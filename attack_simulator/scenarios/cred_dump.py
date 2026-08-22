from datetime import datetime, timezone, timedelta
from junction_nodes.common.models.events import ProcessEvent, SeverityLevel

class CredDumpScenario:
    def __init__(self, target_host="WIN-SERVER-01"):
        self.target_host = target_host

    def generate_events(self, duration_seconds=60):
        events = []
        base_time = datetime.now(timezone.utc)
        
        # 1. Attacker drops procdump
        events.append(ProcessEvent(
            sensor_id="sensor-ep-02",
            sensor_type="endpoint",
            timestamp=base_time,
            hostname=self.target_host,
            process_name="cmd.exe",
            process_id=4512,
            parent_process_name="explorer.exe",
            parent_process_id=2210,
            command_line="cmd.exe /c start procdump.exe -ma lsass.exe lsass.dmp",
            user="SYSTEM",
            mitre_tactic="TA0006",
            mitre_technique="T1003.001",
            severity=SeverityLevel.HIGH
        ))
        
        # 2. Execution of procdump
        events.append(ProcessEvent(
            sensor_id="sensor-ep-02",
            sensor_type="endpoint",
            timestamp=base_time + timedelta(seconds=2),
            hostname=self.target_host,
            process_name="procdump.exe",
            process_id=8832,
            parent_process_name="cmd.exe",
            parent_process_id=4512,
            command_line="procdump.exe -ma lsass.exe lsass.dmp",
            user="SYSTEM",
            mitre_tactic="TA0006",
            mitre_technique="T1003.001",
            severity=SeverityLevel.CRITICAL
        ))
            
        return events
