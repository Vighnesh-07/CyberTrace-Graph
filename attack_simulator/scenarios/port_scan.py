import random
from datetime import datetime, timezone, timedelta
from junction_nodes.common.models.events import NetworkEvent, SeverityLevel

class PortScanScenario:
    def __init__(self, source_ip="192.168.1.105", target_ip="10.0.0.50"):
        self.source_ip = source_ip
        self.target_ip = target_ip
        
        # Common ports to scan
        self.ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

    def generate_events(self, duration_seconds=60):
        events = []
        base_time = datetime.now(timezone.utc)
        
        # Fast scan: attempt to connect to all ports in a few seconds
        for i, port in enumerate(self.ports):
            event_time = base_time + timedelta(seconds=(i * 0.1))
            
            # Simulate a quick SYN scan (failed connection)
            events.append(NetworkEvent(
                sensor_id="sensor-edge-01",
                sensor_type="network",
                timestamp=event_time,
                source_ip=self.source_ip,
                source_port=random.randint(10000, 60000),
                destination_ip=self.target_ip,
                destination_port=port,
                protocol="TCP",
                connection_state="REJECTED",
                bytes_sent=0,
                bytes_received=0,
                mitre_tactic="TA0007",
                mitre_technique="T1046",
                severity=SeverityLevel.LOW
            ))
            
        return events
