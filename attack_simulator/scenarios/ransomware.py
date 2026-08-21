"""
Ransomware Scenario.

Simulates a ransomware infection:
  Stage 1: Initial payload execution (ProcessEvent for malicious exe)
  Stage 2: Volume Shadow Copy deletion (ProcessEvent for vssadmin.exe)
  Stage 3: C2 Key Exchange (NetworkEvent to malicious domain/IP)
"""

import random
from datetime import datetime, timezone, timedelta
from typing import List

from junction_nodes.common.models.events import (
    ProcessEvent, NetworkEvent, EventType, SeverityLevel, SecurityEvent
)

class RansomwareScenario:
    def __init__(
        self,
        sensor_id: str = "sim-ransom-01",
        c2_ip: str = "45.33.10.12",
    ):
        self.sensor_id = sensor_id
        self.c2_ip = c2_ip
        self.infected_host = "192.168.1.105"

    def generate_events(
        self,
        duration_seconds: int = 300,
    ) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        base_time = datetime.now(timezone.utc)
        current_time = 0.0

        # ── Stage 1: Initial Execution (0-10s) ──
        t = base_time + timedelta(seconds=current_time)
        events.append(ProcessEvent(
            sensor_id=self.sensor_id,
            sensor_type="EDR",
            timestamp=t,
            severity=SeverityLevel.HIGH,
            source_ip=self.infected_host,
            process_name="invoice_update.exe",
            process_id=4102,
            parent_process_name="explorer.exe",
            parent_process_id=1024,
            command_line="invoice_update.exe /silent",
            user="SYSTEM",
            mitre_tactic="TA0002",
            mitre_technique="T1204.002",
            confidence_score=0.9
        ))
        current_time += 5.0

        # ── Stage 2: C2 Key Exchange (10-30s) ──
        while current_time < min(30, duration_seconds):
            t = base_time + timedelta(seconds=current_time)
            events.append(NetworkEvent(
                sensor_id=self.sensor_id,
                sensor_type="NETWORK",
                timestamp=t,
                severity=SeverityLevel.HIGH,
                source_ip=self.infected_host,
                destination_ip=self.c2_ip,
                destination_port=443,
                protocol="TCP",
                bytes_sent=random.randint(500, 2000),
                bytes_received=random.randint(100, 500),
                mitre_tactic="TA0011",
                mitre_technique="T1573.001",
                confidence_score=0.95
            ))
            current_time += random.uniform(5, 10)

        # ── Stage 3: Inhibit System Recovery (30s+) ──
        if duration_seconds > 30:
            t = base_time + timedelta(seconds=35)
            events.append(ProcessEvent(
                sensor_id=self.sensor_id,
                sensor_type="EDR",
                timestamp=t,
                severity=SeverityLevel.CRITICAL,
                source_ip=self.infected_host,
                process_name="vssadmin.exe",
                process_id=5032,
                parent_process_name="invoice_update.exe",
                parent_process_id=4102,
                command_line="vssadmin.exe Delete Shadows /All /Quiet",
                user="SYSTEM",
                mitre_tactic="TA0040",
                mitre_technique="T1490",
                confidence_score=0.99
            ))
            
            # Simulate rapid process executions for encryption
            for i in range(10):
                t = base_time + timedelta(seconds=40 + i)
                events.append(ProcessEvent(
                    sensor_id=self.sensor_id,
                    sensor_type="EDR",
                    timestamp=t,
                    severity=SeverityLevel.HIGH,
                    source_ip=self.infected_host,
                    process_name="cmd.exe",
                    process_id=6000 + i,
                    parent_process_name="invoice_update.exe",
                    parent_process_id=4102,
                    command_line=f"cmd.exe /c move C:\\Users\\User\\Documents\\file{i}.docx C:\\Users\\User\\Documents\\file{i}.docx.enc",
                    user="SYSTEM",
                    mitre_tactic="TA0040",
                    mitre_technique="T1486",
                    confidence_score=0.95
                ))

        return events
