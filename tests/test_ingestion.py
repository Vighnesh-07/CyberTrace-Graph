import pytest
from junction_nodes.ingestion_gateway.parsers.sysmon import parse_sysmon_event

class TestSysmonParser:
    def test_parse_process_creation_event(self):
        event = {
            "System": {
                "EventID": 1,
                "Computer": "WORKSTATION1",
                "TimeCreated": {"SystemTime": "2023-01-01T10:00:00Z"}
            },
            "EventData": {
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c dir",
                "User": "DOMAIN\\user",
                "ParentImage": "C:\\Windows\\explorer.exe"
            }
        }
        internal_event, topic = parse_sysmon_event(event)
        
        assert internal_event is not None
        assert internal_event["event_type"] == "PROCESS_CREATION"
        assert internal_event["host"] == "WORKSTATION1"
        assert internal_event["process_name"] == "cmd.exe"
        assert internal_event["parent_process"] == "explorer.exe"
        assert topic == "endpoint"

    def test_parse_network_connection_event(self):
        event = {
            "System": {
                "EventID": 3,
                "Computer": "WORKSTATION1"
            },
            "EventData": {
                "SourceIp": "192.168.1.100",
                "SourcePort": "12345",
                "DestinationIp": "1.1.1.1",
                "DestinationPort": "443",
                "Protocol": "tcp",
                "Image": "C:\\Program Files\\Browser\\browser.exe"
            }
        }
        internal_event, topic = parse_sysmon_event(event)
        
        assert internal_event is not None
        assert internal_event["event_type"] == "NETWORK_CONNECTION"
        assert internal_event["destination_ip"] == "1.1.1.1"
        assert internal_event["process_name"] == "browser.exe"
        assert topic == "network"

    def test_parse_process_access_event(self):
        event = {
            "System": {
                "EventID": 10,
                "Computer": "WORKSTATION1"
            },
            "EventData": {
                "SourceImage": "C:\\temp\\mimikatz.exe",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1410"
            }
        }
        internal_event, topic = parse_sysmon_event(event)
        
        assert internal_event is not None
        assert internal_event["event_type"] == "PROCESS_ACCESS"
        assert internal_event["source_process"] == "mimikatz.exe"
        assert internal_event["target_process"] == "lsass.exe"
        assert topic == "endpoint"

    def test_parse_dns_query_event(self):
        event = {
            "System": {
                "EventID": 22,
                "Computer": "WORKSTATION1"
            },
            "EventData": {
                "QueryName": "malicious.com",
                "Image": "C:\\malware.exe"
            }
        }
        internal_event, topic = parse_sysmon_event(event)
        
        assert internal_event is not None
        assert internal_event["event_type"] == "DNS_QUERY"
        assert internal_event["query"] == "malicious.com"
        assert topic == "dns"

    def test_returns_none_for_unsupported_event_id(self):
        event = {
            "System": {
                "EventID": 99,
                "Computer": "WORKSTATION1"
            },
            "EventData": {}
        }
        internal_event, topic = parse_sysmon_event(event)
        
        assert internal_event is None
        assert topic == ""

    def test_handles_missing_event_data_gracefully(self):
        event = {
            "System": {
                "EventID": 1
            }
        }
        internal_event, topic = parse_sysmon_event(event)
        
        assert internal_event is not None
        assert internal_event["event_type"] == "PROCESS_CREATION"
        assert internal_event["process_name"] == ""
