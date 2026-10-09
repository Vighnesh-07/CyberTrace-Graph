import pytest
import time
from unittest.mock import patch, MagicMock

from junction_nodes.stream_processor.detectors.cred_dump import CredDumpDetector
from junction_nodes.stream_processor.detectors.beaconing import BeaconingDetector
from junction_nodes.stream_processor.detectors.port_scan import PortScanDetector
from junction_nodes.stream_processor.detectors.brute_force import LateralMovementDetector

class MockSlidingWindow:
    def __init__(self, *args, **kwargs):
        self.data = {}
    def add(self, *args, **kwargs): pass
    def add_event(self, *args, **kwargs): pass
    def count_events(self, key, *args, **kwargs): return self.data.get(key, 0)
    def set_count(self, key, count): self.data[key] = count
    def clear(self, key): self.data.pop(key, None)

# --- CredDumpDetector ---
def test_cred_dump_ignores_unrelated():
    detector = CredDumpDetector()
    assert len(detector.add_event({'event_type': 'NETWORK_CONNECTION'})) == 0

def test_cred_dump_detects_mimikatz():
    detector = CredDumpDetector()
    event = {'event_type': 'PROCESS_CREATION', 'command_line': 'mimikatz.exe privilege::debug'}
    alerts = detector.add_event(event)
    assert len(alerts) > 0

# --- BeaconingDetector ---
def test_beaconing_ignores_non_network():
    detector = BeaconingDetector(window_seconds=300, min_samples=5)
    assert not detector.add_event({'event_type': 'PROCESS_CREATION'})

def test_beaconing_no_alert_below_threshold():
    detector = BeaconingDetector(window_seconds=300, min_samples=5)
    event = {'event_type': 'NETWORK_CONNECTION', 'source_ip': '1.1.1.1', 'destination_ip': '2.2.2.2', 'timestamp': time.time()}
    assert not detector.add_event(event)

# --- PortScanDetector ---
@patch('junction_nodes.stream_processor.detectors.port_scan.RedisSlidingWindow', new=MockSlidingWindow)
def test_port_scan_no_alert_below_threshold():
    detector = PortScanDetector(port_threshold=15, window_seconds=10)
    event = {'event_type': 'NETWORK_CONNECTION', 'source_ip': '1.1.1.1', 'destination_port': 80}
    assert len(detector.add_event(event)) == 0

@patch('junction_nodes.stream_processor.detectors.port_scan.RedisSlidingWindow')
def test_port_scan_detects(mock_window_class):
    mock_window = MockSlidingWindow()
    mock_window.set_count('1.1.1.1:1.1.1.2', 20)
    mock_window_class.return_value = mock_window
    
    detector = PortScanDetector(port_threshold=15, window_seconds=10)
    event = {'event_type': 'NETWORK_CONNECTION', 'source_ip': '1.1.1.1', 'destination_ip': '1.1.1.2', 'destination_port': 80}
    alerts = detector.add_event(event)
    assert len(alerts) > 0

# --- LateralMovementDetector ---
@patch('junction_nodes.stream_processor.detectors.brute_force.redis.from_url')
@patch('junction_nodes.stream_processor.detectors.brute_force.RedisSlidingWindow')
def test_lateral_movement_ignores(mock_window_class, mock_redis_func):
    mock_window_class.return_value = MockSlidingWindow()
    mock_redis = MagicMock()
    mock_redis_func.return_value = mock_redis
    
    detector = LateralMovementDetector(brute_force_threshold=5, window_seconds=60)
    event = {'event_type': 'PROCESS_CREATION'}
    assert len(detector.add_event(event)) == 0
