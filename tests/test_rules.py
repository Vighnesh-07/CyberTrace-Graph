import pytest
from unittest.mock import patch, MagicMock
from junction_nodes.stream_processor.rules.engine import RuleEngine

class TestRuleEngine:
    @patch('junction_nodes.stream_processor.rules.engine.os.path.exists', return_value=True)
    @patch('junction_nodes.stream_processor.rules.engine.glob.glob', return_value=['dummy.yaml'])
    @patch('junction_nodes.stream_processor.rules.engine.open', create=True)
    @patch('junction_nodes.stream_processor.rules.engine.yaml.safe_load')
    @patch('junction_nodes.stream_processor.rules.engine.RedisSlidingWindow')
    def test_evaluate_condition(self, mock_redis, mock_yaml, mock_open, mock_glob, mock_exists):
        mock_yaml.return_value = {}
        engine = RuleEngine()
        
        # Test ==
        assert engine.evaluate_condition({'field': 'action', 'operator': '==', 'value': 'drop'}, {'action': 'drop'}) == True
        assert engine.evaluate_condition({'field': 'action', 'operator': '==', 'value': 'drop'}, {'action': 'allow'}) == False
        
        # Test contains
        assert engine.evaluate_condition({'field': 'cmd', 'operator': 'contains', 'value': 'lsass'}, {'cmd': 'dump lsass'}) == True
        
        # Test regex
        assert engine.evaluate_condition({'field': 'user', 'operator': 'regex', 'value': 'admin.*'}, {'user': 'admin123'}) == True
        
        # Test in
        assert engine.evaluate_condition({'field': 'port', 'operator': 'in', 'value': [80, 443]}, {'port': 443}) == True
        assert engine.evaluate_condition({'field': 'port', 'operator': 'in', 'value': [80, 443]}, {'port': 22}) == False

        # Missing field
        assert engine.evaluate_condition({'field': 'missing', 'value': 'val'}, {'other': 'val'}) == False
