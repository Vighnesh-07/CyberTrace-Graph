import yaml
import os
import glob
import logging
import re
from typing import Dict, Any, List

from junction_nodes.stream_processor.models.alerts import AlertEvent, AlertType, SeverityLevel
from junction_nodes.stream_processor.state.redis_window import RedisSlidingWindow

logger = logging.getLogger(__name__)

class RuleEngine:
    def __init__(self, rules_dir: str = "rules", redis_url: str = "redis://localhost:6379/0"):
        self.rules_dir = rules_dir
        self.rules = []
        self.window = RedisSlidingWindow(redis_url=redis_url, namespace="rule_engine")
        self.reload_rules()

    def reload_rules(self):
        """Loads all YAML rules from the rules directory."""
        self.rules = []
        if not os.path.exists(self.rules_dir):
            logger.warning(f"Rules directory {self.rules_dir} does not exist.")
            return

        for filepath in glob.glob(os.path.join(self.rules_dir, "*.yaml")):
            try:
                with open(filepath, "r") as f:
                    rule = yaml.safe_load(f)
                    self.rules.append(rule)
                    logger.info(f"Loaded rule: {rule.get('name', filepath)}")
            except Exception as e:
                logger.error(f"Failed to load rule {filepath}: {e}")

    def evaluate_condition(self, condition: dict, event: dict) -> bool:
        """Evaluates a single condition against an event."""
        field = condition.get("field")
        operator = condition.get("operator", "==")
        value = condition.get("value")

        if not field or field not in event:
            return False

        event_val = event.get(field)
        
        if operator == "==":
            return event_val == value
        elif operator == "contains":
            return value in str(event_val)
        elif operator == "regex":
            return bool(re.search(value, str(event_val)))
        elif operator == "in":
            return event_val in value
        return False

    def process_event(self, event: dict) -> List[AlertEvent]:
        """Evaluates all rules against the incoming event."""
        alerts = []
        ts = event.get("timestamp", 0)
        
        # In a real environment, ts would be parsed correctly. 
        # Since we use this downstream from pipeline, it might be a datetime obj or float.
        if hasattr(ts, "timestamp"):
            ts = ts.timestamp()
            
        for rule in self.rules:
            # 1. Check Event Type
            if event.get("event_type") not in rule.get("event_types", []):
                continue
                
            # 2. Evaluate Conditions (AND logic)
            conditions = rule.get("conditions", [])
            match = True
            for cond in conditions:
                if not self.evaluate_condition(cond, event):
                    match = False
                    break
                    
            if not match:
                continue
                
            # 3. Check Thresholds (if applicable)
            threshold_cfg = rule.get("threshold")
            if threshold_cfg:
                window_sec = threshold_cfg.get("window_seconds", 60)
                count_thresh = threshold_cfg.get("count", 5)
                group_by = threshold_cfg.get("group_by", "source_ip")
                
                group_val = event.get(group_by, "unknown")
                rule_id = rule.get("id", rule.get("name", "unknown_rule"))
                key = f"{rule_id}:{group_val}"
                event_id = event.get("event_id", str(ts))
                
                self.window.add_event(key, event_id, ts, ttl_seconds=window_sec)
                count = self.window.count_events(key, window_sec)
                
                if count < count_thresh:
                    continue
                else:
                    self.window.clear(key) # Prevent alert spam
            
            # 4. Generate Alert
            alert_cfg = rule.get("alert", {})
            try:
                severity = SeverityLevel[alert_cfg.get("severity", "MEDIUM").upper()]
            except KeyError:
                severity = SeverityLevel.MEDIUM
                
            try:
                alert_type = AlertType[alert_cfg.get("type", "ANOMALY_DETECTION").upper()]
            except KeyError:
                alert_type = AlertType.ANOMALY_DETECTION
                
            alerts.append(AlertEvent(
                alert_type=alert_type,
                severity=severity,
                confidence_score=alert_cfg.get("confidence", 0.8),
                title=rule.get("name", "Rule Triggered"),
                description=rule.get("description", ""),
                source_ip=event.get("source_ip", ""),
                mitre_tactic=rule.get("mitre_tactic", ""),
                mitre_technique=rule.get("mitre_technique", ""),
                tags=rule.get("tags", []),
                evidence=event
            ))
            
        return alerts
