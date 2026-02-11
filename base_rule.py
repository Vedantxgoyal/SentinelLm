# detection/base_rule.py

class DetectionRule:
    RULE_ID = "BASE-000"
    NAME = "Base Detection Rule"
    SEVERITY = "low"
    MITRE_TACTIC = None
    MITRE_TECHNIQUE = None

    def match(self, event):
        raise NotImplementedError

    def alert(self, event, reason):
        return {
            "alert_id": self.RULE_ID,
            "alert_name": self.NAME,
            "severity": self.SEVERITY,
            "event_type": event["event_type"],
            "reason": reason,
            "mitre": {
                "tactic": self.MITRE_TACTIC,
                "technique": self.MITRE_TECHNIQUE
            },
            "evidence": {
                "process_name": event.get("process_name"),
                "command_line": event.get("command_line"),
                "user": event.get("user"),
                "host": event.get("host"),
                "event_id": event.get("event_id")
            },
            "timestamp": event["timestamp"]
        }
