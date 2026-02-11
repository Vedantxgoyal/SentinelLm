# detection/rules/defense_evasion.py

from ..base_rule import DetectionRule

class LogTamperingRule(DetectionRule):
    RULE_ID = "DEF-001"
    NAME = "Windows Event Log Tampering"
    SEVERITY = "high"
    MITRE_TACTIC = "Defense Evasion"
    MITRE_TECHNIQUE = "T1070.001 - Clear Windows Event Logs"

    def match(self, event):
        if event.get("event_id") == 1102:
            return self.alert(
                event,
                "Security event log was cleared"
            )

        return None
