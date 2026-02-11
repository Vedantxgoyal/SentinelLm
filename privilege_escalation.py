# detection/rules/privilege_escalation.py

from ..base_rule import DetectionRule

class PrivilegedLogonRule(DetectionRule):
    RULE_ID = "PRIV-001"
    NAME = "Privileged Logon Detected"
    SEVERITY = "medium"
    MITRE_TACTIC = "Privilege Escalation"
    MITRE_TECHNIQUE = "T1068 - Exploitation for Privilege Escalation"

    def match(self, event):
        if event.get("event_type") == "privileged_logon":
            return self.alert(
                event,
                "User logged on with elevated privileges"
            )

        return None
