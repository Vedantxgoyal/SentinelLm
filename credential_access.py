# detection/rules/credential_access.py

from ..base_rule import DetectionRule

class LsassAccessRule(DetectionRule):
    RULE_ID = "CRED-001"
    NAME = "Possible Credential Dumping"
    SEVERITY = "critical"
    MITRE_TACTIC = "Credential Access"
    MITRE_TECHNIQUE = "T1003 - OS Credential Dumping"

    def match(self, event):
        if event.get("event_type") != "process_creation":
            return None

        cmd = (event.get("command_line") or "").lower()

        if "lsass" in cmd and "dump" in cmd:
            return self.alert(
                event,
                "LSASS memory access detected"
            )

        return None
