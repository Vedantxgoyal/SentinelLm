# detection/rules/execution.py

from ..base_rule import DetectionRule

SUSPICIOUS_LOLBINS = {
    "bitsadmin.exe",
    "wevtutil.exe",
    "mshta.exe",
    "certutil.exe"
}

class SuspiciousExecutionRule(DetectionRule):
    RULE_ID = "EXEC-001"
    NAME = "Suspicious LOLBin Execution"
    SEVERITY = "high"
    MITRE_TACTIC = "Execution"
    MITRE_TECHNIQUE = "T1105 - Ingress Tool Transfer"

    def match(self, event):
        if event.get("event_type") != "process_creation":
            return None

        process = (event.get("process_name") or "").lower()
        cmd = (event.get("command_line") or "").lower()

        if (
            process in SUSPICIOUS_LOLBINS
            and any(k in cmd for k in ["http", "https", "download"])
        ):
            return self.alert(
                event,
                f"{process} executed with suspicious parameters"
            )

        return None
