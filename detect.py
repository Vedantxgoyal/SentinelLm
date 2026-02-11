# detection/detect.py

import json
from pathlib import Path

from .rules.execution import SuspiciousExecutionRule
from .rules.credential_access import LsassAccessRule
from .rules.defense_evasion import LogTamperingRule
from .rules.privilege_escalation import PrivilegedLogonRule

RULES = [
    SuspiciousExecutionRule(),
    LsassAccessRule(),
    LogTamperingRule(),
    PrivilegedLogonRule()
]

def run_detection(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as f:
        events = json.load(f)

    alerts = []

    for event in events:
        for rule in RULES:
            alert = rule.match(event)
            if alert:
                alerts.append(alert)

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)

    print(f"🚨 Generated {len(alerts)} alerts → {output_file}")
