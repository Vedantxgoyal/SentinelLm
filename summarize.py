# llm/summarize.py

import json
from pathlib import Path

from .local_llm import query_llm
from .prompt_templates import incident_prompt


def summarize_alerts(alerts_file: str, output_file: str):
    with open(alerts_file, "r", encoding="utf-8") as f:
        alerts = json.load(f)

    incidents = []

    for alert in alerts:
        prompt = incident_prompt(alert)
        summary = query_llm(prompt)

        incidents.append({
            "alert_id": alert["alert_id"],
            "alert_name": alert["alert_name"],
            "severity": alert["severity"],
            "summary": summary
        })

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2)

    print(
        f"🧠 Generated {len(incidents)} incident reports → {output_file}"
    )
