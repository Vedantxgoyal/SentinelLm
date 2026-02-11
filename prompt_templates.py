# llm/prompt_templates.py

def incident_prompt(alert: dict) -> str:
    return f"""
You are a professional SOC (Security Operations Center) analyst.

Analyze the following security alert and generate a clear, structured
incident summary.

ALERT DETAILS:
- Alert Name: {alert['alert_name']}
- Severity: {alert['severity']}
- Event Type: {alert['event_type']}
- Reason: {alert['reason']}
- Evidence: {alert['evidence']}

Your response MUST include:
1. What happened
2. Why it is suspicious
3. Possible attacker intent
4. Recommended actions

Write in clear, professional SOC report style.
"""
