# llm/run_summarization.py

from .summarize import summarize_alerts


INPUT_ALERTS_FILE = "reports/alerts/alerts_bitsadmin.json"
OUTPUT_INCIDENTS_FILE = "reports/incidents/incidents_bitsadmin.json"


summarize_alerts(
    INPUT_ALERTS_FILE,
    OUTPUT_INCIDENTS_FILE
)
