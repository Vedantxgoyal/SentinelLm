# Offline SOC Threat Detection System

A modular, open-source threat detection pipeline for Windows environments that ingests raw event logs, normalizes heterogeneous data formats, detects high-risk behaviors using rule-based engines, and generates actionable incident intelligence—all offline and without cloud dependencies.

## Overview

This system replicates real Security Operations Center (SOC) workflows by implementing a complete detection-to-analysis pipeline. It processes Windows event logs through a canonical normalization layer, applies MITRE ATT&CK-aligned detection rules, correlates related alerts into incidents, and synthesizes technical findings into human-readable summaries using a local LLM.

### Key Features

- **Offline & Private**: Runs entirely locally; no cloud dependencies or data exfiltration
- **Canonical Log Normalization**: Standardizes heterogeneous Windows event log formats into a unified schema
- **Rule-Based Detection Engine**: Identifies high-risk behaviors including log tampering, privileged logons, and suspicious LOLBin execution
- **MITRE ATT&CK Alignment**: Every detection maps to tactics and techniques for industry-standard explainability
- **Incident Correlation**: Groups related alerts into cohesive security incidents, mimicking SOC workflows
- **Forensic-Ready Alerts**: Structured evidence fields enable analyst investigation and response
- **Offline LLM Integration**: Transforms technical alerts into SOC-quality incident summaries locally
- **Production-Ready**: Handles real-world challenges: log inconsistency, missing fields, encoding issues, and Python packaging

## Architecture

```
Windows Event Logs
       ↓
[Log Ingestion Layer]
       ↓
[Canonical Normalization] → Unified Event Schema
       ↓
[Rule-Based Detection Engine] → Raw Detections
       ↓
[Incident Correlation] → Grouped Incidents
       ↓
[Offline LLM Summarizer] → Human-Readable Reports
       ↓
Alert/Incident Output
```

### Components

| Component | Purpose |
|-----------|---------|
| **Log Ingestion** | Reads Windows event logs (.evtx) and syslog formats |
| **Normalization Layer** | Maps diverse log formats to canonical schema with field validation |
| **Detection Engine** | Evaluates events against MITRE ATT&CK–aligned rules |
| **Correlation Engine** | Groups related alerts by time, source, and behavior patterns |
| **LLM Summarizer** | Generates incident narratives from technical alert chains |

## Quick Start

### Prerequisites

- Python 3.10+
- Windows 10/11 (for live log collection; analysis works on any OS)
- ~2GB disk space for local LLM model
- `pip` or `conda` for dependency management

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/offline-soc-detection.git
cd offline-soc-detection

# Install dependencies
pip install -r requirements.txt

# Download local LLM model (if using LLM summarizer)
python scripts/download_model.py
```

### Basic Usage

```bash
# Ingest and analyze local Windows event logs
python main.py \
  --input path/to/logs \
  --format evtx \
  --output reports/

# Analyze with rule engine and correlation
python main.py \
  --input path/to/logs \
  --enable-correlation \
  --enable-llm-summary \
  --output reports/

# View generated incidents
cat reports/incidents.json
```

### Configuration

Edit `config/detection_rules.yaml` to customize rule thresholds and behaviors:

```yaml
detection_rules:
  log_tampering:
    enabled: true
    severity: critical
    
  suspicious_logons:
    enabled: true
    fail_threshold: 10
    time_window_minutes: 30
    
  lolbin_execution:
    enabled: true
    severity: high
```

## Detection Capabilities

### Covered Threat Categories

- **Credential Access**: Suspicious logon attempts, pass-the-hash, credential dumping
- **Defense Evasion**: Log tampering, Sysmon evasion, service stopping
- **Lateral Movement**: Suspicious SMB activity, WMI execution
- **Privilege Escalation**: Token impersonation, UAC bypass patterns
- **Persistence**: Startup folder modifications, scheduled task creation
- **Execution**: PowerShell obfuscation, LOLBin abuse (certutil, regsvcs, msbuild)

### Example Detections

All detections reference MITRE ATT&CK framework:

| Detection | MITRE Tactic | MITRE Technique |
|-----------|-------------|-----------------|
| Event log clearing | Defense Evasion | T1070.001 |
| Failed logon spike | Credential Access | T1110.001 |
| LOLBIN execution (certutil) | Execution | T1218.* |
| Suspicious PowerShell execution | Execution | T1059.001 |
| Service stopped | Defense Evasion | T1562 |

## Output Formats

### Raw Alert JSON
```json
{
  "alert_id": "ALT-20250210-001",
  "timestamp": "2025-02-10T14:23:45Z",
  "severity": "high",
  "detection_rule": "suspicious_logons",
  "mitre_tactic": "Credential Access",
  "mitre_technique": "T1110.001",
  "evidence": {
    "source_ip": "192.168.1.100",
    "failed_attempts": 15,
    "time_window_minutes": 30,
    "target_account": "administrator"
  }
}
```

### Correlated Incident (with LLM Summary)
```json
{
  "incident_id": "INC-20250210-001",
  "severity": "critical",
  "alert_count": 7,
  "correlation_reason": "Same source IP, temporal proximity, escalating tactics",
  "timeline": [
    { "timestamp": "2025-02-10T14:23:45Z", "alert_id": "ALT-20250210-001" },
    { "timestamp": "2025-02-10T14:45:30Z", "alert_id": "ALT-20250210-002" }
  ],
  "llm_summary": "Detected credential attack from 192.168.1.100 with 15 failed logon attempts against the administrator account over 30 minutes (T1110.001), followed by suspicious LOLBin execution via certutil (T1218.009). Pattern suggests compromised workstation attempting lateral movement to domain admin account."
}
```

## Challenge Solutions

This project overcomes real-world production issues:

| Challenge | Solution |
|-----------|----------|
| **Log Format Heterogeneity** | Canonical schema validation; pluggable parsers for evtx, syslog, JSON |
| **Missing/Null Fields** | Schema-enforced defaults; graceful handling in detection rules |
| **Windows Encoding** | UTF-16 detection; codec fallbacks for malformed logs |
| **Python Packaging** | requirements.txt + lock file; tested on Windows/Linux/macOS |
| **Subprocess Reliability** | Robust error handling; timeout management for log parsing |
| **LLM Integration** | Local CPU-optimized models; no API calls or internet required |
| **Alert Fatigue** | Correlation engine groups related alerts; tunable rule thresholds |

## Project Structure

```
offline-soc-detection/
├── main.py                      # Entry point
├── requirements.txt             # Python dependencies
├── config/
│   ├── detection_rules.yaml     # Modular detection rule definitions
│   └── correlation_config.yaml  # Incident grouping logic
├── src/
│   ├── ingestion/
│   │   ├── __init__.py
│   │   └── log_reader.py        # EVTX/syslog parsing
│   ├── normalization/
│   │   ├── __init__.py
│   │   ├── schema.py            # Canonical event schema
│   │   └── parser.py            # Format-specific parsers
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── rule_engine.py       # Core detection logic
│   │   └── rules.py             # Rule implementations
│   ├── correlation/
│   │   ├── __init__.py
│   │   └── incident_grouper.py  # Alert correlation
│   └── llm/
│       ├── __init__.py
│       ├── summarizer.py        # LLM-based report generation
│       └── model_loader.py      # Offline model management
├── data/
│   ├── mitre_mappings.json      # ATT&CK technique references
│   └── sample_logs/             # Example event logs for testing
├── tests/
│   ├── test_normalization.py
│   ├── test_detection.py
│   └── test_correlation.py
└── docs/
    ├── ARCHITECTURE.md          # Detailed system design
    ├── RULE_DEVELOPMENT.md      # Guide for writing custom rules
    └── TROUBLESHOOTING.md       # Common issues & fixes
```

## Advanced Usage

### Custom Rule Development

Create a new detection rule in `src/detection/rules.py`:

```python
from src.detection.rule_engine import BaseRule

class SuspiciousRegistryModification(BaseRule):
    name = "suspicious_registry_modification"
    severity = "medium"
    mitre_tactic = "Persistence"
    mitre_technique = "T1547"
    
    def evaluate(self, event):
        return (
            event.event_type == "RegistryEvent" and
            event.registry_path.startswith("HKLM\\Run") and
            event.source_process not in self.trusted_processes
        )
```

### Extend Normalization

Add support for custom log formats by extending the canonical schema:

```python
from src.normalization.parser import BaseParser

class CustomLogParser(BaseParser):
    def parse(self, raw_event):
        normalized = {
            "timestamp": self._parse_timestamp(raw_event["time"]),
            "event_type": self._map_event_type(raw_event["type"]),
            "source_ip": raw_event.get("src_ip"),
            # ... map remaining fields
        }
        return self.validate_schema(normalized)
```

### Tuning Incident Correlation

Adjust grouping logic in `config/correlation_config.yaml`:

```yaml
correlation:
  time_window_minutes: 60
  group_by:
    - source_ip
    - target_account
    - mitre_tactic
  min_alerts_to_correlate: 2
```

## Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src tests/

# Test specific component
pytest tests/test_detection.py -v
```

## Performance

- **Ingestion**: ~100K events/minute (modern hardware)
- **Normalization**: Negligible overhead (<2% CPU)
- **Detection**: ~50K events/minute (depends on rule complexity)
- **Correlation**: <1s for 10K events
- **LLM Summarization**: ~3-5s per incident (CPU-bound)
