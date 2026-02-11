# normalisation/normalize.py

import json
from .field_mapper import EVENT_ID_TO_TYPE, SEVERITY_BY_EVENT
from .schema_validator import validate_event_schema


def normalize_event(raw_event):
    event_id = int(
        raw_event.get("EventID")
        or raw_event.get("event_id")
        or -1
    )

    event_type = EVENT_ID_TO_TYPE.get(event_id, "unknown")
    severity = SEVERITY_BY_EVENT.get(event_type, "low")

    return {
        "timestamp": raw_event.get("TimeCreated") or raw_event.get("@timestamp"),
        "host": raw_event.get("ComputerName"),
        "user": raw_event.get("SubjectUserName"),
        "event_id": event_id,
        "event_type": event_type,
        "source": "windows_security",
        "process_name": raw_event.get("NewProcessName"),
        "command_line": raw_event.get("CommandLine"),
        "logon_id": raw_event.get("SubjectLogonId"),
        "severity": severity,
        "raw_event": raw_event
    }


def load_events(input_path):
    """
    Supports:
    - JSON array files
    - JSON Lines / NDJSON files (one JSON object per line)
    """
    events = []

    with open(input_path, "r", encoding="utf-8") as f:
        first_char = f.read(1)
        f.seek(0)

        # Case 1: JSON array
        if first_char == "[":
            events = json.load(f)

        # Case 2: JSON Lines / NDJSON
        else:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                events.append(json.loads(line))

    return events


def normalize_file(input_path, output_path):
    raw_events = load_events(input_path)

    normalized_events = []
    for raw in raw_events:
        normalized = normalize_event(raw)

        missing, type_errors = validate_event_schema(normalized)
        if missing or type_errors:
            raise ValueError(
                f"Schema validation failed\nMissing: {missing}\nType errors: {type_errors}"
            )

        normalized_events.append(normalized)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(normalized_events, f, indent=2)

    print(f"✅ Normalized {len(normalized_events)} events → {output_path}")
