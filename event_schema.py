CANONICAL_SCHEMA = {
    "timestamp": str,
    "host": (str, type(None)),
    "user": (str, type(None)),
    "event_id": int,
    "event_type": str,
    "source": str,
    "process_name": (str, type(None)),
    "command_line": (str, type(None)),
    "logon_id": (str, type(None)),
    "severity": str,
    "raw_event": dict
}
