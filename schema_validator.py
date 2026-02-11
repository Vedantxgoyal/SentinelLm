# normalization/schema_validator.py

from .event_schema import CANONICAL_SCHEMA


def validate_event_schema(event):
    missing = []
    type_errors = []

    for field, expected_type in CANONICAL_SCHEMA.items():
        if field not in event:
            missing.append(field)
        elif not isinstance(event[field], expected_type):
            type_errors.append(
                (field, type(event[field]), expected_type)
            )

    return missing, type_errors
