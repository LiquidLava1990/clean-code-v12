"""Sample clean cc.shape.fn_length: small composed functions."""

from typing import Any


def process_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return enriched records, skipping rejected ones."""
    return [enrich(r) for r in records if not is_rejected(r)]


def is_rejected(record: dict[str, Any]) -> bool:
    """Return True when the record has been pre-rejected upstream."""
    return record.get("status") == "rejected"


def enrich(record: dict[str, Any]) -> dict[str, Any]:
    """Attach a normalised score to a record."""
    score = record.get("score", 0)
    return {**record, "normalised_score": score / 100.0}
