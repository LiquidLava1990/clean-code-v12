"""Sample clean cc.shape.nesting_depth: early-returns keep depth shallow."""

from typing import Any


def classify(records: list[dict[str, Any]]) -> list[str]:
    """Return ids of gold-tier active US records with positive scores."""
    return [r["id"] for r in records if is_gold_us_active(r)]


def is_gold_us_active(record: dict[str, Any]) -> bool:
    """Return True when the record is gold-tier, US, active, scoring."""
    if not record:
        return False
    if not record.get("active"):
        return False
    if record.get("score", 0) <= 0:
        return False
    return record.get("region") == "us" and record.get("tier") == "gold"
