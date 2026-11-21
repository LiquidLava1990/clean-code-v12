"""Sample clean cc.shape.duplication: shared helper, parameterised region."""

from typing import Any


def total_for_region(records: list[dict[str, Any]], region: str) -> int:
    """Sum the score field for records matching the given region."""
    return sum(r.get("score", 0) for r in records if r.get("region") == region)
