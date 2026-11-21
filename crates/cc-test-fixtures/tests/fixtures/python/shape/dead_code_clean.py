"""Sample clean cc.shape.dead_code: every branch reachable, every fn used."""


def label(score: int) -> str:
    """Return a tier label for the given numeric score."""
    if score >= 90:
        return "gold"
    if score >= 50:
        return "silver"
    return "bronze"


def render(scores: list[int]) -> list[str]:
    """Apply ``label`` across a list of scores."""
    return [label(s) for s in scores]
