"""Sample violating cc.shape.duplication: two near-identical helpers."""


def total_for_us(records):
    # Sum scores for US records.
    total = 0
    for r in records:
        if r.get("region") == "us":
            total += r.get("score", 0)
    return total


def total_for_eu(records):
    # Sum scores for EU records — duplicated logic.
    total = 0
    for r in records:
        if r.get("region") == "eu":
            total += r.get("score", 0)
    return total
