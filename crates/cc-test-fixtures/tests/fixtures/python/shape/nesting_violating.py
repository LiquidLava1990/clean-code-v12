"""Sample violating cc.shape.nesting_depth: nested >3 levels deep."""


def classify(records):
    # Five-deep nesting on purpose to trip the rule.
    out = []
    for r in records:
        if r:
            if r.get("active"):
                if r.get("score", 0) > 0:
                    if r.get("region") == "us":
                        if r.get("tier") == "gold":
                            out.append(r["id"])
    return out
