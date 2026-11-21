"""Sample violating cc.shape.dead_code: unreachable branch + unused helper."""


def label(score):
    # Dead branch — return precedes the second arm.
    if score >= 90:
        return "gold"
    return "ok"
    # The line below can never execute.
    return "platinum"


def _unused_helper(value):
    # Never referenced anywhere — dead.
    return value * 2
