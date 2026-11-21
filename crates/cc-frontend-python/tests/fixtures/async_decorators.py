import functools


def memoize(fn):
    return functools.lru_cache(maxsize=None)(fn)


@memoize
async def slow_add(a: int, b: int) -> int:
    return a + b
