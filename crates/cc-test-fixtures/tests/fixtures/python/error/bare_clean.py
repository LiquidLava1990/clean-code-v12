"""Sample clean cc.error.bare: typed except with actionable error."""


class FixtureLoadError(Exception):
    """Raised when a fixture file cannot be read.

    Recovery: verify the path exists and is UTF-8 encoded.
    """


def safe_load(path: str) -> str:
    """Read a UTF-8 file, raising a typed error on failure."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise FixtureLoadError(
            f"failed to read fixture path={type(path).__name__}; "
            f"verify the path exists and is readable"
        ) from exc
