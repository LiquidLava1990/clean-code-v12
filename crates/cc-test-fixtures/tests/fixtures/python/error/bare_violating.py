"""Sample violating cc.error.bare: bare ``except`` swallowing exceptions."""


def safe_load(path: str) -> str | None:
    """Read a file, returning None on any failure (bad practice)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except:  # noqa: E722 — bare except is the violation under test.
        return None
