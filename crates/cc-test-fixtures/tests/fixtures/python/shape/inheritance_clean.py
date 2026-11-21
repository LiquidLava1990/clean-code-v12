"""Sample clean cc.shape.no_inheritance: composition, not inheritance."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Worker:
    """A named worker."""

    name: str

    def announce(self) -> str:
        """Return the worker's announce string."""
        return f"worker:{self.name}"


@dataclass(frozen=True)
class Manager:
    """A manager — composed of a worker plus a list of reports."""

    worker: Worker
    reports: tuple[str, ...]

    def announce(self) -> str:
        """Return the manager's announce string."""
        return f"manager:{self.worker.name}:{len(self.reports)}"
