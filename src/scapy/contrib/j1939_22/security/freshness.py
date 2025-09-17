"""Freshness counter and replay protection primitives."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class FreshnessCounter:
    """Tracks freshness values per participant."""

    current: int = 0
    history: set[int] = field(default_factory=set)

    def next(self) -> int:
        """Return the next monotonic freshness value."""

        self.current += 1
        self.history.add(self.current)
        return self.current

    def seen(self, value: int) -> bool:
        """Check if a freshness value was already observed."""

        return value in self.history
