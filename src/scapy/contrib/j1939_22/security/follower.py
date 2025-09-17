"""Follower state machine skeleton for J1939-91C security."""
from __future__ import annotations

from dataclasses import dataclass

from .freshness import FreshnessCounter


@dataclass(slots=True)
class FollowerStateMachine:
    """Maintains local state for a follower node."""

    freshness: FreshnessCounter

    def join_network(self) -> None:
        """Placeholder for the follower join handshake."""

        if not self.freshness.seen(self.freshness.current):
            self.freshness.history.add(self.freshness.current)
