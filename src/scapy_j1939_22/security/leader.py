"""Leader state machine skeleton for J1939-91C network formation."""
from __future__ import annotations

from dataclasses import dataclass

from .freshness import FreshnessCounter


@dataclass(slots=True)
class LeaderStateMachine:
    """Coordinates epoch distribution and signing keys for followers."""

    freshness: FreshnessCounter

    def form_network(self) -> None:
        """Placeholder for the network formation handshake."""

        self.freshness.next()
