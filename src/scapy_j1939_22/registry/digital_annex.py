"""In-memory representation of normalized Digital Annex data."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional


@dataclass(slots=True)
class PGDefinition:
    """Represents a single Parameter Group definition."""

    pgn: int
    name: str
    length: int
    spns: Mapping[str, int]


class DigitalAnnexRegistry:
    """Lookup helper for PG and SPN definitions."""

    def __init__(self) -> None:
        self._pgns: dict[int, PGDefinition] = {}

    def register_pg(self, definition: PGDefinition) -> None:
        """Add a Parameter Group definition to the registry."""

        self._pgns[definition.pgn] = definition

    def get_pg(self, pgn: int) -> Optional[PGDefinition]:
        """Return a parameter group definition when available."""

        return self._pgns.get(pgn)
