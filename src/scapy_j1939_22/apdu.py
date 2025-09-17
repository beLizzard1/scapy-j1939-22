"""APDU abstractions for SAE J1939-22.

Defines high-level packet groupings (Single PG, Multi PG, Composite PG) and
helpers for packing and unpacking parameter groups.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional


class APDUType(str, Enum):
    """Enumerates supported J1939 APDU categories."""

    SINGLE_PG = "single-pg"
    MULTI_PG = "multi-pg"
    CPG = "composite-pg"


@dataclass(slots=True)
class J1939APDU:
    """Container for a J1939 Application Protocol Data Unit.

    Attributes:
        pgn: The Parameter Group Number that identifies the PG payload.
        payload: Raw byte payload for the PG contents.
        apdu_type: Indicates whether the data is a single, multi, or composite PG.
    """

    pgn: int
    payload: bytes
    apdu_type: APDUType = APDUType.SINGLE_PG
    spn_values: Optional[dict[str, int]] = None

    def is_segmented(self) -> bool:
        """Return True when this APDU requires transport segmentation."""

        return self.apdu_type in {APDUType.MULTI_PG, APDUType.CPG}

    def referenced_pgns(self) -> Iterable[int]:
        """Yield all Parameter Group Numbers referenced by this APDU."""

        if self.apdu_type != APDUType.CPG:
            return (self.pgn,)
        if self.spn_values is None:
            return (self.pgn,)
        referenced = self.spn_values.get("referenced_pgns")
        if isinstance(referenced, (list, tuple)):
            return tuple(int(p) for p in referenced)
        return (self.pgn,)
