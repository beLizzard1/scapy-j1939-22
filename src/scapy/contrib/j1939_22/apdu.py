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
class ApplicationPDU:
    """Base container for a J1939-22 application PDU."""

    pgn: int
    payload: bytes
    assurance_type: Optional[int] = None
    assurance_data: bytes = b""
    source_address: Optional[int] = None
    destination_address: Optional[int] = None
    priority: Optional[int] = None

    def total_payload_length(self) -> int:
        """Return the combined length of PG data and assurance data."""

        return len(self.payload) + len(self.assurance_data)

    def to_j1939_apdu(self, *, apdu_type: APDUType = APDUType.SINGLE_PG) -> "J1939APDU":
        """Convert to the generic :class:`J1939APDU` container."""

        return J1939APDU(
            pgn=self.pgn,
            payload=self.payload,
            apdu_type=apdu_type,
            assurance_type=self.assurance_type,
            assurance_data=self.assurance_data or None,
            source_address=self.source_address,
            destination_address=self.destination_address,
            priority=self.priority,
        )


@dataclass(slots=True)
class APDU1(ApplicationPDU):
    """Destination-specific application PDU (A_PDU1 format)."""

    destination_address: int = 0xFF

    def __post_init__(self) -> None:
        if not 0 <= self.destination_address <= 0xFF:
            raise ValueError("Destination address must fit in 8 bits")
        pf = (self.pgn >> 8) & 0xFF
        if pf >= 240:
            raise ValueError("A_PDU1 PGNs must map to a PDU1 format (< 240)")
        if self.pgn & 0xFF:
            raise ValueError("A_PDU1 PGNs must have the PS byte cleared to zero")
        self.priority = self.priority if self.priority is not None else 6
        self.source_address = self.source_address if self.source_address is not None else 0x00


@dataclass(slots=True)
class APDU2(ApplicationPDU):
    """Global application PDU (A_PDU2 format)."""

    def __post_init__(self) -> None:
        pf = (self.pgn >> 8) & 0xFF
        if pf < 240:
            raise ValueError("A_PDU2 PGNs must map to a PDU2 format (>= 240)")
        self.priority = self.priority if self.priority is not None else 6
        self.source_address = self.source_address if self.source_address is not None else 0x00
        self.destination_address = 0xFF


@dataclass(slots=True)
class J1939APDU:
    """Container for a J1939 Application Protocol Data Unit.

    Attributes:
        pgn: The Parameter Group Number that identifies the PG payload.
        payload: Raw byte payload for the PG contents.
        apdu_type: Indicates whether the data is a single, multi, or composite PG.
        assurance_type: Optional assurance data type reported in transport metadata.
        assurance_data: Optional assurance data blob accompanying the PG contents.
    """

    pgn: int
    payload: bytes
    apdu_type: APDUType = APDUType.SINGLE_PG
    spn_values: Optional[dict[str, int]] = None
    assurance_type: Optional[int] = None
    assurance_data: Optional[bytes] = None
    source_address: Optional[int] = None
    destination_address: Optional[int] = None
    priority: Optional[int] = None

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
