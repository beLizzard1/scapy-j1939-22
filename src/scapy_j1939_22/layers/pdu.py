"""Scapy layer for the J1939-22 PDU header."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class J1939PDU:
    """Minimal representation of a J1939 PDU header."""

    priority: int
    pgn: int
    source_address: int
    destination_address: int

    def to_can_id(self) -> int:
        """Encode the header into an 29-bit CAN identifier."""

        return (self.priority << 26) | (self.pgn << 8) | self.source_address
