"""Helpers for encoding J1939-22 Multi-PG payloads."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List

__all__ = ["ContainedParameterGroup", "MultiPGMessage"]


@dataclass(slots=True)
class ContainedParameterGroup:
    """Represents a C-PG entry inside a Multi-PG message."""

    tos: int
    trailer_format: int
    pgn: int
    payload: bytes = b""
    padding_header_bytes: int = 3

    def __post_init__(self) -> None:
        if not 0 <= self.tos <= 7:
            raise ValueError("TOS must be between 0 and 7")
        if not 0 <= self.trailer_format <= 7:
            raise ValueError("Trailer Format must be between 0 and 7")
        if not 0 <= self.pgn <= 0x3FFFF:
            raise ValueError("CPGN must fit within 18 bits")
        if self.tos == 0:
            if not 1 <= self.padding_header_bytes <= 3:
                raise ValueError("Padding header must be 1 to 3 bytes in length")
            if len(self.payload) > 12:
                raise ValueError("Padding payload may not exceed 12 bytes")
        else:
            if len(self.payload) > 60:
                raise ValueError("C-PG payload may not exceed 60 bytes")

    def header_bytes(self) -> bytes:
        """Return the encoded header bytes for the C-PG."""

        if self.tos == 0:
            return b"\x00" * self.padding_header_bytes

        edp = (self.pgn >> 17) & 0x1
        dp = (self.pgn >> 16) & 0x1
        pf = (self.pgn >> 8) & 0xFF
        ps = self.pgn & 0xFF
        payload_length = len(self.payload)

        first_byte = ((self.tos & 0x7) << 5) | ((self.trailer_format & 0x7) << 2) | (edp << 1) | dp
        return bytes([first_byte, pf, ps, payload_length])

    def encode(self) -> bytes:
        """Return the encoded bytes for this C-PG."""

        return self.header_bytes() + self.payload


@dataclass(slots=True)
class MultiPGMessage:
    """Aggregates multiple C-PGs into a Multi-PG payload."""

    cpgs: List[ContainedParameterGroup] = field(default_factory=list)

    def encode(self) -> bytes:
        return b"".join(cpg.encode() for cpg in self.cpgs)

    def append(self, cpg: ContainedParameterGroup) -> None:
        self.cpgs.append(cpg)

    def total_length(self) -> int:
        return sum(len(cpg.encode()) for cpg in self.cpgs)

    def __iter__(self) -> Iterable[ContainedParameterGroup]:
        return iter(self.cpgs)
