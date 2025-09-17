"""Helpers for encoding J1939-22 Multi-PG payloads."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List

try:  # pragma: no cover - scapy may be unavailable in bare environments
    from scapy.fields import FieldLenField, StrLenField  # type: ignore
    from scapy.packet import Packet  # type: ignore
except ImportError:  # pragma: no cover
    Packet = None  # type: ignore

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

    @classmethod
    def decode(cls, raw: bytes, *, padding_header_bytes: int = 3) -> "ContainedParameterGroup":
        if not raw:
            raise ValueError("C-PG header requires data")
        tos = (raw[0] >> 5) & 0x7
        tf = (raw[0] >> 2) & 0x7
        edp = (raw[0] >> 1) & 0x1
        dp = raw[0] & 0x1

        if tos == 0:
            if len(raw) < padding_header_bytes:
                raise ValueError("Padding C-PG header truncated")
            payload = raw[padding_header_bytes:]
            return cls(
                tos=0,
                trailer_format=tf,
                pgn=0,
                payload=payload,
                padding_header_bytes=padding_header_bytes,
            )

        if len(raw) < 4:
            raise ValueError("C-PG header truncated")
        pf = raw[1]
        ps = raw[2]
        length = raw[3]
        payload = raw[4 : 4 + length]
        if len(payload) != length:
            raise ValueError("C-PG payload truncated")
        pgn = (edp << 17) | (dp << 16) | (pf << 8) | ps
        return cls(tos=tos, trailer_format=tf, pgn=pgn, payload=payload)


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

    @classmethod
    def from_bytes(cls, data: bytes) -> "MultiPGMessage":
        cpgs: List[ContainedParameterGroup] = []
        i = 0
        while i < len(data):
            header = data[i]
            tos = (header >> 5) & 0x7
            if tos == 0:
                cpg = ContainedParameterGroup.decode(data[i:])
                cpgs.append(cpg)
                break
            if i + 4 > len(data):
                raise ValueError("C-PG header truncated")
            length = data[i + 3]
            chunk = data[i : i + 4 + length]
            if len(chunk) < 4 + length:
                raise ValueError("C-PG payload truncated")
            cpg = ContainedParameterGroup.decode(chunk)
            cpgs.append(cpg)
            i += len(chunk)
        return cls(cpgs=cpgs)


if Packet is not None:  # pragma: no branch

    class MultiPGPacket(Packet):
        """Scapy Packet wrapper for Multi-PG payloads."""

        name = "J1939-22 Multi-PG"
        fields_desc = [
            FieldLenField("length", None, length_of="data", fmt="B"),
            StrLenField("data", b"", length_from=lambda pkt: pkt.length),
        ]

        def to_message(self) -> MultiPGMessage:
            return MultiPGMessage.from_bytes(bytes(self.data))

        @classmethod
        def from_message(cls, message: MultiPGMessage) -> "MultiPGPacket":
            data = message.encode()
            return cls(length=len(data), data=data)

        def extract_padding(self, s: bytes) -> tuple[bytes, bytes]:  # pragma: no cover - Scapy hook
            return b"", s

    __all__.append("MultiPGPacket")
