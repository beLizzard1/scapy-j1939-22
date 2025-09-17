"""Helpers for encoding SAE J1939-22 FD Transport protocol frames.

This module models the Connection Management (FD.TP.CM) and Data Transfer
(FD.TP.DT) messages described in SAE J1939-22. The classes provide lightweight
serialisation helpers to keep the :mod:`tp22` state machine logic focused on
session orchestration.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Optional

import struct

try:  # pragma: no cover - scapy may be unavailable when running unit tests
    from scapy.fields import BitField, ByteField, StrField  # type: ignore
    from scapy.packet import Packet  # type: ignore
except ImportError:  # pragma: no cover
    Packet = None  # type: ignore

__all__ = [
    "FDTPControl",
    "FDTPConnectionMessage",
    "FDTPDataTransferFrame",
]

if Packet is not None:  # pragma: no branch

    from scapy.fields import Field  # type: ignore

    class LEUInt24Field(Field):
        """Little endian unsigned 24-bit integer field."""

        def __init__(self, name: str, default: int = 0) -> None:
            super().__init__(name, default, fmt="3s")

        def addfield(self, pkt, s: bytes, val: int) -> bytes:  # type: ignore[override]
            if not 0 <= val <= 0xFFFFFF:
                raise ValueError(f"value {val} out of range for 24-bit field")
            return s + struct.pack("<I", val & 0xFFFFFF)[:3]

        def getfield(self, pkt, s: bytes):  # type: ignore[override]
            if len(s) < 3:
                raise ValueError("Buffer underrun for 24-bit field")
            raw = s[:3]
            return s[3:], struct.unpack("<I", raw + b"\x00")[0]

        def i2repr(self, pkt, val: int) -> str:  # type: ignore[override]
            return hex(val)


class FDTPControl(Enum):
    """Control codes for FD.TP connection management messages."""

    RTS = 0x0
    CTS = 0x1
    EOMS = 0x2
    EOMA = 0x3
    BAM = 0x4
    ABORT = 0xF

    def __int__(self) -> int:  # pragma: no cover - trivial
        return self.value


def _encode_u24(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError(f"value {value} out of range for 24-bit field")
    return value.to_bytes(3, byteorder="little", signed=False)


def _decode_u24(data: bytes) -> Optional[int]:
    if len(data) != 3:
        raise ValueError("u24 field requires exactly 3 bytes")
    value = int.from_bytes(data, byteorder="little", signed=False)
    if value == 0xFFFFFF:
        return None
    return value


def _validate_u8(value: int, allow_zero: bool = True) -> int:
    if not (0 <= value <= 0xFF):
        raise ValueError(f"value {value} out of range for 8-bit field")
    if not allow_zero and value == 0:
        raise ValueError("field value must be non-zero")
    return value


def _encode_pgn(pgn: int) -> bytes:
    if not 0 <= pgn <= 0x3FFFF:
        raise ValueError(f"PGN {pgn} out of range (must fit in 18 bits)")
    return pgn.to_bytes(3, byteorder="little", signed=False)


@dataclass(slots=True)
class FDTPConnectionMessage:
    """Represents an FD Transport Protocol connection management frame."""

    control: FDTPControl
    session: int
    _bytes_2_4: bytes
    _bytes_5_7: bytes
    byte8: int
    byte9: int
    pgn: int
    assurance_data: bytes = b""

    BASE_LENGTH: ClassVar[int] = 12

    def __post_init__(self) -> None:
        if not 0 <= self.session <= 0x0F:
            raise ValueError("session must fit in 4 bits")
        if len(self._bytes_2_4) != 3 or len(self._bytes_5_7) != 3:
            raise ValueError("multi-byte fields must be three bytes long")
        if len(self.assurance_data) > 52:
            raise ValueError("assurance data cannot exceed 52 bytes")
        _validate_u8(self.byte8)
        _validate_u8(self.byte9)
        _encode_pgn(self.pgn)  # validate range

    def encode(self) -> bytes:
        """Return the on-wire representation of the message."""

        header = ((self.session & 0x0F) << 4) | (self.control.value & 0x0F)
        payload = (
            self._bytes_2_4
            + self._bytes_5_7
            + bytes([self.byte8, self.byte9])
            + _encode_pgn(self.pgn)
        )
        return bytes([header]) + payload + self.assurance_data

    @classmethod
    def decode(cls, data: bytes) -> "FDTPConnectionMessage":
        """Create a :class:`FDTPConnectionMessage` from raw bytes."""

        if len(data) < cls.BASE_LENGTH:
            raise ValueError("FDTPConnectionMessage requires at least 12 bytes")
        header = data[0]
        control = FDTPControl(header & 0x0F)
        session = (header >> 4) & 0x0F
        bytes_2_4 = data[1:4]
        bytes_5_7 = data[4:7]
        byte8 = data[7]
        byte9 = data[8]
        pgn = int.from_bytes(data[9:12], byteorder="little", signed=False)
        assurance_data = data[12:]
        return cls(control, session, bytes_2_4, bytes_5_7, byte8, byte9, pgn, assurance_data)

    # Convenience accessors -------------------------------------------------
    @property
    def total_bytes(self) -> Optional[int]:
        """Return the total byte count field (None when reserved)."""

        return _decode_u24(self._bytes_2_4)

    @property
    def total_segments(self) -> Optional[int]:
        """Return the total segment count field (None when reserved)."""

        return _decode_u24(self._bytes_5_7)

    @property
    def param_2_4(self) -> Optional[int]:
        """Raw three-byte value carried in bytes 2-4."""

        return _decode_u24(self._bytes_2_4)

    @property
    def param_5_7(self) -> Optional[int]:
        """Raw three-byte value carried in bytes 5-7."""

        return _decode_u24(self._bytes_5_7)

    @property
    def pgn_value(self) -> int:
        """Return the PGN referenced by the message."""

        return self.pgn

    # Factory helpers -------------------------------------------------------
    @classmethod
    def rts(
        cls,
        *,
        session: int,
        total_bytes: int,
        total_segments: int,
        max_segments: int,
        assurance_type: int,
        pgn: int,
    ) -> "FDTPConnectionMessage":
        return cls(
            FDTPControl.RTS,
            session,
            _encode_u24(total_bytes),
            _encode_u24(total_segments),
            _validate_u8(max_segments, allow_zero=False),
            _validate_u8(assurance_type),
            pgn,
        )

    @classmethod
    def cts(
        cls,
        *,
        session: int,
        next_segment: int,
        segments_to_send: int,
        request_code: int,
        pgn: int,
    ) -> "FDTPConnectionMessage":
        return cls(
            FDTPControl.CTS,
            session,
            b"\xFF\xFF\xFF",
            _encode_u24(next_segment),
            _validate_u8(segments_to_send),
            _validate_u8(request_code),
            pgn,
        )

    @classmethod
    def eoms(
        cls,
        *,
        session: int,
        total_bytes: int,
        total_segments: int,
        assurance_type: int,
        assurance_data: bytes,
        pgn: int,
    ) -> "FDTPConnectionMessage":
        return cls(
            FDTPControl.EOMS,
            session,
            _encode_u24(total_bytes),
            _encode_u24(total_segments),
            _validate_u8(len(assurance_data)),
            _validate_u8(assurance_type),
            pgn,
            assurance_data,
        )

    @classmethod
    def eoma(
        cls,
        *,
        session: int,
        total_bytes: int,
        total_segments: int,
        pgn: int,
    ) -> "FDTPConnectionMessage":
        return cls(
            FDTPControl.EOMA,
            session,
            _encode_u24(total_bytes),
            _encode_u24(total_segments),
            0xFF,
            0xFF,
            pgn,
        )

    @classmethod
    def bam(
        cls,
        *,
        session: int,
        total_bytes: int,
        total_segments: int,
        assurance_type: int,
        pgn: int,
    ) -> "FDTPConnectionMessage":
        return cls(
            FDTPControl.BAM,
            session,
            _encode_u24(total_bytes),
            _encode_u24(total_segments),
            0xFF,
            _validate_u8(assurance_type),
            pgn,
        )

    @classmethod
    def abort(
        cls,
        *,
        session: int,
        reason: int,
        role: int,
        pgn: int,
    ) -> "FDTPConnectionMessage":
        byte8 = 0b11111100 | (role & 0x03)
        return cls(
            FDTPControl.ABORT,
            session,
            b"\xFF\xFF\xFF",
            b"\xFF\xFF\xFF",
            byte8,
            _validate_u8(reason),
            pgn,
        )


@dataclass(slots=True)
class FDTPDataTransferFrame:
    """Represents an FD.TP data transfer segment."""

    session: int
    segment_number: int
    data: bytes
    dt_format_indicator: int = 0

    MAX_SEGMENT_SIZE: ClassVar[int] = 60

    def __post_init__(self) -> None:
        if not 0 <= self.session <= 0x0F:
            raise ValueError("session must fit in 4 bits")
        if not 1 <= self.segment_number <= 0xFFFFFF:
            raise ValueError("segment number must be between 1 and 16,777,215")
        if not 0 <= self.dt_format_indicator <= 0x0F:
            raise ValueError("DTFI must fit in 4 bits")
        if len(self.data) > self.MAX_SEGMENT_SIZE:
            raise ValueError("segment payload exceeds 60 bytes")

    def encode(self) -> bytes:
        """Return the on-wire representation of the DT frame."""

        header = ((self.session & 0x0F) << 4) | (self.dt_format_indicator & 0x0F)
        segment_bytes = self.segment_number.to_bytes(3, byteorder="little", signed=False)
        return bytes([header]) + segment_bytes + self.data

    @classmethod
    def decode(cls, data: bytes) -> "FDTPDataTransferFrame":
        """Create a :class:`FDTPDataTransferFrame` from raw bytes."""

        if len(data) < 4:
            raise ValueError("FDTPDataTransferFrame requires at least 4 bytes")
        header = data[0]
        session = (header >> 4) & 0x0F
        dtfi = header & 0x0F
        segment_number = int.from_bytes(data[1:4], byteorder="little", signed=False)
        payload = data[4:]
        return cls(session=session, segment_number=segment_number, data=payload, dt_format_indicator=dtfi)

    @property
    def padded(self) -> bool:
        """Return True when the frame likely contains padding bytes."""

        return len(self.data) != self.MAX_SEGMENT_SIZE


if Packet is not None:  # pragma: no branch

    class FDTPConnectionPacket(Packet):
        """Scapy Packet representation of FD.TP connection management frames."""

        name = "J1939-22 FD.TP.CM"
        fields_desc = [
            BitField("session", 0, 4),
            BitField("control_raw", 0, 4),
            LEUInt24Field("param_2_4", 0),
            LEUInt24Field("param_5_7", 0),
            ByteField("byte8", 0),
            ByteField("byte9", 0),
            LEUInt24Field("pgn", 0),
            StrField("assurance_data", b""),
        ]

        def control(self) -> FDTPControl:
            return FDTPControl(self.control_raw)

        def to_message(self) -> FDTPConnectionMessage:
            return FDTPConnectionMessage(
                control=self.control(),
                session=self.session,
                _bytes_2_4=_encode_u24(self.param_2_4),
                _bytes_5_7=_encode_u24(self.param_5_7),
                byte8=self.byte8,
                byte9=self.byte9,
                pgn=self.pgn,
                assurance_data=bytes(self.assurance_data),
            )

        @classmethod
        def from_message(cls, message: FDTPConnectionMessage) -> "FDTPConnectionPacket":
            return cls(
                session=message.session,
                control_raw=message.control.value,
                param_2_4=int.from_bytes(message._bytes_2_4, byteorder="little"),
                param_5_7=int.from_bytes(message._bytes_5_7, byteorder="little"),
                byte8=message.byte8,
                byte9=message.byte9,
                pgn=message.pgn,
                assurance_data=message.assurance_data,
            )

        def extract_padding(self, s: bytes) -> tuple[bytes, bytes]:  # pragma: no cover
            return b"", s


    class FDTPDataTransferPacket(Packet):
        """Scapy Packet representation of FD.TP data transfer frames."""

        name = "J1939-22 FD.TP.DT"
        fields_desc = [
            BitField("session", 0, 4),
            BitField("dtfi", 0, 4),
            LEUInt24Field("segment_number", 1),
            StrField("segment_data", b""),
        ]

        def to_frame(self) -> FDTPDataTransferFrame:
            return FDTPDataTransferFrame(
                session=self.session,
                segment_number=self.segment_number,
                data=bytes(self.segment_data),
                dt_format_indicator=self.dtfi,
            )

        @classmethod
        def from_frame(cls, frame: FDTPDataTransferFrame) -> "FDTPDataTransferPacket":
            return cls(
                session=frame.session,
                dtfi=frame.dt_format_indicator,
                segment_number=frame.segment_number,
                segment_data=frame.data,
            )

        def extract_padding(self, s: bytes) -> tuple[bytes, bytes]:  # pragma: no cover
            return b"", s


    __all__.extend(["FDTPConnectionPacket", "FDTPDataTransferPacket"])

else:  # pragma: no cover - Scapy not available

    FDTPConnectionPacket = None
    FDTPDataTransferPacket = None
