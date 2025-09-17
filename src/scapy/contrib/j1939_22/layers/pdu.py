"""Scapy Packet models for J1939-22 D_PDU formats."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

try:  # pragma: no cover - scapy may not be installed in minimal environments
    from scapy.fields import ByteField, FieldLenField, StrLenField  # type: ignore
    from scapy.packet import Packet  # type: ignore
except ImportError:  # pragma: no cover - fallback to lightweight stubs
    Packet = None  # type: ignore

from ..apdu import APDU1, APDU2

__all__ = ["ApplicationProtocolIndicator", "DPDU1", "DPDU2", "DPDU3"]


class ApplicationProtocolIndicator(IntEnum):
    """Enumerates FBFF application protocol indicators."""

    MULTI_PG = 0b000
    AUTOSAR_CAN_NM_WAKE = 0b001
    PROPRIETARY = 0b010
    XCP = 0b011
    RESERVED_100 = 0b100
    RESERVED_101 = 0b101
    ISO15765_FUNCTIONAL = 0b110
    ISO15765_PHYSICAL = 0b111


if Packet is not None:  # pragma: no branch - either scapy packet implementation or fallback
    class _DPDUBase(Packet):
        """Base packet shared by D_PDU variants."""

        def extract_padding(self, s: bytes) -> tuple[bytes, bytes]:  # pragma: no cover - scapy API hook
            return b"", s

        def data_field(self) -> bytes:
            return bytes(self.payload)


    class DPDU1(_DPDUBase):
        """Destination specific D_PDU (PDU1)."""

        name = "J1939-22 D_PDU1"
        fields_desc = [
            ByteField("priority", 6),
            ByteField("edp", 0),
            ByteField("dp", 0),
            ByteField("pf", 0),
            ByteField("ps", 0),
            ByteField("sa", 0),
            FieldLenField("length", None, length_of="payload", fmt="B"),
            StrLenField("payload", b"", length_from=lambda pkt: pkt.length),
        ]

        @property
        def pgn(self) -> int:
            return ((self.edp & 0x1) << 17) | ((self.dp & 0x1) << 16) | ((self.pf & 0xFF) << 8)

        @property
        def destination_address(self) -> int:
            return self.ps & 0xFF

        @property
        def source_address(self) -> int:
            return self.sa & 0xFF

        def to_can_id(self) -> int:
            return (
                (self.priority & 0x7) << 26
                | (self.edp & 0x1) << 25
                | (self.dp & 0x1) << 24
                | (self.pf & 0xFF) << 16
                | (self.ps & 0xFF) << 8
                | (self.sa & 0xFF)
            )

        def to_apdu(self) -> APDU1:
            return APDU1(
                pgn=self.pgn,
                payload=bytes(self.payload),
                destination_address=self.ps,
                source_address=self.sa,
                priority=self.priority,
            )

        @classmethod
        def from_apdu(
            cls,
            apdu: APDU1,
            *,
            priority: int | None = None,
            source_address: int | None = None,
            destination_address: int | None = None,
            edp: int = 0,
            dp: int = 0,
        ) -> "DPDU1":
            pf = (apdu.pgn >> 8) & 0xFF
            if pf >= 240:
                raise ValueError("APDU1 PGNs must use a PDU1 format (< 240)")
            dest = destination_address if destination_address is not None else (apdu.destination_address or 0xFF)
            data = apdu.payload + (apdu.assurance_data or b"")
            return cls(
                priority=priority if priority is not None else (apdu.priority or 6),
                edp=edp,
                dp=dp,
                pf=pf,
                ps=dest & 0xFF,
                sa=(source_address if source_address is not None else (apdu.source_address or 0x00)) & 0xFF,
                length=len(data),
                payload=data,
            )

        @classmethod
        def from_can_id(cls, can_id: int, data: bytes) -> "DPDU1":
            priority = (can_id >> 26) & 0x7
            edp = (can_id >> 25) & 0x1
            dp = (can_id >> 24) & 0x1
            pf = (can_id >> 16) & 0xFF
            ps = (can_id >> 8) & 0xFF
            sa = can_id & 0xFF
            return cls(
                priority=priority,
                edp=edp,
                dp=dp,
                pf=pf,
                ps=ps,
                sa=sa,
                length=len(data),
                payload=data,
            )


    class DPDU2(_DPDUBase):
        """Globally addressed D_PDU (PDU2)."""

        name = "J1939-22 D_PDU2"
        fields_desc = [
            ByteField("priority", 6),
            ByteField("edp", 0),
            ByteField("dp", 0),
            ByteField("pf", 0),
            ByteField("ps", 0),
            ByteField("sa", 0),
            FieldLenField("length", None, length_of="payload", fmt="B"),
            StrLenField("payload", b"", length_from=lambda pkt: pkt.length),
        ]

        @property
        def pgn(self) -> int:
            return (
                ((self.edp & 0x1) << 17)
                | ((self.dp & 0x1) << 16)
                | ((self.pf & 0xFF) << 8)
                | (self.ps & 0xFF)
            )

        @property
        def source_address(self) -> int:
            return self.sa & 0xFF

        def to_can_id(self) -> int:
            return (
                (self.priority & 0x7) << 26
                | (self.edp & 0x1) << 25
                | (self.dp & 0x1) << 24
                | (self.pf & 0xFF) << 16
                | (self.ps & 0xFF) << 8
                | (self.sa & 0xFF)
            )

        def to_apdu(self) -> APDU2:
            return APDU2(
                pgn=self.pgn,
                payload=bytes(self.payload),
                source_address=self.sa,
                priority=self.priority,
            )

        @classmethod
        def from_apdu(
            cls,
            apdu: APDU2,
            *,
            priority: int | None = None,
            source_address: int | None = None,
            edp: int = 0,
            dp: int = 0,
        ) -> "DPDU2":
            pf = (apdu.pgn >> 8) & 0xFF
            if pf < 240:
                raise ValueError("APDU2 PGNs must use a PDU2 format (>= 240)")
            ps = apdu.pgn & 0xFF
            data = apdu.payload + (apdu.assurance_data or b"")
            return cls(
                priority=priority if priority is not None else (apdu.priority or 6),
                edp=edp,
                dp=dp,
                pf=pf,
                ps=ps,
                sa=(source_address if source_address is not None else (apdu.source_address or 0x00)) & 0xFF,
                length=len(data),
                payload=data,
            )

        @classmethod
        def from_can_id(cls, can_id: int, data: bytes) -> "DPDU2":
            priority = (can_id >> 26) & 0x7
            edp = (can_id >> 25) & 0x1
            dp = (can_id >> 24) & 0x1
            pf = (can_id >> 16) & 0xFF
            ps = (can_id >> 8) & 0xFF
            sa = can_id & 0xFF
            return cls(
                priority=priority,
                edp=edp,
                dp=dp,
                pf=pf,
                ps=ps,
                sa=sa,
                length=len(data),
                payload=data,
            )


    class DPDU3(_DPDUBase):
        """FBFF D_PDU with Application Protocol Indicator."""

        name = "J1939-22 D_PDU3"
        fields_desc = [
            ByteField("app_pi", 0),
            ByteField("sa", 0),
            FieldLenField("length", None, length_of="payload", fmt="B"),
            StrLenField("payload", b"", length_from=lambda pkt: pkt.length),
        ]

        def to_can_id(self) -> int:
            return ((self.app_pi & 0x7) << 8) | (self.sa & 0xFF)

        def is_multi_pg(self) -> bool:
            return ApplicationProtocolIndicator(self.app_pi) is ApplicationProtocolIndicator.MULTI_PG

        @classmethod
        def from_can_id(cls, can_id: int, payload: bytes) -> "DPDU3":
            app_pi = ApplicationProtocolIndicator((can_id >> 8) & 0x7)
            sa = can_id & 0xFF
            return cls(app_pi=int(app_pi), sa=sa, length=len(payload), payload=payload)

else:

    @dataclass
    class DPDU1:
        priority: int = 6
        edp: int = 0
        dp: int = 0
        pf: int = 0
        ps: int = 0
        sa: int = 0
        payload: bytes = b""

        def __post_init__(self) -> None:
            self.length = len(self.payload)

        @property
        def destination_address(self) -> int:
            return self.ps & 0xFF

        @property
        def source_address(self) -> int:
            return self.sa & 0xFF

        @property
        def pgn(self) -> int:
            return ((self.edp & 0x1) << 17) | ((self.dp & 0x1) << 16) | ((self.pf & 0xFF) << 8)

        def data_field(self) -> bytes:
            return bytes(self.payload)

        def to_can_id(self) -> int:
            return (
                (self.priority & 0x7) << 26
                | (self.edp & 0x1) << 25
                | (self.dp & 0x1) << 24
                | (self.pf & 0xFF) << 16
                | (self.ps & 0xFF) << 8
                | (self.sa & 0xFF)
            )

        def to_apdu(self) -> APDU1:
            return APDU1(
                pgn=self.pgn,
                payload=bytes(self.payload),
                destination_address=self.ps,
                source_address=self.sa,
                priority=self.priority,
            )

        @classmethod
        def from_apdu(
            cls,
            apdu: APDU1,
            *,
            priority: Optional[int] = None,
            source_address: Optional[int] = None,
            destination_address: Optional[int] = None,
            edp: int = 0,
            dp: int = 0,
        ) -> "DPDU1":
            pf = (apdu.pgn >> 8) & 0xFF
            if pf >= 240:
                raise ValueError("APDU1 PGNs must use a PDU1 format (< 240)")
            dest = destination_address if destination_address is not None else (apdu.destination_address or 0xFF)
            data = apdu.payload + (apdu.assurance_data or b"")
            return cls(
                priority=priority if priority is not None else (apdu.priority or 6),
                edp=edp,
                dp=dp,
                pf=pf,
                ps=dest & 0xFF,
                sa=(source_address if source_address is not None else (apdu.source_address or 0x00)) & 0xFF,
                payload=data,
            )

        @classmethod
        def from_can_id(cls, can_id: int, data: bytes) -> "DPDU1":
            priority = (can_id >> 26) & 0x7
            edp = (can_id >> 25) & 0x1
            dp = (can_id >> 24) & 0x1
            pf = (can_id >> 16) & 0xFF
            ps = (can_id >> 8) & 0xFF
            sa = can_id & 0xFF
            return cls(priority=priority, edp=edp, dp=dp, pf=pf, ps=ps, sa=sa, payload=data)


    @dataclass
    class DPDU2:
        priority: int = 6
        edp: int = 0
        dp: int = 0
        pf: int = 0
        ps: int = 0
        sa: int = 0
        payload: bytes = b""

        def __post_init__(self) -> None:
            self.length = len(self.payload)

        @property
        def pgn(self) -> int:
            return (
                ((self.edp & 0x1) << 17)
                | ((self.dp & 0x1) << 16)
                | ((self.pf & 0xFF) << 8)
                | (self.ps & 0xFF)
            )

        @property
        def source_address(self) -> int:
            return self.sa & 0xFF

        def data_field(self) -> bytes:
            return bytes(self.payload)

        def to_can_id(self) -> int:
            return (
                (self.priority & 0x7) << 26
                | (self.edp & 0x1) << 25
                | (self.dp & 0x1) << 24
                | (self.pf & 0xFF) << 16
                | (self.ps & 0xFF) << 8
                | (self.sa & 0xFF)
            )

        def to_apdu(self) -> APDU2:
            return APDU2(
                pgn=self.pgn,
                payload=bytes(self.payload),
                source_address=self.sa,
                priority=self.priority,
            )

        @classmethod
        def from_apdu(
            cls,
            apdu: APDU2,
            *,
            priority: Optional[int] = None,
            source_address: Optional[int] = None,
            edp: int = 0,
            dp: int = 0,
        ) -> "DPDU2":
            pf = (apdu.pgn >> 8) & 0xFF
            if pf < 240:
                raise ValueError("APDU2 PGNs must use a PDU2 format (>= 240)")
            ps = apdu.pgn & 0xFF
            data = apdu.payload + (apdu.assurance_data or b"")
            return cls(
                priority=priority if priority is not None else (apdu.priority or 6),
                edp=edp,
                dp=dp,
                pf=pf,
                ps=ps,
                sa=(source_address if source_address is not None else (apdu.source_address or 0x00)) & 0xFF,
                payload=data,
            )

        @classmethod
        def from_can_id(cls, can_id: int, data: bytes) -> "DPDU2":
            priority = (can_id >> 26) & 0x7
            edp = (can_id >> 25) & 0x1
            dp = (can_id >> 24) & 0x1
            pf = (can_id >> 16) & 0xFF
            ps = (can_id >> 8) & 0xFF
            sa = can_id & 0xFF
            return cls(priority=priority, edp=edp, dp=dp, pf=pf, ps=ps, sa=sa, payload=data)


    @dataclass
    class DPDU3:
        app_pi: int = 0
        sa: int = 0
        payload: bytes = b""

        def __post_init__(self) -> None:
            self.length = len(self.payload)

        def data_field(self) -> bytes:
            return bytes(self.payload)

        def to_can_id(self) -> int:
            return ((self.app_pi & 0x7) << 8) | (self.sa & 0xFF)

        def is_multi_pg(self) -> bool:
            return ApplicationProtocolIndicator(self.app_pi) is ApplicationProtocolIndicator.MULTI_PG

        @classmethod
        def from_can_id(cls, can_id: int, payload: bytes) -> "DPDU3":
            app_pi = ApplicationProtocolIndicator((can_id >> 8) & 0x7)
            sa = can_id & 0xFF
            return cls(app_pi=int(app_pi), sa=sa, payload=payload)
