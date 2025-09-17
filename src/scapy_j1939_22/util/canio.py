"""Lightweight abstraction for CAN/CAN-FD sockets."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..apdu import J1939APDU


@dataclass(slots=True)
class CANIOSocket:
    """Placeholder socket-like interface for unit testing."""

    channel: str

    def send_apdu(self, apdu: J1939APDU) -> None:
        """Send an APDU on the socket (not yet implemented)."""

        raise NotImplementedError("Socket send not yet implemented")

    def recv_apdus(self) -> Iterable[J1939APDU]:
        """Iterate over received APDUs (not yet implemented)."""

        raise NotImplementedError("Socket receive not yet implemented")
