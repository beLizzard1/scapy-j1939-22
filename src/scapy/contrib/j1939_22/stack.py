"""High-level facade for sending and receiving J1939 APDUs."""
from __future__ import annotations

from typing import Iterable, Protocol

from .apdu import J1939APDU


class TransportAdapter(Protocol):
    """Protocol implemented by transport stacks (TP-22, TP-21 adapter)."""

    def send(self, apdu: J1939APDU) -> None: ...

    def receive(self) -> Iterable[J1939APDU]: ...


class J1939Stack:
    """Thin orchestrator that wires APDU converters, transport, and security."""

    def __init__(self, transport: TransportAdapter) -> None:
        self._transport = transport

    def send_apdu(self, apdu: J1939APDU) -> None:
        """Send an APDU using the underlying transport."""

        self._transport.send(apdu)

    def sniff_apdus(self) -> Iterable[J1939APDU]:
        """Yield APDUs from the transport as they arrive."""

        yield from self._transport.receive()
