"""Compatibility shim bridging TP-21 semantics onto TP-22 transport."""
from __future__ import annotations

from typing import Iterable

from ..apdu import J1939APDU
from .tp22 import TP22Transport


class TP21CompatTransport:
    """Provides a TP-21 compatible API using the TP-22 state machine."""

    def __init__(self, tp22: TP22Transport | None = None) -> None:
        self._tp22 = tp22 or TP22Transport()

    def send(self, apdu: J1939APDU) -> None:
        """Proxy call into the TP-22 transport."""

        self._tp22.send(apdu)

    def receive(self) -> Iterable[J1939APDU]:
        """Proxy call into the TP-22 transport."""

        yield from self._tp22.receive()
