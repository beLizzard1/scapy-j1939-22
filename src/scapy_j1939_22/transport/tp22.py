"""Native TP-22 CAN-FD transport implementation skeleton."""
from __future__ import annotations

from typing import Iterable, List

from ..apdu import J1939APDU


class TP22Transport:
    """State machine for TP-22 segmentation and reassembly."""

    def __init__(self) -> None:
        self._rx_buffer: List[J1939APDU] = []

    def send(self, apdu: J1939APDU) -> None:
        """Serialize and transmit an APDU over CAN-FD.

        This placeholder implementation simply stores the APDU locally so unit
        tests can exercise the stack without a socket backend.
        """

        if apdu.is_segmented():
            # TODO: Add segmentation framing for TP-22.
            self._rx_buffer.append(apdu)
        else:
            self._rx_buffer.append(apdu)

    def receive(self) -> Iterable[J1939APDU]:
        """Yield APDUs buffered by :meth:`send`."""

        while self._rx_buffer:
            yield self._rx_buffer.pop(0)
