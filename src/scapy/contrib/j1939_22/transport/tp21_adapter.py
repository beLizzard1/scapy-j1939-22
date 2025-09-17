"""Compatibility shim bridging TP-21 semantics onto TP-22 transport."""
from __future__ import annotations

import math
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from ..apdu import APDU1, APDU2, APDUType, J1939APDU
from ..layers import DPDU1, DPDU2
from ..util.canio import CANFrame, CANIOSocket, LoopbackCAN


TP21_CM_PGN = 0x00EC00
TP21_DT_PGN = 0x00EB00


class TP21CompatTransport:
    """TP-21 (classic CAN) transport compatible with the TP-22 façade."""

    def __init__(
        self,
        *,
        can_socket: Optional[CANIOSocket] = None,
        source_address: int = 0x00,
    ) -> None:
        self._can_socket = can_socket or LoopbackCAN()
        self._source_address = source_address & 0xFF
        self._rx_buffer: List[J1939APDU] = []

    # ------------------------------------------------------------------ API
    def send(self, apdu: J1939APDU) -> None:
        payload = apdu.payload
        priority = (apdu.priority or 6) & 0x7
        sa = (apdu.source_address or self._source_address) & 0xFF
        pf = (apdu.pgn >> 8) & 0xFF
        dest = apdu.destination_address if apdu.destination_address is not None else 0xFF

        if len(payload) <= 8:
            frame = self._build_single_frame(apdu, priority, sa, dest, pf)
            self._can_socket.send_frame(frame)
        else:
            self._send_transport_protocol(apdu, payload, priority, sa, dest)

        self._rx_buffer.append(apdu)

    def receive(self) -> Iterable[J1939APDU]:
        while self._rx_buffer:
            yield self._rx_buffer.pop(0)

    # ----------------------------------------------------------- internals
    def _build_single_frame(
        self,
        apdu: J1939APDU,
        priority: int,
        sa: int,
        dest: int,
        pf: int,
    ) -> CANFrame:
        if pf < 240:
            apdu1 = APDU1(
                pgn=apdu.pgn,
                payload=apdu.payload,
                destination_address=dest & 0xFF,
                assurance_type=apdu.assurance_type,
                assurance_data=apdu.assurance_data or b"",
                source_address=sa,
                priority=priority,
            )
            dpdu = DPDU1.from_apdu(
                apdu1,
                priority=priority,
                source_address=sa,
                destination_address=dest & 0xFF,
            )
        else:
            apdu2 = APDU2(
                pgn=apdu.pgn,
                payload=apdu.payload,
                assurance_type=apdu.assurance_type,
                assurance_data=apdu.assurance_data or b"",
                source_address=sa,
                priority=priority,
            )
            dpdu = DPDU2.from_apdu(
                apdu2,
                priority=priority,
                source_address=sa,
            )
        return CANFrame(can_id=dpdu.to_can_id(), data=dpdu.data_field())

    def _send_transport_protocol(
        self,
        apdu: J1939APDU,
        payload: bytes,
        priority: int,
        sa: int,
        dest: int,
    ) -> None:
        total_bytes = len(payload)
        total_packets = math.ceil(total_bytes / 7)
        segments = [payload[i : i + 7] for i in range(0, total_bytes, 7)]
        segments[-1] = segments[-1].ljust(7, b"\xFF")

        if dest == 0xFF:
            self._send_tp21_bam(apdu.pgn, priority, sa, segments, total_bytes)
        else:
            self._send_tp21_rts(apdu.pgn, priority, sa, dest, segments, total_bytes)

    def _send_tp21_bam(
        self,
        pgn: int,
        priority: int,
        sa: int,
        segments: List[bytes],
        total_bytes: int,
    ) -> None:
        total_packets = len(segments)
        payload = bytes(
            [
                0x20,
                total_bytes & 0xFF,
                (total_bytes >> 8) & 0xFF,
                total_packets & 0xFF,
                0xFF,
            ]
        ) + pgn.to_bytes(3, byteorder="little")

        bam_apdu = APDU2(
            pgn=TP21_CM_PGN,
            payload=payload,
            source_address=sa,
            priority=priority,
        )
        dpdu = DPDU2.from_apdu(bam_apdu, priority=priority, source_address=sa)
        self._can_socket.send_frame(CANFrame(can_id=dpdu.to_can_id(), data=dpdu.data_field(), is_extended=True))

        self._send_tp21_data_frames(pgn, priority, sa, 0xFF, segments)

    def _send_tp21_rts(
        self,
        pgn: int,
        priority: int,
        sa: int,
        dest: int,
        segments: List[bytes],
        total_bytes: int,
    ) -> None:
        total_packets = len(segments)
        max_packets = min(total_packets, 255)
        payload = bytes(
            [
                0x10,
                total_bytes & 0xFF,
                (total_bytes >> 8) & 0xFF,
                total_packets & 0xFF,
                max_packets,
            ]
        ) + pgn.to_bytes(3, byteorder="little")

        rts_apdu = APDU1(
            pgn=TP21_CM_PGN,
            payload=payload,
            destination_address=dest & 0xFF,
            source_address=sa,
            priority=priority,
        )
        dpdu = DPDU1.from_apdu(
            rts_apdu,
            priority=priority,
            source_address=sa,
            destination_address=dest & 0xFF,
        )
        self._can_socket.send_frame(CANFrame(can_id=dpdu.to_can_id(), data=dpdu.data_field(), is_extended=True))

        self._send_tp21_data_frames(pgn, priority, sa, dest, segments)

    def _send_tp21_data_frames(
        self,
        pgn: int,
        priority: int,
        sa: int,
        dest: int,
        segments: List[bytes],
    ) -> None:
        for index, segment in enumerate(segments, start=1):
            payload = bytes([index & 0xFF]) + segment
            dt_apdu = APDU1(
                pgn=TP21_DT_PGN,
                payload=payload,
                destination_address=dest & 0xFF,
                source_address=sa,
                priority=priority,
            )
            dpdu = DPDU1.from_apdu(
                dt_apdu,
                priority=priority,
                source_address=sa,
                destination_address=dest & 0xFF,
            )
            self._can_socket.send_frame(CANFrame(can_id=dpdu.to_can_id(), data=dpdu.data_field(), is_extended=True))

    # -------------------------------------------------------- frame handling
    # No automatic ingestion logic yet; frames can be inspected via the CAN socket
