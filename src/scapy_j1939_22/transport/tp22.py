"""Native TP-22 CAN-FD transport implementation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List

from ..apdu import APDUType, J1939APDU
from .fdtp import FDTPConnectionMessage, FDTPControl, FDTPDataTransferFrame


@dataclass(slots=True)
class _OriginatorSession:
    """Bookkeeping for an outbound segmented transfer."""

    apdu: J1939APDU
    segments: List[bytes]
    total_bytes: int
    total_segments: int
    assurance_type: int
    assurance_data: bytes


@dataclass(slots=True)
class _ResponderSession:
    """Tracks inbound transfer state for RTS/CTS and BAM flows."""

    pgn: int
    total_bytes: int
    total_segments: int
    assurance_type: int
    bam: bool
    window_size: int
    next_segment: int = 1
    window_remaining: int = 0
    payload: bytearray = field(default_factory=bytearray)
    assurance_data: bytes = b""


class TP22Transport:
    """State machine for TP-22 segmentation and reassembly."""

    _SEGMENT_SIZE = FDTPDataTransferFrame.MAX_SEGMENT_SIZE

    def __init__(self) -> None:
        self._rx_buffer: List[J1939APDU] = []
        self._tx_frames: List[object] = []
        self._next_session: int = 0
        self._originator_sessions: Dict[int, _OriginatorSession] = {}
        self._responder_sessions: Dict[int, _ResponderSession] = {}

    # ------------------------------------------------------------------ API
    def send(self, apdu: J1939APDU) -> None:
        """Serialize and transmit an APDU over CAN-FD."""

        if not apdu.is_segmented() and len(apdu.payload) <= self._SEGMENT_SIZE:
            # Single frame transport: no segmentation required.
            self._rx_buffer.append(apdu)
            return

        self._start_originator_session(apdu)

    def receive(self) -> Iterable[J1939APDU]:
        """Yield APDUs buffered by :meth:`send` or inbound flows."""

        while self._rx_buffer:
            yield self._rx_buffer.pop(0)

    def transmitted_frames(self) -> List[object]:
        """Return frames emitted during transport interactions."""

        return list(self._tx_frames)

    def process_connection_message(self, message: FDTPConnectionMessage) -> None:
        """Handle an incoming FD.TP connection management frame."""

        if message.control is FDTPControl.CTS:
            self._handle_cts(message)
        elif message.control is FDTPControl.EOMA:
            self._handle_eoma(message)
        elif message.control is FDTPControl.RTS:
            self._handle_rts(message)
        elif message.control is FDTPControl.BAM:
            self._handle_bam(message)
        elif message.control is FDTPControl.EOMS:
            self._handle_eoms(message)
        elif message.control is FDTPControl.ABORT:
            self._handle_abort(message)

    def process_data_transfer_frame(self, frame: FDTPDataTransferFrame) -> None:
        """Handle an inbound FD.TP data transfer frame."""

        session = self._responder_sessions.get(frame.session)
        if session is None:
            return

        if frame.segment_number != session.next_segment:
            return

        session.payload.extend(frame.data)
        session.next_segment += 1

        if session.bam:
            return

        if session.window_remaining > 0:
            session.window_remaining -= 1

        if session.window_remaining == 0 and session.next_segment <= session.total_segments:
            remaining = session.total_segments - (session.next_segment - 1)
            to_request = min(session.window_size, remaining)
            if to_request > 0:
                session.window_remaining = to_request
                self._tx_frames.append(
                    FDTPConnectionMessage.cts(
                        session=frame.session,
                        next_segment=session.next_segment,
                        segments_to_send=to_request,
                        request_code=0,
                        pgn=session.pgn,
                    )
                )

    # ------------------------------------------------------------ internals
    def _start_originator_session(self, apdu: J1939APDU) -> int:
        session_id = self._allocate_session()
        segments = list(self._iter_segments(apdu.payload))
        if not segments:
            segments = [b""]
        total_segments = len(segments)
        total_bytes = len(apdu.payload)
        state = _OriginatorSession(
            apdu=apdu,
            segments=segments,
            total_bytes=total_bytes,
            total_segments=total_segments,
            assurance_type=apdu.assurance_type or 0,
            assurance_data=apdu.assurance_data or b"",
        )
        self._originator_sessions[session_id] = state

        self._tx_frames.append(
            FDTPConnectionMessage.rts(
                session=session_id,
                total_bytes=total_bytes,
                total_segments=total_segments,
                max_segments=max(1, min(total_segments, 255)),
                assurance_type=state.assurance_type,
                pgn=apdu.pgn,
            )
        )
        return session_id

    def _handle_cts(self, message: FDTPConnectionMessage) -> None:
        session = self._originator_sessions.get(message.session)
        if session is None:
            return

        next_segment = message.param_5_7 or 1
        segments_to_send = message.byte8

        if message.param_5_7 is None and segments_to_send == 0:
            self._send_eoms(message.session, session)
            return

        for offset in range(segments_to_send):
            segment_number = next_segment + offset
            if segment_number > session.total_segments:
                break
            data = session.segments[segment_number - 1]
            self._tx_frames.append(
                FDTPDataTransferFrame(
                    session=message.session,
                    segment_number=segment_number,
                    data=data,
                )
            )

        last_sent = min(next_segment + segments_to_send - 1, session.total_segments)
        if last_sent >= session.total_segments:
            self._send_eoms(message.session, session)

    def _handle_eoma(self, message: FDTPConnectionMessage) -> None:
        session = self._originator_sessions.pop(message.session, None)
        if session is None:
            return

        self._rx_buffer.append(session.apdu)

    def _handle_rts(self, message: FDTPConnectionMessage) -> None:
        total_bytes = message.total_bytes or 0
        total_segments = message.total_segments or 0
        if total_segments == 0:
            return

        window_size = message.byte8 or 1
        session = _ResponderSession(
            pgn=message.pgn,
            total_bytes=total_bytes,
            total_segments=total_segments,
            assurance_type=message.byte9,
            bam=False,
            window_size=max(1, window_size),
        )
        to_request = min(session.window_size, session.total_segments)
        session.window_remaining = to_request
        self._responder_sessions[message.session] = session

        self._tx_frames.append(
            FDTPConnectionMessage.cts(
                session=message.session,
                next_segment=1,
                segments_to_send=to_request,
                request_code=0,
                pgn=message.pgn,
            )
        )

    def _handle_bam(self, message: FDTPConnectionMessage) -> None:
        total_bytes = message.total_bytes or 0
        total_segments = message.total_segments or 0
        session = _ResponderSession(
            pgn=message.pgn,
            total_bytes=total_bytes,
            total_segments=total_segments,
            assurance_type=message.byte9,
            bam=True,
            window_size=0,
        )
        self._responder_sessions[message.session] = session

    def _handle_eoms(self, message: FDTPConnectionMessage) -> None:
        session = self._responder_sessions.get(message.session)
        if session is None:
            return

        session.assurance_data = message.assurance_data
        session.assurance_type = message.byte9
        self._finalize_responder_session(message.session, session)

    def _handle_abort(self, message: FDTPConnectionMessage) -> None:
        self._originator_sessions.pop(message.session, None)
        self._responder_sessions.pop(message.session, None)

    def _send_eoms(self, session_id: int, session: _OriginatorSession) -> None:
        self._tx_frames.append(
            FDTPConnectionMessage.eoms(
                session=session_id,
                total_bytes=session.total_bytes,
                total_segments=session.total_segments,
                assurance_type=session.assurance_type,
                assurance_data=session.assurance_data,
                pgn=session.apdu.pgn,
            )
        )

    def _finalize_responder_session(self, session_id: int, session: _ResponderSession) -> None:
        payload = bytes(session.payload)[: session.total_bytes or len(session.payload)]
        assurance_type = session.assurance_type or None
        assurance_data = session.assurance_data or None
        apdu = J1939APDU(
            pgn=session.pgn,
            payload=payload,
            apdu_type=APDUType.MULTI_PG,
            assurance_type=assurance_type,
            assurance_data=assurance_data,
        )
        self._rx_buffer.append(apdu)

        if not session.bam:
            self._tx_frames.append(
                FDTPConnectionMessage.eoma(
                    session=session_id,
                    total_bytes=session.total_bytes,
                    total_segments=session.total_segments,
                    pgn=session.pgn,
                )
            )

        self._responder_sessions.pop(session_id, None)

    def _allocate_session(self) -> int:
        session = self._next_session & 0x0F
        self._next_session = (self._next_session + 1) & 0x0F
        return session

    def _iter_segments(self, payload: bytes) -> Iterator[bytes]:
        for offset in range(0, len(payload), self._SEGMENT_SIZE):
            yield payload[offset : offset + self._SEGMENT_SIZE]
