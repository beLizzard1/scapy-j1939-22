"""Unit tests for the native TP-22 transport implementation."""
from scapy_j1939_22.apdu import APDUType, J1939APDU
from scapy_j1939_22.transport import (
    FDTPConnectionMessage,
    FDTPControl,
    FDTPDataTransferFrame,
    TP22Transport,
)


def _control_frames(frames, control):
    return [
        frame
        for frame in frames
        if isinstance(frame, FDTPConnectionMessage) and frame.control is control
    ]


def _segment_frames(frames, session):
    return [
        frame
        for frame in frames
        if isinstance(frame, FDTPDataTransferFrame) and frame.session == session
    ]


def test_originator_rts_cts_flow_round_trip() -> None:
    payload = bytes(range(70))
    apdu = J1939APDU(pgn=0x1234, payload=payload, apdu_type=APDUType.MULTI_PG)

    transport = TP22Transport()
    transport.send(apdu)

    frames = transport.transmitted_frames()
    rts_frames = _control_frames(frames, FDTPControl.RTS)
    assert len(rts_frames) == 1
    session = rts_frames[0].session

    transport.process_connection_message(
        FDTPConnectionMessage.cts(
            session=session,
            next_segment=1,
            segments_to_send=2,
            request_code=0,
            pgn=apdu.pgn,
        )
    )

    frames = transport.transmitted_frames()
    segments = _segment_frames(frames, session)
    assert [frame.segment_number for frame in segments] == [1, 2]
    assert len(segments[1].data) == 10

    eoms_frames = _control_frames(frames, FDTPControl.EOMS)
    assert eoms_frames and eoms_frames[-1].session == session
    assert not _control_frames(frames, FDTPControl.EOMA)

    transport.process_connection_message(
        FDTPConnectionMessage.eoma(
            session=session,
            total_bytes=len(payload),
            total_segments=2,
            pgn=apdu.pgn,
        )
    )

    received = list(transport.receive())
    assert received == [apdu]


def test_responder_handles_rts_flow() -> None:
    payload = bytes(range(70))
    pgn = 0x2233

    transport = TP22Transport()
    transport.process_connection_message(
        FDTPConnectionMessage.rts(
            session=1,
            total_bytes=len(payload),
            total_segments=2,
            max_segments=2,
            assurance_type=0,
            pgn=pgn,
        )
    )

    frames = transport.transmitted_frames()
    cts_frames = _control_frames(frames, FDTPControl.CTS)
    assert len(cts_frames) == 1
    assert cts_frames[0].byte8 == 2

    transport.process_data_transfer_frame(
        FDTPDataTransferFrame(session=1, segment_number=1, data=payload[:60])
    )
    transport.process_data_transfer_frame(
        FDTPDataTransferFrame(session=1, segment_number=2, data=payload[60:])
    )

    transport.process_connection_message(
        FDTPConnectionMessage.eoms(
            session=1,
            total_bytes=len(payload),
            total_segments=2,
            assurance_type=0,
            assurance_data=b"",
            pgn=pgn,
        )
    )

    frames = transport.transmitted_frames()
    eoma_frames = _control_frames(frames, FDTPControl.EOMA)
    assert eoma_frames and eoma_frames[-1].session == 1

    received = list(transport.receive())
    assert len(received) == 1
    assert received[0].payload == payload
    assert received[0].apdu_type is APDUType.MULTI_PG


def test_responder_handles_bam_flow_without_ack() -> None:
    payload = bytes(range(70))
    pgn = 0x7788

    transport = TP22Transport()
    transport.process_connection_message(
        FDTPConnectionMessage.bam(
            session=2,
            total_bytes=len(payload),
            total_segments=2,
            assurance_type=0,
            pgn=pgn,
        )
    )

    frames = transport.transmitted_frames()
    assert not _control_frames(frames, FDTPControl.CTS)

    transport.process_data_transfer_frame(
        FDTPDataTransferFrame(session=2, segment_number=1, data=payload[:60])
    )
    transport.process_data_transfer_frame(
        FDTPDataTransferFrame(session=2, segment_number=2, data=payload[60:])
    )
    transport.process_connection_message(
        FDTPConnectionMessage.eoms(
            session=2,
            total_bytes=len(payload),
            total_segments=2,
            assurance_type=0,
            assurance_data=b"",
            pgn=pgn,
        )
    )

    frames = transport.transmitted_frames()
    assert not _control_frames(frames, FDTPControl.EOMA)

    received = list(transport.receive())
    assert len(received) == 1
    assert received[0].payload == payload
    assert received[0].assurance_type is None
