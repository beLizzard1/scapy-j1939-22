"""Unit tests for the native TP-22 transport implementation."""
from scapy.contrib.j1939_22.apdu import APDUType, J1939APDU
from scapy.contrib.j1939_22.transport import (
    FDTPConnectionMessage,
    FDTPControl,
    FDTPDataTransferFrame,
    TP22Transport,
)
from scapy.contrib.j1939_22.util import LoopbackCAN

try:
    from scapy.contrib.j1939_22.transport import FDTPConnectionPacket, FDTPDataTransferPacket
except ImportError:  # pragma: no cover - Scapy not installed
    FDTPConnectionPacket = None
    FDTPDataTransferPacket = None


def _render(packet) -> str | None:
    if packet is None:
        return None
    show = getattr(packet, "show", None)
    if show is None:
        return None
    try:
        return show(dump=True)
    except TypeError:  # pragma: no cover
        return show()


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


def test_assurance_metadata_carries_into_eoms() -> None:
    payload = bytes(range(61))
    apdu = J1939APDU(
        pgn=0x4321,
        payload=payload,
        apdu_type=APDUType.MULTI_PG,
        assurance_type=5,
        assurance_data=b"\xAA\xBB",
    )

    transport = TP22Transport()
    transport.send(apdu)

    session = transport.transmitted_frames()[0].session

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
    eoms = [
        frame
        for frame in frames
        if isinstance(frame, FDTPConnectionMessage) and frame.control is FDTPControl.EOMS
    ][-1]
    assert eoms.byte9 == 5
    assert eoms.byte8 == 2
    assert eoms.assurance_data == b"\xAA\xBB"

    transport.process_connection_message(
        FDTPConnectionMessage.eoma(
            session=session,
            total_bytes=len(payload),
            total_segments=2,
            pgn=apdu.pgn,
        )
    )

    received = list(transport.receive())
    assert received[0].assurance_type == 5
    assert received[0].assurance_data == b"\xAA\xBB"


def test_tp22_can_socket_emits_single_frame() -> None:
    loop = LoopbackCAN()
    transport = TP22Transport(can_socket=loop, source_address=0x12)
    apdu = J1939APDU(
        pgn=0x00F004,
        payload=b"\x01\x02",
        apdu_type=APDUType.SINGLE_PG,
        source_address=0x12,
        priority=3,
    )

    transport.send(apdu)

    frames = list(loop.recv_frames())
    assert len(frames) == 1
    expected_can_id = (3 << 26) | (0xF0 << 16) | (0x04 << 8) | 0x12
    assert frames[0].can_id == expected_can_id
    assert frames[0].data.startswith(b"\x01\x02")


def test_fdtp_packet_round_trip() -> None:
    conn = FDTPConnectionMessage.rts(
        session=5,
        total_bytes=128,
        total_segments=3,
        max_segments=2,
        assurance_type=7,
        pgn=0x00F004,
    )
    frame = FDTPDataTransferFrame(session=5, segment_number=2, data=b"\x00" * 60)

    if FDTPConnectionPacket is not None:
        pkt = FDTPConnectionPacket.from_message(conn)
        raw = bytes(pkt)
        rebuilt = FDTPConnectionPacket(raw).to_message()
        assert rebuilt.encode() == conn.encode()
        rendered = _render(pkt)
        if rendered:
            assert "session" in rendered and "pgn" in rendered
            print("FDTP Connection Packet:\n", rendered)
    else:
        print(
            "FDTP Connection Message:\n",
            f"control={conn.control.name} session={conn.session} bytes={conn.total_bytes} segs={conn.total_segments}",
        )

    if FDTPDataTransferPacket is not None:
        pkt_dt = FDTPDataTransferPacket.from_frame(frame)
        raw_dt = bytes(pkt_dt)
        rebuilt_dt = FDTPDataTransferPacket(raw_dt).to_frame()
        assert rebuilt_dt.encode() == frame.encode()
        rendered_dt = _render(pkt_dt)
        if rendered_dt:
            assert "segment_number" in rendered_dt
            print("FDTP Data Transfer Packet:\n", rendered_dt)
    else:
        print("FDTP Data Transfer Frame:\n", f"session={frame.session} segment={frame.segment_number} len={len(frame.data)}")
