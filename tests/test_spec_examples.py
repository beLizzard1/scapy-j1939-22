"""Regression tests derived from SAE J1939-22 specification examples."""

from scapy.contrib.j1939_22.apdu import APDU1, APDUType, J1939APDU
from scapy.contrib.j1939_22.layers import ContainedParameterGroup, MultiPGMessage, DPDU1
from scapy.contrib.j1939_22.transport import (
    FDTPConnectionMessage,
    FDTPControl,
    FDTPDataTransferFrame,
    TP22Transport,
)


def _get_new_frames(transport: TP22Transport, previous_length: int) -> list:
    frames = transport.transmitted_frames()
    return frames[previous_length:]


def test_figure_a1_rts_cts_sequence() -> None:
    """Replicate the Appendix A RTS/CTS example with 207 bytes across four segments."""

    payload = bytes(range(207))
    apdu = J1939APDU(pgn=65259, payload=payload, apdu_type=APDUType.MULTI_PG)

    transport = TP22Transport()
    transport.send(apdu)

    frames = transport.transmitted_frames()
    assert isinstance(frames[-1], FDTPConnectionMessage)
    rts = frames[-1]

    assert rts.control is FDTPControl.RTS
    assert rts.total_bytes == 207
    assert rts.total_segments == 4
    assert rts.byte8 == 255  # capable of sending 255 segments per CTS as in Figure A1

    session = rts.session
    baseline = len(frames)

    # Responder allows two segments starting with segment 1.
    transport.process_connection_message(
        FDTPConnectionMessage.cts(
            session=session,
            next_segment=1,
            segments_to_send=2,
            request_code=0,
            pgn=apdu.pgn,
        )
    )
    new_frames = _get_new_frames(transport, baseline)
    segments = [frame for frame in new_frames if isinstance(frame, FDTPDataTransferFrame)]
    assert [seg.segment_number for seg in segments] == [1, 2]
    assert all(len(seg.data) == 60 for seg in segments)

    baseline = len(transport.transmitted_frames())

    # Responder holds the connection open without requesting data (segments_to_send == 0).
    transport.process_connection_message(
        FDTPConnectionMessage.cts(
            session=session,
            next_segment=3,
            segments_to_send=0,
            request_code=0,
            pgn=apdu.pgn,
        )
    )
    assert len(transport.transmitted_frames()) == baseline

    # Responder requests the final two segments (3 and 4).
    transport.process_connection_message(
        FDTPConnectionMessage.cts(
            session=session,
            next_segment=3,
            segments_to_send=2,
            request_code=0,
            pgn=apdu.pgn,
        )
    )
    new_frames = _get_new_frames(transport, baseline)
    segments = [frame for frame in new_frames if isinstance(frame, FDTPDataTransferFrame)]
    assert [seg.segment_number for seg in segments] == [3, 4]
    assert len(segments[0].data) == 60
    assert len(segments[1].data) == 27  # final segment is shorter and padded

    eoms = [frame for frame in new_frames if isinstance(frame, FDTPConnectionMessage) and frame.control is FDTPControl.EOMS]
    assert len(eoms) == 1
    assert eoms[0].total_bytes == 207
    assert eoms[0].total_segments == 4

    # Responder acknowledges completion.
    transport.process_connection_message(
        FDTPConnectionMessage.eoma(
            session=session,
            total_bytes=207,
            total_segments=4,
            pgn=apdu.pgn,
        )
    )

    received = list(transport.receive())
    assert len(received) == 1
    assert received[0].payload == payload


def test_figure_26_cpg_header_bytes() -> None:
    """Validate the header encoding for the first C-PG in Figure 26 (Multi-PG example 1)."""

    cpg = ContainedParameterGroup(
        tos=2,
        trailer_format=0,
        pgn=0x00EA00,
        payload=bytes.fromhex("00EE00"),
    )

    assert cpg.header_bytes() == bytes.fromhex("40EA0003")
    assert len(cpg.encode()) == 4 + 3


def test_padding_cpg_matches_spec() -> None:
    """Padding service C-PGs should emit zeroed headers and AAh payload, per Figure 27."""

    padding_payload = b"\xAA" * 12
    cpg = ContainedParameterGroup(tos=0, trailer_format=0, pgn=0, payload=padding_payload)

    header = cpg.header_bytes()
    assert header == b"\x00\x00\x00"
    encoded = cpg.encode()
    assert encoded[:3] == b"\x00\x00\x00"
    assert encoded[3:] == padding_payload

    message = MultiPGMessage([cpg])
    assert message.total_length() == len(encoded)


def test_figure_27_destination_specific_multi_pg() -> None:
    """Encode the Figure 27 Multi-PG example (four Requests plus padding)."""

    cpg1 = ContainedParameterGroup(
        tos=2,
        trailer_format=0,
        pgn=0x00EA00,
        payload=(0x00FECE).to_bytes(3, byteorder="little"),
    )
    cpg2_payload = (0x00C100).to_bytes(3, byteorder="little") + bytes.fromhex("C80DC80D80FE80FE")
    cpg2 = ContainedParameterGroup(
        tos=1,
        trailer_format=5,
        pgn=0x00EA00,
        payload=cpg2_payload,
    )
    cpg3 = ContainedParameterGroup(
        tos=2,
        trailer_format=0,
        pgn=0x00EA00,
        payload=(0x00FDB8).to_bytes(3, byteorder="little"),
    )
    cpg4 = ContainedParameterGroup(
        tos=2,
        trailer_format=0,
        pgn=0x00EA00,
        payload=(0x009E00).to_bytes(3, byteorder="little"),
    )
    cpg5 = ContainedParameterGroup(tos=0, trailer_format=0, pgn=0, payload=b"\xAA" * 9, padding_header_bytes=3)

    message = MultiPGMessage([cpg1, cpg2, cpg3, cpg4, cpg5])
    encoded_payload = message.encode()

    assert message.total_length() == len(encoded_payload) == 48

    apdu = APDU1(
        pgn=0x002500,
        payload=encoded_payload,
        destination_address=0x03,
        source_address=0xF9,
        priority=6,
    )
    dpdu = DPDU1.from_apdu(apdu)

    expected_can_id = (6 << 26) | (0 << 24) | (0x25 << 16) | (0x03 << 8) | 0xF9
    assert dpdu.to_can_id() == expected_can_id
    assert dpdu.data_field() == encoded_payload
