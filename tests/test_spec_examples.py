"""Regression tests derived from SAE J1939-22 specification examples."""

from scapy.contrib.j1939_22.apdu import APDU1, APDUType, J1939APDU
from scapy.contrib.j1939_22.layers import ContainedParameterGroup, MultiPGMessage, DPDU1

try:
    from scapy.contrib.j1939_22.layers import MultiPGPacket
except ImportError:  # pragma: no cover - Scapy not installed
    MultiPGPacket = None


def _render(packet) -> str | None:
    if packet is None:
        return None
    show = getattr(packet, "show", None)
    if show is None:
        return None
    try:
        return show(dump=True)
    except TypeError:  # pragma: no cover - older Scapy versions
        return show()
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

    decoded_message = MultiPGMessage.from_bytes(encoded_payload)
    assert len(decoded_message.cpgs) == 5
    assert [c.tos for c in decoded_message.cpgs] == [2, 1, 2, 2, 0]

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

    if MultiPGPacket is not None:
        pkt = MultiPGPacket.from_message(message)
        assert pkt.length == len(encoded_payload)
        assert pkt.to_message().encode() == encoded_payload

    # When Scapy is available, exercise the Packet build/dissection pipeline.
    if hasattr(DPDU1, "fields_desc") and MultiPGPacket is not None:
        dpdu_pkt = DPDU1(
            priority=6,
            edp=0,
            dp=0,
            pf=0x25,
            ps=0x03,
            sa=0xF9,
            length=len(encoded_payload),
            payload=encoded_payload,
        )
        raw_bytes = bytes(dpdu_pkt)
        # Prepend CAN identifier for clarity (not used directly by Scapy here)
        assert raw_bytes.endswith(encoded_payload)
        decoded_pkt = DPDU1(raw_bytes)
        assert decoded_pkt.length == len(encoded_payload)
        msg = MultiPGPacket(len(encoded_payload), encoded_payload).to_message()
        assert msg.encode() == encoded_payload
        rendered = _render(dpdu_pkt)
        if rendered:
            assert "priority" in rendered and "pf" in rendered
            print("Figure 27 DPDU1 packet:\n", rendered)
    else:
        # Fallback textual output when Scapy packets are unavailable
        summary = [
            (
                f"C-PG {idx+1}: TOS={c.tos:03b}\u208Db\u208E TF={c.trailer_format:03b}\u208Db\u208E "
                f"CPGN={c.pgn:05X}\u208Dh\u208E payload={c.payload.hex().upper()}\u208Dh\u208E"
            )
            for idx, c in enumerate(message)
        ]
        print("Figure 27 Multi-PG summary:\n" + "\n".join(summary))
