"""TP-21 compatibility transport tests."""

from scapy.contrib.j1939_22.apdu import APDUType, J1939APDU
from scapy.contrib.j1939_22.transport.tp21_adapter import TP21CompatTransport
from scapy.contrib.j1939_22.util import LoopbackCAN


def test_tp21_single_frame_emission() -> None:
    loop = LoopbackCAN()
    tp21 = TP21CompatTransport(can_socket=loop, source_address=0x2A)
    apdu = J1939APDU(pgn=0x00F004, payload=b"\x11\x22", apdu_type=APDUType.SINGLE_PG, source_address=0x2A)

    tp21.send(apdu)

    frames = list(loop.recv_frames())
    assert len(frames) >= 1
    expected_can_id = (6 << 26) | (0xF0 << 16) | (0x04 << 8) | 0x2A
    assert frames[0].can_id == expected_can_id
    assert frames[0].data.startswith(b"\x11\x22")
