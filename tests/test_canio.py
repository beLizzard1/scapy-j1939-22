"""Tests covering CAN socket abstractions."""

from scapy.contrib.j1939_22.util import CANFrame, CANIOSocket, LoopbackCAN


def test_loopback_can_round_trip() -> None:
    loop = LoopbackCAN()
    frame = CANFrame(can_id=0x1ABCDE, data=b"\x01\x02\x03")

    loop.send_frame(frame)
    received = list(loop.recv_frames())

    assert received == [frame]


def test_socketcan_vcan0_optional() -> None:
    try:
        with CANIOSocket("vcan0") as sock:
            frame = CANFrame(can_id=0x123, data=b"\xAA")
            sock.send_frame(frame)
    except (OSError, RuntimeError):
        # Environment lacks SocketCAN or vcan0; skip without failing.
        return
