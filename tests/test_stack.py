"""Sanity checks for the high level stack facade."""
from scapy_j1939_22.apdu import APDUType, J1939APDU
from scapy_j1939_22.stack import J1939Stack
from scapy_j1939_22.transport.tp22 import TP22Transport


def test_stack_round_trip() -> None:
    transport = TP22Transport()
    stack = J1939Stack(transport)
    apdu = J1939APDU(pgn=0x1234, payload=b"abc", apdu_type=APDUType.SINGLE_PG)

    stack.send_apdu(apdu)
    received = list(stack.sniff_apdus())

    assert received == [apdu]
