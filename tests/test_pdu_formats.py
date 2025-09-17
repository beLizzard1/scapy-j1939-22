"""Tests for A_PDU and D_PDU helper classes."""

from scapy.contrib.j1939_22.apdu import APDU1, APDU2
from scapy.contrib.j1939_22.layers import (
    ApplicationProtocolIndicator,
    DPDU1,
    DPDU2,
    DPDU3,
)


def _expect_value_error(callable_obj, *args, **kwargs) -> None:
    try:
        callable_obj(*args, **kwargs)
    except ValueError:
        return
    raise AssertionError("ValueError was not raised")


def test_apdu1_total_length_and_validation() -> None:
    apdu = APDU1(pgn=0x00EE00, payload=b"abc", assurance_data=b"\x01", destination_address=0x80)
    assert apdu.total_payload_length() == 4

    _expect_value_error(APDU1, pgn=0x00F004, payload=b"", destination_address=0x01)


def test_dpdu1_round_trip_encoding() -> None:
    apdu = APDU1(pgn=0x00EE00, payload=b"data", destination_address=0x34)
    dpdu = DPDU1.from_apdu(apdu, priority=3, source_address=0x56, destination_address=0x34)

    can_id = dpdu.to_can_id()
    expected = (3 << 26) | (0xEE << 16) | (0x34 << 8) | 0x56
    assert can_id == expected
    decoded = DPDU1.from_can_id(can_id, dpdu.data_field())
    assert decoded.priority == 3
    assert decoded.source_address == 0x56
    assert decoded.destination_address == 0x34
    decoded_apdu = decoded.to_apdu()
    assert decoded_apdu.pgn == apdu.pgn
    assert decoded_apdu.payload == apdu.payload


def test_dpdu2_round_trip_encoding() -> None:
    apdu = APDU2(pgn=0x00F004, payload=b"\x10\x20")
    dpdu = DPDU2.from_apdu(apdu, priority=6, source_address=0x9A)

    can_id = dpdu.to_can_id()
    expected = (6 << 26) | (0xF0 << 16) | (0x04 << 8) | 0x9A
    assert can_id == expected

    decoded = DPDU2.from_can_id(can_id, dpdu.data_field())
    assert decoded.priority == 6
    assert decoded.source_address == 0x9A
    decoded_apdu = decoded.to_apdu()
    assert decoded_apdu.pgn == apdu.pgn
    assert decoded_apdu.payload == apdu.payload


def test_dpdu3_multi_pg_identifier() -> None:
    dpdu3 = DPDU3(
        app_pi=ApplicationProtocolIndicator.MULTI_PG,
        sa=0x7D,
        payload=b"payload",
    )
    assert dpdu3.to_can_id() == 0x07D

    decoded = DPDU3.from_can_id(0x07D, b"payload")
    assert ApplicationProtocolIndicator(decoded.app_pi) is ApplicationProtocolIndicator.MULTI_PG
    assert decoded.sa == 0x7D
    assert decoded.payload == b"payload"

    assert dpdu3.is_multi_pg()
