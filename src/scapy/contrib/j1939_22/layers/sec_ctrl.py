"""Security Control TLVs for J1939-91C domain management."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class SecurityControlTLV:
    """Base representation of a 91C security control TLV."""

    tlv_type: int
    value: bytes

    def encode(self) -> bytes:
        """Return a TLV encoded byte string."""

        length = len(self.value)
        return bytes([self.tlv_type, length]) + self.value
