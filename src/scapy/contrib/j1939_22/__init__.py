"""Scapy contrib module providing SAE J1939-22 helpers.

This package is an interim bridge while the project transitions into the
`scapy.contrib` layout recommended by the Scapy project documentation. The
modules currently mirror the standalone ``scapy_j1939_22`` package and will be
converted to native :class:`scapy.packet.Packet` implementations in subsequent
steps.
"""
from __future__ import annotations

__version__ = "0.1.0"

from . import apdu, stack
from .layers import *  # noqa: F401,F403
from .registry import *  # noqa: F401,F403
from .security import *  # noqa: F401,F403
from .transport import TP21CompatTransport, TP22Transport  # noqa: F401
from .util import *  # noqa: F401,F403

__all__ = [
    "apdu",
    "stack",
    "TP21CompatTransport",
    "TP22Transport",
]
