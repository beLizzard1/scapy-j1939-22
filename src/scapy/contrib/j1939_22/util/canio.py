

from __future__ import annotations
"""Lightweight abstraction for CAN/CAN-FD sockets."""

import socket
import struct
from collections import deque
from dataclasses import dataclass
from typing import Deque, Iterable, Iterator, Optional


def split_payload_and_assurance(data: bytes, tos: int, tf: int):
    """
    Split CAN payload and assurance data based on TOS and TF values.
    Returns (payload, assurance_data) tuple.
    """
    # TOS = 2, TF = 0: All payload
    if tos == 0b010 and tf == 0b000:
        return data, b''
    # TOS = 1, TF = 1,2: 4 bytes assurance
    elif tos == 0b001 and tf in (0b001, 0b010):
        return data[:-4], data[-4:]
    # TOS = 1, TF = 3,5,6: 8 bytes assurance
    elif tos == 0b001 and tf in (0b011, 0b101, 0b110):
        return data[:-8], data[-8:]
    # Reserved or undefined, treat all as payload
    else:
        return data, b''




"""Lightweight abstraction for CAN/CAN-FD sockets."""

import socket
import struct
from collections import deque
from dataclasses import dataclass
from typing import Deque, Iterable, Iterator, Optional


try:  # pragma: no cover - availability depends on platform
    from socket import AF_CAN, CAN_RAW
except ImportError:  # pragma: no cover - type checker support
    AF_CAN = None  # type: ignore
    CAN_RAW = None  # type: ignore


@dataclass(slots=True)
class CANFrame:
    """Represents a raw CAN/CAN-FD frame."""

    can_id: int
    data: bytes
    is_extended: bool = True

    def __post_init__(self) -> None:
        if not 0 <= self.can_id <= 0x1FFFFFFF:
            raise ValueError("CAN identifier must fit within 29 bits")
        if len(self.data) > 64:
            raise ValueError("CAN-FD payloads cannot exceed 64 bytes")


class CANIOSocket:
    """Simple CAN/CAN-FD I/O abstraction.

    By default this class opens a real CAN RAW socket when the platform supports
    it. For tests or environments without CAN support, the :class:`LoopbackCAN`
    subclass offers an in-memory queue.
    """

    def __init__(self, channel: Optional[str] = None) -> None:
        self.channel = channel
        self._socket: Optional[socket.socket] = None
        if channel and AF_CAN is not None:
            self._socket = socket.socket(AF_CAN, socket.SOCK_RAW, CAN_RAW)
            self._socket.bind((channel,))
        elif channel:
            raise RuntimeError("CAN sockets are not supported on this platform")

    # ------------------------------------------------------------------ send/recv
    def send_frame(self, frame: CANFrame) -> None:
        if self._socket is None:
            raise RuntimeError("No CAN socket available; use LoopbackCAN for tests")
        # linux CAN frame structure: can_id (uint32), data length code (uint8),
        # padding, payload (8 bytes). CAN-FD adds flags; we encode classic CAN-FD
        # using the CAN_RAW_TX_FRAMES format.
        dlc = len(frame.data)
        padded = frame.data.ljust(64, b"\x00")  # CAN-FD max
        can_frame_fmt = "=IB3x64s"
        packed_id = frame.can_id | 0x80000000 if frame.is_extended else frame.can_id
        raw = struct.pack(can_frame_fmt, packed_id, dlc, padded)
        self._socket.send(raw)

    def recv_frames(self) -> Iterator[CANFrame]:
        if self._socket is None:
            raise RuntimeError("No CAN socket available; use LoopbackCAN for tests")
        can_frame_fmt = "=IB3x64s"
        size = struct.calcsize(can_frame_fmt)
        while True:
            raw = self._socket.recv(size)
            can_id, dlc, data = struct.unpack(can_frame_fmt, raw)
            is_extended = bool(can_id & 0x80000000)
            yield CANFrame(can_id=can_id & 0x1FFFFFFF, data=data[:dlc], is_extended=is_extended)

    def close(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def __enter__(self) -> "CANIOSocket":  # pragma: no cover - trivial
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # pragma: no cover - trivial
        self.close()
        return False


class LoopbackCAN(CANIOSocket):
    """In-memory CAN interface used for testing and examples."""

    def __init__(self) -> None:
        super().__init__(channel=None)
        self._queue: Deque[CANFrame] = deque()

    def send_frame(self, frame: CANFrame) -> None:  # pragma: no cover - simple
        self._queue.append(frame)

    def recv_frames(self) -> Iterator[CANFrame]:  # pragma: no cover - simple iterator
        while self._queue:
            yield self._queue.popleft()

    def close(self) -> None:  # pragma: no cover - simple cleanup
        self._queue.clear()
