# Scapy J1939-22 Architecture

This document captures high level goals for the library and the current
implementation status. The runtime implementation now lives beneath
``scapy.contrib.j1939_22`` so it can be discovered through Scapy's contrib
loader while the legacy ``scapy_j1939_22`` package re-exports the same objects
for backwards compatibility.

## Transport Stack

- TP-22 first transport with TP-21 compatibility adapters.
- `transport/fdtp.py` provides Connection Management / Data Transfer frame
  encoders so higher level state machines can focus on orchestration logic.
- `transport/tp22.py` currently implements the Appendix A RTS/CTS and BAM flows
  including the spec-mandated 60-byte segments, EOMS/EOMA handshake, and
  session windowing. Tests mirror Figure A1 to ensure behaviour stays aligned
  with SAE J1939-22 §6.6.
- `util/canio.py` supplies SocketCAN integration (with optional loopback) so
  transports can emit real CAN/CAN-FD frames. `TP22Transport` now pushes
  FD.TP.CM/FD.TP.DT traffic to the socket when provided.
- `transport/tp21_adapter.py` offers a classic TP-21 bridge that reuses the
  CAN helpers to send RTS/BAM semantics over CAN 2.0, enabling legacy nodes to
  exercise the same high-level stack.

## Datalink Layer

- Registry-backed APDU modelling that mirrors the SAE Digital Annex.
- `apdu.py` now exposes `ApplicationPDU`, `APDU1`, and `APDU2` to enforce
  routing constraints when packing PGs.
- `layers/pdu.py` models D_PDU1/D_PDU2/D_PDU3 CAN identifiers with helpers to
  convert between CAN IDs and the 29-bit/11-bit layouts in §6.2.
- `layers/multipg.py` encodes contained parameter groups (C-PGs) and padding as
  specified in §6.5, allowing Multi-PG payloads to be assembled programmatically.
- Tests cover the Figure 26 layout to confirm header bit placement.
- Multi-PG and RTS/CTS tests link to extracted spec figures stored under
  `docs/figures/` for easy visual comparison (e.g. Figure 26 and Figure 27).

## Security

- 91C security leader/follower flows with freshness management.
- `security/freshness.py`, `leader.py`, and `follower.py` remain scaffolding and
  will be expanded as the 91C spec work progresses.

## Documentation & Tests

- Spec-oriented regression tests live in `tests/test_spec_examples.py` and
  reference specific figures from the J1939-22 document for traceability.
- Additional documentation will elaborate the state machines, transport frames,
  and security TLVs as they evolve.
