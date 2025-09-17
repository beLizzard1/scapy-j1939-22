# Scapy J1939-22 Contrib Library

This project extends Scapy with layers, transport state machines, and security
helpers focused on SAE J1939-22 (CAN-FD) while retaining compatibility with
J1939-21. The library offers:

- Unified TP-22 transport with TP-21 adapters for classic CAN networks.
- High level APDU abstractions backed by a registry derived from the SAE Digital
  Annex.
- 91C security scaffolding that includes freshness tracking and leader/follower
  flows.
- Tooling to normalize Digital Annex CSV dumps into structured JSON suitable
  for Scapy field definitions.

## Layout

```
src/scapy_j1939_22/    # Core library modules
  transport/           # TP-22 state machine and TP-21 shim
  layers/              # Scapy layer definitions
  security/            # 91C leader/follower helpers
  registry/            # Digital Annex registry utilities
  util/                # Shared helpers for CAN/CAN-FD IO
da_tools/              # Digital Annex cleaning scripts
tests/                 # Pytest-based unit tests
docs/                  # Design documents and notes
```

## Getting Started

Install the project in editable mode and run the unit tests:

```bash
pip install -e .[dev]
pytest
```
