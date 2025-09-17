# Scapy J1939-22 Contrib Library

This project extends Scapy with layers, transport state machines, and security
helpers focused on SAE J1939-22 (CAN-FD) while retaining compatibility with
J1939-21. The code now follows the Scapy contrib layout under
``scapy.contrib.j1939_22`` so it can be loaded with ``load_contrib("j1939_22")``
in an interactive Scapy session. The library offers:

- Unified TP-22 transport with TP-21 adapters for classic CAN networks.
- High level APDU abstractions, including explicit A_PDU1/A_PDU2 containers that
  enforce SAE routing rules and expose `J1939APDU` conversion helpers.
- Datalink helpers that model D_PDU1/2/3 CAN identifiers and Multi-PG contained
  Parameter Groups, following the figures in J1939-22.
- SocketCAN integration via `util.canio` plus TP-21 compatibility transport for
  bridging classic CAN nodes.
- 91C security scaffolding that includes freshness tracking and leader/follower
  flows.
- Tooling to normalize Digital Annex CSV dumps into structured JSON suitable
  for Scapy field definitions.

## Layout

```
src/scapy/contrib/j1939_22/  # Scapy contrib module
  layers/                    # D_PDU packets, Multi-PG helpers, bind hooks
  transport/                 # TP-22/TP-21 transport helpers
  security/                  # 91C scaffolding
  registry/                  # Digital Annex registry utilities
  util/                      # SocketCAN helpers
src/scapy_j1939_22/          # Thin wrappers re-exporting contrib symbols
da_tools/                    # Digital Annex cleaning scripts
tests/                       # Pytest-based unit tests
docs/                        # Design documents and notes
```

## Getting Started

Install the project in editable mode and run the unit tests:

```bash
pip install -e .[dev]
pytest
```

When `pytest` is unavailable (e.g. minimal sandboxes) you can still execute the
unit suite using the stdlib runner:

```bash
PYTHONPATH=src python - <<'PY'
from tests import (
    test_canio,
    test_pdu_formats,
    test_spec_examples,
    test_stack,
    test_tp21,
    test_tp22,
)

for module in (test_stack, test_tp22, test_tp21, test_pdu_formats, test_spec_examples, test_canio):
    for attr in dir(module):
        if attr.startswith("test_"):
            getattr(module, attr)()

print("tests passed")
PY
```

### Loading the contrib module in Scapy

```python
from scapy.all import load_contrib

load_contrib("j1939_22")

from scapy.contrib.j1939_22 import TP22Transport
```

## Reference Coverage

Tests in `tests/test_spec_examples.py` encode sequences published in SAE
J1939-22 (e.g. Appendix A Figure A1 RTS/CTS flow and Figure 26 Multi-PG
headers, Figure 27 destination-specific Multi-PG). This offers guard rails that the helpers continue to match the
standard as additional behaviour is implemented. The `layers/multipg.py`
module mirrors the contained-parameter-group format described in §6.5, and
`transport/fdtp.py` encodes the connection management fields referenced in
§6.6.

PNG renders for Figures 26 and 27 (see `docs/figures/figure_26_multi_pg_example.png`
and `docs/figures/figure_27_multi_pg_destination_specific.png`) were extracted
directly from the SAE publication to simplify cross-referencing between tests
and the standard.
