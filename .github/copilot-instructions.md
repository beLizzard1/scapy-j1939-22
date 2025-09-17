# Copilot instructions for scapy-j1939-22

Purpose: give an AI coding agent the minimum, specific knowledge to be productive editing and testing this repo.

Quick start
- Use the repository Python virtualenv at `~/.virtualenvs/scapy-j1939-22` in CI/local development; tests run under that env in dev workflows. Install dev deps with:

```bash
python -m pip install -e .[dev]
```

- Run the unit test suite with:

```bash
pytest
# or (when pytest unavailable):
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

Code layout / big picture
- The runtime package is placed under `src/scapy/contrib/j1939_22/` to implement a Scapy contrib module. Import surface is re-exported by `src/scapy/contrib/j1939_22/__init__.py`.
- Major areas:
  - `layers/` - D_PDU packet helpers and Multi-PG (contained parameter group) logic (`layers/multipg.py` is the authoritative C-PG encoder/decoder used by tests).
  - `transport/` - TP-22 core transport state machine and FDTP helpers (`fdtp.py`, `tp22.py`, `tp21_adapter.py`). This folder contains the control/data frame encoding and the behavior for RTS/CTS/BAM/EOMS flows.
  - `security/` - 91C freshness, leader/follower logic used by assurance flows.
  - `registry/` - Digital Annex normalization utilities; CSV->JSON helpers live under `da_tools/`.
  - `util/` - helpers for SocketCAN/Loopback IO (`util/canio.py`) — a useful place to add small utility helpers.

Patterns & conventions
- Use dataclasses for message containers (see `layers/multipg.py` and many transport messages).
- Public API mirrors Scapy contrib expectations: classes in `src/scapy/contrib/j1939_22/` are importable via `from scapy.contrib.j1939_22 import ...`.
- Tests assert byte-level encodings that correspond to SAE J1939-22 figures; prefer reproducing the example bytes in tests.
- Scapy integration is optional: modules attempt to import Scapy and provide fallbacks so tests can run without Scapy in minimal environments.

Important files to inspect when making changes
- `src/scapy/contrib/j1939_22/layers/multipg.py` - Multi-PG C-PG encoding/decoding rules and limits.
- `src/scapy/contrib/j1939_22/transport/fdtp.py` - FDTP frame formats and control message encoding/decoding.
- `src/scapy/contrib/j1939_22/transport/tp22.py` - TP-22 transport logic and flow handlers.
- `src/scapy/contrib/j1939_22/util/canio.py` - SocketCAN abstraction and the `split_payload_and_assurance` helper recently added.
- `tests/test_spec_examples.py` - Good examples of expected formatting and summary helpers; mirrors SAE figures used as ground truth.

Developer workflows / useful commands
- Install dev deps: `python -m pip install -e .[dev]`
- Run tests: `pytest -q` (or `pytest -x` to stop on first failure)
- Run a single test file: `pytest tests/test_spec_examples.py::test_figure_26_multi_pg_example -q`
- Run tests with the project's virtualenv: `. ~/.virtualenvs/scapy-j1939-22/bin/activate && pytest`

Project-specific notes for AI edits
- When adding or moving functions, prefer placing shared helpers in `util/` and update `src/scapy/contrib/j1939_22/util/__init__.py` to export them.
- Maintain strict byte-level behavior: many tests compare exact hex sequences. Any change to encoding/decoding must include updated tests that reproduce the SAE examples.
- Avoid importing Scapy-only symbols at module top-level without a try/except. Many modules use `try: import scapy ... except ImportError: Packet=None`.

Examples to follow
- To add a new helper used by tests, mirror how `ContainedParameterGroup.decode` constructs and validates fields: explicit length checks, bit extraction from header bytes, and clear ValueError messages.
- For TP-22 transport behaviors, follow the state-machine style in `tp22.py`: small handler methods (`_handle_cts`, `_handle_eoma`, etc.) and an `_emit_transport_dt` method that constructs frames and forwards to the CAN IO layer.

Commit & PR guidance
- Keep test updates adjacent to behavior changes.
- Use descriptive commit messages referencing SAE sections or figure numbers when changing encoding logic.

If anything is unclear or you'd like this file extended with quick editing checklists (e.g., preferred linters, formatting rules, or a `make` target), tell me what to add and I'll iterate.