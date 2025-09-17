"""Compatibility wrapper around the Scapy contrib implementation."""
from __future__ import annotations

def _alias(submodule: str):
    import importlib
    import sys

    module = importlib.import_module(f"scapy.contrib.j1939_22.{submodule}")
    sys.modules[f"{__name__}.{submodule}"] = module
    return module

_contrib = _alias("__init__")  # load base package for side effects and metadata

apdu = _alias("apdu")
stack = _alias("stack")
layers = _alias("layers")
transport = _alias("transport")
security = _alias("security")
registry = _alias("registry")
util = _alias("util")

# Ensure submodules resolve (e.g. scapy_j1939_22.transport.tp22)
for base, subs in {
    "transport": ["fdtp", "tp22", "tp21_adapter"],
    "layers": ["pdu", "multipg", "sec_ctrl"],
    "registry": ["digital_annex", "validation"],
    "security": ["freshness", "leader", "follower"],
    "util": ["canio"],
}.items():
    for name in subs:
        _alias(f"{base}.{name}")

del _alias

__all__ = getattr(_contrib, "__all__", [])
__version__ = getattr(_contrib, "__version__", "0.1.0")
