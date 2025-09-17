# Scapy J1939-22 Architecture

This document captures high level goals for the library:

- TP-22 first transport with TP-21 compatibility adapters.
- Registry-backed APDU modelling that mirrors the SAE Digital Annex.
- 91C security leader/follower flows with freshness management.

Future sections will elaborate the state machines, transport frames, and
security TLVs.
