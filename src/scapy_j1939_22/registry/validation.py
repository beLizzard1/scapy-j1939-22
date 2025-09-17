"""Validation helpers for the Digital Annex registry."""
from __future__ import annotations

from typing import Iterable

from .digital_annex import DigitalAnnexRegistry, PGDefinition


class RegistryValidator:
    """Runs sanity checks on registry content."""

    def __init__(self, registry: DigitalAnnexRegistry) -> None:
        self._registry = registry

    def validate(self) -> Iterable[str]:
        """Yield validation error strings."""

        for pgn, definition in self._registry._pgns.items():
            if definition.length <= 0:
                yield f"PGN {pgn} has non-positive length"
            if not definition.spns:
                yield f"PGN {pgn} is missing SPN definitions"

    def validate_definition(self, definition: PGDefinition) -> Iterable[str]:
        """Validate a single definition instance."""

        if definition.length <= 0:
            yield "Length must be positive"
        if not definition.spns:
            yield "SPN mapping must not be empty"
