"""CSV → JSON normalization pipeline for the SAE Digital Annex."""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


@dataclass(slots=True)
class AnnexRow:
    """Normalized representation of a raw Digital Annex row."""

    pgn: int
    spn: int
    name: str
    bit_length: int


def normalize_digital_annex(csv_path: Path, output_path: Path) -> None:
    """Normalize a Digital Annex CSV file into structured JSON."""

    rows = list(_read_csv(csv_path))
    payload = [asdict(row) for row in rows]
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _read_csv(csv_path: Path) -> Iterable[AnnexRow]:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for raw in reader:
            try:
                yield AnnexRow(
                    pgn=int(raw["PGN"], 0),
                    spn=int(raw["SPN"], 0),
                    name=raw["Label"].strip(),
                    bit_length=int(raw["Length"]),
                )
            except (KeyError, ValueError) as exc:
                raise ValueError(f"Invalid Digital Annex row: {raw!r}") from exc
