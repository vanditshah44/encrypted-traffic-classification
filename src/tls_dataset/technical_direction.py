"""Single source of truth for high-level architecture decisions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TechnicalDirection:
    production_extractors: tuple[str, ...]
    thesis_legacy_extractors: tuple[str, ...]
    decision_summary: str


TECHNICAL_DIRECTION = TechnicalDirection(
    production_extractors=("zeek", "nfstream"),
    thesis_legacy_extractors=("cicflowmeter",),
    decision_summary=(
        "Zeek + NFStream is the official production extraction stack. "
        "CICFlowMeter remains thesis-era legacy and is not part of the forward build path."
    ),
)
