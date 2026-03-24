"""Provenance tracking for dataset artifacts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProvenanceEntry:
    stage: str
    path: str
    sha256: str
    size_bytes: int
    parent_path: str | None = None
    source_url: str | None = None
    source_rel_path: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    command: str | None = None
    notes: str | None = None


def sha256_file(path: str | Path, *, chunk_size: int = 1024 * 1024) -> str:
    target = Path(path).expanduser().resolve()
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_provenance_entry(
    *,
    stage: str,
    path: str | Path,
    parent_path: str | Path | None = None,
    source_url: str | None = None,
    source_rel_path: str | None = None,
    tool: str | None = None,
    tool_version: str | None = None,
    command: str | None = None,
    notes: str | None = None,
) -> ProvenanceEntry:
    target = Path(path).expanduser().resolve()
    return ProvenanceEntry(
        stage=stage,
        path=str(target),
        sha256=sha256_file(target),
        size_bytes=target.stat().st_size,
        parent_path=str(Path(parent_path).expanduser().resolve()) if parent_path else None,
        source_url=source_url,
        source_rel_path=source_rel_path,
        tool=tool,
        tool_version=tool_version,
        command=command,
        notes=notes,
    )


def write_provenance(entries: list[ProvenanceEntry], output_path: str | Path) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {"entries": [asdict(entry) for entry in entries]}
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
