"""Canonical labeled dataset builder."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd
import yaml


LABEL_TO_ID = {
    "benign": 0,
    "malicious": 1,
}

BASE_METADATA_COLUMNS = [
    "record_id",
    "sample_id",
    "label",
    "label_id",
    "attack_family",
    "attack_category",
    "traffic_role",
    "capture_id",
    "protocol_family",
    "window_id",
    "flow_start_ms",
    "flow_end_ms",
    "window_start_ms",
    "window_end_ms",
    "source_dataset",
    "source_name",
    "feature_view",
    "source_row_index",
    "quality_status",
    "quality_failed",
    "quality_report_path",
    "provenance_path",
    "input_csv",
    "is_encrypted",
]


@dataclass(frozen=True)
class CanonicalSource:
    name: str
    input_csv: str
    source_dataset: str
    capture_id: str
    label: str
    attack_family: str
    attack_category: str
    feature_view: str
    encrypted_only: bool
    window_size_ms: int
    traffic_role: str
    quality_report_json: str | None = None
    provenance_json: str | None = None
    extra_labels: dict[str, Any] = field(default_factory=dict)


def _load_yaml(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).expanduser().resolve()
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise RuntimeError(f"Expected a mapping in config file: {config_path}")
    return data


def load_canonical_sources(config_path: str | Path) -> tuple[dict[str, Any], list[CanonicalSource]]:
    config = _load_yaml(config_path)
    default_window_size_ms = int(config.get("window_size_ms", 60_000))
    raw_sources = config.get("sources", [])
    if not isinstance(raw_sources, list) or not raw_sources:
        raise RuntimeError("Canonical dataset config must define a non-empty 'sources' list")

    sources: list[CanonicalSource] = []
    for raw_source in raw_sources:
        if not isinstance(raw_source, dict):
            raise RuntimeError("Each source entry must be a mapping")
        extra_labels = raw_source.get("extra_labels", {})
        if extra_labels is None:
            extra_labels = {}
        if not isinstance(extra_labels, dict):
            raise RuntimeError(f"extra_labels must be a mapping for canonical source '{raw_source.get('name', '?')}'")
        label = str(raw_source["label"]).lower()
        sources.append(
            CanonicalSource(
                name=str(raw_source["name"]),
                input_csv=str(raw_source["input_csv"]),
                source_dataset=str(raw_source["source_dataset"]),
                capture_id=str(raw_source["capture_id"]),
                label=label,
                attack_family=str(raw_source.get("attack_family", "unknown")),
                attack_category=str(raw_source.get("attack_category", "unknown")),
                feature_view=str(raw_source.get("feature_view", "nfstream")),
                encrypted_only=bool(raw_source.get("encrypted_only", True)),
                window_size_ms=int(raw_source.get("window_size_ms", default_window_size_ms)),
                traffic_role=str(raw_source.get("traffic_role", label)),
                quality_report_json=str(raw_source["quality_report_json"]) if raw_source.get("quality_report_json") else None,
                provenance_json=str(raw_source["provenance_json"]) if raw_source.get("provenance_json") else None,
                extra_labels={str(key): value for key, value in extra_labels.items()},
            )
        )
    return config, sources


def _load_quality_failed(path: str | None) -> bool | None:
    if path is None:
        return None
    target = Path(path).expanduser().resolve()
    if not target.exists():
        return None
    payload = json.loads(target.read_text(encoding="utf-8"))
    failed = payload.get("failed")
    return bool(failed) if failed is not None else None


def derive_quality_status(quality_failed: bool | None) -> str:
    if quality_failed is True:
        return "fail"
    if quality_failed is False:
        return "pass"
    return "unknown"


def derive_protocol_family(df: pd.DataFrame) -> pd.Series:
    protocol_family = pd.Series("other", index=df.index, dtype="string")
    if "application_name" in df.columns:
        app_name = df["application_name"].fillna("").astype(str).str.upper()
        protocol_family[app_name.str.startswith("TLS")] = "tls"
        protocol_family[app_name.str.startswith("QUIC")] = "quic"

    if "version" in df.columns:
        version = df["version"].fillna("").astype(str).str.upper()
        protocol_family[(protocol_family == "other") & version.str.startswith("TLS")] = "tls"

    for quic_column in ("client_scid", "server_scid", "quic_version"):
        if quic_column in df.columns:
            values = df[quic_column].fillna("").astype(str).str.strip()
            protocol_family[(protocol_family == "other") & values.ne("")] = "quic"

    return protocol_family


def _build_record_id(source: CanonicalSource, source_row_index: int) -> str:
    basis = f"{source.source_dataset}|{source.capture_id}|{source.feature_view}|{source_row_index}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _build_window_columns(
    *,
    df: pd.DataFrame,
    capture_id: str,
    window_size_ms: int,
) -> tuple[pd.Series, pd.Series, pd.Series, pd.Series, pd.Series]:
    if "bidirectional_first_seen_ms" in df.columns:
        flow_start = pd.to_numeric(df["bidirectional_first_seen_ms"], errors="coerce").astype("Int64")
    else:
        flow_start = pd.Series([pd.NA] * len(df), dtype="Int64")
    if "bidirectional_last_seen_ms" in df.columns:
        flow_end = pd.to_numeric(df["bidirectional_last_seen_ms"], errors="coerce").astype("Int64")
    else:
        flow_end = pd.Series([pd.NA] * len(df), dtype="Int64")
    if flow_start.isna().all():
        window_id = pd.Series([f"{capture_id}:w000000"] * len(df), dtype="string")
        window_start = pd.Series([pd.NA] * len(df), dtype="Int64")
        window_end = pd.Series([pd.NA] * len(df), dtype="Int64")
        return flow_start, flow_end, window_id, window_start, window_end

    valid_flow_start = flow_start.dropna()
    baseline_ms = int(valid_flow_start.min())
    bucket_index = ((flow_start - baseline_ms) // window_size_ms).astype("Int64")
    window_start = (bucket_index * window_size_ms + baseline_ms).astype("Int64")
    window_end = (window_start + window_size_ms - 1).astype("Int64")
    window_id = bucket_index.map(
        lambda value: f"{capture_id}:w{int(value):06d}" if value is not pd.NA and pd.notna(value) else f"{capture_id}:wunknown"
    ).astype("string")
    return flow_start, flow_end, window_id, window_start, window_end


def _extra_label_columns(sources: list[CanonicalSource]) -> list[str]:
    keys = {key for source in sources for key in source.extra_labels}
    return sorted(keys)


def canonicalize_source(source: CanonicalSource) -> pd.DataFrame:
    input_path = Path(source.input_csv).expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Source CSV does not exist: {input_path}")

    df = pd.read_csv(input_path, low_memory=False)
    protocol_family = derive_protocol_family(df)
    is_encrypted = protocol_family.isin(["tls", "quic"])
    if source.encrypted_only:
        df = df[is_encrypted].copy()
        protocol_family = protocol_family.loc[df.index]
        is_encrypted = is_encrypted.loc[df.index]
    else:
        df = df.copy()
        is_encrypted = is_encrypted.copy()

    df = df.reset_index(drop=True)
    protocol_family = protocol_family.reset_index(drop=True)
    is_encrypted = is_encrypted.reset_index(drop=True)

    quality_failed = _load_quality_failed(source.quality_report_json)
    quality_status = derive_quality_status(quality_failed)
    label_id = LABEL_TO_ID.get(source.label)
    if label_id is None:
        raise RuntimeError(f"Unsupported label '{source.label}' in canonical source '{source.name}'")

    invalid_extra_labels = set(source.extra_labels).intersection(set(BASE_METADATA_COLUMNS).union(df.columns))
    if invalid_extra_labels:
        invalid = ", ".join(sorted(invalid_extra_labels))
        raise RuntimeError(f"Extra label columns collide with existing columns for canonical source '{source.name}': {invalid}")

    source_row_index = pd.Series(range(len(df)), dtype="int64")
    record_ids = [_build_record_id(source, int(index)) for index in source_row_index]
    flow_start_ms, flow_end_ms, window_ids, window_start_ms, window_end_ms = _build_window_columns(
        df=df,
        capture_id=source.capture_id,
        window_size_ms=source.window_size_ms,
    )

    metadata_df = pd.DataFrame(
        {
            "record_id": record_ids,
            "sample_id": [record_id[:16] for record_id in record_ids],
            "label": source.label,
            "label_id": label_id,
            "attack_family": source.attack_family,
            "attack_category": source.attack_category,
            "traffic_role": source.traffic_role,
            "capture_id": source.capture_id,
            "protocol_family": protocol_family.astype("string"),
            "window_id": window_ids.astype("string"),
            "flow_start_ms": flow_start_ms,
            "flow_end_ms": flow_end_ms,
            "window_start_ms": window_start_ms,
            "window_end_ms": window_end_ms,
            "source_dataset": source.source_dataset,
            "source_name": source.name,
            "feature_view": source.feature_view,
            "source_row_index": source_row_index,
            "quality_status": quality_status,
            "quality_failed": quality_failed,
            "quality_report_path": str(Path(source.quality_report_json).expanduser().resolve()) if source.quality_report_json else "",
            "provenance_path": str(Path(source.provenance_json).expanduser().resolve()) if source.provenance_json else "",
            "input_csv": str(input_path),
            "is_encrypted": is_encrypted.astype(bool),
        }
    )
    for key, value in sorted(source.extra_labels.items()):
        if key in metadata_df.columns or key in df.columns:
            raise RuntimeError(f"Extra label '{key}' collides with an existing column for canonical source '{source.name}'")
        metadata_df[key] = value

    return pd.concat([metadata_df, df], axis=1)


def build_canonical_dataset(
    *,
    config_path: str | Path,
    output_csv: str | Path,
    output_summary_json: str | Path | None = None,
) -> dict[str, Any]:
    config, sources = load_canonical_sources(config_path)
    frames = [canonicalize_source(source) for source in sources]
    canonical_df = pd.concat(frames, ignore_index=True, sort=False)
    extra_label_columns = _extra_label_columns(sources)

    sort_columns = [column for column in ("capture_id", "flow_start_ms", "source_row_index") if column in canonical_df.columns]
    if sort_columns:
        canonical_df = canonical_df.sort_values(sort_columns, kind="stable").reset_index(drop=True)

    ordered_columns = BASE_METADATA_COLUMNS + extra_label_columns + [
        column for column in canonical_df.columns if column not in BASE_METADATA_COLUMNS and column not in extra_label_columns
    ]
    canonical_df = canonical_df[ordered_columns]

    output_path = Path(output_csv).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    canonical_df.to_csv(output_path, index=False)

    summary: dict[str, Any] = {
        "config_path": str(Path(config_path).expanduser().resolve()),
        "output_csv": str(output_path),
        "rows": int(len(canonical_df)),
        "columns": int(len(canonical_df.columns)),
        "label_counts": canonical_df["label"].value_counts(dropna=False).to_dict(),
        "protocol_counts": canonical_df["protocol_family"].value_counts(dropna=False).to_dict(),
        "source_counts": canonical_df["source_name"].value_counts(dropna=False).to_dict(),
        "capture_counts": canonical_df["capture_id"].value_counts(dropna=False).to_dict(),
        "quality_status_counts": canonical_df["quality_status"].value_counts(dropna=False).to_dict(),
        "metadata_columns": BASE_METADATA_COLUMNS,
        "extra_label_columns": extra_label_columns,
        "window_size_ms_by_source": {source.name: source.window_size_ms for source in sources},
        "config_version": config.get("version", 1),
    }

    if output_summary_json is not None:
        summary_path = Path(output_summary_json).expanduser().resolve()
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the canonical labeled dataset used for training and dashboarding")
    parser.add_argument("--config", required=True, help="YAML config describing the canonical dataset sources")
    parser.add_argument("--output-csv", required=True, help="Destination CSV for the canonical dataset")
    parser.add_argument("--output-summary-json", default=None, help="Optional JSON summary output")
    args = parser.parse_args(argv)

    summary = build_canonical_dataset(
        config_path=args.config,
        output_csv=args.output_csv,
        output_summary_json=args.output_summary_json,
    )
    for key, value in summary.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
