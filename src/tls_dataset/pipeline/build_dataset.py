#!/usr/bin/env python3
"""Dataset building utilities for merged Zeek/NFStream features."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from tls_dataset.pipeline.common import build_dataset_artifacts

TEXT_COLUMNS_TO_LENGTH = (
    "server_name",
    "requested_server_name",
    "client_fingerprint",
    "server_fingerprint",
    "user_agent",
    "content_type",
)

IDENTIFIER_COLUMNS = (
    "id",
    "expiration_id",
    "uid",
    "src_ip",
    "dst_ip",
    "src_mac",
    "dst_mac",
    "src_port",
    "dst_port",
    "vlan_id",
    "tunnel_id",
    "first_seen_ms",
    "last_seen_ms",
    "bidirectional_first_seen_ms",
    "bidirectional_last_seen_ms",
    "ts",
)


def detect_protocol_masks(df: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    ssl_indicator_cols = [c for c in df.columns if c in ("version", "cipher", "server_name", "ja3", "ja3s")]
    if ssl_indicator_cols:
        tls_mask = df[ssl_indicator_cols].notna().any(axis=1)
    else:
        tls_mask = pd.Series(False, index=df.index)

    likely_quic_cols = [
        c for c in df.columns if any(token in c.lower() for token in ("quic", "cid", "scid", "dcid", "h3", "http3"))
    ]
    if likely_quic_cols:
        quic_mask = df[likely_quic_cols].notna().any(axis=1)
    else:
        quic_mask = pd.Series(False, index=df.index)

    return tls_mask, quic_mask


def build_ml_ready_frame(df: pd.DataFrame) -> pd.DataFrame:
    working_df = df.copy()

    for column in TEXT_COLUMNS_TO_LENGTH:
        if column in working_df.columns:
            working_df[f"{column}_len"] = working_df[column].astype("string").str.len()

    drop_cols = [column for column in IDENTIFIER_COLUMNS if column in working_df.columns]
    drop_text = [column for column in working_df.columns if working_df[column].dtype == "object"]
    ml_df = working_df.drop(columns=list(set(drop_cols + drop_text)), errors="ignore")
    ml_df = ml_df.select_dtypes(include=[np.number]).copy()
    ml_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    ml_df.fillna(0, inplace=True)
    return ml_df


def build_dataset_outputs(
    merged_csv: str | Path,
    *,
    output_dir: str | Path,
    dataset_name: str,
    protocol_filter: str = "encrypted_only",
) -> dict[str, str | int]:
    merged_path = Path(merged_csv).expanduser().resolve()
    artifacts = build_dataset_artifacts(dataset_name=dataset_name, output_dir=output_dir)
    artifacts.output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(merged_path, low_memory=False)
    if "uid" not in df.columns:
        raise RuntimeError("Expected column 'uid' not found. Did feature merge succeed?")

    tls_mask, quic_mask = detect_protocol_masks(df)
    encrypted_mask = tls_mask | quic_mask
    ml_source = df[encrypted_mask].copy() if protocol_filter == "encrypted_only" else df.copy()
    ml_df = build_ml_ready_frame(ml_source)

    df.to_csv(artifacts.all_merged_csv, index=False)
    df[tls_mask].to_csv(artifacts.tls_csv, index=False)
    df[quic_mask].to_csv(artifacts.quic_csv, index=False)
    ml_df.to_csv(artifacts.ml_ready_csv, index=False)

    return {
        "all_merged_csv": str(artifacts.all_merged_csv),
        "tls_csv": str(artifacts.tls_csv),
        "quic_csv": str(artifacts.quic_csv),
        "ml_ready_csv": str(artifacts.ml_ready_csv),
        "total_rows": int(len(df)),
        "tls_rows": int(tls_mask.sum()),
        "quic_rows": int(quic_mask.sum()),
        "encrypted_rows": int(encrypted_mask.sum()),
        "ml_rows": int(len(ml_df)),
        "ml_columns": int(ml_df.shape[1]),
        "protocol_filter": protocol_filter,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build canonical dataset outputs from a merged feature CSV")
    parser.add_argument("--merged", required=True, help="Merged CSV from the feature merge step")
    parser.add_argument("--dataset-name", required=True, help="Dataset name used for output file naming")
    parser.add_argument("--output-dir", required=True, help="Directory for generated dataset outputs")
    parser.add_argument(
        "--protocol-filter",
        choices=("encrypted_only", "all"),
        default="encrypted_only",
        help="Whether ML-ready outputs should keep only TLS/QUIC-tagged rows or all merged rows",
    )
    args = parser.parse_args(argv)

    results = build_dataset_outputs(
        merged_csv=args.merged,
        output_dir=args.output_dir,
        dataset_name=args.dataset_name,
        protocol_filter=args.protocol_filter,
    )

    for key, value in results.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
