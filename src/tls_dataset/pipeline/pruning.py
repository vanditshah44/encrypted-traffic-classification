#!/usr/bin/env python3
"""Feature pruning utilities for ML-ready datasets."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_selection import VarianceThreshold

from tls_dataset.pipeline.common import build_dataset_artifacts


def prune_feature_dataset(
    input_csv: str | Path,
    *,
    output_dir: str | Path,
    dataset_name: str,
    near_const_threshold: float = 0.995,
    corr_threshold: float = 0.95,
) -> dict[str, str | int]:
    input_path = Path(input_csv).expanduser().resolve()
    artifacts = build_dataset_artifacts(dataset_name=dataset_name, output_dir=output_dir)
    artifacts.output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(input_path, low_memory=False)
    df = df.apply(pd.to_numeric, errors="coerce")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    total_nans = int(df.isna().sum().sum())
    df.fillna(0, inplace=True)
    duplicate_rows = int(df.duplicated().sum())

    matrix = df.to_numpy(dtype=float)
    variance_filter = VarianceThreshold(threshold=0.0)
    variance_filter.fit(matrix)
    constant_mask = variance_filter.get_support()
    constant_dropped = df.columns[~constant_mask].tolist()
    df_no_constant = df[df.columns[constant_mask]].copy()
    df_no_constant.to_csv(artifacts.ml_no_constant_csv, index=False)

    near_constant_dropped: list[str] = []
    for column in df_no_constant.columns:
        top_freq = df_no_constant[column].value_counts(normalize=True, dropna=False).iloc[0]
        if top_freq > near_const_threshold:
            near_constant_dropped.append(column)
    df_no_var = df_no_constant.drop(columns=near_constant_dropped)
    df_no_var.to_csv(artifacts.ml_no_constant_novar_csv, index=False)

    corr = df_no_var.corr(numeric_only=True).abs()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
    correlated_dropped = [column for column in upper.columns if (upper[column] > corr_threshold).any()]
    df_pruned = df_no_var.drop(columns=correlated_dropped)
    df_pruned.to_csv(artifacts.ml_pruned_csv, index=False)

    return {
        "input_csv": str(input_path),
        "ml_no_constant_csv": str(artifacts.ml_no_constant_csv),
        "ml_no_constant_novar_csv": str(artifacts.ml_no_constant_novar_csv),
        "ml_pruned_csv": str(artifacts.ml_pruned_csv),
        "rows": int(df_pruned.shape[0]),
        "columns": int(df_pruned.shape[1]),
        "total_nans_before_fill": total_nans,
        "duplicate_rows": duplicate_rows,
        "constant_features_dropped": len(constant_dropped),
        "near_constant_features_dropped": len(near_constant_dropped),
        "correlated_features_dropped": len(correlated_dropped),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prune constant, near-constant, and correlated features")
    parser.add_argument("--input", required=True, help="Input ML-ready CSV")
    parser.add_argument("--dataset-name", required=True, help="Dataset name used for output file naming")
    parser.add_argument("--output-dir", required=True, help="Directory for generated pruning outputs")
    parser.add_argument("--near-constant-threshold", type=float, default=0.995)
    parser.add_argument("--correlation-threshold", type=float, default=0.95)
    args = parser.parse_args(argv)

    results = prune_feature_dataset(
        input_csv=args.input,
        output_dir=args.output_dir,
        dataset_name=args.dataset_name,
        near_const_threshold=args.near_constant_threshold,
        corr_threshold=args.correlation_threshold,
    )

    for key, value in results.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
