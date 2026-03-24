#!/usr/bin/env python3
"""Final cleanup utilities for pruned ML datasets."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

DEFAULT_DROP_COLS = [
    "src2dst_first_seen_ms",
    "dst2src_first_seen_ms",
    "ts_zeek_ssl",
    "ts_zeek_quic",
]


def finalize_feature_dataset(
    input_csv: str | Path,
    output_csv: str | Path,
    *,
    drop_cols: list[str] | None = None,
) -> dict[str, str | int]:
    input_path = Path(input_csv).expanduser().resolve()
    output_path = Path(output_csv).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(input_path, low_memory=False)
    final_drop_cols = [column for column in (drop_cols or DEFAULT_DROP_COLS) if column in df.columns]
    df_final = df.drop(columns=final_drop_cols)
    df_final.to_csv(output_path, index=False)

    return {
        "input_csv": str(input_path),
        "output_csv": str(output_path),
        "dropped_columns": len(final_drop_cols),
        "rows": int(df_final.shape[0]),
        "columns": int(df_final.shape[1]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Finalize a pruned ML dataset into its final feature table")
    parser.add_argument("--input", required=True, help="Input pruned CSV")
    parser.add_argument("--output", required=True, help="Output final CSV")
    parser.add_argument(
        "--drop-cols",
        nargs="*",
        default=None,
        help="Optional explicit list of columns to drop; defaults to the repository baseline",
    )
    args = parser.parse_args(argv)

    results = finalize_feature_dataset(args.input, args.output, drop_cols=args.drop_cols)
    for key, value in results.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
