#!/usr/bin/env python3
"""Inspection helpers for NFStream outputs."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def inspect_nfstream_csv(input_csv: str | Path, *, top_n: int = 5) -> dict[str, object]:
    input_path = Path(input_csv).expanduser().resolve()
    df = pd.read_csv(input_path, low_memory=False)

    summary: dict[str, object] = {
        "input_csv": str(input_path),
        "flows": int(len(df)),
        "columns": int(len(df.columns)),
    }

    if "protocol" in df.columns:
        summary["top_protocols"] = df["protocol"].value_counts().head(top_n).to_dict()
    if "tls_version" in df.columns:
        summary["tls_version_distribution"] = df["tls_version"].value_counts(dropna=False).head(top_n).to_dict()

    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect an NFStream CSV and print basic distributions")
    parser.add_argument("--input", required=True, help="Input NFStream CSV")
    parser.add_argument("--top-n", type=int, default=5, help="Number of top values to report")
    args = parser.parse_args(argv)

    summary = inspect_nfstream_csv(args.input, top_n=args.top_n)
    for key, value in summary.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
