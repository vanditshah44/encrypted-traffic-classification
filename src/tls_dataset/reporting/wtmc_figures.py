"""WTMC-ready figures and tables from capture-shift and LOCO artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import numpy as np
import pandas as pd
from matplotlib import pyplot as plt

from tls_dataset.ml.workflow import save_json


MODEL_LABELS = {
    "gaussian_nb": "Gaussian NB",
    "random_forest": "Random Forest",
    "gradient_boosting": "Gradient Boosting",
    "xgboost": "XGBoost",
}


def normalize_capture_pair(capture_a: str, capture_b: str) -> str:
    left, right = sorted((str(capture_a), str(capture_b)))
    return f"{left}__{right}"


def parse_capture_ids(value: Any) -> tuple[str, ...]:
    if pd.isna(value):
        return ()
    return tuple(part.strip() for part in str(value).split(",") if part.strip())


def add_capture_pair_key(frame: pd.DataFrame) -> pd.DataFrame:
    result = frame.copy()
    if {"capture_a", "capture_b"}.issubset(result.columns):
        result["capture_pair_key"] = [
            normalize_capture_pair(left, right)
            for left, right in zip(result["capture_a"], result["capture_b"], strict=False)
        ]
        return result
    if "test_capture_ids" not in result.columns:
        raise RuntimeError("Expected either capture_a/capture_b or test_capture_ids columns")
    keys: list[str | None] = []
    for value in result["test_capture_ids"]:
        capture_ids = parse_capture_ids(value)
        keys.append(normalize_capture_pair(capture_ids[0], capture_ids[1]) if len(capture_ids) == 2 else None)
    result["capture_pair_key"] = keys
    return result


def build_loco_distance_frame(
    paired_metrics: pd.DataFrame,
    distance_pairs: pd.DataFrame,
) -> pd.DataFrame:
    metrics = add_capture_pair_key(paired_metrics)
    distances = add_capture_pair_key(distance_pairs)
    distance_columns = [
        "capture_pair_key",
        "capture_a",
        "capture_b",
        "label_a",
        "label_b",
        "pair_type",
        "distance",
    ]
    merged = metrics.merge(
        distances[distance_columns],
        on="capture_pair_key",
        how="left",
        suffixes=("", "_distance"),
        validate="many_to_one",
    )
    missing = merged[merged["distance"].isna()]["capture_pair_key"].dropna().unique().tolist()
    if missing:
        raise RuntimeError(f"Missing capture-distance rows for LOCO pairs: {missing}")
    return merged.sort_values(["model", "distance", "split_name"], ascending=[True, False, True])


def build_loco_distance_correlations(
    loco_distance: pd.DataFrame,
    *,
    metrics: tuple[str, ...] = ("f1", "roc_auc", "average_precision"),
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for model, group in loco_distance.groupby("model", dropna=False):
        for metric in metrics:
            valid = group[["distance", metric]].replace([np.inf, -np.inf], np.nan).dropna()
            rows.append(
                {
                    "model": model,
                    "metric": metric,
                    "pair_count": int(len(valid)),
                    "pearson_r": float(valid["distance"].corr(valid[metric], method="pearson"))
                    if len(valid) >= 2
                    else None,
                    "spearman_r": float(valid["distance"].corr(valid[metric], method="spearman"))
                    if len(valid) >= 2
                    else None,
                }
            )
    return pd.DataFrame(rows)


def build_ranked_capture_pair_table(loco_distance: pd.DataFrame, *, top_n: int = 12) -> pd.DataFrame:
    pair_columns = [
        "capture_pair_key",
        "capture_a",
        "capture_b",
        "label_a",
        "label_b",
        "pair_type",
        "distance",
    ]
    pairs = (
        loco_distance[pair_columns]
        .drop_duplicates("capture_pair_key")
        .sort_values("distance", ascending=False, kind="stable")
        .head(top_n)
        .reset_index(drop=True)
    )
    metric_wide = loco_distance.pivot_table(
        index="capture_pair_key",
        columns="model",
        values=["f1", "roc_auc"],
        aggfunc="first",
    )
    metric_wide.columns = [f"{model}_{metric}" for metric, model in metric_wide.columns]
    return pairs.merge(metric_wide.reset_index(), on="capture_pair_key", how="left")


def save_markdown_table(frame: pd.DataFrame, output_path: str | Path) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    display = frame.copy()
    for column in display.columns:
        if pd.api.types.is_float_dtype(display[column]):
            display[column] = display[column].map(lambda value: "" if pd.isna(value) else f"{value:.4f}")
        else:
            display[column] = display[column].map(lambda value: "" if pd.isna(value) else str(value))
    headers = [str(column) for column in display.columns]
    rows = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for _, row in display.iterrows():
        rows.append("| " + " | ".join(str(row[column]) for column in display.columns) + " |")
    target.write_text("\n".join(rows) + "\n", encoding="utf-8")


def plot_capture_distance_heatmap(distance_matrix: pd.DataFrame, *, output_path: str | Path) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    matrix = distance_matrix.astype(float)
    labels = matrix.index.tolist()

    plt.figure(figsize=(10, 8))
    image = plt.imshow(matrix.to_numpy(), cmap="viridis")
    plt.colorbar(image, fraction=0.046, pad=0.04, label="Robust standardized distance")
    positions = np.arange(len(labels))
    plt.xticks(positions, labels, rotation=45, ha="right")
    plt.yticks(positions, labels)
    plt.title("Capture Feature-Shift Distance")
    for row_idx in range(matrix.shape[0]):
        for col_idx in range(matrix.shape[1]):
            value = float(matrix.iloc[row_idx, col_idx])
            color = "white" if value > matrix.to_numpy().max() * 0.55 else "black"
            plt.text(col_idx, row_idx, f"{value:.1f}", ha="center", va="center", fontsize=7, color=color)
    plt.tight_layout()
    plt.savefig(target, dpi=220)
    plt.close()


def plot_loco_vs_distance(
    loco_distance: pd.DataFrame,
    *,
    metric: str,
    output_path: str | Path,
) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(9, 6))
    for model, group in loco_distance.groupby("model", sort=True):
        label = MODEL_LABELS.get(str(model), str(model))
        plt.scatter(group["distance"], group[metric], label=label, alpha=0.75, s=45)
        valid = group[["distance", metric]].replace([np.inf, -np.inf], np.nan).dropna()
        if len(valid) >= 2 and valid["distance"].nunique() >= 2:
            slope, intercept = np.polyfit(valid["distance"].to_numpy(), valid[metric].to_numpy(), deg=1)
            x_values = np.linspace(valid["distance"].min(), valid["distance"].max(), 50)
            plt.plot(x_values, slope * x_values + intercept, linewidth=1.4, alpha=0.75)
    plt.title(f"Paired LOCO {metric.replace('_', '-').upper()} vs Capture Shift")
    plt.xlabel("Robust standardized capture-pair distance")
    plt.ylabel(metric.replace("_", "-").upper())
    if metric in {"f1", "roc_auc", "average_precision"}:
        plt.ylim(-0.02, 1.02)
    plt.grid(alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(target, dpi=220)
    plt.close()


def run_wtmc_figure_export(
    *,
    diagnostics_dir: str | Path,
    loco_dir: str | Path,
    output_dir: str | Path,
    top_pairs: int = 12,
) -> dict[str, Any]:
    diagnostics_path = Path(diagnostics_dir).expanduser().resolve()
    loco_path = Path(loco_dir).expanduser().resolve()
    output_path = Path(output_dir).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    distance_matrix = pd.read_csv(diagnostics_path / "capture_distance_matrix.csv", index_col=0)
    distance_pairs = pd.read_csv(diagnostics_path / "capture_distance_pairs.csv")
    paired_metrics = pd.read_csv(loco_path / "paired_capture_metrics.csv")
    paired_metrics = paired_metrics[paired_metrics["split_kind"] == "malicious_benign_pair"].copy()

    loco_distance = build_loco_distance_frame(paired_metrics, distance_pairs)
    correlations = build_loco_distance_correlations(loco_distance)
    ranked_pairs = build_ranked_capture_pair_table(loco_distance, top_n=top_pairs)

    loco_distance.to_csv(output_path / "loco_distance_joined.csv", index=False)
    correlations.to_csv(output_path / "loco_distance_correlations.csv", index=False)
    ranked_pairs.to_csv(output_path / "ranked_capture_pair_table.csv", index=False)
    save_markdown_table(ranked_pairs, output_path / "ranked_capture_pair_table.md")

    plot_capture_distance_heatmap(distance_matrix, output_path=output_path / "capture_distance_heatmap.png")
    plot_loco_vs_distance(loco_distance, metric="f1", output_path=output_path / "loco_f1_vs_distance.png")
    plot_loco_vs_distance(loco_distance, metric="roc_auc", output_path=output_path / "loco_auc_vs_distance.png")

    summary = {
        "diagnostics_dir": str(diagnostics_path),
        "loco_dir": str(loco_path),
        "output_dir": str(output_path),
        "paired_metric_rows": int(len(paired_metrics)),
        "joined_rows": int(len(loco_distance)),
        "capture_pair_count": int(loco_distance["capture_pair_key"].nunique()),
        "top_pairs": int(top_pairs),
        "outputs": {
            "loco_distance_joined_csv": str((output_path / "loco_distance_joined.csv").resolve()),
            "loco_distance_correlations_csv": str((output_path / "loco_distance_correlations.csv").resolve()),
            "ranked_capture_pair_table_csv": str((output_path / "ranked_capture_pair_table.csv").resolve()),
            "ranked_capture_pair_table_md": str((output_path / "ranked_capture_pair_table.md").resolve()),
            "capture_distance_heatmap_png": str((output_path / "capture_distance_heatmap.png").resolve()),
            "loco_f1_vs_distance_png": str((output_path / "loco_f1_vs_distance.png").resolve()),
            "loco_auc_vs_distance_png": str((output_path / "loco_auc_vs_distance.png").resolve()),
        },
        "correlations": correlations.to_dict(orient="records"),
    }
    save_json(summary, output_path / "wtmc_figures_summary.json")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export WTMC-ready capture-shift figures and tables")
    parser.add_argument("--diagnostics-dir", default="artifacts/diagnostics/capture_shift")
    parser.add_argument("--loco-dir", default="artifacts/ml_workflow/loco")
    parser.add_argument("--output-dir", default="artifacts/wtmc_figures")
    parser.add_argument("--top-pairs", type=int, default=12)
    args = parser.parse_args(argv)

    summary = run_wtmc_figure_export(
        diagnostics_dir=args.diagnostics_dir,
        loco_dir=args.loco_dir,
        output_dir=args.output_dir,
        top_pairs=args.top_pairs,
    )
    for key, value in summary.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
