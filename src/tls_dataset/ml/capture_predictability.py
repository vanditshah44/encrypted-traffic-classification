"""Measure how easily flow features identify the source capture."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path
from typing import Any

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "tls_dataset_mplconfig"))
import matplotlib

matplotlib.use("Agg")
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.pipeline import Pipeline

from tls_dataset.ml.workflow import WorkflowConfig, load_workflow_config, save_json, select_feature_columns


DISPLAY_NAMES = {
    "all_captures": "All captures",
    "benign_captures": "Benign only",
    "malicious_captures": "Malicious only",
}


def prepare_capture_source_features(
    df: pd.DataFrame,
    *,
    config: WorkflowConfig,
    target_column: str = "capture_id",
) -> tuple[pd.DataFrame, pd.Series, list[str], list[str]]:
    excluded = tuple(sorted(set(config.extra_excluded_columns + (config.target_column, config.label_column))))
    feature_columns, _ = select_feature_columns(
        df,
        target_column=target_column,
        extra_excluded_columns=excluded,
    )
    X = df[feature_columns].copy()
    bool_columns = [column for column in X.columns if pd.api.types.is_bool_dtype(X[column])]
    if bool_columns:
        X[bool_columns] = X[bool_columns].astype(int)

    constant_columns = [column for column in X.columns if X[column].nunique(dropna=False) <= 1]
    all_missing_columns = [column for column in X.columns if X[column].isna().all()]
    dropped_columns = sorted(set(constant_columns + all_missing_columns))
    if dropped_columns:
        X = X.drop(columns=dropped_columns)

    y = df[target_column].astype(str)
    return X, y, list(X.columns), dropped_columns


def majority_baseline_accuracy(y: pd.Series) -> float:
    counts = y.value_counts(normalize=True)
    return float(counts.max()) if not counts.empty else 0.0


def stratified_random_baseline_accuracy(y: pd.Series) -> float:
    probabilities = y.value_counts(normalize=True)
    return float(np.sum(np.square(probabilities.to_numpy(dtype=float)))) if not probabilities.empty else 0.0


def build_capture_predictor(*, random_state: int, n_estimators: int, n_jobs: int) -> Pipeline:
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            (
                "model",
                RandomForestClassifier(
                    n_estimators=n_estimators,
                    random_state=random_state,
                    n_jobs=n_jobs,
                    class_weight="balanced_subsample",
                ),
            ),
        ]
    )


def _feature_importance_frame(model: Pipeline, feature_columns: list[str], *, top_k: int) -> pd.DataFrame:
    estimator = model.named_steps["model"]
    importances = getattr(estimator, "feature_importances_", None)
    if importances is None:
        return pd.DataFrame()
    frame = pd.DataFrame({"feature": feature_columns, "importance": importances})
    return frame.sort_values("importance", ascending=False, kind="stable").head(top_k).reset_index(drop=True)


def evaluate_capture_predictability_subset(
    df: pd.DataFrame,
    *,
    config: WorkflowConfig,
    experiment_name: str,
    output_dir: str | Path,
    test_size: float,
    random_state: int,
    n_estimators: int,
    n_jobs: int,
    top_k_features: int,
) -> dict[str, Any]:
    if df["capture_id"].nunique() < 2:
        raise RuntimeError(f"{experiment_name} needs at least two captures")

    output_path = Path(output_dir).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    X, y, feature_columns, dropped_columns = prepare_capture_source_features(df, config=config)
    splitter = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(splitter.split(X, y))
    X_train = X.iloc[train_idx].reset_index(drop=True)
    X_test = X.iloc[test_idx].reset_index(drop=True)
    y_train = y.iloc[train_idx].reset_index(drop=True)
    y_test = y.iloc[test_idx].reset_index(drop=True)

    model = build_capture_predictor(
        random_state=random_state,
        n_estimators=n_estimators,
        n_jobs=n_jobs,
    )
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    labels = sorted(y.unique().tolist())

    report = classification_report(y_test, predictions, labels=labels, output_dict=True, zero_division=0)
    report_rows = []
    for label in labels:
        metrics = report.get(label, {})
        report_rows.append(
            {
                "experiment": experiment_name,
                "capture_id": label,
                "precision": float(metrics.get("precision", 0.0)),
                "recall": float(metrics.get("recall", 0.0)),
                "f1": float(metrics.get("f1-score", 0.0)),
                "support": int(metrics.get("support", 0)),
            }
        )
    per_capture = pd.DataFrame(report_rows)
    matrix = pd.DataFrame(
        confusion_matrix(y_test, predictions, labels=labels),
        index=labels,
        columns=labels,
    )
    feature_importance = _feature_importance_frame(model, feature_columns, top_k=top_k_features)
    if not feature_importance.empty:
        feature_importance.insert(0, "experiment", experiment_name)

    per_capture.to_csv(output_path / f"{experiment_name}_per_capture_metrics.csv", index=False)
    matrix.to_csv(output_path / f"{experiment_name}_confusion_matrix.csv")
    feature_importance.to_csv(output_path / f"{experiment_name}_feature_importance.csv", index=False)

    return {
        "experiment": experiment_name,
        "rows": int(len(df)),
        "capture_count": int(y.nunique()),
        "feature_count": int(len(feature_columns)),
        "dropped_columns": dropped_columns,
        "train_rows": int(len(y_train)),
        "test_rows": int(len(y_test)),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, predictions)),
        "macro_f1": float(f1_score(y_test, predictions, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_test, predictions, average="weighted", zero_division=0)),
        "majority_baseline_accuracy": majority_baseline_accuracy(y_test),
        "stratified_random_baseline_accuracy": stratified_random_baseline_accuracy(y_test),
        "outputs": {
            "per_capture_metrics_csv": str((output_path / f"{experiment_name}_per_capture_metrics.csv").resolve()),
            "confusion_matrix_csv": str((output_path / f"{experiment_name}_confusion_matrix.csv").resolve()),
            "feature_importance_csv": str((output_path / f"{experiment_name}_feature_importance.csv").resolve()),
        },
    }


def build_capture_predictability_experiments(
    df: pd.DataFrame,
    *,
    label_column: str = "label",
) -> list[tuple[str, pd.DataFrame]]:
    experiments = [("all_captures", df)]
    for label in ("benign", "malicious"):
        subset = df[df[label_column].astype(str) == label].copy()
        if subset["capture_id"].nunique() >= 2:
            experiments.append((f"{label}_captures", subset))
    return experiments


def run_capture_predictability(
    *,
    config_path: str | Path,
    output_dir: str | Path,
    test_size: float = 0.25,
    n_estimators: int = 200,
    n_jobs: int = -1,
    top_k_features: int = 25,
) -> dict[str, Any]:
    output_path = Path(output_dir).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    config = load_workflow_config(config_path)
    df = pd.read_csv(config.dataset_csv, low_memory=False)
    rows = []
    for experiment_name, subset in build_capture_predictability_experiments(
        df,
        label_column=config.label_column,
    ):
        rows.append(
            evaluate_capture_predictability_subset(
                subset,
                config=config,
                experiment_name=experiment_name,
                output_dir=output_path,
                test_size=test_size,
                random_state=config.random_state,
                n_estimators=n_estimators,
                n_jobs=n_jobs,
                top_k_features=top_k_features,
            )
        )

    results = pd.DataFrame(
        [
            {key: value for key, value in row.items() if key not in {"dropped_columns", "outputs"}}
            for row in rows
        ]
    )
    results.to_csv(output_path / "capture_predictability_results.csv", index=False)

    summary = {
        "config_path": str(Path(config_path).expanduser().resolve()),
        "dataset_csv": str(Path(config.dataset_csv).expanduser().resolve()),
        "output_dir": str(output_path),
        "test_size": float(test_size),
        "n_estimators": int(n_estimators),
        "n_jobs": int(n_jobs),
        "top_k_features": int(top_k_features),
        "experiments": rows,
        "outputs": {
            "results_csv": str((output_path / "capture_predictability_results.csv").resolve()),
        },
    }
    save_json(summary, output_path / "capture_predictability_summary.json")
    return summary


def _format_float(value: Any) -> str:
    if pd.isna(value):
        return ""
    return f"{float(value):.4f}"


def save_capture_predictability_markdown(results: pd.DataFrame, output_path: str | Path) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "experiment",
        "rows",
        "capture_count",
        "accuracy",
        "balanced_accuracy",
        "macro_f1",
        "majority_baseline_accuracy",
        "stratified_random_baseline_accuracy",
    ]
    display = results[columns].copy()
    display["experiment"] = display["experiment"].map(lambda value: DISPLAY_NAMES.get(str(value), str(value)))
    for column in (
        "accuracy",
        "balanced_accuracy",
        "macro_f1",
        "majority_baseline_accuracy",
        "stratified_random_baseline_accuracy",
    ):
        display[column] = display[column].map(_format_float)
    headers = [
        "Experiment",
        "Rows",
        "Captures",
        "Accuracy",
        "Balanced Acc.",
        "Macro F1",
        "Majority Base",
        "Random Base",
    ]
    rows = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for _, row in display.iterrows():
        rows.append("| " + " | ".join(str(row[column]) for column in display.columns) + " |")
    target.write_text("\n".join(rows) + "\n", encoding="utf-8")


def plot_capture_predictability_metrics(results: pd.DataFrame, *, output_path: str | Path) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    labels = [DISPLAY_NAMES.get(str(value), str(value)) for value in results["experiment"]]
    positions = np.arange(len(labels))
    width = 0.2

    plt.figure(figsize=(10, 6))
    plt.bar(positions - 1.5 * width, results["accuracy"], width=width, label="Accuracy")
    plt.bar(positions - 0.5 * width, results["balanced_accuracy"], width=width, label="Balanced accuracy")
    plt.bar(positions + 0.5 * width, results["majority_baseline_accuracy"], width=width, label="Majority baseline")
    plt.bar(
        positions + 1.5 * width,
        results["stratified_random_baseline_accuracy"],
        width=width,
        label="Random baseline",
    )
    plt.xticks(positions, labels)
    plt.ylim(0.0, 1.05)
    plt.ylabel("Score")
    plt.title("Capture-ID Predictability From Flow Features")
    plt.grid(axis="y", alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(target, dpi=220)
    plt.close()


def plot_capture_predictability_feature_importance(
    output_dir: str | Path,
    *,
    top_k: int,
    output_path: str | Path,
) -> None:
    source_path = Path(output_dir).expanduser().resolve()
    frames: list[pd.DataFrame] = []
    for experiment_name in ("all_captures", "benign_captures", "malicious_captures"):
        path = source_path / f"{experiment_name}_feature_importance.csv"
        if path.exists():
            frame = pd.read_csv(path).head(top_k).copy()
            frame["experiment"] = experiment_name
            frames.append(frame)
    if not frames:
        return

    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    combined = pd.concat(frames, ignore_index=True)
    experiments = combined["experiment"].drop_duplicates().tolist()
    fig, axes = plt.subplots(len(experiments), 1, figsize=(10, max(4, 3.4 * len(experiments))))
    if len(experiments) == 1:
        axes = [axes]
    for axis, experiment_name in zip(axes, experiments, strict=False):
        frame = combined[combined["experiment"] == experiment_name].sort_values("importance", ascending=True)
        axis.barh(frame["feature"], frame["importance"], color="#4c78a8")
        axis.set_title(DISPLAY_NAMES.get(experiment_name, experiment_name))
        axis.set_xlabel("Random Forest importance")
        axis.grid(axis="x", alpha=0.25)
    plt.tight_layout()
    plt.savefig(target, dpi=220)
    plt.close()


def summarize_capture_predictability_outputs(
    *,
    output_dir: str | Path,
    top_k_features: int = 12,
) -> dict[str, Any]:
    output_path = Path(output_dir).expanduser().resolve()
    results = pd.read_csv(output_path / "capture_predictability_results.csv")
    save_capture_predictability_markdown(
        results,
        output_path / "capture_predictability_results.md",
    )
    plot_capture_predictability_metrics(
        results,
        output_path=output_path / "capture_predictability_metric_bars.png",
    )
    plot_capture_predictability_feature_importance(
        output_path,
        top_k=top_k_features,
        output_path=output_path / "capture_predictability_feature_importance.png",
    )

    summary = {
        "output_dir": str(output_path),
        "experiment_count": int(len(results)),
        "top_k_features": int(top_k_features),
        "max_accuracy": float(results["accuracy"].max()),
        "min_accuracy": float(results["accuracy"].min()),
        "max_macro_f1": float(results["macro_f1"].max()),
        "min_macro_f1": float(results["macro_f1"].min()),
        "outputs": {
            "results_md": str((output_path / "capture_predictability_results.md").resolve()),
            "metric_bars_png": str((output_path / "capture_predictability_metric_bars.png").resolve()),
            "feature_importance_png": str((output_path / "capture_predictability_feature_importance.png").resolve()),
        },
    }
    save_json(summary, output_path / "capture_predictability_report_summary.json")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure source-capture predictability from flow features")
    parser.add_argument("--config", required=True, help="ML workflow YAML config")
    parser.add_argument("--output-dir", default="artifacts/diagnostics/capture_predictability")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--n-jobs", type=int, default=-1)
    parser.add_argument("--top-k-features", type=int, default=25)
    parser.add_argument("--summarize-only", action="store_true", help="Only summarize existing outputs")
    args = parser.parse_args(argv)

    if args.summarize_only:
        summary = summarize_capture_predictability_outputs(
            output_dir=args.output_dir,
            top_k_features=args.top_k_features,
        )
    else:
        summary = run_capture_predictability(
            config_path=args.config,
            output_dir=args.output_dir,
            test_size=args.test_size,
            n_estimators=args.n_estimators,
            n_jobs=args.n_jobs,
            top_k_features=args.top_k_features,
        )
        report_summary = summarize_capture_predictability_outputs(
            output_dir=args.output_dir,
            top_k_features=args.top_k_features,
        )
        summary["report"] = report_summary
    for key, value in summary.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
