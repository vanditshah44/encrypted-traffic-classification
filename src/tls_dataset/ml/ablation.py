"""
Feature group ablation study for EncFlow measurement/evaluation artifacts.

Runs RF and XGBoost with each feature group excluded in turn,
reporting held-out capture F1 and ROC-AUC deltas relative to the full feature
set. The split and training-column cleanup intentionally mirror
``tls_dataset.ml.workflow`` so ablation evidence is comparable with the main
WTMC-oriented held-out evaluation.

Usage:
    python -m tls_dataset.ml.ablation \
        --config configs/ml_workflow_v2.yaml \
        --output artifacts/ablation/latest
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

from tls_dataset.ml.workflow import (
    WorkflowConfig,
    load_workflow_config,
    save_json,
    select_feature_columns,
)

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

# Feature groups keyed by group name → list of column substrings that match
FEATURE_GROUPS: dict[str, list[str]] = {
    "timing_iat": [
        "piat_ms",
    ],
    "packet_size": [
        "_min_ps", "_mean_ps", "_stddev_ps", "_max_ps",
    ],
    "volume": [
        "bidirectional_packets", "bidirectional_bytes",
        "src2dst_packets", "src2dst_bytes",
        "dst2src_packets", "dst2src_bytes",
        "bidirectional_duration_ms", "src2dst_duration_ms", "dst2src_duration_ms",
    ],
    "tcp_flags": [
        "_syn_packets", "_ack_packets", "_psh_packets",
        "_rst_packets", "_fin_packets",
    ],
    "application_dpi": [
        "application_is_guessed", "application_confidence",
    ],
    "port_protocol": [
        "src_port", "dst_port", "protocol",
    ],
}


def _matches_group(col: str, patterns: list[str]) -> bool:
    return any(p in col for p in patterns)


def _group_columns(feature_cols: list[str], group_patterns: list[str]) -> list[str]:
    return [c for c in feature_cols if _matches_group(c, group_patterns)]


def _build_ablation_estimators(config: WorkflowConfig) -> list[tuple[str, Any]]:
    params = config.model_params
    estimators: list[tuple[str, Any]] = [
        (
            "random_forest",
            RandomForestClassifier(**params.get("random_forest", {
                "n_estimators": 300,
                "random_state": config.random_state,
                "n_jobs": -1,
                "class_weight": "balanced_subsample",
            })),
        ),
    ]
    if HAS_XGBOOST:
        estimators.append(
            (
                "xgboost",
                XGBClassifier(**params.get("xgboost", {
                    "n_estimators": 300,
                    "learning_rate": 0.05,
                    "max_depth": 6,
                    "random_state": config.random_state,
                    "n_jobs": -1,
                    "eval_metric": "logloss",
                    "verbosity": 0,
                })),
            )
        )
    return estimators


def _drop_unusable_training_columns(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    constant_columns = [
        column for column in X_train.columns if X_train[column].nunique(dropna=False) <= 1
    ]
    all_missing_columns = [column for column in X_train.columns if X_train[column].isna().all()]
    dropped = sorted(set(constant_columns + all_missing_columns))
    if not dropped:
        return X_train, X_test, []
    return X_train.drop(columns=dropped), X_test.drop(columns=dropped), dropped


def _binary_metrics(y_true: pd.Series, probabilities: np.ndarray) -> dict[str, float | int]:
    predictions = (probabilities >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    specificity = float(tn / (tn + fp)) if (tn + fp) else 0.0
    metrics: dict[str, float | int] = {
        "accuracy": float(accuracy_score(y_true, predictions)),
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "specificity": specificity,
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }
    if y_true.nunique() == 2:
        metrics["roc_auc"] = float(roc_auc_score(y_true, probabilities))
        metrics["average_precision"] = float(average_precision_score(y_true, probabilities))
    else:
        metrics["roc_auc"] = float("nan")
        metrics["average_precision"] = float("nan")
    return metrics


def _fit_predict_metrics(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    *,
    config: WorkflowConfig,
) -> dict[str, dict[str, float | int]]:
    results: dict[str, dict[str, float | int]] = {}
    for model_name, estimator in _build_ablation_estimators(config):
        pipe = Pipeline([("imputer", SimpleImputer(strategy="median")), ("model", estimator)])
        pipe.fit(X_train, y_train)
        probabilities = pipe.predict_proba(X_test)[:, config.positive_label]
        results[model_name] = _binary_metrics(y_test, probabilities)
    return results


def run_ablation(
    *,
    config_path: str | Path,
    output_dir: str | Path,
) -> None:
    output_path = Path(output_dir).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    config = load_workflow_config(config_path)
    df_full = pd.read_csv(config.dataset_csv, low_memory=False)

    if config.test_capture_ids and "capture_id" not in df_full.columns:
        raise RuntimeError("Ablation config defines test_capture_ids but dataset has no capture_id column")

    if config.test_capture_ids and "capture_id" in df_full.columns:
        test_mask = df_full["capture_id"].isin(config.test_capture_ids)
        if not test_mask.any():
            raise RuntimeError(f"test_capture_ids {config.test_capture_ids!r} matched no rows")
        df_train = df_full[~test_mask].reset_index(drop=True)
        df_test = df_full[test_mask].reset_index(drop=True)
        split_mode = "capture_holdout"
        held_out = df_test.groupby("capture_id").size().to_dict()
        print(f"Ablation: held-out captures {held_out}")
    else:
        raise RuntimeError(
            "Ablation requires capture holdout for publication-grade evidence. "
            "Set test_capture_ids in the workflow config."
        )

    feature_cols, _ = select_feature_columns(
        df_full,
        target_column=config.target_column,
        extra_excluded_columns=config.extra_excluded_columns,
    )

    X_train_all = df_train[feature_cols].copy()
    X_test_all = df_test[feature_cols].copy()
    bool_cols = [c for c in X_train_all.columns if pd.api.types.is_bool_dtype(X_train_all[c])]
    if bool_cols:
        X_train_all[bool_cols] = X_train_all[bool_cols].astype(int)
        X_test_all[bool_cols] = X_test_all[bool_cols].astype(int)
    X_train_all, X_test_all, dropped_training_columns = _drop_unusable_training_columns(
        X_train_all,
        X_test_all,
    )
    feature_cols = list(X_train_all.columns)
    y_train = df_train[config.target_column].astype(int)
    y_test = df_test[config.target_column].astype(int)

    print(f"Dataset: {len(df_full)} rows")
    print(f"Train/test: {len(df_train)} / {len(df_test)} rows ({split_mode})")
    print(f"Features: {len(feature_cols)} training features ({len(dropped_training_columns)} dropped)")
    print()

    # Baseline — all features
    print("Running BASELINE (all features)...")
    baseline = _fit_predict_metrics(
        X_train_all,
        y_train,
        X_test_all,
        y_test,
        config=config,
    )
    print(f"  baseline: {baseline}")

    rows: list[dict[str, Any]] = []

    # Add baseline row
    for model_name, metrics in baseline.items():
        rows.append({
            "group_removed": "none (baseline)",
            "features_removed": 0,
            "features_remaining": len(feature_cols),
            "model": model_name,
            **metrics,
            "f1_delta": 0.0,
            "roc_auc_delta": 0.0,
        })

    # Ablation — remove each group in turn
    for group_name, patterns in FEATURE_GROUPS.items():
        cols_to_remove = _group_columns(feature_cols, patterns)
        if not cols_to_remove:
            print(f"  Skipping group '{group_name}' — no matching columns in feature set")
            continue

        X_train_ablated = X_train_all.drop(columns=cols_to_remove, errors="ignore")
        X_test_ablated = X_test_all.drop(columns=cols_to_remove, errors="ignore")
        n_remaining = len(X_train_ablated.columns)
        print(f"Running ablation: remove '{group_name}' ({len(cols_to_remove)} features, {n_remaining} remaining)...")

        ablated_metrics = _fit_predict_metrics(
            X_train_ablated,
            y_train,
            X_test_ablated,
            y_test,
            config=config,
        )
        print(f"  ablated: {ablated_metrics}")

        for model_name, metrics in ablated_metrics.items():
            base = baseline.get(model_name, {"f1": 0.0, "roc_auc": 0.0})
            rows.append({
                "group_removed": group_name,
                "features_removed": len(cols_to_remove),
                "features_remaining": n_remaining,
                "model": model_name,
                **metrics,
                "f1_delta": metrics["f1"] - base["f1"],
                "roc_auc_delta": metrics["roc_auc"] - base["roc_auc"],
            })

    frame = pd.DataFrame(rows)
    frame.to_csv(output_path / "ablation_results.csv", index=False)
    summary = {
        "config_path": str(Path(config_path).expanduser().resolve()),
        "dataset_csv": str(Path(config.dataset_csv).expanduser().resolve()),
        "output_dir": str(output_path),
        "split_mode": split_mode,
        "test_capture_ids": list(config.test_capture_ids),
        "train_rows": int(len(df_train)),
        "test_rows": int(len(df_test)),
        "candidate_numeric_columns": int(len(feature_cols) + len(dropped_training_columns)),
        "training_feature_columns": feature_cols,
        "dropped_training_columns": dropped_training_columns,
        "feature_groups": FEATURE_GROUPS,
        "ablation_rows": rows,
    }
    save_json(summary, output_path / "ablation_summary.json")

    # Print LaTeX table snippet
    print("\n=== LaTeX table (copy into paper) ===")
    print(r"\begin{table}[t]")
    print(r"\centering")
    print(r"\caption{Feature Ablation Study (held-out capture F1 / ROC-AUC, RF column)}")
    print(r"\label{tab:ablation}")
    print(r"\begin{tabular}{lcccc}")
    print(r"\hline")
    print(r"Group Removed & Features & RF F1 & RF AUC & $\Delta$F1 \\")
    print(r"\hline")
    rf_rows = frame[frame["model"] == "random_forest"]
    for _, row in rf_rows.iterrows():
        delta_str = f"{row['f1_delta']:+.3f}"
        print(f"{row['group_removed']} & {row['features_removed']} & "
              f"{row['f1']:.3f} & {row['roc_auc']:.3f} & {delta_str} \\\\")
    print(r"\hline")
    print(r"\end{tabular}")
    print(r"\end{table}")
    print()
    print(f"Full results saved to: {output_path}/ablation_results.csv")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Feature ablation study for EncFlow artifacts")
    parser.add_argument("--config", required=True, help="ML workflow YAML config")
    parser.add_argument("--output", default="artifacts/ablation/latest", help="Output directory")
    args = parser.parse_args(argv)
    run_ablation(config_path=args.config, output_dir=args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
