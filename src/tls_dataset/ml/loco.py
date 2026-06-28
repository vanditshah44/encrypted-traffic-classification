"""Leave-one-capture-out evaluation for EncFlow models."""

from __future__ import annotations

import argparse
from itertools import product
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
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
from sklearn.naive_bayes import GaussianNB
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


def capture_label_summary(
    df: pd.DataFrame,
    *,
    capture_column: str = "capture_id",
    label_column: str = "label",
    target_column: str = "label_id",
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for capture_id, subset in df.groupby(capture_column, dropna=False):
        label_counts = subset[label_column].value_counts(dropna=False).to_dict()
        target_counts = subset[target_column].value_counts(dropna=False).to_dict()
        dominant_label = subset[label_column].mode(dropna=False)
        rows.append(
            {
                "capture_id": str(capture_id),
                "rows": int(len(subset)),
                "label": str(dominant_label.iloc[0]) if not dominant_label.empty else "unknown",
                "label_counts": {str(key): int(value) for key, value in label_counts.items()},
                "target_counts": {str(key): int(value) for key, value in target_counts.items()},
                "unique_labels": int(subset[target_column].nunique(dropna=True)),
            }
        )
    return pd.DataFrame(rows).sort_values(["label", "rows", "capture_id"], ascending=[True, False, True])


def split_loco_capture(
    df: pd.DataFrame,
    *,
    test_capture_ids: tuple[str, ...],
    capture_column: str = "capture_id",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if capture_column not in df.columns:
        raise RuntimeError(f"Dataset has no {capture_column!r} column")
    test_mask = df[capture_column].astype(str).isin(test_capture_ids)
    if not test_mask.any():
        raise RuntimeError(f"test_capture_ids {test_capture_ids!r} matched no rows")
    train = df[~test_mask].reset_index(drop=True)
    test = df[test_mask].reset_index(drop=True)
    if train.empty:
        raise RuntimeError("LOCO split produced an empty training set")
    return train, test


def prepare_loco_features(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    *,
    config: WorkflowConfig,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, list[str], list[str]]:
    feature_columns, _ = select_feature_columns(
        pd.concat([train_df, test_df], ignore_index=True, sort=False),
        target_column=config.target_column,
        extra_excluded_columns=config.extra_excluded_columns,
    )
    X_train = train_df[feature_columns].copy()
    X_test = test_df[feature_columns].copy()
    bool_columns = [column for column in X_train.columns if pd.api.types.is_bool_dtype(X_train[column])]
    if bool_columns:
        X_train[bool_columns] = X_train[bool_columns].astype(int)
        X_test[bool_columns] = X_test[bool_columns].astype(int)

    constant_columns = [
        column for column in X_train.columns if X_train[column].nunique(dropna=False) <= 1
    ]
    all_missing_columns = [column for column in X_train.columns if X_train[column].isna().all()]
    dropped_columns = sorted(set(constant_columns + all_missing_columns))
    if dropped_columns:
        X_train = X_train.drop(columns=dropped_columns)
        X_test = X_test.drop(columns=dropped_columns)

    y_train = train_df[config.target_column].astype(int)
    y_test = test_df[config.target_column].astype(int)
    return X_train, X_test, y_train, y_test, list(X_train.columns), dropped_columns


def build_loco_model_specs(
    config: WorkflowConfig,
    *,
    model_names: tuple[str, ...] = (),
) -> list[tuple[str, Any]]:
    params = config.model_params
    requested = {name.strip() for name in model_names if name.strip()}
    specs: list[tuple[str, Any]] = [
        ("gaussian_nb", GaussianNB(**params.get("gaussian_nb", {}))),
        ("random_forest", RandomForestClassifier(**params.get("random_forest", {}))),
        ("gradient_boosting", GradientBoostingClassifier(**params.get("gradient_boosting", {}))),
    ]
    if config.include_xgboost and HAS_XGBOOST:
        specs.append(("xgboost", XGBClassifier(**params.get("xgboost", {}))))
    if requested:
        specs = [(name, estimator) for name, estimator in specs if name in requested]
        missing = requested - {name for name, _ in specs}
        if missing:
            raise RuntimeError(f"Requested LOCO model(s) are unavailable: {sorted(missing)}")
    return specs


def binary_or_one_class_metrics(
    y_true: pd.Series,
    probabilities: np.ndarray,
    *,
    threshold: float = 0.5,
) -> dict[str, float | int | str | None]:
    predictions = (probabilities >= threshold).astype(int)
    labels_present = sorted(int(value) for value in y_true.dropna().unique())
    positive_rows = int((y_true == 1).sum())
    negative_rows = int((y_true == 0).sum())
    predicted_positive = int(predictions.sum())
    predicted_negative = int(len(predictions) - predicted_positive)

    payload: dict[str, float | int | str | None] = {
        "threshold": float(threshold),
        "test_positive_rows": positive_rows,
        "test_negative_rows": negative_rows,
        "predicted_positive": predicted_positive,
        "predicted_negative": predicted_negative,
        "mean_probability": float(np.mean(probabilities)) if len(probabilities) else None,
        "median_probability": float(np.median(probabilities)) if len(probabilities) else None,
        "labels_present": ",".join(str(value) for value in labels_present),
    }

    if len(labels_present) == 2:
        tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
        payload.update(
            {
                "metric_mode": "binary",
                "accuracy": float(accuracy_score(y_true, predictions)),
                "precision": float(precision_score(y_true, predictions, zero_division=0)),
                "recall": float(recall_score(y_true, predictions, zero_division=0)),
                "specificity": float(tn / (tn + fp)) if (tn + fp) else 0.0,
                "f1": float(f1_score(y_true, predictions, zero_division=0)),
                "roc_auc": float(roc_auc_score(y_true, probabilities)),
                "average_precision": float(average_precision_score(y_true, probabilities)),
                "tp": int(tp),
                "fp": int(fp),
                "tn": int(tn),
                "fn": int(fn),
                "positive_detection_rate": float(tp / (tp + fn)) if (tp + fn) else None,
                "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else None,
            }
        )
        return payload

    if labels_present == [1]:
        detected = predicted_positive
        missed = predicted_negative
        payload.update(
            {
                "metric_mode": "malicious_only",
                "accuracy": float(detected / len(predictions)) if len(predictions) else 0.0,
                "precision": None,
                "recall": float(detected / len(predictions)) if len(predictions) else 0.0,
                "specificity": None,
                "f1": None,
                "roc_auc": None,
                "average_precision": None,
                "tp": detected,
                "fp": 0,
                "tn": 0,
                "fn": missed,
                "positive_detection_rate": float(detected / len(predictions)) if len(predictions) else 0.0,
                "false_positive_rate": None,
            }
        )
        return payload

    if labels_present == [0]:
        false_positives = predicted_positive
        true_negatives = predicted_negative
        payload.update(
            {
                "metric_mode": "benign_only",
                "accuracy": float(true_negatives / len(predictions)) if len(predictions) else 0.0,
                "precision": None,
                "recall": None,
                "specificity": float(true_negatives / len(predictions)) if len(predictions) else 0.0,
                "f1": None,
                "roc_auc": None,
                "average_precision": None,
                "tp": 0,
                "fp": false_positives,
                "tn": true_negatives,
                "fn": 0,
                "positive_detection_rate": None,
                "false_positive_rate": float(false_positives / len(predictions)) if len(predictions) else 0.0,
            }
        )
        return payload

    raise RuntimeError(f"Unsupported label set for LOCO metrics: {labels_present}")


def run_loco_split(
    *,
    df: pd.DataFrame,
    config: WorkflowConfig,
    test_capture_ids: tuple[str, ...],
    split_name: str,
    split_kind: str,
    model_names: tuple[str, ...] = (),
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    train_df, test_df = split_loco_capture(df, test_capture_ids=test_capture_ids)
    X_train, X_test, y_train, y_test, feature_columns, dropped_columns = prepare_loco_features(
        train_df,
        test_df,
        config=config,
    )
    rows: list[dict[str, Any]] = []
    for model_name, estimator in build_loco_model_specs(config, model_names=model_names):
        pipeline = Pipeline([("imputer", SimpleImputer(strategy="median")), ("model", estimator)])
        pipeline.fit(X_train, y_train)
        probabilities = pipeline.predict_proba(X_test)[:, config.positive_label]
        metrics = binary_or_one_class_metrics(y_test, probabilities)
        rows.append(
            {
                "split_name": split_name,
                "split_kind": split_kind,
                "test_capture_ids": ",".join(test_capture_ids),
                "test_rows": int(len(test_df)),
                "train_rows": int(len(train_df)),
                "feature_count": int(len(feature_columns)),
                "model": model_name,
                **metrics,
            }
        )
    split_summary = {
        "split_name": split_name,
        "split_kind": split_kind,
        "test_capture_ids": list(test_capture_ids),
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "feature_count": int(len(feature_columns)),
        "dropped_training_columns": dropped_columns,
    }
    return rows, split_summary


def paired_capture_splits(summary_frame: pd.DataFrame) -> list[tuple[str, str]]:
    benign = summary_frame[summary_frame["label"] == "benign"]["capture_id"].astype(str).tolist()
    malicious = summary_frame[summary_frame["label"] == "malicious"]["capture_id"].astype(str).tolist()
    return [(mal, ben) for mal, ben in product(malicious, benign)]


def _weighted_mean(frame: pd.DataFrame, value_column: str, weight_column: str) -> float | None:
    values = pd.to_numeric(frame[value_column], errors="coerce")
    weights = pd.to_numeric(frame[weight_column], errors="coerce")
    mask = values.notna() & weights.notna() & (weights > 0)
    if not mask.any():
        return None
    return float((values[mask] * weights[mask]).sum() / weights[mask].sum())


def build_pairwise_model_summary(results: pd.DataFrame) -> pd.DataFrame:
    if results.empty:
        return pd.DataFrame()
    pairwise = results[
        (results["split_kind"] == "malicious_benign_pair")
        & (results["metric_mode"] == "binary")
    ].copy()
    if pairwise.empty:
        return pd.DataFrame()

    rows: list[dict[str, Any]] = []
    metric_columns = ("f1", "roc_auc", "precision", "recall", "specificity")
    for model_name, subset in pairwise.groupby("model", sort=True):
        row: dict[str, Any] = {
            "model": str(model_name),
            "pair_count": int(len(subset)),
            "total_test_rows": int(pd.to_numeric(subset["test_rows"], errors="coerce").sum()),
        }
        for metric in metric_columns:
            values = pd.to_numeric(subset[metric], errors="coerce")
            row[f"{metric}_mean"] = float(values.mean())
            row[f"{metric}_std"] = float(values.std(ddof=0))
            row[f"{metric}_weighted_by_rows"] = _weighted_mean(subset, metric, "test_rows")
        best = subset.loc[pd.to_numeric(subset["f1"], errors="coerce").idxmax()]
        worst = subset.loc[pd.to_numeric(subset["f1"], errors="coerce").idxmin()]
        row.update(
            {
                "best_f1_split": str(best["split_name"]),
                "best_f1": float(best["f1"]),
                "worst_f1_split": str(worst["split_name"]),
                "worst_f1": float(worst["f1"]),
            }
        )
        rows.append(row)
    return pd.DataFrame(rows)


def summarize_loco_outputs(
    *,
    output_dir: str | Path,
    config_path: str | Path | None = None,
    dataset_csv: str | Path | None = None,
    split_summaries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    output_path = Path(output_dir).expanduser().resolve()
    results_path = output_path / "loco_results.csv"
    capture_path = output_path / "capture_summary.csv"
    if not results_path.exists():
        raise FileNotFoundError(f"Missing LOCO results: {results_path}")
    if not capture_path.exists():
        raise FileNotFoundError(f"Missing LOCO capture summary: {capture_path}")

    results = pd.read_csv(results_path, low_memory=False)
    capture_summary = pd.read_csv(capture_path, low_memory=False)
    pairwise_summary = build_pairwise_model_summary(results)
    pairwise_summary.to_csv(output_path / "paired_model_summary.csv", index=False)

    model_names = summary_model_names(results)
    single_rows = results[results["split_kind"] == "single_capture"]
    pairwise_rows = results[results["split_kind"] == "malicious_benign_pair"]
    model_count = max(len(model_names), 1)

    summary: dict[str, Any] = {
        "config_path": str(Path(config_path).expanduser().resolve()) if config_path else "",
        "dataset_csv": str(Path(dataset_csv).expanduser().resolve()) if dataset_csv else "",
        "output_dir": str(output_path),
        "rows": int(capture_summary["rows"].sum()) if "rows" in capture_summary.columns else None,
        "capture_count": int(capture_summary["capture_id"].nunique()),
        "include_pairwise": bool(not pairwise_rows.empty),
        "model_names": model_names,
        "single_capture_splits": int(len(single_rows) / model_count),
        "pairwise_splits": int(len(pairwise_rows) / model_count),
        "capture_summary_csv": str(capture_path.resolve()),
        "per_capture_metrics_csv": str((output_path / "per_capture_metrics.csv").resolve()),
        "paired_capture_metrics_csv": str((output_path / "paired_capture_metrics.csv").resolve()),
        "paired_model_summary_csv": str((output_path / "paired_model_summary.csv").resolve()),
        "split_summaries": split_summaries or [],
    }

    if not pairwise_summary.empty:
        summary["paired_binary_aggregate"] = {
            str(row["model"]): {
                key: row[key]
                for key in pairwise_summary.columns
                if key != "model" and pd.notna(row[key])
            }
            for _, row in pairwise_summary.iterrows()
        }

    save_json(summary, output_path / "loco_summary.json")
    return summary


def run_loco_evaluation(
    *,
    config_path: str | Path,
    output_dir: str | Path,
    include_pairwise: bool = True,
    model_names: tuple[str, ...] = (),
) -> dict[str, Any]:
    output_path = Path(output_dir).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    config = load_workflow_config(config_path)
    df = pd.read_csv(config.dataset_csv, low_memory=False)
    capture_summary = capture_label_summary(
        df,
        label_column=config.label_column,
        target_column=config.target_column,
    )
    capture_summary.to_csv(output_path / "capture_summary.csv", index=False)

    all_rows: list[dict[str, Any]] = []
    split_summaries: list[dict[str, Any]] = []

    for capture_id in capture_summary["capture_id"].astype(str).tolist():
        rows, split_summary = run_loco_split(
            df=df,
            config=config,
            test_capture_ids=(capture_id,),
            split_name=f"holdout_{capture_id}",
            split_kind="single_capture",
            model_names=model_names,
        )
        all_rows.extend(rows)
        split_summaries.append(split_summary)

    if include_pairwise:
        for malicious_capture, benign_capture in paired_capture_splits(capture_summary):
            rows, split_summary = run_loco_split(
                df=df,
                config=config,
                test_capture_ids=(malicious_capture, benign_capture),
                split_name=f"pair_{malicious_capture}__{benign_capture}",
                split_kind="malicious_benign_pair",
                model_names=model_names,
            )
            all_rows.extend(rows)
            split_summaries.append(split_summary)

    results = pd.DataFrame(all_rows)
    results.to_csv(output_path / "loco_results.csv", index=False)
    single_capture = results[results["split_kind"] == "single_capture"].copy()
    pairwise = results[results["split_kind"] == "malicious_benign_pair"].copy()
    single_capture.to_csv(output_path / "per_capture_metrics.csv", index=False)
    pairwise.to_csv(output_path / "paired_capture_metrics.csv", index=False)

    return summarize_loco_outputs(
        output_dir=output_path,
        config_path=config_path,
        dataset_csv=config.dataset_csv,
        split_summaries=split_summaries,
    )


def summary_model_names(results: pd.DataFrame) -> list[str]:
    return sorted(results["model"].unique().tolist()) if "model" in results.columns else []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run leave-one-capture-out EncFlow evaluation")
    parser.add_argument("--config", required=True, help="ML workflow YAML config")
    parser.add_argument("--output", default="artifacts/ml_workflow/loco", help="Output directory")
    parser.add_argument("--no-pairwise", action="store_true", help="Skip malicious+benign paired holdouts")
    parser.add_argument(
        "--models",
        default="",
        help="Optional comma-separated model subset, e.g. random_forest,xgboost",
    )
    parser.add_argument(
        "--summarize-only",
        action="store_true",
        help="Only rebuild LOCO summary files from existing CSV outputs; does not retrain models.",
    )
    args = parser.parse_args(argv)

    config = load_workflow_config(args.config)
    if args.summarize_only:
        summary = summarize_loco_outputs(
            output_dir=args.output,
            config_path=args.config,
            dataset_csv=config.dataset_csv,
        )
    else:
        models = tuple(value.strip() for value in args.models.split(",") if value.strip())
        summary = run_loco_evaluation(
            config_path=args.config,
            output_dir=args.output,
            include_pairwise=not args.no_pairwise,
            model_names=models,
        )
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
