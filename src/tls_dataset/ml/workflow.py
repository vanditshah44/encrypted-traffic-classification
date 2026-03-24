"""Full supervised ML workflow for the thesis models."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "tls_dataset_mplconfig"))
import matplotlib
matplotlib.use("Agg")
import numpy as np
import pandas as pd
import yaml
from matplotlib import pyplot as plt
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    make_scorer,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import (
    StratifiedKFold,
    StratifiedShuffleSplit,
    cross_val_predict,
    cross_validate,
    train_test_split,
)
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import Pipeline

from tls_dataset.pipeline.canonical import BASE_METADATA_COLUMNS

DEFAULT_EXCLUDED_FEATURE_COLUMNS = (
    "id",
    "expiration_id",
)
ABSOLUTE_TIME_COLUMNS = (
    "ts",
    "flow_start_ms",
    "flow_end_ms",
    "window_start_ms",
    "window_end_ms",
)
ABSOLUTE_TIME_SUFFIXES = (
    "_first_seen_ms",
    "_last_seen_ms",
)
COMPARISON_METRIC_COLUMNS = (
    "accuracy",
    "precision",
    "recall",
    "f1",
    "specificity",
    "balanced_accuracy",
    "roc_auc",
    "average_precision",
)


@dataclass(frozen=True)
class WorkflowConfig:
    dataset_csv: str
    output_dir: str
    target_column: str
    label_column: str
    record_id_column: str
    positive_label: int
    test_size: float
    random_state: int
    cv_folds: int
    threshold_metric: str
    top_k_feature_importance: int
    extra_excluded_columns: tuple[str, ...]
    permutation_n_repeats: int
    permutation_scoring: str
    permutation_max_samples: int
    model_params: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class ModelSpec:
    name: str
    estimator: Any


def _load_yaml(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).expanduser().resolve()
    with config_path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected mapping config at {config_path}")
    return payload


def load_workflow_config(config_path: str | Path) -> WorkflowConfig:
    payload = _load_yaml(config_path)
    permutation = payload.get("permutation_importance", {}) or {}
    models = payload.get("models", {}) or {}
    return WorkflowConfig(
        dataset_csv=str(payload["dataset_csv"]),
        output_dir=str(payload["output_dir"]),
        target_column=str(payload.get("target_column", "label_id")),
        label_column=str(payload.get("label_column", "label")),
        record_id_column=str(payload.get("record_id_column", "record_id")),
        positive_label=int(payload.get("positive_label", 1)),
        test_size=float(payload.get("test_size", 0.2)),
        random_state=int(payload.get("random_state", 42)),
        cv_folds=int(payload.get("cv_folds", 5)),
        threshold_metric=str(payload.get("threshold_metric", "f1")),
        top_k_feature_importance=int(payload.get("top_k_feature_importance", 20)),
        extra_excluded_columns=tuple(str(value) for value in payload.get("extra_excluded_columns", [])),
        permutation_n_repeats=int(permutation.get("n_repeats", 5)),
        permutation_scoring=str(permutation.get("scoring", "roc_auc")),
        permutation_max_samples=int(permutation.get("max_samples", 4000)),
        model_params={str(key): dict(value or {}) for key, value in models.items()},
    )


def build_model_specs(config: WorkflowConfig) -> list[ModelSpec]:
    params = config.model_params
    return [
        ModelSpec(
            name="gaussian_nb",
            estimator=GaussianNB(**params.get("gaussian_nb", {})),
        ),
        ModelSpec(
            name="random_forest",
            estimator=RandomForestClassifier(**params.get("random_forest", {})),
        ),
        ModelSpec(
            name="gradient_boosting",
            estimator=GradientBoostingClassifier(**params.get("gradient_boosting", {})),
        ),
    ]


def build_label_lookup(df: pd.DataFrame, *, target_column: str, label_column: str) -> dict[int, str]:
    subset = df[[target_column, label_column]].drop_duplicates().sort_values(target_column)
    return {int(row[target_column]): str(row[label_column]) for _, row in subset.iterrows()}


def is_excluded_feature_column(
    column: str,
    *,
    target_column: str,
    extra_excluded_columns: tuple[str, ...],
) -> str | None:
    metadata_columns = set(BASE_METADATA_COLUMNS).union(extra_excluded_columns)
    if column == target_column:
        return "target_column"
    if column in metadata_columns:
        return "metadata"
    if column in DEFAULT_EXCLUDED_FEATURE_COLUMNS:
        return "identifier"
    if column in ABSOLUTE_TIME_COLUMNS:
        return "absolute_time"
    if any(column.endswith(suffix) for suffix in ABSOLUTE_TIME_SUFFIXES):
        return "absolute_time"
    return None


def select_feature_columns(
    df: pd.DataFrame,
    *,
    target_column: str,
    extra_excluded_columns: tuple[str, ...] = (),
) -> tuple[list[str], dict[str, str]]:
    feature_columns: list[str] = []
    excluded: dict[str, str] = {}

    for column in df.columns:
        exclusion_reason = is_excluded_feature_column(
            column,
            target_column=target_column,
            extra_excluded_columns=extra_excluded_columns,
        )
        if exclusion_reason is not None:
            excluded[column] = exclusion_reason
            continue

        if not (
            pd.api.types.is_numeric_dtype(df[column]) or pd.api.types.is_bool_dtype(df[column])
        ):
            excluded[column] = "non_numeric"
            continue

        feature_columns.append(column)

    return feature_columns, excluded


def build_model_pipeline(estimator: Any) -> Pipeline:
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("model", estimator),
        ]
    )


def save_json(payload: dict[str, Any], output_path: str | Path) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def compute_binary_metrics(
    y_true: pd.Series,
    y_pred: np.ndarray,
    y_score: np.ndarray,
    *,
    threshold: float,
) -> dict[str, float]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    specificity = float(tn / (tn + fp)) if (tn + fp) else 0.0
    return {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "specificity": specificity,
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "roc_auc": float(roc_auc_score(y_true, y_score)),
        "average_precision": float(average_precision_score(y_true, y_score)),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }


def evaluate_thresholds(
    y_true: pd.Series,
    y_score: np.ndarray,
    *,
    thresholds: np.ndarray | None = None,
) -> pd.DataFrame:
    threshold_values = thresholds if thresholds is not None else np.linspace(0.0, 1.0, 201)
    rows: list[dict[str, float | int]] = []
    for threshold in threshold_values:
        y_pred = (y_score >= threshold).astype(int)
        metrics = compute_binary_metrics(y_true, y_pred, y_score, threshold=float(threshold))
        rows.append(metrics)
    return pd.DataFrame(rows)


def select_best_threshold(threshold_frame: pd.DataFrame, metric: str) -> dict[str, float]:
    sort_columns = [metric, "precision", "balanced_accuracy", "recall"]
    ranked = threshold_frame.sort_values(sort_columns, ascending=[False, False, False, False], kind="stable")
    best_row = ranked.iloc[0]
    return {
        "threshold": float(best_row["threshold"]),
        "metric": metric,
        "metric_value": float(best_row[metric]),
        "precision": float(best_row["precision"]),
        "recall": float(best_row["recall"]),
        "f1": float(best_row["f1"]),
        "balanced_accuracy": float(best_row["balanced_accuracy"]),
    }


def plot_curve(
    frame: pd.DataFrame,
    *,
    x_col: str,
    y_col: str,
    title: str,
    x_label: str,
    y_label: str,
    output_path: str | Path,
    baseline: tuple[np.ndarray, np.ndarray] | None = None,
) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(8, 6))
    plt.plot(frame[x_col], frame[y_col], linewidth=2)
    if baseline is not None:
        plt.plot(baseline[0], baseline[1], linestyle="--", linewidth=1, color="#888888")
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(target, dpi=180)
    plt.close()


def plot_confusion_matrix(
    matrix: np.ndarray,
    *,
    labels: list[str],
    title: str,
    output_path: str | Path,
) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(6, 5))
    plt.imshow(matrix, cmap="Blues")
    plt.title(title)
    plt.colorbar()
    positions = np.arange(len(labels))
    plt.xticks(positions, labels, rotation=15)
    plt.yticks(positions, labels)
    plt.xlabel("Predicted label")
    plt.ylabel("True label")
    for row_idx in range(matrix.shape[0]):
        for col_idx in range(matrix.shape[1]):
            plt.text(col_idx, row_idx, str(matrix[row_idx, col_idx]), ha="center", va="center", color="black")
    plt.tight_layout()
    plt.savefig(target, dpi=180)
    plt.close()


def plot_threshold_metrics(frame: pd.DataFrame, *, metric: str, output_path: str | Path) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(8, 6))
    for column in ("precision", "recall", "f1", "balanced_accuracy"):
        plt.plot(frame["threshold"], frame[column], linewidth=2, label=column)
    plt.axvline(
        frame.sort_values([metric, "precision", "balanced_accuracy"], ascending=[False, False, False]).iloc[0]["threshold"],
        linestyle="--",
        linewidth=1.5,
        color="#aa3333",
        label=f"best_{metric}",
    )
    plt.title("Threshold Sweep")
    plt.xlabel("Threshold")
    plt.ylabel("Score")
    plt.ylim(0.0, 1.05)
    plt.grid(alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(target, dpi=180)
    plt.close()


def build_native_feature_importance(model: Any, feature_names: list[str]) -> tuple[str, pd.DataFrame] | None:
    if hasattr(model, "feature_importances_"):
        importance = np.asarray(model.feature_importances_, dtype=float)
        frame = pd.DataFrame(
            {
                "feature": feature_names,
                "importance": importance,
            }
        ).sort_values("importance", ascending=False, kind="stable")
        return "native", frame

    if hasattr(model, "theta_") and hasattr(model, "var_"):
        theta = np.asarray(model.theta_, dtype=float)
        var = np.asarray(model.var_, dtype=float)
        if theta.shape[0] == 2:
            importance = np.abs(theta[1] - theta[0]) / np.sqrt(var.mean(axis=0) + 1e-9)
            frame = pd.DataFrame(
                {
                    "feature": feature_names,
                    "importance": importance,
                }
            ).sort_values("importance", ascending=False, kind="stable")
            return "gaussian_mean_gap_over_std", frame

    return None


def stratified_sample(
    X: pd.DataFrame,
    y: pd.Series,
    *,
    max_samples: int,
    random_state: int,
) -> tuple[pd.DataFrame, pd.Series]:
    if len(X) <= max_samples:
        return X, y

    splitter = StratifiedShuffleSplit(n_splits=1, train_size=max_samples, random_state=random_state)
    selected_indices, _ = next(splitter.split(X, y))
    return X.iloc[selected_indices].copy(), y.iloc[selected_indices].copy()


def build_permutation_importance(
    pipeline: Pipeline,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    *,
    scoring: str,
    n_repeats: int,
    max_samples: int,
    random_state: int,
) -> pd.DataFrame:
    sampled_X, sampled_y = stratified_sample(
        X_test,
        y_test,
        max_samples=max_samples,
        random_state=random_state,
    )
    result = permutation_importance(
        pipeline,
        sampled_X,
        sampled_y,
        scoring=scoring,
        n_repeats=n_repeats,
        random_state=random_state,
        n_jobs=1,
    )
    return pd.DataFrame(
        {
            "feature": sampled_X.columns,
            "importance_mean": result.importances_mean,
            "importance_std": result.importances_std,
        }
    ).sort_values("importance_mean", ascending=False, kind="stable")


def plot_feature_importance(
    frame: pd.DataFrame,
    *,
    title: str,
    output_path: str | Path,
    top_k: int,
    value_column: str,
) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    display_frame = frame.head(top_k).iloc[::-1]
    plt.figure(figsize=(10, max(4, 0.35 * len(display_frame))))
    plt.barh(display_frame["feature"], display_frame[value_column], color="#2f6fab")
    plt.title(title)
    plt.xlabel(value_column)
    plt.ylabel("Feature")
    plt.tight_layout()
    plt.savefig(target, dpi=180)
    plt.close()


def analyze_dataset_risks(df: pd.DataFrame, *, label_column: str) -> list[str]:
    warnings: list[str] = []
    if "quality_status" in df.columns:
        quality_counts = df["quality_status"].fillna("unknown").astype(str).value_counts().to_dict()
        if quality_counts.get("fail", 0) > 0:
            warnings.append(
                "The canonical dataset includes rows from at least one quality-failed source. Current training is therefore NFStream-grounded, not fully Zeek-validated."
            )

    if "capture_id" in df.columns:
        capture_counts = df.groupby(label_column)["capture_id"].nunique().to_dict()
        if any(count < 2 for count in capture_counts.values()):
            warnings.append(
                "At least one class is represented by fewer than two distinct captures. Stratified row splits may therefore overestimate generalization."
            )

    label_counts = df[label_column].value_counts()
    if not label_counts.empty and label_counts.max() / max(label_counts.min(), 1) > 1.5:
        warnings.append("The current dataset is class-imbalanced, so threshold optimization and PR metrics matter more than raw accuracy.")

    return warnings


def build_scoring() -> dict[str, Any]:
    return {
        "accuracy": "accuracy",
        "precision": make_scorer(precision_score, zero_division=0),
        "recall": make_scorer(recall_score, zero_division=0),
        "f1": make_scorer(f1_score, zero_division=0),
        "specificity": make_scorer(recall_score, pos_label=0, zero_division=0),
        "balanced_accuracy": "balanced_accuracy",
        "roc_auc": "roc_auc",
        "average_precision": "average_precision",
    }


def save_comparison_plots(
    model_results: dict[str, dict[str, Any]],
    *,
    output_dir: str | Path,
) -> None:
    target_dir = Path(output_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    plt.figure(figsize=(8, 6))
    for model_name, payload in model_results.items():
        roc_frame = payload["roc_curve_frame"]
        plt.plot(roc_frame["fpr"], roc_frame["tpr"], linewidth=2, label=model_name)
    plt.plot([0, 1], [0, 1], linestyle="--", linewidth=1, color="#888888")
    plt.title("ROC Curve Comparison")
    plt.xlabel("False positive rate")
    plt.ylabel("True positive rate")
    plt.legend()
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(target_dir / "roc_curve_comparison.png", dpi=180)
    plt.close()

    plt.figure(figsize=(8, 6))
    for model_name, payload in model_results.items():
        pr_frame = payload["pr_curve_frame"]
        plt.plot(pr_frame["recall"], pr_frame["precision"], linewidth=2, label=model_name)
    plt.title("Precision-Recall Curve Comparison")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.legend()
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(target_dir / "pr_curve_comparison.png", dpi=180)
    plt.close()


def run_ml_workflow(
    *,
    config_path: str | Path,
    dataset_csv_override: str | Path | None = None,
    output_dir_override: str | Path | None = None,
) -> dict[str, Any]:
    config = load_workflow_config(config_path)
    dataset_path = Path(dataset_csv_override or config.dataset_csv).expanduser().resolve()
    output_dir = Path(output_dir_override or config.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(dataset_path, low_memory=False)
    label_lookup = build_label_lookup(df, target_column=config.target_column, label_column=config.label_column)
    feature_columns, excluded_columns = select_feature_columns(
        df,
        target_column=config.target_column,
        extra_excluded_columns=config.extra_excluded_columns,
    )
    X = df[feature_columns].copy()
    bool_columns = [column for column in X.columns if pd.api.types.is_bool_dtype(X[column])]
    if bool_columns:
        X[bool_columns] = X[bool_columns].astype(int)
    y = df[config.target_column].astype(int)
    record_columns = [
        column
        for column in (
            config.record_id_column,
            "sample_id",
            config.label_column,
            "capture_id",
            "source_name",
            "source_dataset",
            "quality_status",
        )
        if column in df.columns
    ]
    record_frame = df[record_columns].copy()

    X_train, X_test, y_train, y_test, records_train, records_test = train_test_split(
        X,
        y,
        record_frame,
        test_size=config.test_size,
        random_state=config.random_state,
        stratify=y,
    )

    constant_columns = [column for column in X_train.columns if X_train[column].nunique(dropna=False) <= 1]
    all_missing_columns = [column for column in X_train.columns if X_train[column].isna().all()]
    dropped_training_columns = sorted(set(constant_columns + all_missing_columns))
    if dropped_training_columns:
        X_train = X_train.drop(columns=dropped_training_columns)
        X_test = X_test.drop(columns=dropped_training_columns)

    feature_manifest = {
        "dataset_csv": str(dataset_path),
        "total_columns": int(len(df.columns)),
        "candidate_numeric_columns": int(len(feature_columns)),
        "training_feature_columns": list(X_train.columns),
        "excluded_columns": excluded_columns,
        "dropped_training_columns": dropped_training_columns,
    }
    save_json(feature_manifest, output_dir / "feature_manifest.json")

    split_frame = pd.concat(
        [
            records_train.assign(split="train", target=y_train.values),
            records_test.assign(split="test", target=y_test.values),
        ],
        ignore_index=True,
    )
    split_frame.to_csv(output_dir / "dataset_split_manifest.csv", index=False)

    cv = StratifiedKFold(n_splits=config.cv_folds, shuffle=True, random_state=config.random_state)
    scoring = build_scoring()
    model_results: dict[str, dict[str, Any]] = {}

    for model_spec in build_model_specs(config):
        model_dir = output_dir / model_spec.name
        model_dir.mkdir(parents=True, exist_ok=True)

        pipeline = build_model_pipeline(model_spec.estimator)
        cv_scores = cross_validate(
            pipeline,
            X_train,
            y_train,
            cv=cv,
            scoring=scoring,
            return_train_score=False,
            n_jobs=1,
        )
        cv_frame = pd.DataFrame(cv_scores)
        cv_frame.rename(columns=lambda name: name.replace("test_", ""), inplace=True)
        cv_frame.to_csv(model_dir / "cv_scores.csv", index=False)

        cv_summary = {
            column: {
                "mean": float(cv_frame[column].mean()),
                "std": float(cv_frame[column].std(ddof=0)),
            }
            for column in cv_frame.columns
            if column != "fit_time" and column != "score_time"
        }
        save_json(cv_summary, model_dir / "cv_summary.json")

        cv_probabilities = cross_val_predict(
            pipeline,
            X_train,
            y_train,
            cv=cv,
            method="predict_proba",
            n_jobs=1,
        )[:, config.positive_label]
        threshold_frame = evaluate_thresholds(y_train, cv_probabilities)
        threshold_frame.to_csv(model_dir / "threshold_sweep.csv", index=False)
        threshold_summary = select_best_threshold(threshold_frame, config.threshold_metric)
        save_json(threshold_summary, model_dir / "threshold_summary.json")
        plot_threshold_metrics(
            threshold_frame,
            metric=config.threshold_metric,
            output_path=model_dir / "threshold_sweep.png",
        )

        pipeline.fit(X_train, y_train)
        joblib.dump(pipeline, model_dir / "model.joblib")

        test_probabilities = pipeline.predict_proba(X_test)[:, config.positive_label]
        default_predictions = (test_probabilities >= 0.5).astype(int)
        optimized_predictions = (test_probabilities >= threshold_summary["threshold"]).astype(int)

        default_metrics = compute_binary_metrics(y_test, default_predictions, test_probabilities, threshold=0.5)
        optimized_metrics = compute_binary_metrics(
            y_test,
            optimized_predictions,
            test_probabilities,
            threshold=float(threshold_summary["threshold"]),
        )
        holdout_metrics = {
            "default_threshold": default_metrics,
            "optimized_threshold": optimized_metrics,
        }
        save_json(holdout_metrics, model_dir / "holdout_metrics.json")

        default_report = classification_report(
            y_test,
            default_predictions,
            output_dict=True,
            zero_division=0,
            target_names=[label_lookup[0], label_lookup[1]],
        )
        optimized_report = classification_report(
            y_test,
            optimized_predictions,
            output_dict=True,
            zero_division=0,
            target_names=[label_lookup[0], label_lookup[1]],
        )
        save_json({"default_threshold": default_report, "optimized_threshold": optimized_report}, model_dir / "classification_report.json")

        prediction_frame = records_test.copy()
        prediction_frame["y_true"] = y_test.values
        prediction_frame["probability_malicious"] = test_probabilities
        prediction_frame["prediction_default"] = default_predictions
        prediction_frame["prediction_optimized"] = optimized_predictions
        prediction_frame.to_csv(model_dir / "test_predictions.csv", index=False)

        default_cm = confusion_matrix(y_test, default_predictions, labels=[0, 1])
        optimized_cm = confusion_matrix(y_test, optimized_predictions, labels=[0, 1])
        pd.DataFrame(default_cm, index=[label_lookup[0], label_lookup[1]], columns=[label_lookup[0], label_lookup[1]]).to_csv(
            model_dir / "confusion_matrix_default.csv"
        )
        pd.DataFrame(optimized_cm, index=[label_lookup[0], label_lookup[1]], columns=[label_lookup[0], label_lookup[1]]).to_csv(
            model_dir / "confusion_matrix_optimized.csv"
        )
        plot_confusion_matrix(
            default_cm,
            labels=[label_lookup[0], label_lookup[1]],
            title=f"{model_spec.name} Confusion Matrix (0.5)",
            output_path=model_dir / "confusion_matrix_default.png",
        )
        plot_confusion_matrix(
            optimized_cm,
            labels=[label_lookup[0], label_lookup[1]],
            title=f"{model_spec.name} Confusion Matrix (optimized)",
            output_path=model_dir / "confusion_matrix_optimized.png",
        )

        roc_fpr, roc_tpr, roc_thresholds = roc_curve(y_test, test_probabilities)
        roc_frame = pd.DataFrame(
            {
                "fpr": roc_fpr,
                "tpr": roc_tpr,
                "threshold": np.append(roc_thresholds[1:], np.nan) if len(roc_thresholds) > 1 else np.full(len(roc_fpr), np.nan),
            }
        )
        roc_frame.to_csv(model_dir / "roc_curve.csv", index=False)
        plot_curve(
            roc_frame,
            x_col="fpr",
            y_col="tpr",
            title=f"{model_spec.name} ROC Curve",
            x_label="False positive rate",
            y_label="True positive rate",
            output_path=model_dir / "roc_curve.png",
            baseline=(np.array([0.0, 1.0]), np.array([0.0, 1.0])),
        )

        pr_precision, pr_recall, pr_thresholds = precision_recall_curve(y_test, test_probabilities)
        pr_frame = pd.DataFrame(
            {
                "precision": pr_precision,
                "recall": pr_recall,
                "threshold": np.append(pr_thresholds, np.nan),
            }
        )
        pr_frame.to_csv(model_dir / "pr_curve.csv", index=False)
        plot_curve(
            pr_frame,
            x_col="recall",
            y_col="precision",
            title=f"{model_spec.name} Precision-Recall Curve",
            x_label="Recall",
            y_label="Precision",
            output_path=model_dir / "pr_curve.png",
        )

        native_importance = build_native_feature_importance(pipeline.named_steps["model"], list(X_train.columns))
        if native_importance is not None:
            importance_method, native_frame = native_importance
            native_frame.to_csv(model_dir / "feature_importance_native.csv", index=False)
            plot_feature_importance(
                native_frame,
                title=f"{model_spec.name} Feature Importance ({importance_method})",
                output_path=model_dir / "feature_importance_native.png",
                top_k=config.top_k_feature_importance,
                value_column="importance",
            )
        else:
            importance_method = "none"
            native_frame = pd.DataFrame(columns=["feature", "importance"])

        permutation_frame = build_permutation_importance(
            pipeline,
            X_test,
            y_test,
            scoring=config.permutation_scoring,
            n_repeats=config.permutation_n_repeats,
            max_samples=config.permutation_max_samples,
            random_state=config.random_state,
        )
        permutation_frame.to_csv(model_dir / "feature_importance_permutation.csv", index=False)
        plot_feature_importance(
            permutation_frame,
            title=f"{model_spec.name} Permutation Importance",
            output_path=model_dir / "feature_importance_permutation.png",
            top_k=config.top_k_feature_importance,
            value_column="importance_mean",
        )

        model_summary = {
            "cv_summary": cv_summary,
            "threshold_summary": threshold_summary,
            "holdout_metrics": holdout_metrics,
            "native_importance_method": importance_method,
            "permutation_importance": {
                "scoring": config.permutation_scoring,
                "n_repeats": config.permutation_n_repeats,
                "max_samples": min(config.permutation_max_samples, len(X_test)),
            },
        }
        save_json(model_summary, model_dir / "model_summary.json")

        model_results[model_spec.name] = {
            "cv_summary": cv_summary,
            "holdout_metrics": holdout_metrics,
            "threshold_summary": threshold_summary,
            "roc_curve_frame": roc_frame,
            "pr_curve_frame": pr_frame,
            "native_importance_frame": native_frame,
            "permutation_importance_frame": permutation_frame,
        }

    comparison_rows: list[dict[str, Any]] = []
    for model_name, payload in model_results.items():
        row: dict[str, Any] = {
            "model": model_name,
            "threshold_metric": config.threshold_metric,
            "selected_threshold": payload["threshold_summary"]["threshold"],
        }
        for metric_name in COMPARISON_METRIC_COLUMNS:
            cv_metric = payload["cv_summary"].get(metric_name, {"mean": float("nan"), "std": float("nan")})
            row[f"cv_{metric_name}_mean"] = cv_metric["mean"]
            row[f"cv_{metric_name}_std"] = cv_metric["std"]
            row[f"test_default_{metric_name}"] = payload["holdout_metrics"]["default_threshold"][metric_name]
            row[f"test_optimized_{metric_name}"] = payload["holdout_metrics"]["optimized_threshold"][metric_name]
        comparison_rows.append(row)

    comparison_frame = pd.DataFrame(comparison_rows).sort_values("test_optimized_f1", ascending=False, kind="stable")
    comparison_frame.to_csv(output_dir / "model_comparison.csv", index=False)
    save_comparison_plots(model_results, output_dir=output_dir)

    workflow_summary = {
        "config_path": str(Path(config_path).expanduser().resolve()),
        "dataset_csv": str(dataset_path),
        "output_dir": str(output_dir),
        "rows": int(len(df)),
        "columns": int(len(df.columns)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "feature_count": int(len(X_train.columns)),
        "label_lookup": label_lookup,
        "warnings": analyze_dataset_risks(df, label_column=config.label_column),
        "quality_status_counts": df["quality_status"].fillna("unknown").astype(str).value_counts().to_dict()
        if "quality_status" in df.columns
        else {},
        "model_comparison_csv": str((output_dir / "model_comparison.csv").resolve()),
    }
    save_json(workflow_summary, output_dir / "workflow_summary.json")

    return {
        "workflow_summary": workflow_summary,
        "model_comparison": comparison_frame.to_dict(orient="records"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the full supervised ML workflow for the canonical dataset")
    parser.add_argument("--config", required=True, help="YAML config describing the ML workflow")
    parser.add_argument("--dataset-csv", default=None, help="Optional override for the canonical dataset CSV")
    parser.add_argument("--output-dir", default=None, help="Optional override for the output directory")
    args = parser.parse_args(argv)

    results = run_ml_workflow(
        config_path=args.config,
        dataset_csv_override=args.dataset_csv,
        output_dir_override=args.output_dir,
    )
    for section, payload in results.items():
        print(f"[{section}]")
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
