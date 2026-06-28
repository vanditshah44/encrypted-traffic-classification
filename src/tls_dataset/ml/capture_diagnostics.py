"""Capture-level feature shift diagnostics for EncFlow datasets."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from tls_dataset.ml.workflow import load_workflow_config, save_json, select_feature_columns


def _safe_float(value: Any) -> float | None:
    try:
        if pd.isna(value):
            return None
    except Exception:
        pass
    if value is None:
        return None
    return float(value)


def _robust_scale(series: pd.Series) -> float:
    numeric = pd.to_numeric(series, errors="coerce").dropna()
    if numeric.empty:
        return 1.0
    q75 = float(numeric.quantile(0.75))
    q25 = float(numeric.quantile(0.25))
    iqr = q75 - q25
    if iqr > 0:
        return iqr
    std = float(numeric.std(ddof=0))
    if std > 0:
        return std
    return 1.0


def _drop_unusable_columns(frame: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    all_missing = [column for column in frame.columns if frame[column].isna().all()]
    constant = [column for column in frame.columns if frame[column].nunique(dropna=False) <= 1]
    dropped = sorted(set(all_missing + constant))
    if dropped:
        frame = frame.drop(columns=dropped)
    return frame, dropped


def prepare_diagnostic_features(
    df: pd.DataFrame,
    *,
    target_column: str,
    extra_excluded_columns: tuple[str, ...] = (),
) -> tuple[pd.DataFrame, list[str], list[str]]:
    feature_columns, _ = select_feature_columns(
        df,
        target_column=target_column,
        extra_excluded_columns=extra_excluded_columns,
    )
    X = df[feature_columns].copy()
    bool_columns = [column for column in X.columns if pd.api.types.is_bool_dtype(X[column])]
    if bool_columns:
        X[bool_columns] = X[bool_columns].astype(int)
    X, dropped = _drop_unusable_columns(X)
    return X, list(X.columns), dropped


def build_capture_feature_summary(
    df: pd.DataFrame,
    X: pd.DataFrame,
    *,
    capture_column: str = "capture_id",
    label_column: str = "label",
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for capture_id, index in df.groupby(capture_column, dropna=False).groups.items():
        subset = X.loc[index]
        label_values = df.loc[index, label_column].dropna().astype(str)
        label = label_values.mode().iloc[0] if not label_values.empty else "unknown"
        for feature in X.columns:
            values = pd.to_numeric(subset[feature], errors="coerce")
            rows.append(
                {
                    "capture_id": str(capture_id),
                    "label": label,
                    "feature": feature,
                    "rows": int(len(values)),
                    "non_null_rows": int(values.notna().sum()),
                    "missing_rate": float(values.isna().mean()) if len(values) else 0.0,
                    "mean": _safe_float(values.mean()),
                    "std": _safe_float(values.std(ddof=0)),
                    "median": _safe_float(values.median()),
                    "q25": _safe_float(values.quantile(0.25)),
                    "q75": _safe_float(values.quantile(0.75)),
                }
            )
    return pd.DataFrame(rows)


def build_capture_profile_matrix(summary: pd.DataFrame, *, value_column: str = "median") -> pd.DataFrame:
    profile = summary.pivot_table(
        index="capture_id",
        columns="feature",
        values=value_column,
        aggfunc="first",
    )
    return profile.sort_index(axis=0).sort_index(axis=1)


def robust_standardize_profiles(profile: pd.DataFrame) -> pd.DataFrame:
    standardized = profile.copy()
    for feature in standardized.columns:
        values = standardized[feature]
        median = float(values.median(skipna=True)) if values.notna().any() else 0.0
        scale = _robust_scale(values)
        standardized[feature] = (values - median) / scale
    return standardized.fillna(0.0)


def build_capture_distance_matrix(profile: pd.DataFrame) -> pd.DataFrame:
    standardized = robust_standardize_profiles(profile)
    captures = standardized.index.tolist()
    distances = pd.DataFrame(0.0, index=captures, columns=captures)
    values = standardized.to_numpy(dtype=float)
    for left_idx, left_capture in enumerate(captures):
        for right_idx, right_capture in enumerate(captures):
            if right_idx < left_idx:
                distances.loc[left_capture, right_capture] = distances.loc[right_capture, left_capture]
                continue
            diff = values[left_idx] - values[right_idx]
            distance = float(np.sqrt(np.mean(diff * diff))) if diff.size else 0.0
            distances.loc[left_capture, right_capture] = distance
    return distances


def build_capture_distance_pairs(
    distance_matrix: pd.DataFrame,
    capture_labels: dict[str, str],
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    captures = list(distance_matrix.index)
    for idx, left in enumerate(captures):
        for right in captures[idx + 1:]:
            left_label = capture_labels.get(str(left), "unknown")
            right_label = capture_labels.get(str(right), "unknown")
            rows.append(
                {
                    "capture_a": str(left),
                    "capture_b": str(right),
                    "label_a": left_label,
                    "label_b": right_label,
                    "pair_type": "same_label" if left_label == right_label else "cross_label",
                    "distance": float(distance_matrix.loc[left, right]),
                }
            )
    return pd.DataFrame(rows).sort_values("distance", ascending=False, kind="stable")


def top_shifted_features_between_captures(
    profile: pd.DataFrame,
    *,
    capture_a: str,
    capture_b: str,
    top_k: int,
) -> pd.DataFrame:
    if capture_a not in profile.index:
        raise RuntimeError(f"Unknown capture_id: {capture_a}")
    if capture_b not in profile.index:
        raise RuntimeError(f"Unknown capture_id: {capture_b}")
    standardized = robust_standardize_profiles(profile)
    delta = standardized.loc[capture_a] - standardized.loc[capture_b]
    frame = pd.DataFrame(
        {
            "capture_a": capture_a,
            "capture_b": capture_b,
            "feature": delta.index,
            "standardized_delta": delta.values,
            "abs_standardized_delta": np.abs(delta.values),
            "capture_a_median": profile.loc[capture_a].values,
            "capture_b_median": profile.loc[capture_b].values,
        }
    )
    return frame.sort_values("abs_standardized_delta", ascending=False, kind="stable").head(top_k)


def build_top_shifted_features(
    profile: pd.DataFrame,
    distance_pairs: pd.DataFrame,
    *,
    top_pairs: int,
    top_features: int,
) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for _, row in distance_pairs.head(top_pairs).iterrows():
        shifted = top_shifted_features_between_captures(
            profile,
            capture_a=str(row["capture_a"]),
            capture_b=str(row["capture_b"]),
            top_k=top_features,
        )
        shifted.insert(2, "pair_type", row["pair_type"])
        shifted.insert(3, "pair_distance", float(row["distance"]))
        frames.append(shifted)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def run_capture_diagnostics(
    *,
    config_path: str | Path,
    output_dir: str | Path,
    top_pairs: int = 12,
    top_features: int = 12,
) -> dict[str, Any]:
    output_path = Path(output_dir).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    config = load_workflow_config(config_path)
    df = pd.read_csv(config.dataset_csv, low_memory=False)
    X, feature_columns, dropped_columns = prepare_diagnostic_features(
        df,
        target_column=config.target_column,
        extra_excluded_columns=config.extra_excluded_columns,
    )
    capture_labels = (
        df.groupby("capture_id")[config.label_column]
        .agg(lambda values: values.dropna().astype(str).mode().iloc[0] if not values.dropna().empty else "unknown")
        .astype(str)
        .to_dict()
    )

    capture_summary = (
        df.groupby(["capture_id", config.label_column], dropna=False)
        .size()
        .rename("rows")
        .reset_index()
        .sort_values([config.label_column, "rows", "capture_id"], ascending=[True, False, True])
    )
    feature_summary = build_capture_feature_summary(
        df,
        X,
        capture_column="capture_id",
        label_column=config.label_column,
    )
    profile = build_capture_profile_matrix(feature_summary)
    distance_matrix = build_capture_distance_matrix(profile)
    distance_pairs = build_capture_distance_pairs(distance_matrix, capture_labels)
    shifted_features = build_top_shifted_features(
        profile,
        distance_pairs,
        top_pairs=top_pairs,
        top_features=top_features,
    )

    capture_summary.to_csv(output_path / "capture_summary.csv", index=False)
    feature_summary.to_csv(output_path / "capture_feature_summary.csv", index=False)
    profile.to_csv(output_path / "capture_feature_profile_median.csv")
    distance_matrix.to_csv(output_path / "capture_distance_matrix.csv")
    distance_pairs.to_csv(output_path / "capture_distance_pairs.csv", index=False)
    shifted_features.to_csv(output_path / "top_shifted_features.csv", index=False)

    by_pair_type = (
        distance_pairs.groupby("pair_type")["distance"]
        .agg(["count", "mean", "std", "min", "max"])
        .reset_index()
        .to_dict(orient="records")
    )
    summary = {
        "config_path": str(Path(config_path).expanduser().resolve()),
        "dataset_csv": str(Path(config.dataset_csv).expanduser().resolve()),
        "output_dir": str(output_path),
        "rows": int(len(df)),
        "capture_count": int(df["capture_id"].nunique()),
        "feature_count": int(len(feature_columns)),
        "dropped_columns": dropped_columns,
        "top_pairs": int(top_pairs),
        "top_features": int(top_features),
        "largest_shift_pairs": distance_pairs.head(top_pairs).to_dict(orient="records"),
        "distance_by_pair_type": by_pair_type,
        "outputs": {
            "capture_summary_csv": str((output_path / "capture_summary.csv").resolve()),
            "capture_feature_summary_csv": str((output_path / "capture_feature_summary.csv").resolve()),
            "capture_feature_profile_median_csv": str((output_path / "capture_feature_profile_median.csv").resolve()),
            "capture_distance_matrix_csv": str((output_path / "capture_distance_matrix.csv").resolve()),
            "capture_distance_pairs_csv": str((output_path / "capture_distance_pairs.csv").resolve()),
            "top_shifted_features_csv": str((output_path / "top_shifted_features.csv").resolve()),
        },
    }
    save_json(summary, output_path / "capture_diagnostics_summary.json")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run capture-level feature shift diagnostics")
    parser.add_argument("--config", required=True, help="ML workflow YAML config")
    parser.add_argument("--output", default="artifacts/diagnostics/capture_shift")
    parser.add_argument("--top-pairs", type=int, default=12)
    parser.add_argument("--top-features", type=int, default=12)
    args = parser.parse_args(argv)

    summary = run_capture_diagnostics(
        config_path=args.config,
        output_dir=args.output,
        top_pairs=args.top_pairs,
        top_features=args.top_features,
    )
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
