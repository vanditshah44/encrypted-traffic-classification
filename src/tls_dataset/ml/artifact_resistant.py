"""Artifact-resistant LOCO experiment.

This experiment ranks feature groups by how strongly they predict the source
capture, then removes the most source-predictive groups cumulatively and reruns
LOCO/paired LOCO. The goal is to test whether reducing capture/source leakage
preserves malware signal or causes generalization to collapse.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path
from typing import Any

import pandas as pd

from tls_dataset.ml.ablation import FEATURE_GROUPS, _group_columns
from tls_dataset.ml.capture_predictability import (
    build_capture_predictor,
    prepare_capture_source_features,
)
from tls_dataset.ml.loco import (
    build_pairwise_model_summary,
    capture_label_summary,
    paired_capture_splits,
    run_loco_split,
)
from tls_dataset.ml.workflow import WorkflowConfig, load_workflow_config, save_json


SOURCE_SCOPES = ("all", "benign", "malicious", "within_label")


def _source_scope_frame(
    df: pd.DataFrame,
    *,
    label_column: str,
    source_scope: str,
) -> pd.DataFrame:
    scope = source_scope.strip().lower()
    if scope == "all":
        return df.copy()
    if scope not in {"benign", "malicious"}:
        raise RuntimeError(f"Unsupported source_scope={source_scope!r}; expected one of {SOURCE_SCOPES}")
    subset = df[df[label_column].astype(str) == scope].copy()
    if subset.empty:
        raise RuntimeError(f"source_scope={source_scope!r} matched no rows")
    return subset


def rank_source_predictive_feature_groups(
    df: pd.DataFrame,
    *,
    config: WorkflowConfig,
    feature_groups: dict[str, list[str]] | None = None,
    source_scope: str = "within_label",
    n_estimators: int = 200,
    n_jobs: int = -1,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return source-predictive group ranking and per-feature importances.

    ``source_scope="within_label"`` ranks capture predictiveness separately
    inside benign and malicious subsets, then averages group importance across
    the available label scopes. This avoids treating malware-vs-benign signal
    as if it were source/capture leakage.
    """
    if source_scope == "within_label":
        return rank_within_label_source_predictive_feature_groups(
            df,
            config=config,
            feature_groups=feature_groups,
            n_estimators=n_estimators,
            n_jobs=n_jobs,
        )
    scoped = _source_scope_frame(
        df,
        label_column=config.label_column,
        source_scope=source_scope,
    )
    if scoped["capture_id"].nunique() < 2:
        raise RuntimeError(f"source_scope={source_scope!r} needs at least two captures")

    X, y, feature_columns, dropped_columns = prepare_capture_source_features(scoped, config=config)
    model = build_capture_predictor(
        random_state=config.random_state,
        n_estimators=n_estimators,
        n_jobs=n_jobs,
    )
    model.fit(X, y)
    estimator = model.named_steps["model"]
    importances = getattr(estimator, "feature_importances_", None)
    if importances is None:
        raise RuntimeError("Capture-source predictor did not expose feature_importances_")

    feature_importance = pd.DataFrame(
        {
            "feature": feature_columns,
            "importance": importances,
        }
    ).sort_values("importance", ascending=False, kind="stable")

    groups = feature_groups or FEATURE_GROUPS
    rows: list[dict[str, Any]] = []
    for group_name, patterns in groups.items():
        group_features = _group_columns(feature_columns, patterns)
        group_frame = feature_importance[feature_importance["feature"].isin(group_features)]
        rows.append(
            {
                "group": group_name,
                "patterns": ",".join(patterns),
                "feature_count": int(len(group_features)),
                "source_importance": float(group_frame["importance"].sum()) if not group_frame.empty else 0.0,
                "top_features": ",".join(group_frame.head(5)["feature"].tolist()),
            }
        )

    ranking = pd.DataFrame(rows).sort_values(
        ["source_importance", "feature_count", "group"],
        ascending=[False, False, True],
        kind="stable",
    )
    ranking.attrs["dropped_columns"] = dropped_columns
    return ranking.reset_index(drop=True), feature_importance.reset_index(drop=True)


def rank_within_label_source_predictive_feature_groups(
    df: pd.DataFrame,
    *,
    config: WorkflowConfig,
    feature_groups: dict[str, list[str]] | None = None,
    n_estimators: int = 200,
    n_jobs: int = -1,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Rank feature groups by within-label capture predictiveness."""
    scope_results: list[pd.DataFrame] = []
    feature_frames: list[pd.DataFrame] = []
    for scope in ("benign", "malicious"):
        subset = df[df[config.label_column].astype(str) == scope].copy()
        if subset.empty:
            continue
        if subset["capture_id"].nunique() < 2:
            continue
        ranking, feature_importance = rank_source_predictive_feature_groups(
            df,
            config=config,
            feature_groups=feature_groups,
            source_scope=scope,
            n_estimators=n_estimators,
            n_jobs=n_jobs,
        )
        ranking = ranking.copy()
        ranking["scope"] = scope
        scope_results.append(ranking)
        feature_importance = feature_importance.copy()
        feature_importance.insert(0, "scope", scope)
        feature_frames.append(feature_importance)

    if not scope_results:
        raise RuntimeError("within_label source ranking needs at least two captures in one label scope")

    combined = pd.concat(scope_results, ignore_index=True)
    rows: list[dict[str, Any]] = []
    for group_name, subset in combined.groupby("group", sort=False):
        scope_values = {
            str(row["scope"]): float(row["source_importance"])
            for _, row in subset.iterrows()
        }
        rows.append(
            {
                "group": str(group_name),
                "patterns": str(subset.iloc[0]["patterns"]),
                "feature_count": int(subset["feature_count"].max()),
                "source_importance": float(subset["source_importance"].mean()),
                "source_importance_max_scope": float(subset["source_importance"].max()),
                "benign_source_importance": scope_values.get("benign", 0.0),
                "malicious_source_importance": scope_values.get("malicious", 0.0),
                "top_features": str(subset.iloc[0]["top_features"]),
            }
        )

    ranking = pd.DataFrame(rows).sort_values(
        ["source_importance", "source_importance_max_scope", "feature_count", "group"],
        ascending=[False, False, False, True],
        kind="stable",
    )
    return ranking.reset_index(drop=True), pd.concat(feature_frames, ignore_index=True).reset_index(drop=True)


def build_cumulative_removal_plan(
    ranking: pd.DataFrame,
    *,
    max_groups: int,
    min_source_importance: float = 0.0,
) -> list[dict[str, Any]]:
    """Build baseline plus cumulative top-k source-predictive group removals."""
    if max_groups < 0:
        raise RuntimeError("max_groups must be >= 0")
    eligible = ranking[pd.to_numeric(ranking["source_importance"], errors="coerce") > min_source_importance]
    ordered_groups = eligible["group"].astype(str).tolist()[:max_groups]
    plan: list[dict[str, Any]] = [
        {
            "variant": "baseline",
            "removed_groups": [],
            "removed_group_count": 0,
        }
    ]
    for idx in range(1, len(ordered_groups) + 1):
        removed = ordered_groups[:idx]
        plan.append(
            {
                "variant": f"remove_top_{idx}_source_groups",
                "removed_groups": removed,
                "removed_group_count": idx,
            }
        )
    return plan


def _columns_for_removed_groups(
    feature_columns: list[str],
    removed_groups: list[str],
    *,
    feature_groups: dict[str, list[str]],
) -> list[str]:
    removed_columns: set[str] = set()
    for group in removed_groups:
        if group not in feature_groups:
            raise RuntimeError(f"Unknown feature group in removal plan: {group}")
        removed_columns.update(_group_columns(feature_columns, feature_groups[group]))
    return sorted(removed_columns)


def _run_loco_for_config(
    *,
    df: pd.DataFrame,
    config: WorkflowConfig,
    include_pairwise: bool,
    model_names: tuple[str, ...],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    capture_summary = capture_label_summary(
        df,
        label_column=config.label_column,
        target_column=config.target_column,
    )
    all_rows: list[dict[str, Any]] = []
    for capture_id in capture_summary["capture_id"].astype(str).tolist():
        rows, _ = run_loco_split(
            df=df,
            config=config,
            test_capture_ids=(capture_id,),
            split_name=f"holdout_{capture_id}",
            split_kind="single_capture",
            model_names=model_names,
        )
        all_rows.extend(rows)

    if include_pairwise:
        for malicious_capture, benign_capture in paired_capture_splits(capture_summary):
            rows, _ = run_loco_split(
                df=df,
                config=config,
                test_capture_ids=(malicious_capture, benign_capture),
                split_name=f"pair_{malicious_capture}__{benign_capture}",
                split_kind="malicious_benign_pair",
                model_names=model_names,
            )
            all_rows.extend(rows)

    return pd.DataFrame(all_rows), capture_summary


def _variant_model_summary(results: pd.DataFrame, *, variant: str, removed_groups: list[str], removed_columns: list[str]) -> pd.DataFrame:
    pairwise = build_pairwise_model_summary(results)
    rows: list[dict[str, Any]] = []
    if not pairwise.empty:
        for _, row in pairwise.iterrows():
            rows.append(
                {
                    "variant": variant,
                    "removed_groups": ",".join(removed_groups),
                    "removed_columns": len(removed_columns),
                    "model": row["model"],
                    "pair_count": row["pair_count"],
                    "f1_mean": row["f1_mean"],
                    "f1_weighted_by_rows": row["f1_weighted_by_rows"],
                    "roc_auc_mean": row["roc_auc_mean"],
                    "roc_auc_weighted_by_rows": row["roc_auc_weighted_by_rows"],
                    "precision_mean": row["precision_mean"],
                    "recall_mean": row["recall_mean"],
                    "specificity_mean": row["specificity_mean"],
                    "worst_f1_split": row["worst_f1_split"],
                    "worst_f1": row["worst_f1"],
                }
            )

    if rows:
        return pd.DataFrame(rows)

    # Fallback for tiny fixtures or no pairwise binary rows.
    single = results[results["split_kind"] == "single_capture"].copy()
    for model_name, subset in single.groupby("model", sort=True):
        rows.append(
            {
                "variant": variant,
                "removed_groups": ",".join(removed_groups),
                "removed_columns": len(removed_columns),
                "model": model_name,
                "pair_count": 0,
                "f1_mean": pd.to_numeric(subset["f1"], errors="coerce").mean(),
                "f1_weighted_by_rows": pd.to_numeric(subset["f1"], errors="coerce").mean(),
                "roc_auc_mean": pd.to_numeric(subset["roc_auc"], errors="coerce").mean(),
                "roc_auc_weighted_by_rows": pd.to_numeric(subset["roc_auc"], errors="coerce").mean(),
                "precision_mean": pd.to_numeric(subset["precision"], errors="coerce").mean(),
                "recall_mean": pd.to_numeric(subset["recall"], errors="coerce").mean(),
                "specificity_mean": pd.to_numeric(subset["specificity"], errors="coerce").mean(),
                "worst_f1_split": "",
                "worst_f1": pd.to_numeric(subset["f1"], errors="coerce").min(),
            }
        )
    return pd.DataFrame(rows)


def add_baseline_deltas(summary: pd.DataFrame) -> pd.DataFrame:
    if summary.empty:
        return summary
    frame = summary.copy()
    for metric in ("f1_mean", "f1_weighted_by_rows", "roc_auc_mean", "roc_auc_weighted_by_rows"):
        frame[f"{metric}_delta_vs_baseline"] = pd.NA
    for model_name, subset in frame.groupby("model", sort=False):
        baseline_rows = subset[subset["variant"] == "baseline"]
        if baseline_rows.empty:
            continue
        baseline = baseline_rows.iloc[0]
        mask = frame["model"] == model_name
        for metric in ("f1_mean", "f1_weighted_by_rows", "roc_auc_mean", "roc_auc_weighted_by_rows"):
            base_value = pd.to_numeric(pd.Series([baseline[metric]]), errors="coerce").iloc[0]
            frame.loc[mask, f"{metric}_delta_vs_baseline"] = pd.to_numeric(frame.loc[mask, metric], errors="coerce") - base_value
    return frame


def run_artifact_resistant_loco(
    *,
    config_path: str | Path,
    output_dir: str | Path,
    max_groups: int = 3,
    source_scope: str = "within_label",
    include_pairwise: bool = True,
    model_names: tuple[str, ...] = (),
    n_estimators: int = 200,
    n_jobs: int = -1,
) -> dict[str, Any]:
    output_path = Path(output_dir).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    config = load_workflow_config(config_path)
    df = pd.read_csv(config.dataset_csv, low_memory=False)
    ranking, source_feature_importance = rank_source_predictive_feature_groups(
        df,
        config=config,
        source_scope=source_scope,
        n_estimators=n_estimators,
        n_jobs=n_jobs,
    )
    ranking.to_csv(output_path / "source_predictive_group_ranking.csv", index=False)
    source_feature_importance.to_csv(output_path / "source_predictive_feature_importance.csv", index=False)

    feature_columns = source_feature_importance["feature"].astype(str).tolist()
    plan = build_cumulative_removal_plan(ranking, max_groups=max_groups)

    variant_summaries: list[pd.DataFrame] = []
    variant_payloads: list[dict[str, Any]] = []
    feature_groups = FEATURE_GROUPS
    for item in plan:
        variant = str(item["variant"])
        removed_groups = list(item["removed_groups"])
        removed_columns = _columns_for_removed_groups(
            feature_columns,
            removed_groups,
            feature_groups=feature_groups,
        )
        variant_dir = output_path / variant
        variant_dir.mkdir(parents=True, exist_ok=True)
        variant_config = replace(
            config,
            extra_excluded_columns=tuple(sorted(set(config.extra_excluded_columns).union(removed_columns))),
        )
        results, capture_summary = _run_loco_for_config(
            df=df,
            config=variant_config,
            include_pairwise=include_pairwise,
            model_names=model_names,
        )
        results.to_csv(variant_dir / "loco_results.csv", index=False)
        capture_summary.to_csv(variant_dir / "capture_summary.csv", index=False)
        summary = _variant_model_summary(
            results,
            variant=variant,
            removed_groups=removed_groups,
            removed_columns=removed_columns,
        )
        summary.to_csv(variant_dir / "model_summary.csv", index=False)
        variant_summaries.append(summary)
        variant_payloads.append(
            {
                "variant": variant,
                "removed_groups": removed_groups,
                "removed_columns": removed_columns,
                "loco_results_csv": str((variant_dir / "loco_results.csv").resolve()),
                "model_summary_csv": str((variant_dir / "model_summary.csv").resolve()),
            }
        )

    combined = add_baseline_deltas(pd.concat(variant_summaries, ignore_index=True) if variant_summaries else pd.DataFrame())
    combined.to_csv(output_path / "artifact_resistant_loco_summary.csv", index=False)

    summary_payload = {
        "config_path": str(Path(config_path).expanduser().resolve()),
        "dataset_csv": str(Path(config.dataset_csv).expanduser().resolve()),
        "output_dir": str(output_path),
        "source_scope": source_scope,
        "max_groups": int(max_groups),
        "include_pairwise": bool(include_pairwise),
        "model_names": list(model_names),
        "n_estimators": int(n_estimators),
        "n_jobs": int(n_jobs),
        "feature_groups": feature_groups,
        "ranking_csv": str((output_path / "source_predictive_group_ranking.csv").resolve()),
        "summary_csv": str((output_path / "artifact_resistant_loco_summary.csv").resolve()),
        "variants": variant_payloads,
    }
    save_json(summary_payload, output_path / "artifact_resistant_loco_summary.json")
    return summary_payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run artifact-resistant LOCO experiment")
    parser.add_argument("--config", required=True, help="ML workflow YAML config")
    parser.add_argument("--output", default="artifacts/artifact_resistant/latest", help="Output directory")
    parser.add_argument("--max-groups", type=int, default=3, help="Cumulatively remove top-k source-predictive groups")
    parser.add_argument("--source-scope", default="within_label", choices=SOURCE_SCOPES)
    parser.add_argument("--no-pairwise", action="store_true", help="Skip paired malicious+benign holdouts")
    parser.add_argument("--models", default="", help="Optional comma-separated model subset, e.g. random_forest,xgboost")
    parser.add_argument("--n-estimators", type=int, default=200, help="Capture-source RF estimators for group ranking")
    parser.add_argument("--n-jobs", type=int, default=-1)
    args = parser.parse_args(argv)

    models = tuple(value.strip() for value in args.models.split(",") if value.strip())
    summary = run_artifact_resistant_loco(
        config_path=args.config,
        output_dir=args.output,
        max_groups=args.max_groups,
        source_scope=args.source_scope,
        include_pairwise=not args.no_pairwise,
        model_names=models,
        n_estimators=args.n_estimators,
        n_jobs=args.n_jobs,
    )
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
