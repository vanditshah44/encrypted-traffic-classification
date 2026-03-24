"""Artifact snapshot aggregation and explorer queries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tls_dataset.backend.config import BackendSettings, get_backend_settings
from tls_dataset.backend.models import ProcessingJob
from tls_dataset.backend.registry import resolve_model_bundle_dir


@dataclass(frozen=True)
class DashboardArtifacts:
    canonical_csv: Path
    canonical_summary_json: Path
    model_bundle_dir: Path
    multi_tier_dir: Path


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path, low_memory=False)


def _json_safe_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe_value(inner) for key, inner in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe_value(inner) for inner in value]
    if hasattr(value, "item") and not isinstance(value, (str, bytes)):
        try:
            value = value.item()
        except Exception:
            pass
    try:
        if pd.isna(value):
            return None
    except Exception:
        pass
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return float(value)
    return value


def _json_safe_records(df: pd.DataFrame, *, limit: int | None = None) -> list[dict[str, Any]]:
    if df.empty:
        return []
    rows = df.head(limit).to_dict(orient="records") if limit is not None else df.to_dict(orient="records")
    return [
        {str(key): _json_safe_value(value) for key, value in row.items()}
        for row in rows
    ]


def _resolve_multi_tier_dir(project_root: Path) -> Path:
    multi_root = project_root / "artifacts" / "multi_tier"
    preferred = multi_root / "latest"
    if preferred.exists():
        return preferred.resolve()
    candidates = sorted(path for path in multi_root.iterdir() if path.is_dir()) if multi_root.exists() else []
    if not candidates:
        raise FileNotFoundError(f"No multi-tier outputs found under {multi_root}")
    return candidates[-1].resolve()


def resolve_dashboard_artifacts(settings: BackendSettings | None = None) -> DashboardArtifacts:
    resolved_settings = settings or get_backend_settings()
    project_root = resolved_settings.project_root
    return DashboardArtifacts(
        canonical_csv=(project_root / "artifacts" / "canonical" / "canonical_labeled_flows.csv").resolve(),
        canonical_summary_json=(project_root / "artifacts" / "canonical" / "canonical_labeled_flows_summary.json").resolve(),
        model_bundle_dir=resolve_model_bundle_dir(settings=resolved_settings),
        multi_tier_dir=_resolve_multi_tier_dir(project_root),
    )


def _bool_series(df: pd.DataFrame, column: str) -> pd.Series:
    if column not in df.columns:
        return pd.Series(False, index=df.index)
    series = df[column]
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    return series.astype(str).str.lower().isin({"true", "1", "yes"})


def _top_values(series: pd.Series, limit: int = 5) -> list[str]:
    if series.empty:
        return []
    cleaned = series.dropna().astype(str).str.strip()
    cleaned = cleaned[cleaned.ne("")]
    if cleaned.empty:
        return []
    return cleaned.value_counts().head(limit).index.tolist()


def _window_sort_frame(df: pd.DataFrame, window_column: str = "window_id") -> pd.DataFrame:
    working = df.copy()
    if "window_start_ms" in working.columns:
        working["window_start_ms"] = pd.to_numeric(working["window_start_ms"], errors="coerce")
        return working.sort_values(["window_start_ms", window_column], kind="stable")
    return working.sort_values(window_column, kind="stable")


def _normalize_float(value: Any) -> float | None:
    if pd.isna(value):
        return None
    return float(value)


def _normalize_int(value: Any) -> int | None:
    if pd.isna(value):
        return None
    return int(value)


def _job_status_counts(session: Session | None) -> dict[str, int]:
    if session is None:
        return {}
    rows = session.execute(
        select(ProcessingJob.status, func.count()).group_by(ProcessingJob.status)
    ).all()
    return {str(status): int(count) for status, count in rows}


def _collect_quality_reports(project_root: Path) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    runs_root = project_root / "artifacts" / "runs"
    if not runs_root.exists():
        return reports
    paths = sorted(
        runs_root.rglob("*_quality_report.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for path in paths[:8]:
        payload = _read_json(path)
        outcomes = payload.get("outcomes", [])
        reports.append(
            {
                "path": str(path),
                "path_name": path.name,
                "dataset_name": payload.get("dataset_name", path.stem),
                "failed": bool(payload.get("failed", False)),
                "failed_gates": [
                    str(outcome.get("name", "unknown"))
                    for outcome in outcomes
                    if str(outcome.get("status", "")).lower() == "fail"
                ],
                "outcomes": outcomes,
            }
        )
    return reports


def build_dashboard_summary(
    *,
    session: Session | None = None,
    settings: BackendSettings | None = None,
) -> dict[str, Any]:
    resolved_settings = settings or get_backend_settings()
    artifacts = resolve_dashboard_artifacts(resolved_settings)

    canonical_df = _read_csv(artifacts.canonical_csv)
    canonical_summary = _read_json(artifacts.canonical_summary_json)
    tiered_df = _read_csv(artifacts.multi_tier_dir / "tiered_flow_scores.csv")
    clusters_df = _read_csv(artifacts.multi_tier_dir / "suspicious_clusters.csv")
    nodes_df = _read_csv(artifacts.multi_tier_dir / "graph_nodes.csv")
    windows_df = _read_csv(artifacts.multi_tier_dir / "cluster_window_summary.csv")
    model_comparison_df = _read_csv(artifacts.model_bundle_dir / "model_comparison.csv")
    model_summary = _read_json(artifacts.model_bundle_dir / "workflow_summary.json")

    tier1_pass = _bool_series(tiered_df, "tier1_pass")
    tier2_pass = _bool_series(tiered_df, "tier2_pass")
    protocol_counts = canonical_df["protocol_family"].value_counts(dropna=False).to_dict() if "protocol_family" in canonical_df.columns else {}
    label_counts = canonical_df["label"].value_counts(dropna=False).to_dict() if "label" in canonical_df.columns else {}
    capture_count = int(canonical_df["capture_id"].nunique(dropna=True)) if "capture_id" in canonical_df.columns else 0
    source_count = int(canonical_df["source_name"].nunique(dropna=True)) if "source_name" in canonical_df.columns else 0
    quality_status_counts = canonical_summary.get("quality_status_counts", {})
    dataset_mode = "benchmark_corpus" if len(label_counts) >= 2 else "single_label_corpus"
    quality_signal = "quality_caveat_present" if quality_status_counts.get("fail", 0) else "quality_clear"

    overview = {
        "total_flows": int(len(tiered_df)),
        "candidate_flows": int(tier1_pass.sum()),
        "suspicious_flows": int(tier2_pass.sum()),
        "suspicious_rate": float(tier2_pass.mean()) if len(tiered_df) else 0.0,
        "tls_flows": int(protocol_counts.get("tls", 0)),
        "quic_flows": int(protocol_counts.get("quic", 0)),
        "cluster_count": int(len(clusters_df)),
        "model_count": int(len(model_comparison_df)),
        "capture_count": capture_count,
        "source_count": source_count,
        "label_counts": {str(key): int(value) for key, value in label_counts.items()},
        "dataset_mode": dataset_mode,
        "quality_signal": quality_signal,
        "job_status_counts": _job_status_counts(session),
        "quality_status_counts": quality_status_counts,
        "active_model_bundle": artifacts.model_bundle_dir.name,
    }

    protocol_trend: list[dict[str, Any]] = []
    if not canonical_df.empty and {"window_id", "protocol_family"}.issubset(canonical_df.columns):
        trend = canonical_df.copy()
        if "window_start_ms" in trend.columns:
            trend["window_start_ms"] = pd.to_numeric(trend["window_start_ms"], errors="coerce")
        grouped = (
            trend.groupby(["window_id", "protocol_family"], dropna=False)
            .size()
            .rename("count")
            .reset_index()
        )
        pivot = grouped.pivot_table(
            index="window_id",
            columns="protocol_family",
            values="count",
            fill_value=0,
            aggfunc="sum",
        ).reset_index()
        if "window_start_ms" in trend.columns:
            window_meta = trend.groupby("window_id", dropna=False).agg(window_start_ms=("window_start_ms", "min")).reset_index()
            pivot = pivot.merge(window_meta, on="window_id", how="left")
        pivot = _window_sort_frame(pivot)
        for _, row in pivot.iterrows():
            protocol_trend.append(
                {
                    "window_id": str(row["window_id"]),
                    "window_start_ms": _normalize_int(row.get("window_start_ms")),
                    "tls": int(row.get("tls", 0) or 0),
                    "quic": int(row.get("quic", 0) or 0),
                }
            )

    alert_timeline: list[dict[str, Any]] = []
    if not tiered_df.empty and "window_id" in tiered_df.columns:
        timeline = tiered_df.copy()
        if "window_start_ms" in timeline.columns:
            timeline["window_start_ms"] = pd.to_numeric(timeline["window_start_ms"], errors="coerce")
        timeline["tier1_pass_bool"] = tier1_pass
        timeline["tier2_pass_bool"] = tier2_pass
        timeline["tier2_consensus_score"] = pd.to_numeric(timeline.get("tier2_consensus_score"), errors="coerce")
        grouped = timeline.groupby("window_id", dropna=False).agg(
            candidate_flows=("tier1_pass_bool", "sum"),
            suspicious_flows=("tier2_pass_bool", "sum"),
            mean_score=("tier2_consensus_score", "mean"),
        ).reset_index()
        if "window_start_ms" in timeline.columns:
            window_meta = timeline.groupby("window_id", dropna=False).agg(window_start_ms=("window_start_ms", "min")).reset_index()
            grouped = grouped.merge(window_meta, on="window_id", how="left")
        grouped["high_alerts"] = (
            timeline.groupby("window_id", dropna=False)["alert_level"].apply(lambda values: int(pd.Series(values).astype(str).eq("high").sum())).values
            if "alert_level" in timeline.columns
            else 0
        )
        grouped = _window_sort_frame(grouped)
        for _, row in grouped.iterrows():
            alert_timeline.append(
                {
                    "window_id": str(row["window_id"]),
                    "window_start_ms": _normalize_int(row.get("window_start_ms")),
                    "candidate_flows": int(row["candidate_flows"]),
                    "suspicious_flows": int(row["suspicious_flows"]),
                    "mean_score": _normalize_float(row["mean_score"]),
                    "high_alerts": int(row["high_alerts"]),
                }
            )

    protocol_breakdown: list[dict[str, Any]] = []
    if not tiered_df.empty and "protocol_family" in tiered_df.columns:
        protocol_frame = tiered_df.copy()
        protocol_frame["tier1_pass_bool"] = tier1_pass
        protocol_frame["tier2_pass_bool"] = tier2_pass
        protocol_frame["tier2_consensus_score"] = pd.to_numeric(protocol_frame.get("tier2_consensus_score"), errors="coerce")
        for protocol_family, subset in protocol_frame.groupby("protocol_family", dropna=False):
            protocol_breakdown.append(
                {
                    "protocol_family": str(protocol_family),
                    "total_flows": int(len(subset)),
                    "candidate_flows": int(subset["tier1_pass_bool"].sum()),
                    "suspicious_flows": int(subset["tier2_pass_bool"].sum()),
                    "suspicious_rate": float(subset["tier2_pass_bool"].mean()) if len(subset) else 0.0,
                    "mean_score": _normalize_float(subset["tier2_consensus_score"].mean()),
                    "top_requested_server_names": _top_values(subset.get("requested_server_name", pd.Series(dtype="object"))),
                }
            )
        protocol_breakdown.sort(key=lambda row: row["suspicious_flows"], reverse=True)

    feature_importance: dict[str, list[dict[str, Any]]] = {}
    for model_dir in sorted(path for path in artifacts.model_bundle_dir.iterdir() if path.is_dir()):
        importance_path = model_dir / "feature_importance_native.csv"
        if not importance_path.exists():
            importance_path = model_dir / "feature_importance_permutation.csv"
        importance_df = _read_csv(importance_path)
        if importance_df.empty:
            continue
        value_column = "importance" if "importance" in importance_df.columns else "importance_mean"
        top_rows = []
        for _, row in importance_df.head(12).iterrows():
            top_rows.append(
                {
                    "feature": str(row["feature"]),
                    "value": _normalize_float(row[value_column]) or 0.0,
                }
            )
        feature_importance[model_dir.name] = top_rows

    model_quality = {
        "warnings": _json_safe_value(model_summary.get("warnings", [])),
        "models": _json_safe_records(model_comparison_df),
    }

    top_endpoints: list[dict[str, Any]] = []
    if not nodes_df.empty:
        ranking = nodes_df.sort_values(
            ["suspicious_flow_count", "unique_neighbors", "max_incident_score"],
            ascending=[False, False, False],
            kind="stable",
        )
        for _, row in ranking.head(8).iterrows():
            top_endpoints.append(
                {
                    "endpoint": str(row["endpoint"]),
                    "cluster_id": str(row.get("cluster_id", "")),
                    "is_private": bool(row["is_private"]) if not pd.isna(row.get("is_private")) else None,
                    "suspicious_flow_count": _normalize_int(row.get("suspicious_flow_count")) or 0,
                    "unique_neighbors": _normalize_int(row.get("unique_neighbors")) or 0,
                    "risk_mass": _normalize_float(row.get("risk_mass")) or 0.0,
                }
            )

    top_alerts: list[dict[str, Any]] = []
    if not tiered_df.empty:
        ranking = tiered_df.copy()
        ranking["tier2_pass"] = tier2_pass
        ranking["tier2_consensus_score"] = pd.to_numeric(ranking.get("tier2_consensus_score"), errors="coerce")
        ranking = ranking.sort_values(
            ["tier2_pass", "tier2_consensus_score", "tier1_probability"],
            ascending=[False, False, False],
            kind="stable",
        )
        display_columns = [
            column
            for column in (
                "record_id",
                "capture_id",
                "window_id",
                "protocol_family",
                "src_ip",
                "dst_ip",
                "requested_server_name",
                "alert_level",
                "tier2_consensus_score",
                "tier2_pass_count",
            )
            if column in ranking.columns
        ]
        for _, row in ranking.head(10)[display_columns].iterrows():
            payload = {
                column: _json_safe_value(value)
                for column, value in row.items()
            }
            top_alerts.append(payload)

    ingestion_health = {
        "quality_status_counts": canonical_summary.get("quality_status_counts", {}),
        "source_counts": canonical_summary.get("source_counts", {}),
        "capture_counts": canonical_summary.get("capture_counts", {}),
        "job_status_counts": _job_status_counts(session),
        "quality_reports": _collect_quality_reports(resolved_settings.project_root),
    }

    graph_overview = {
        "cluster_count": int(len(clusters_df)),
        "top_clusters": _json_safe_records(clusters_df, limit=6),
        "cluster_windows": _json_safe_records(windows_df, limit=20),
    }

    return {
        "artifacts": {
            "canonical_csv": str(artifacts.canonical_csv),
            "model_bundle_dir": str(artifacts.model_bundle_dir),
            "multi_tier_dir": str(artifacts.multi_tier_dir),
        },
        "overview": overview,
        "protocol_trend": protocol_trend,
        "alert_timeline": alert_timeline,
        "protocol_breakdown": protocol_breakdown,
        "feature_importance": feature_importance,
        "model_quality": model_quality,
        "graph_overview": graph_overview,
        "top_endpoints": top_endpoints,
        "top_alerts": top_alerts,
        "ingestion_health": ingestion_health,
    }


def query_flow_explorer(
    *,
    search: str | None = None,
    protocol_family: str | None = None,
    alert_level: str | None = None,
    only_suspicious: bool = False,
    limit: int = 100,
    offset: int = 0,
    settings: BackendSettings | None = None,
) -> dict[str, Any]:
    artifacts = resolve_dashboard_artifacts(settings)
    tiered_df = _read_csv(artifacts.multi_tier_dir / "tiered_flow_scores.csv")
    if tiered_df.empty:
        return {"total": 0, "limit": limit, "offset": offset, "items": []}

    working = tiered_df.copy()
    working["tier1_pass"] = _bool_series(working, "tier1_pass")
    working["tier2_pass"] = _bool_series(working, "tier2_pass")
    working["tier2_consensus_score"] = pd.to_numeric(working.get("tier2_consensus_score"), errors="coerce")
    working["tier1_probability"] = pd.to_numeric(working.get("tier1_probability"), errors="coerce")

    if protocol_family and "protocol_family" in working.columns:
        working = working[working["protocol_family"].astype(str).str.lower() == protocol_family.lower()]
    if alert_level and "alert_level" in working.columns:
        working = working[working["alert_level"].astype(str).str.lower() == alert_level.lower()]
    if only_suspicious:
        working = working[working["tier2_pass"]]
    if search:
        lowered = search.lower()
        search_columns = [
            column
            for column in (
                "record_id",
                "capture_id",
                "src_ip",
                "dst_ip",
                "requested_server_name",
                "protocol_family",
                "alert_level",
            )
            if column in working.columns
        ]
        if search_columns:
            haystack = working[search_columns].fillna("").astype(str).agg(" ".join, axis=1).str.lower()
            working = working[haystack.str.contains(lowered, na=False)]

    working = working.sort_values(
        ["tier2_pass", "tier2_consensus_score", "tier1_probability"],
        ascending=[False, False, False],
        kind="stable",
    )
    total = int(len(working))

    display_columns = [
        column
        for column in (
            "record_id",
            "capture_id",
            "window_id",
            "protocol_family",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "requested_server_name",
            "application_name",
            "bidirectional_packets",
            "bidirectional_duration_ms",
            "tier1_probability",
            "tier2_consensus_score",
            "tier2_pass_count",
            "alert_level",
            "tier1_pass",
            "tier2_pass",
        )
        if column in working.columns
    ]
    page = working.iloc[offset : offset + limit][display_columns].copy()
    items: list[dict[str, Any]] = []
    for _, row in page.iterrows():
        payload = {
            column: _json_safe_value(value)
            for column, value in row.items()
        }
        items.append(payload)
    return {
        "total": total,
        "limit": int(limit),
        "offset": int(offset),
        "items": items,
    }


def build_graph_view(
    *,
    cluster_id: str | None = None,
    max_nodes: int = 160,
    settings: BackendSettings | None = None,
) -> dict[str, Any]:
    artifacts = resolve_dashboard_artifacts(settings)
    clusters_df = _read_csv(artifacts.multi_tier_dir / "suspicious_clusters.csv")
    nodes_df = _read_csv(artifacts.multi_tier_dir / "graph_nodes.csv")
    edges_df = _read_csv(artifacts.multi_tier_dir / "graph_edges.csv")

    if nodes_df.empty or edges_df.empty or clusters_df.empty:
        return {"cluster_id": cluster_id, "nodes": [], "edges": [], "cluster_summary": None}

    selected_cluster_id = cluster_id or str(clusters_df.iloc[0]["cluster_id"])
    nodes = nodes_df[nodes_df["cluster_id"].astype(str) == selected_cluster_id].copy()
    edges = edges_df[edges_df["cluster_id"].astype(str) == selected_cluster_id].copy()
    cluster_rows = clusters_df[clusters_df["cluster_id"].astype(str) == selected_cluster_id]
    cluster_summary = (
        {
            str(key): _json_safe_value(value)
            for key, value in cluster_rows.iloc[0].to_dict().items()
        }
        if not cluster_rows.empty
        else None
    )

    nodes = nodes.sort_values(
        ["suspicious_flow_count", "unique_neighbors", "max_incident_score"],
        ascending=[False, False, False],
        kind="stable",
    )
    selected = nodes.head(max_nodes).copy()
    selected_endpoints = set(selected["endpoint"].astype(str))
    filtered_edges = edges[
        edges["endpoint_a"].astype(str).isin(selected_endpoints)
        & edges["endpoint_b"].astype(str).isin(selected_endpoints)
    ].copy()

    if filtered_edges.empty and not edges.empty:
        filtered_edges = edges.sort_values(
            ["suspicious_flow_count", "mean_consensus_score"],
            ascending=[False, False],
            kind="stable",
        ).head(max_nodes * 2)
        selected_endpoints = set(filtered_edges["endpoint_a"].astype(str)).union(filtered_edges["endpoint_b"].astype(str))
        selected = nodes[nodes["endpoint"].astype(str).isin(selected_endpoints)].copy()

    return {
        "cluster_id": selected_cluster_id,
        "cluster_summary": cluster_summary,
        "returned_node_count": int(len(selected)),
        "returned_edge_count": int(len(filtered_edges)),
        "nodes": _json_safe_records(selected),
        "edges": _json_safe_records(filtered_edges),
        "available_clusters": _json_safe_records(
            clusters_df[["cluster_id", "suspicious_flow_count", "endpoint_count"]]
        ),
    }
