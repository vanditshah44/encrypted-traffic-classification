"""Multi-tier suspicious flow detection and graph enrichment."""

from __future__ import annotations

import argparse
import ipaddress
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def _load_yaml(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).expanduser().resolve()
    with config_path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected mapping config at {config_path}")
    return payload


def _json_default(value: Any) -> Any:
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.bool_,)):
        return bool(value)
    if isinstance(value, Path):
        return str(value)
    if pd.isna(value):
        return None
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def save_json(payload: dict[str, Any], output_path: str | Path) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")


@dataclass(frozen=True)
class MultiTierConfig:
    dataset_csv: str
    model_bundle_dir: str
    output_dir: str
    target_column: str | None
    label_column: str | None
    record_id_column: str
    src_ip_column: str
    dst_ip_column: str
    src_port_column: str
    dst_port_column: str
    capture_id_column: str
    window_id_column: str
    protocol_family_column: str
    requested_server_name_column: str
    tier1_model_name: str
    tier1_threshold: float | None
    deep_model_names: tuple[str, ...]
    deep_model_weights: dict[str, float]
    deep_consensus_threshold: float
    min_deep_model_passes: int
    use_optimized_thresholds: bool
    cluster_min_suspicious_flows: int


@dataclass(frozen=True)
class LoadedModel:
    name: str
    pipeline: Any
    threshold: float


def load_multitier_config(config_path: str | Path) -> MultiTierConfig:
    payload = _load_yaml(config_path)
    deep_model_names = tuple(str(value) for value in payload.get("deep_model_names", ["random_forest", "gradient_boosting"]))
    deep_model_weights_payload = payload.get("deep_model_weights", {}) or {}
    return MultiTierConfig(
        dataset_csv=str(payload["dataset_csv"]),
        model_bundle_dir=str(payload["model_bundle_dir"]),
        output_dir=str(payload["output_dir"]),
        target_column=str(payload["target_column"]) if payload.get("target_column") else None,
        label_column=str(payload["label_column"]) if payload.get("label_column") else None,
        record_id_column=str(payload.get("record_id_column", "record_id")),
        src_ip_column=str(payload.get("src_ip_column", "src_ip")),
        dst_ip_column=str(payload.get("dst_ip_column", "dst_ip")),
        src_port_column=str(payload.get("src_port_column", "src_port")),
        dst_port_column=str(payload.get("dst_port_column", "dst_port")),
        capture_id_column=str(payload.get("capture_id_column", "capture_id")),
        window_id_column=str(payload.get("window_id_column", "window_id")),
        protocol_family_column=str(payload.get("protocol_family_column", "protocol_family")),
        requested_server_name_column=str(payload.get("requested_server_name_column", "requested_server_name")),
        tier1_model_name=str(payload.get("tier1_model_name", "gaussian_nb")),
        tier1_threshold=float(payload["tier1_threshold"]) if payload.get("tier1_threshold") is not None else None,
        deep_model_names=deep_model_names,
        deep_model_weights={str(key): float(value) for key, value in deep_model_weights_payload.items()},
        deep_consensus_threshold=float(payload.get("deep_consensus_threshold", 0.5)),
        min_deep_model_passes=int(payload.get("min_deep_model_passes", 1)),
        use_optimized_thresholds=bool(payload.get("use_optimized_thresholds", True)),
        cluster_min_suspicious_flows=int(payload.get("cluster_min_suspicious_flows", 1)),
    )


def load_feature_columns(model_bundle_dir: str | Path) -> list[str]:
    bundle_dir = Path(model_bundle_dir).expanduser().resolve()
    payload = json.loads((bundle_dir / "feature_manifest.json").read_text(encoding="utf-8"))
    return [str(column) for column in payload["training_feature_columns"]]


def load_model(
    model_bundle_dir: str | Path,
    model_name: str,
    *,
    use_optimized_thresholds: bool,
    threshold_override: float | None = None,
) -> LoadedModel:
    bundle_dir = Path(model_bundle_dir).expanduser().resolve() / model_name
    pipeline = joblib.load(bundle_dir / "model.joblib")
    threshold_payload = json.loads((bundle_dir / "threshold_summary.json").read_text(encoding="utf-8"))
    threshold = float(threshold_payload["threshold"]) if use_optimized_thresholds else 0.5
    if threshold_override is not None:
        threshold = float(threshold_override)
    return LoadedModel(name=model_name, pipeline=pipeline, threshold=threshold)


def align_inference_frame(df: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    X = df.reindex(columns=feature_columns).copy()
    bool_columns = [column for column in X.columns if pd.api.types.is_bool_dtype(X[column])]
    if bool_columns:
        X[bool_columns] = X[bool_columns].astype(int)
    return X


def predict_model_probability(model: LoadedModel, X: pd.DataFrame) -> np.ndarray:
    if hasattr(model.pipeline, "predict_proba"):
        return model.pipeline.predict_proba(X)[:, 1]
    raise RuntimeError(f"Model '{model.name}' does not expose predict_proba")


def weighted_mean_scores(score_frame: pd.DataFrame, weights: dict[str, float]) -> pd.Series:
    if score_frame.empty:
        return pd.Series(dtype="float64")
    effective_weights = np.array([weights.get(column, 1.0) for column in score_frame.columns], dtype=float)
    weight_sum = float(effective_weights.sum())
    if weight_sum <= 0:
        raise RuntimeError("Deep model weights must sum to a positive value")
    weighted_values = score_frame.to_numpy(dtype=float) * effective_weights
    return pd.Series(weighted_values.sum(axis=1) / weight_sum, index=score_frame.index, dtype="float64")


def assign_alert_level(
    *,
    tier1_pass: pd.Series,
    tier2_pass: pd.Series,
    deep_pass_count: pd.Series,
    deep_model_total: int,
    deep_consensus_score: pd.Series,
) -> pd.Series:
    alert_level = pd.Series("none", index=tier1_pass.index, dtype="string")
    alert_level[tier1_pass] = "candidate"
    medium_mask = tier2_pass
    alert_level[medium_mask] = "medium"
    high_mask = tier2_pass & (deep_pass_count >= deep_model_total) & (deep_consensus_score >= 0.9)
    alert_level[high_mask] = "high"
    return alert_level


def compute_stage_metrics(
    y_true: pd.Series,
    y_pred: pd.Series,
    y_score: pd.Series | None = None,
) -> dict[str, float | int]:
    y_true_series = y_true.astype(int)
    y_pred_series = y_pred.astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true_series, y_pred_series, labels=[0, 1]).ravel()
    metrics: dict[str, float | int] = {
        "accuracy": float(accuracy_score(y_true_series, y_pred_series)),
        "precision": float(precision_score(y_true_series, y_pred_series, zero_division=0)),
        "recall": float(recall_score(y_true_series, y_pred_series, zero_division=0)),
        "f1": float(f1_score(y_true_series, y_pred_series, zero_division=0)),
        "specificity": float(tn / (tn + fp)) if (tn + fp) else 0.0,
        "balanced_accuracy": float(balanced_accuracy_score(y_true_series, y_pred_series)),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }
    if y_score is not None and len(pd.Series(y_true_series).unique()) == 2:
        metrics["roc_auc"] = float(roc_auc_score(y_true_series, y_score))
        metrics["average_precision"] = float(average_precision_score(y_true_series, y_score))
    return metrics


def safe_ip_private(value: str) -> bool | None:
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return None


def build_connected_components(pairs: list[tuple[str, str]]) -> dict[str, str]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    for left, right in pairs:
        adjacency[left].add(right)
        adjacency[right].add(left)

    assignments: dict[str, str] = {}
    cluster_index = 0
    for node in sorted(adjacency):
        if node in assignments:
            continue
        cluster_id = f"cluster_{cluster_index:04d}"
        queue: deque[str] = deque([node])
        assignments[node] = cluster_id
        while queue:
            current = queue.popleft()
            for neighbor in adjacency[current]:
                if neighbor not in assignments:
                    assignments[neighbor] = cluster_id
                    queue.append(neighbor)
        cluster_index += 1
    return assignments


def _top_string_values(series: pd.Series, limit: int = 5) -> list[str]:
    cleaned = series.dropna().astype(str)
    if cleaned.empty:
        return []
    return cleaned.value_counts().head(limit).index.tolist()


def build_graph_enrichment(
    suspicious_df: pd.DataFrame,
    *,
    src_ip_column: str,
    dst_ip_column: str,
    src_port_column: str,
    dst_port_column: str,
    capture_id_column: str,
    window_id_column: str,
    protocol_family_column: str,
    requested_server_name_column: str,
    min_suspicious_flows: int,
) -> dict[str, pd.DataFrame]:
    if suspicious_df.empty:
        empty_nodes = pd.DataFrame(columns=["endpoint", "cluster_id"])
        empty_edges = pd.DataFrame(columns=["endpoint_a", "endpoint_b", "cluster_id"])
        empty_clusters = pd.DataFrame(columns=["cluster_id"])
        empty_windows = pd.DataFrame(columns=["cluster_id", "window_id"])
        return {
            "suspicious_flows": suspicious_df.copy(),
            "nodes": empty_nodes,
            "edges": empty_edges,
            "clusters": empty_clusters,
            "windows": empty_windows,
        }

    working = suspicious_df.copy()
    working["endpoint_a"] = working[[src_ip_column, dst_ip_column]].astype(str).min(axis=1)
    working["endpoint_b"] = working[[src_ip_column, dst_ip_column]].astype(str).max(axis=1)

    edge_group = working.groupby(["endpoint_a", "endpoint_b"], dropna=False)
    edges = edge_group.agg(
        suspicious_flow_count=("record_id", "count"),
        mean_consensus_score=("tier2_consensus_score", "mean"),
        max_consensus_score=("tier2_consensus_score", "max"),
        unique_captures=(capture_id_column, "nunique"),
        unique_windows=(window_id_column, "nunique"),
    ).reset_index()
    edges = edges[edges["suspicious_flow_count"] >= min_suspicious_flows].copy()
    edge_top_protocols = edge_group[protocol_family_column].apply(_top_string_values).rename("top_protocol_families").reset_index()
    edges = edges.merge(edge_top_protocols, on=["endpoint_a", "endpoint_b"], how="left")
    if requested_server_name_column in working.columns:
        edge_top_server_names = (
            edge_group[requested_server_name_column]
            .apply(_top_string_values)
            .rename("top_requested_server_names")
            .reset_index()
        )
        edges = edges.merge(edge_top_server_names, on=["endpoint_a", "endpoint_b"], how="left")
    else:
        edges["top_requested_server_names"] = [[] for _ in range(len(edges))]

    if edges.empty:
        empty_nodes = pd.DataFrame(columns=["endpoint", "cluster_id"])
        empty_windows = pd.DataFrame(columns=["cluster_id", "window_id"])
        return {
            "suspicious_flows": suspicious_df.assign(cluster_id=pd.NA),
            "nodes": empty_nodes,
            "edges": edges,
            "clusters": pd.DataFrame(columns=["cluster_id"]),
            "windows": empty_windows,
        }

    component_pairs = list(edges[["endpoint_a", "endpoint_b"]].itertuples(index=False, name=None))
    cluster_lookup = build_connected_components(component_pairs)
    edges["cluster_id"] = edges["endpoint_a"].map(cluster_lookup)

    node_records: list[dict[str, Any]] = []
    endpoint_groups: dict[str, list[pd.Series]] = defaultdict(list)
    for _, row in edges.iterrows():
        endpoint_groups[str(row["endpoint_a"])].append(row)
        endpoint_groups[str(row["endpoint_b"])].append(row)

    for endpoint, edge_rows in endpoint_groups.items():
        cluster_id = str(edge_rows[0]["cluster_id"])
        suspicious_flow_count = int(sum(int(edge_row["suspicious_flow_count"]) for edge_row in edge_rows))
        mean_scores = [float(edge_row["mean_consensus_score"]) for edge_row in edge_rows]
        max_scores = [float(edge_row["max_consensus_score"]) for edge_row in edge_rows]
        neighbors = {
            str(edge_row["endpoint_b"]) if str(edge_row["endpoint_a"]) == endpoint else str(edge_row["endpoint_a"])
            for edge_row in edge_rows
        }
        node_records.append(
            {
                "endpoint": endpoint,
                "cluster_id": cluster_id,
                "is_private": safe_ip_private(endpoint),
                "edge_count": len(edge_rows),
                "unique_neighbors": len(neighbors),
                "suspicious_flow_count": suspicious_flow_count,
                "mean_incident_score": float(np.mean(mean_scores)) if mean_scores else 0.0,
                "max_incident_score": float(np.max(max_scores)) if max_scores else 0.0,
                "risk_mass": float(sum(mean_scores)),
            }
        )
    nodes = pd.DataFrame(node_records).sort_values(
        ["cluster_id", "suspicious_flow_count", "max_incident_score"],
        ascending=[True, False, False],
        kind="stable",
    )

    cluster_edge_counts = edges.groupby("cluster_id").size().rename("edge_count")
    cluster_node_counts = nodes.groupby("cluster_id").size().rename("endpoint_count")
    flow_cluster_lookup = nodes.set_index("endpoint")["cluster_id"].to_dict()
    working["cluster_id"] = working[src_ip_column].astype(str).map(flow_cluster_lookup)

    cluster_group = working.groupby("cluster_id", dropna=False)
    clusters = cluster_group.agg(
        suspicious_flow_count=("record_id", "count"),
        mean_consensus_score=("tier2_consensus_score", "mean"),
        max_consensus_score=("tier2_consensus_score", "max"),
        unique_captures=(capture_id_column, "nunique"),
        unique_windows=(window_id_column, "nunique"),
    ).reset_index()
    clusters = clusters.merge(cluster_edge_counts, on="cluster_id", how="left")
    clusters = clusters.merge(cluster_node_counts, on="cluster_id", how="left")
    clusters["top_protocol_families"] = cluster_group[protocol_family_column].apply(_top_string_values).values
    clusters["top_requested_server_names"] = (
        cluster_group[requested_server_name_column].apply(_top_string_values).values
        if requested_server_name_column in working.columns
        else [[] for _ in range(len(clusters))]
    )
    private_counts = nodes.groupby("cluster_id")["is_private"].apply(lambda values: int(pd.Series(values).fillna(False).sum()))
    clusters["private_endpoint_count"] = clusters["cluster_id"].map(private_counts).fillna(0).astype(int)
    clusters["public_endpoint_count"] = clusters["endpoint_count"].fillna(0).astype(int) - clusters["private_endpoint_count"]
    clusters = clusters.sort_values(
        ["suspicious_flow_count", "mean_consensus_score", "endpoint_count"],
        ascending=[False, False, False],
        kind="stable",
    )

    window_summary = working.groupby(["cluster_id", window_id_column], dropna=False).agg(
        suspicious_flow_count=("record_id", "count"),
        mean_consensus_score=("tier2_consensus_score", "mean"),
        unique_src_endpoints=(src_ip_column, "nunique"),
        unique_dst_endpoints=(dst_ip_column, "nunique"),
    ).reset_index().rename(columns={window_id_column: "window_id"})

    cluster_map = clusters.set_index("cluster_id")[["endpoint_count", "edge_count", "suspicious_flow_count", "mean_consensus_score", "max_consensus_score"]]
    node_map = nodes.set_index("endpoint")[["edge_count", "unique_neighbors", "suspicious_flow_count", "max_incident_score", "is_private"]]
    working["cluster_endpoint_count"] = working["cluster_id"].map(cluster_map["endpoint_count"])
    working["cluster_edge_count"] = working["cluster_id"].map(cluster_map["edge_count"])
    working["cluster_suspicious_flow_count"] = working["cluster_id"].map(cluster_map["suspicious_flow_count"])
    working["cluster_mean_consensus_score"] = working["cluster_id"].map(cluster_map["mean_consensus_score"])
    working["cluster_max_consensus_score"] = working["cluster_id"].map(cluster_map["max_consensus_score"])
    working["src_endpoint_degree"] = working[src_ip_column].astype(str).map(node_map["edge_count"])
    working["dst_endpoint_degree"] = working[dst_ip_column].astype(str).map(node_map["edge_count"])
    working["src_unique_neighbors"] = working[src_ip_column].astype(str).map(node_map["unique_neighbors"])
    working["dst_unique_neighbors"] = working[dst_ip_column].astype(str).map(node_map["unique_neighbors"])
    working["src_max_incident_score"] = working[src_ip_column].astype(str).map(node_map["max_incident_score"])
    working["dst_max_incident_score"] = working[dst_ip_column].astype(str).map(node_map["max_incident_score"])
    working["src_is_private"] = working[src_ip_column].astype(str).map(node_map["is_private"])
    working["dst_is_private"] = working[dst_ip_column].astype(str).map(node_map["is_private"])

    return {
        "suspicious_flows": working,
        "nodes": nodes,
        "edges": edges,
        "clusters": clusters,
        "windows": window_summary,
    }


def run_multitier_detection(
    *,
    config_path: str | Path,
    dataset_csv_override: str | Path | None = None,
    model_bundle_dir_override: str | Path | None = None,
    output_dir_override: str | Path | None = None,
) -> dict[str, Any]:
    config = load_multitier_config(config_path)
    dataset_path = Path(dataset_csv_override or config.dataset_csv).expanduser().resolve()
    model_bundle_dir = Path(model_bundle_dir_override or config.model_bundle_dir).expanduser().resolve()
    output_dir = Path(output_dir_override or config.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(dataset_path, low_memory=False)
    feature_columns = load_feature_columns(model_bundle_dir)
    X = align_inference_frame(df, feature_columns)

    tier1_model = load_model(
        model_bundle_dir,
        config.tier1_model_name,
        use_optimized_thresholds=config.use_optimized_thresholds,
        threshold_override=config.tier1_threshold,
    )
    tier1_probability = predict_model_probability(tier1_model, X)
    tier1_pass = pd.Series(tier1_probability >= tier1_model.threshold, index=df.index)

    deep_models = [
        load_model(model_bundle_dir, model_name, use_optimized_thresholds=config.use_optimized_thresholds)
        for model_name in config.deep_model_names
    ]
    deep_score_columns: list[str] = []
    deep_pass_columns: list[str] = []
    scored = df.copy()
    scored["tier1_probability"] = tier1_probability
    scored["tier1_threshold"] = tier1_model.threshold
    scored["tier1_pass"] = tier1_pass
    scored["tier1_model_name"] = tier1_model.name

    stage2_index = scored.index[scored["tier1_pass"]]
    if len(stage2_index):
        X_stage2 = X.loc[stage2_index]
    else:
        X_stage2 = X.iloc[0:0]

    for model in deep_models:
        score_column = f"{model.name}_probability"
        pass_column = f"{model.name}_pass"
        threshold_column = f"{model.name}_threshold"
        deep_score_columns.append(score_column)
        deep_pass_columns.append(pass_column)

        probabilities = pd.Series(np.nan, index=scored.index, dtype="float64")
        if len(stage2_index):
            probabilities.loc[stage2_index] = predict_model_probability(model, X_stage2)
        scored[score_column] = probabilities
        scored[threshold_column] = float(model.threshold)
        scored[pass_column] = probabilities >= float(model.threshold)

    if deep_score_columns:
        deep_score_frame = scored.loc[stage2_index, deep_score_columns].copy()
        deep_weights = {model_name + "_probability": config.deep_model_weights.get(model_name, 1.0) for model_name in config.deep_model_names}
        deep_consensus_subset = weighted_mean_scores(deep_score_frame, deep_weights)
        scored["tier2_consensus_score"] = np.nan
        scored.loc[stage2_index, "tier2_consensus_score"] = deep_consensus_subset
        deep_pass_count = scored[deep_pass_columns].fillna(False).sum(axis=1).astype(int)
    else:
        scored["tier2_consensus_score"] = np.nan
        deep_pass_count = pd.Series(0, index=scored.index, dtype="int64")

    scored["tier2_pass_count"] = deep_pass_count
    scored["tier2_consensus_threshold"] = config.deep_consensus_threshold
    required_deep_passes = min(config.min_deep_model_passes, len(deep_models)) if deep_models else 0
    scored["tier2_consensus_pass"] = scored["tier2_consensus_score"] >= config.deep_consensus_threshold
    scored["tier2_pass"] = scored["tier1_pass"] & (
        (scored["tier2_pass_count"] >= required_deep_passes) | scored["tier2_consensus_pass"].fillna(False)
    )
    scored["alert_level"] = assign_alert_level(
        tier1_pass=scored["tier1_pass"].fillna(False),
        tier2_pass=scored["tier2_pass"].fillna(False),
        deep_pass_count=scored["tier2_pass_count"],
        deep_model_total=len(deep_models),
        deep_consensus_score=scored["tier2_consensus_score"].fillna(0.0),
    )

    scored.to_csv(output_dir / "tiered_flow_scores.csv", index=False)
    scored[scored["tier1_pass"]].to_csv(output_dir / "tier1_candidates.csv", index=False)

    suspicious_df = scored[scored["tier2_pass"]].copy()
    graph_outputs = build_graph_enrichment(
        suspicious_df,
        src_ip_column=config.src_ip_column,
        dst_ip_column=config.dst_ip_column,
        src_port_column=config.src_port_column,
        dst_port_column=config.dst_port_column,
        capture_id_column=config.capture_id_column,
        window_id_column=config.window_id_column,
        protocol_family_column=config.protocol_family_column,
        requested_server_name_column=config.requested_server_name_column,
        min_suspicious_flows=config.cluster_min_suspicious_flows,
    )

    graph_outputs["suspicious_flows"].to_csv(output_dir / "suspicious_flows.csv", index=False)
    graph_outputs["nodes"].to_csv(output_dir / "graph_nodes.csv", index=False)
    graph_outputs["edges"].to_csv(output_dir / "graph_edges.csv", index=False)
    graph_outputs["clusters"].to_csv(output_dir / "suspicious_clusters.csv", index=False)
    graph_outputs["windows"].to_csv(output_dir / "cluster_window_summary.csv", index=False)

    graph_bundle = {
        "nodes": graph_outputs["nodes"].to_dict(orient="records"),
        "edges": graph_outputs["edges"].to_dict(orient="records"),
        "clusters": graph_outputs["clusters"].to_dict(orient="records"),
    }
    save_json(graph_bundle, output_dir / "graph_bundle.json")

    metrics_payload: dict[str, Any] = {}
    if config.target_column and config.target_column in scored.columns:
        y_true = scored[config.target_column].astype(int)
        metrics_payload["tier1"] = compute_stage_metrics(y_true, scored["tier1_pass"].astype(int), scored["tier1_probability"])
        tier2_score = scored["tier2_consensus_score"].fillna(0.0)
        metrics_payload["tier2"] = compute_stage_metrics(y_true, scored["tier2_pass"].astype(int), tier2_score)
    save_json(metrics_payload, output_dir / "stage_metrics.json")

    summary = {
        "config_path": str(Path(config_path).expanduser().resolve()),
        "dataset_csv": str(dataset_path),
        "model_bundle_dir": str(model_bundle_dir),
        "output_dir": str(output_dir),
        "rows": int(len(scored)),
        "tier1_candidate_rows": int(scored["tier1_pass"].sum()),
        "tier2_suspicious_rows": int(scored["tier2_pass"].sum()),
        "tier1_candidate_rate": float(scored["tier1_pass"].mean()),
        "tier2_suspicious_rate": float(scored["tier2_pass"].mean()),
        "required_deep_passes": int(required_deep_passes),
        "cluster_count": int(len(graph_outputs["clusters"])),
        "graph_node_count": int(len(graph_outputs["nodes"])),
        "graph_edge_count": int(len(graph_outputs["edges"])),
        "top_clusters": graph_outputs["clusters"].head(10).to_dict(orient="records"),
        "stage_metrics": metrics_payload,
    }
    save_json(summary, output_dir / "workflow_summary.json")

    return {
        "summary": summary,
        "stage_metrics": metrics_payload,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run multi-tier suspicious flow scoring and cluster enrichment")
    parser.add_argument("--config", required=True, help="YAML config describing the multi-tier workflow")
    parser.add_argument("--dataset-csv", default=None, help="Optional canonical dataset CSV override")
    parser.add_argument("--model-bundle-dir", default=None, help="Optional trained model bundle directory override")
    parser.add_argument("--output-dir", default=None, help="Optional output directory override")
    args = parser.parse_args(argv)

    results = run_multitier_detection(
        config_path=args.config,
        dataset_csv_override=args.dataset_csv,
        model_bundle_dir_override=args.model_bundle_dir,
        output_dir_override=args.output_dir,
    )
    for section, payload in results.items():
        print(f"[{section}]")
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
