"""Inference dataset building and queued PCAP scoring."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from tls_dataset.detection.multitier import (
    align_inference_frame,
    assign_alert_level,
    build_graph_enrichment,
    load_feature_columns,
    load_model,
    predict_model_probability,
    save_json,
    weighted_mean_scores,
)
from tls_dataset.pipeline.canonical import (
    BASE_METADATA_COLUMNS,
    _build_window_columns,
    _load_quality_failed,
    derive_protocol_family,
    derive_quality_status,
)
from tls_dataset.pipeline.malicious import run_malicious_pipeline


@dataclass(frozen=True)
class ScoringDatasetResult:
    dataset_csv: Path
    summary_json: Path
    summary: dict[str, Any]


@dataclass(frozen=True)
class ScoringRunResult:
    dataset_name: str
    workspace_dir: Path
    pipeline_output_dir: Path
    inference_output_dir: Path
    scoring_dataset_csv: Path
    platform_summary_json: Path
    summary: dict[str, Any]


def _record_id(dataset_name: str, source_row_index: int) -> str:
    basis = f"inference|{dataset_name}|{source_row_index}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def build_scoring_dataset(
    *,
    merged_csv: str | Path,
    output_csv: str | Path,
    output_summary_json: str | Path,
    dataset_name: str,
    source_dataset: str = "pcap_scoring",
    feature_view: str = "zeek_nfstream_inference",
    traffic_role: str = "inference",
    window_size_ms: int = 60_000,
    quality_report_json: str | Path | None = None,
    provenance_json: str | Path | None = None,
) -> ScoringDatasetResult:
    input_path = Path(merged_csv).expanduser().resolve()
    df = pd.read_csv(input_path, low_memory=False)
    protocol_family = derive_protocol_family(df)
    is_encrypted = protocol_family.isin(["tls", "quic"])
    working = df[is_encrypted].copy().reset_index(drop=True)
    protocol_family = protocol_family[is_encrypted].reset_index(drop=True)
    is_encrypted = is_encrypted[is_encrypted].reset_index(drop=True)

    quality_failed = _load_quality_failed(str(quality_report_json)) if quality_report_json else None
    quality_status = derive_quality_status(quality_failed)

    source_row_index = pd.Series(range(len(working)), dtype="int64")
    record_ids = [_record_id(dataset_name, int(index)) for index in source_row_index]
    flow_start_ms, flow_end_ms, window_ids, window_start_ms, window_end_ms = _build_window_columns(
        df=working,
        capture_id=dataset_name,
        window_size_ms=window_size_ms,
    )

    metadata_df = pd.DataFrame(
        {
            "record_id": record_ids,
            "sample_id": [record_id[:16] for record_id in record_ids],
            "label": "",
            "label_id": pd.Series([pd.NA] * len(working), dtype="Int64"),
            "attack_family": "unknown",
            "attack_category": "unknown",
            "traffic_role": traffic_role,
            "capture_id": dataset_name,
            "protocol_family": protocol_family.astype("string"),
            "window_id": window_ids.astype("string"),
            "flow_start_ms": flow_start_ms,
            "flow_end_ms": flow_end_ms,
            "window_start_ms": window_start_ms,
            "window_end_ms": window_end_ms,
            "source_dataset": source_dataset,
            "source_name": dataset_name,
            "feature_view": feature_view,
            "source_row_index": source_row_index,
            "quality_status": quality_status,
            "quality_failed": quality_failed,
            "quality_report_path": str(Path(quality_report_json).expanduser().resolve()) if quality_report_json else "",
            "provenance_path": str(Path(provenance_json).expanduser().resolve()) if provenance_json else "",
            "input_csv": str(input_path),
            "is_encrypted": is_encrypted.astype(bool),
        }
    )
    ordered_columns = BASE_METADATA_COLUMNS + [column for column in working.columns if column not in BASE_METADATA_COLUMNS]
    scored_df = pd.concat([metadata_df, working], axis=1)[ordered_columns]

    output_path = Path(output_csv).expanduser().resolve()
    summary_path = Path(output_summary_json).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    scored_df.to_csv(output_path, index=False)

    summary = {
        "input_csv": str(input_path),
        "output_csv": str(output_path),
        "rows": int(len(scored_df)),
        "columns": int(len(scored_df.columns)),
        "protocol_counts": scored_df["protocol_family"].value_counts(dropna=False).to_dict(),
        "quality_status": quality_status,
        "capture_id": dataset_name,
        "source_dataset": source_dataset,
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return ScoringDatasetResult(dataset_csv=output_path, summary_json=summary_path, summary=summary)


def run_multitier_inference(
    *,
    dataset_csv: str | Path,
    model_bundle_dir: str | Path,
    output_dir: str | Path,
    record_id_column: str = "record_id",
    src_ip_column: str = "src_ip",
    dst_ip_column: str = "dst_ip",
    src_port_column: str = "src_port",
    dst_port_column: str = "dst_port",
    capture_id_column: str = "capture_id",
    window_id_column: str = "window_id",
    protocol_family_column: str = "protocol_family",
    requested_server_name_column: str = "requested_server_name",
    tier1_model_name: str = "gaussian_nb",
    deep_model_names: tuple[str, ...] = ("random_forest", "gradient_boosting"),
    deep_consensus_threshold: float = 0.5,
    min_deep_model_passes: int = 2,
    cluster_min_suspicious_flows: int = 1,
    use_optimized_thresholds: bool = True,
) -> dict[str, Any]:
    dataset_path = Path(dataset_csv).expanduser().resolve()
    bundle_dir = Path(model_bundle_dir).expanduser().resolve()
    target_dir = Path(output_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(dataset_path, low_memory=False)
    feature_columns = load_feature_columns(bundle_dir)
    X = align_inference_frame(df, feature_columns)

    tier1_model = load_model(bundle_dir, tier1_model_name, use_optimized_thresholds=use_optimized_thresholds)
    tier1_probability = predict_model_probability(tier1_model, X)
    tier1_pass = pd.Series(tier1_probability >= tier1_model.threshold, index=df.index)

    scored = df.copy()
    scored["tier1_probability"] = tier1_probability
    scored["tier1_threshold"] = float(tier1_model.threshold)
    scored["tier1_model_name"] = tier1_model.name
    scored["tier1_pass"] = tier1_pass

    stage2_index = scored.index[scored["tier1_pass"]]
    X_stage2 = X.loc[stage2_index] if len(stage2_index) else X.iloc[0:0]

    deep_score_columns: list[str] = []
    deep_pass_columns: list[str] = []
    for model_name in deep_model_names:
        model = load_model(bundle_dir, model_name, use_optimized_thresholds=use_optimized_thresholds)
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
        deep_consensus_subset = weighted_mean_scores(deep_score_frame, {})
        scored["tier2_consensus_score"] = np.nan
        scored.loc[stage2_index, "tier2_consensus_score"] = deep_consensus_subset
        deep_pass_count = scored[deep_pass_columns].fillna(False).sum(axis=1).astype(int)
    else:
        scored["tier2_consensus_score"] = np.nan
        deep_pass_count = pd.Series(0, index=scored.index, dtype="int64")

    required_deep_passes = min(min_deep_model_passes, len(deep_model_names)) if deep_model_names else 0
    scored["tier2_pass_count"] = deep_pass_count
    scored["tier2_consensus_threshold"] = deep_consensus_threshold
    scored["tier2_consensus_pass"] = scored["tier2_consensus_score"] >= deep_consensus_threshold
    scored["tier2_pass"] = scored["tier1_pass"] & (
        (scored["tier2_pass_count"] >= required_deep_passes) | scored["tier2_consensus_pass"].fillna(False)
    )
    scored["alert_level"] = assign_alert_level(
        tier1_pass=scored["tier1_pass"].fillna(False),
        tier2_pass=scored["tier2_pass"].fillna(False),
        deep_pass_count=scored["tier2_pass_count"],
        deep_model_total=len(deep_model_names),
        deep_consensus_score=scored["tier2_consensus_score"].fillna(0.0),
    )

    scored.to_csv(target_dir / "tiered_flow_scores.csv", index=False)
    scored[scored["tier1_pass"]].to_csv(target_dir / "tier1_candidates.csv", index=False)

    suspicious_df = scored[scored["tier2_pass"]].copy()
    graph_outputs = build_graph_enrichment(
        suspicious_df,
        src_ip_column=src_ip_column,
        dst_ip_column=dst_ip_column,
        src_port_column=src_port_column,
        dst_port_column=dst_port_column,
        capture_id_column=capture_id_column,
        window_id_column=window_id_column,
        protocol_family_column=protocol_family_column,
        requested_server_name_column=requested_server_name_column,
        min_suspicious_flows=cluster_min_suspicious_flows,
    )

    graph_outputs["suspicious_flows"].to_csv(target_dir / "suspicious_flows.csv", index=False)
    graph_outputs["nodes"].to_csv(target_dir / "graph_nodes.csv", index=False)
    graph_outputs["edges"].to_csv(target_dir / "graph_edges.csv", index=False)
    graph_outputs["clusters"].to_csv(target_dir / "suspicious_clusters.csv", index=False)
    graph_outputs["windows"].to_csv(target_dir / "cluster_window_summary.csv", index=False)

    graph_bundle = {
        "nodes": graph_outputs["nodes"].to_dict(orient="records"),
        "edges": graph_outputs["edges"].to_dict(orient="records"),
        "clusters": graph_outputs["clusters"].to_dict(orient="records"),
    }
    save_json(graph_bundle, target_dir / "graph_bundle.json")
    save_json({}, target_dir / "stage_metrics.json")

    summary = {
        "dataset_csv": str(dataset_path),
        "model_bundle_dir": str(bundle_dir),
        "output_dir": str(target_dir),
        "rows": int(len(scored)),
        "tier1_candidate_rows": int(scored["tier1_pass"].sum()),
        "tier2_suspicious_rows": int(scored["tier2_pass"].sum()),
        "tier1_candidate_rate": float(scored["tier1_pass"].mean()) if len(scored) else 0.0,
        "tier2_suspicious_rate": float(scored["tier2_pass"].mean()) if len(scored) else 0.0,
        "required_deep_passes": int(required_deep_passes),
        "cluster_count": int(len(graph_outputs["clusters"])),
        "graph_node_count": int(len(graph_outputs["nodes"])),
        "graph_edge_count": int(len(graph_outputs["edges"])),
        "top_clusters": graph_outputs["clusters"].head(10).to_dict(orient="records"),
        "record_id_column": record_id_column,
    }
    save_json(summary, target_dir / "workflow_summary.json")
    return summary


def run_pcap_scoring_job(
    *,
    input_pcap: str | Path,
    workspace_dir: str | Path,
    dataset_name: str,
    model_bundle_dir: str | Path,
    allow_quality_failures: bool,
    display_filter: str = "tls or quic",
) -> ScoringRunResult:
    workspace = Path(workspace_dir).expanduser().resolve()
    pipeline_output_dir = workspace / "pipeline"
    inference_output_dir = workspace / "scoring"
    workspace.mkdir(parents=True, exist_ok=True)

    pipeline_results = run_malicious_pipeline(
        dataset_name=dataset_name,
        input_pcap=input_pcap,
        output_dir=pipeline_output_dir,
        display_filter=display_filter,
        run_zeek=True,
        allow_quality_failures=allow_quality_failures,
    )
    nested_pipeline = pipeline_results.get("pipeline")
    if not isinstance(nested_pipeline, dict):
        raise RuntimeError("Pipeline stage did not return the expected artifact payload")
    artifacts = nested_pipeline.get("artifacts")
    if not isinstance(artifacts, dict) or "merged_csv" not in artifacts:
        raise RuntimeError("Pipeline results are missing merged_csv and artifact metadata")

    scoring_dataset = build_scoring_dataset(
        merged_csv=artifacts["merged_csv"],
        output_csv=workspace / "scoring_dataset.csv",
        output_summary_json=workspace / "scoring_dataset_summary.json",
        dataset_name=dataset_name,
        quality_report_json=artifacts.get("quality_report_json"),
        provenance_json=artifacts.get("provenance_json"),
    )
    inference_summary = run_multitier_inference(
        dataset_csv=scoring_dataset.dataset_csv,
        model_bundle_dir=model_bundle_dir,
        output_dir=inference_output_dir,
    )

    platform_summary = {
        "dataset_name": dataset_name,
        "input_pcap": str(Path(input_pcap).expanduser().resolve()),
        "model_bundle_dir": str(Path(model_bundle_dir).expanduser().resolve()),
        "workspace_dir": str(workspace),
        "pipeline_output_dir": str(pipeline_output_dir),
        "inference_output_dir": str(inference_output_dir),
        "scoring_dataset_csv": str(scoring_dataset.dataset_csv),
        "pipeline_quality_failed": bool(nested_pipeline.get("quality", {}).get("failed", False)),
        "pipeline_artifacts": artifacts,
        "scoring_dataset_summary": scoring_dataset.summary,
        "inference_summary": inference_summary,
    }
    summary_path = workspace / "platform_summary.json"
    save_json(platform_summary, summary_path)

    return ScoringRunResult(
        dataset_name=dataset_name,
        workspace_dir=workspace,
        pipeline_output_dir=pipeline_output_dir,
        inference_output_dir=inference_output_dir,
        scoring_dataset_csv=scoring_dataset.dataset_csv,
        platform_summary_json=summary_path,
        summary=platform_summary,
    )
