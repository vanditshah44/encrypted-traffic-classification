"""High-level orchestration for standardized dataset processing."""

from __future__ import annotations

from pathlib import Path

from tls_dataset.pipeline.build_dataset import build_dataset_outputs
from tls_dataset.pipeline.common import DatasetArtifacts, build_dataset_artifacts
from tls_dataset.pipeline.finalize import DEFAULT_DROP_COLS, finalize_feature_dataset
from tls_dataset.pipeline.inspect import inspect_nfstream_csv
from tls_dataset.pipeline.merge_features import merge_nfstream_with_zeek
from tls_dataset.pipeline.nfstream import extract_nfstream_csv
from tls_dataset.pipeline.pruning import prune_feature_dataset
from tls_dataset.pipeline.quality import (
    QualityReport,
    check_merged_dataset,
    check_nfstream_csv,
    check_pcap_health,
    check_zeek_outputs,
    raise_for_failed_gates,
)
from tls_dataset.pipeline.zeek import convert_zeek_logs


def run_dataset_pipeline(
    *,
    dataset_name: str,
    output_dir: str | Path,
    pcap: str | Path | None = None,
    nfstream_csv: str | Path | None = None,
    zeek_log_dir: str | Path | None = None,
    zeek_csv_dir: str | Path | None = None,
    extract_nfstream: bool = False,
    convert_zeek: bool = False,
    all_zeek_logs: bool = False,
    merge_tolerance_sec: float = 2.0,
    protocol_filter: str = "encrypted_only",
    near_const_threshold: float = 0.995,
    corr_threshold: float = 0.95,
    final_drop_cols: list[str] | None = None,
    allow_quality_failures: bool = False,
    min_merge_match_rate: float = 0.90,
    max_unmatched_uid_rate: float = 0.10,
    max_non_tls_quic_rate: float = 0.05,
    max_duplicate_flow_rate: float = 0.0,
    max_duplicate_uid_rate: float = 0.0,
    decode_tunnels: bool = True,
    bpf_filter: str | None = None,
    statistical_analysis: bool = True,
    splt_analysis: int = 20,
    n_meters: int = 4,
) -> dict[str, object]:
    artifacts: DatasetArtifacts = build_dataset_artifacts(dataset_name=dataset_name, output_dir=output_dir)
    artifacts.output_dir.mkdir(parents=True, exist_ok=True)
    quality_report = QualityReport(dataset_name=dataset_name)

    resolved_nfstream_csv = Path(nfstream_csv).expanduser().resolve() if nfstream_csv else artifacts.nfstream_csv
    resolved_zeek_csv_dir = Path(zeek_csv_dir).expanduser().resolve() if zeek_csv_dir else artifacts.zeek_csv_dir

    if extract_nfstream:
        if pcap is None:
            raise ValueError("pcap must be provided when extract_nfstream=True")
        extract_nfstream_csv(
            pcap_file=pcap,
            output_csv=resolved_nfstream_csv,
            decode_tunnels=decode_tunnels,
            bpf_filter=bpf_filter,
            statistical_analysis=statistical_analysis,
            splt_analysis=splt_analysis,
            n_meters=n_meters,
        )
    elif not resolved_nfstream_csv.exists():
        raise FileNotFoundError(f"NFStream CSV not found: {resolved_nfstream_csv}")
    quality_report.add(check_nfstream_csv(resolved_nfstream_csv, max_duplicate_flow_rate=max_duplicate_flow_rate))

    if convert_zeek:
        if zeek_log_dir is None:
            raise ValueError("zeek_log_dir must be provided when convert_zeek=True")
        convert_zeek_logs(zeek_dir=zeek_log_dir, out_dir=resolved_zeek_csv_dir, all_logs=all_zeek_logs)
    elif not resolved_zeek_csv_dir.exists():
        raise FileNotFoundError(f"Zeek CSV directory not found: {resolved_zeek_csv_dir}")
    quality_report.add(check_zeek_outputs(resolved_zeek_csv_dir))

    if pcap is not None:
        quality_report.add(check_pcap_health(pcap))

    quality_report.write(artifacts.quality_report_json)
    if not allow_quality_failures:
        raise_for_failed_gates(quality_report)

    merge_results = merge_nfstream_with_zeek(
        nfstream_csv=resolved_nfstream_csv,
        zeek_dir=resolved_zeek_csv_dir,
        out_csv=artifacts.merged_csv,
        tolerance_sec=merge_tolerance_sec,
    )
    quality_report.add(
        check_merged_dataset(
            artifacts.merged_csv,
            min_match_rate=min_merge_match_rate,
            max_unmatched_uid_rate=max_unmatched_uid_rate,
            max_non_tls_quic_rate=max_non_tls_quic_rate,
            max_duplicate_uid_rate=max_duplicate_uid_rate,
        )
    )
    quality_report.write(artifacts.quality_report_json)
    if not allow_quality_failures:
        raise_for_failed_gates(quality_report)

    build_results = build_dataset_outputs(
        merged_csv=artifacts.merged_csv,
        output_dir=artifacts.output_dir,
        dataset_name=dataset_name,
        protocol_filter=protocol_filter,
    )
    prune_results = prune_feature_dataset(
        input_csv=artifacts.ml_ready_csv,
        output_dir=artifacts.output_dir,
        dataset_name=dataset_name,
        near_const_threshold=near_const_threshold,
        corr_threshold=corr_threshold,
    )
    finalize_results = finalize_feature_dataset(
        input_csv=artifacts.ml_pruned_csv,
        output_csv=artifacts.ml_final_csv,
        drop_cols=final_drop_cols or DEFAULT_DROP_COLS,
    )
    inspect_results = inspect_nfstream_csv(resolved_nfstream_csv)

    return {
        "artifacts": artifacts.as_dict(),
        "quality": quality_report.to_dict(),
        "merge": merge_results,
        "build": build_results,
        "prune": prune_results,
        "finalize": finalize_results,
        "inspect": inspect_results,
    }
