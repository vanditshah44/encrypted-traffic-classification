"""Minimal command-line entrypoint for the repository scaffold."""

from __future__ import annotations

import argparse
from pathlib import Path

from tls_dataset import __version__
from tls_dataset.technical_direction import TECHNICAL_DIRECTION


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-dataset",
        description="Repository scaffold and future entrypoint for the TLS analytics platform.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("info", help="Print the current repository scaffold information.")

    run_parser = subparsers.add_parser(
        "run-dataset-pipeline",
        help="Run the standardized dataset pipeline for benign or malicious inputs.",
    )
    run_parser.add_argument("--dataset-name", required=True, help="Dataset name used for output naming")
    run_parser.add_argument("--output-dir", required=True, help="Directory for all generated outputs")
    run_parser.add_argument("--pcap", help="Input PCAP/PCAPNG file")
    run_parser.add_argument("--nfstream-csv", help="Existing NFStream CSV to reuse instead of re-extracting")
    run_parser.add_argument("--zeek-log-dir", help="Directory containing raw Zeek .log files")
    run_parser.add_argument("--zeek-csv-dir", help="Existing converted Zeek CSV directory to reuse")
    run_parser.add_argument("--extract-nfstream", action="store_true", help="Run NFStream extraction")
    run_parser.add_argument("--convert-zeek", action="store_true", help="Convert raw Zeek logs to CSV")
    run_parser.add_argument("--all-zeek-logs", action="store_true", help="Convert all Zeek logs instead of the core set")
    run_parser.add_argument("--merge-tolerance-sec", type=float, default=2.0)
    run_parser.add_argument(
        "--protocol-filter",
        choices=("encrypted_only", "all"),
        default="encrypted_only",
        help="Whether ML-ready outputs keep only TLS/QUIC rows or all merged rows",
    )
    run_parser.add_argument("--near-constant-threshold", type=float, default=0.995)
    run_parser.add_argument("--correlation-threshold", type=float, default=0.95)
    run_parser.add_argument("--allow-quality-failures", action="store_true", help="Continue even if quality gates fail")
    run_parser.add_argument("--min-merge-match-rate", type=float, default=0.90)
    run_parser.add_argument("--max-unmatched-uid-rate", type=float, default=0.10)
    run_parser.add_argument("--max-non-tls-quic-rate", type=float, default=0.05)
    run_parser.add_argument("--max-duplicate-flow-rate", type=float, default=0.0)
    run_parser.add_argument("--max-duplicate-uid-rate", type=float, default=0.0)
    run_parser.add_argument("--bpf-filter", default=None, help="Optional BPF filter for NFStream extraction")
    run_parser.add_argument("--no-decode-tunnels", action="store_true", help="Disable NFStream tunnel decoding")
    run_parser.add_argument("--no-statistical-analysis", action="store_true", help="Disable NFStream statistical analysis")
    run_parser.add_argument("--splt-analysis", type=int, default=20)
    run_parser.add_argument("--n-meters", type=int, default=4)

    malicious_parser = subparsers.add_parser(
        "run-malicious-pipeline",
        help="Prepare, filter, trace, and process malicious captures through the standardized pipeline.",
    )
    malicious_parser.add_argument("--dataset-name", required=True)
    malicious_parser.add_argument("--input-pcap", required=True)
    malicious_parser.add_argument("--output-dir", required=True)
    malicious_parser.add_argument("--display-filter", default="tls or quic")
    malicious_parser.add_argument("--source-url", default=None)
    malicious_parser.add_argument("--source-rel-path", default=None)
    malicious_parser.add_argument("--manifest-csv", default=None)
    malicious_parser.add_argument("--zeek-log-dir", default=None)
    malicious_parser.add_argument("--zeek-csv-dir", default=None)
    malicious_parser.add_argument("--skip-zeek", action="store_true")
    malicious_parser.add_argument("--prepare-only", action="store_true")
    malicious_parser.add_argument("--extract-nfstream-after-prepare", action="store_true")
    malicious_parser.add_argument("--allow-quality-failures", action="store_true")
    malicious_parser.add_argument("--min-merge-match-rate", type=float, default=0.90)
    malicious_parser.add_argument("--max-unmatched-uid-rate", type=float, default=0.10)
    malicious_parser.add_argument("--max-non-tls-quic-rate", type=float, default=0.05)
    malicious_parser.add_argument("--max-duplicate-flow-rate", type=float, default=0.0)
    malicious_parser.add_argument("--max-duplicate-uid-rate", type=float, default=0.0)
    malicious_parser.add_argument("--merge-tolerance-sec", type=float, default=2.0)
    malicious_parser.add_argument("--near-constant-threshold", type=float, default=0.995)
    malicious_parser.add_argument("--correlation-threshold", type=float, default=0.95)

    canonical_parser = subparsers.add_parser(
        "build-canonical-dataset",
        help="Build the canonical labeled dataset used by training and reporting workflows.",
    )
    canonical_parser.add_argument("--config", required=True, help="YAML config describing the canonical data sources")
    canonical_parser.add_argument("--output-csv", required=True, help="Destination CSV for the canonical labeled dataset")
    canonical_parser.add_argument("--output-summary-json", default=None, help="Optional JSON summary output path")

    ml_parser = subparsers.add_parser(
        "run-ml-workflow",
        help="Train and evaluate NB, RF, and GB on the canonical labeled dataset.",
    )
    ml_parser.add_argument("--config", required=True, help="YAML config describing the ML workflow")
    ml_parser.add_argument("--dataset-csv", default=None, help="Optional override for the canonical dataset CSV")
    ml_parser.add_argument("--output-dir", default=None, help="Optional override for the ML output directory")

    multi_tier_parser = subparsers.add_parser(
        "run-multi-tier",
        help="Run the multi-tier scoring workflow with graph-based endpoint enrichment.",
    )
    multi_tier_parser.add_argument("--config", required=True, help="YAML config describing the multi-tier workflow")
    multi_tier_parser.add_argument("--dataset-csv", default=None, help="Optional canonical dataset CSV override")
    multi_tier_parser.add_argument("--model-bundle-dir", default=None, help="Optional trained model bundle override")
    multi_tier_parser.add_argument("--output-dir", default=None, help="Optional multi-tier output directory override")

    static_dashboard_parser = subparsers.add_parser(
        "export-static-dashboard",
        help="Export a static analytical dashboard data bundle.",
    )
    static_dashboard_parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional output directory for the static dashboard bundle",
    )
    static_dashboard_parser.add_argument(
        "--max-graph-nodes",
        type=int,
        default=36,
        help="Maximum graph nodes to include in the static dashboard export",
    )

    return parser


def handle_info() -> int:
    root = project_root()
    print(f"tls-dataset v{__version__}")
    print(f"project_root={root}")
    print("status=repository scaffold initialized")
    print(
        "production_extractors="
        + ",".join(TECHNICAL_DIRECTION.production_extractors)
    )
    print(
        "thesis_legacy_extractors="
        + ",".join(TECHNICAL_DIRECTION.thesis_legacy_extractors)
    )
    print("next_phase=dependency installation and data-quality validation")
    return 0


def handle_run_dataset_pipeline(args: argparse.Namespace) -> int:
    from tls_dataset.pipeline.orchestration import run_dataset_pipeline

    results = run_dataset_pipeline(
        dataset_name=args.dataset_name,
        output_dir=args.output_dir,
        pcap=args.pcap,
        nfstream_csv=args.nfstream_csv,
        zeek_log_dir=args.zeek_log_dir,
        zeek_csv_dir=args.zeek_csv_dir,
        extract_nfstream=args.extract_nfstream,
        convert_zeek=args.convert_zeek,
        all_zeek_logs=args.all_zeek_logs,
        merge_tolerance_sec=args.merge_tolerance_sec,
        protocol_filter=args.protocol_filter,
        near_const_threshold=args.near_constant_threshold,
        corr_threshold=args.correlation_threshold,
        allow_quality_failures=args.allow_quality_failures,
        min_merge_match_rate=args.min_merge_match_rate,
        max_unmatched_uid_rate=args.max_unmatched_uid_rate,
        max_non_tls_quic_rate=args.max_non_tls_quic_rate,
        max_duplicate_flow_rate=args.max_duplicate_flow_rate,
        max_duplicate_uid_rate=args.max_duplicate_uid_rate,
        decode_tunnels=not args.no_decode_tunnels,
        bpf_filter=args.bpf_filter,
        statistical_analysis=not args.no_statistical_analysis,
        splt_analysis=args.splt_analysis,
        n_meters=args.n_meters,
    )

    for section, payload in results.items():
        print(f"[{section}]")
        if isinstance(payload, dict):
            for key, value in payload.items():
                print(f"{key}={value}")
        else:
            print(payload)
    return 0


def handle_run_malicious_pipeline(args: argparse.Namespace) -> int:
    from tls_dataset.pipeline.malicious import run_malicious_pipeline

    results = run_malicious_pipeline(
        dataset_name=args.dataset_name,
        input_pcap=args.input_pcap,
        output_dir=args.output_dir,
        display_filter=args.display_filter,
        source_url=args.source_url,
        source_rel_path=args.source_rel_path,
        manifest_csv=args.manifest_csv,
        zeek_log_dir=args.zeek_log_dir,
        zeek_csv_dir=args.zeek_csv_dir,
        run_zeek=not args.skip_zeek,
        prepare_only=args.prepare_only,
        extract_nfstream_after_prepare=args.extract_nfstream_after_prepare,
        allow_quality_failures=args.allow_quality_failures,
        min_merge_match_rate=args.min_merge_match_rate,
        max_unmatched_uid_rate=args.max_unmatched_uid_rate,
        max_non_tls_quic_rate=args.max_non_tls_quic_rate,
        max_duplicate_flow_rate=args.max_duplicate_flow_rate,
        max_duplicate_uid_rate=args.max_duplicate_uid_rate,
        merge_tolerance_sec=args.merge_tolerance_sec,
        near_const_threshold=args.near_constant_threshold,
        corr_threshold=args.correlation_threshold,
    )

    for section, payload in results.items():
        print(f"[{section}]")
        print(payload)
    return 0


def handle_build_canonical_dataset(args: argparse.Namespace) -> int:
    from tls_dataset.pipeline.canonical import build_canonical_dataset

    summary = build_canonical_dataset(
        config_path=args.config,
        output_csv=args.output_csv,
        output_summary_json=args.output_summary_json,
    )
    for key, value in summary.items():
        print(f"{key}={value}")
    return 0


def handle_run_ml_workflow(args: argparse.Namespace) -> int:
    from tls_dataset.ml.workflow import run_ml_workflow

    results = run_ml_workflow(
        config_path=args.config,
        dataset_csv_override=args.dataset_csv,
        output_dir_override=args.output_dir,
    )
    for section, payload in results.items():
        print(f"[{section}]")
        print(payload)
    return 0


def handle_run_multi_tier(args: argparse.Namespace) -> int:
    from tls_dataset.detection.multitier import run_multitier_detection

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


def handle_export_static_dashboard(args: argparse.Namespace) -> int:
    from tls_dataset.static_site import export_static_dashboard_bundle

    results = export_static_dashboard_bundle(
        output_dir=args.output_dir,
        max_graph_nodes=args.max_graph_nodes,
    )
    for key, value in results.items():
        print(f"{key}={value}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "info":
        return handle_info()
    if args.command == "run-dataset-pipeline":
        return handle_run_dataset_pipeline(args)
    if args.command == "run-malicious-pipeline":
        return handle_run_malicious_pipeline(args)
    if args.command == "build-canonical-dataset":
        return handle_build_canonical_dataset(args)
    if args.command == "run-ml-workflow":
        return handle_run_ml_workflow(args)
    if args.command == "run-multi-tier":
        return handle_run_multi_tier(args)
    if args.command == "export-static-dashboard":
        return handle_export_static_dashboard(args)

    parser.error(f"Unknown command: {args.command}")
    return 2
