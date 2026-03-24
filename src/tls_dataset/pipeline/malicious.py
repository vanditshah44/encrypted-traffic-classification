"""Malicious capture preparation and end-to-end orchestration."""

from __future__ import annotations

import argparse
import csv
import shutil
from pathlib import Path

from tls_dataset.pipeline.common import build_dataset_artifacts
from tls_dataset.pipeline.filtering import filter_encrypted_pcap, sanitize_pcap
from tls_dataset.pipeline.nfstream import extract_nfstream_csv
from tls_dataset.pipeline.orchestration import run_dataset_pipeline
from tls_dataset.pipeline.provenance import ProvenanceEntry, build_provenance_entry, write_provenance
from tls_dataset.pipeline.zeek_runner import run_zeek_on_pcap, zeek_available


def resolve_manifest_source(
    input_pcap: str | Path,
    manifest_csv: str | Path | None,
) -> tuple[str | None, str | None]:
    if manifest_csv is None:
        return None, None

    target = Path(input_pcap).expanduser().resolve()
    manifest_path = Path(manifest_csv).expanduser().resolve()
    if not manifest_path.exists():
        return None, None

    with manifest_path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            local_path = row.get("local_path", "")
            rel_path = row.get("rel_path", "")
            candidates = {
                Path(local_path).name if local_path else "",
                Path(rel_path).name if rel_path else "",
            }
            if target.name in candidates or str(target) == local_path:
                return row.get("url") or None, row.get("rel_path") or None

    return None, None


def _copy_raw_capture(input_pcap: str | Path, output_pcap: str | Path) -> Path:
    source = Path(input_pcap).expanduser().resolve()
    target = Path(output_pcap).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if source != target:
        shutil.copy2(source, target)
    return target


def prepare_malicious_capture(
    *,
    dataset_name: str,
    input_pcap: str | Path,
    output_dir: str | Path,
    display_filter: str = "tls or quic",
    source_url: str | None = None,
    source_rel_path: str | None = None,
    manifest_csv: str | Path | None = None,
) -> dict[str, object]:
    artifacts = build_dataset_artifacts(dataset_name=dataset_name, output_dir=output_dir)
    artifacts.output_dir.mkdir(parents=True, exist_ok=True)
    manifest_source_url, manifest_source_rel_path = resolve_manifest_source(input_pcap, manifest_csv)
    resolved_source_url = source_url or manifest_source_url
    resolved_source_rel_path = source_rel_path or manifest_source_rel_path

    raw_copy = _copy_raw_capture(input_pcap, artifacts.raw_pcap)
    sanitize_result = sanitize_pcap(raw_copy, artifacts.sanitized_pcap)
    filter_result = filter_encrypted_pcap(artifacts.sanitized_pcap, artifacts.filtered_pcap, display_filter=display_filter)

    provenance_entries: list[ProvenanceEntry] = [
        build_provenance_entry(
            stage="raw_capture",
            path=raw_copy,
            source_url=resolved_source_url,
            source_rel_path=resolved_source_rel_path,
            notes="Original malicious source capture copied into the managed run directory.",
        ),
        build_provenance_entry(
            stage="sanitized_capture",
            path=artifacts.sanitized_pcap,
            parent_path=raw_copy,
            tool="editcap",
            tool_version=sanitize_result["tool_version"],
            command=sanitize_result["command"],
            notes=sanitize_result["stderr"] or "Sanitized with editcap.",
        ),
        build_provenance_entry(
            stage="filtered_capture",
            path=artifacts.filtered_pcap,
            parent_path=artifacts.sanitized_pcap,
            tool="tshark",
            tool_version=filter_result["tool_version"],
            command=filter_result["command"],
            notes=f"Display filter: {display_filter}",
        ),
    ]

    write_provenance(provenance_entries, artifacts.provenance_json)
    return {
        "artifacts": artifacts.as_dict(),
        "sanitize": sanitize_result,
        "filter": filter_result,
        "provenance_entries": len(provenance_entries),
    }


def run_malicious_pipeline(
    *,
    dataset_name: str,
    input_pcap: str | Path,
    output_dir: str | Path,
    display_filter: str = "tls or quic",
    source_url: str | None = None,
    source_rel_path: str | None = None,
    manifest_csv: str | Path | None = None,
    zeek_log_dir: str | Path | None = None,
    zeek_csv_dir: str | Path | None = None,
    run_zeek: bool = True,
    prepare_only: bool = False,
    extract_nfstream_after_prepare: bool = False,
    allow_quality_failures: bool = False,
    min_merge_match_rate: float = 0.90,
    max_unmatched_uid_rate: float = 0.10,
    max_non_tls_quic_rate: float = 0.05,
    max_duplicate_flow_rate: float = 0.0,
    max_duplicate_uid_rate: float = 0.0,
    merge_tolerance_sec: float = 2.0,
    near_const_threshold: float = 0.995,
    corr_threshold: float = 0.95,
) -> dict[str, object]:
    prepare_results = prepare_malicious_capture(
        dataset_name=dataset_name,
        input_pcap=input_pcap,
        output_dir=output_dir,
        display_filter=display_filter,
        source_url=source_url,
        source_rel_path=source_rel_path,
        manifest_csv=manifest_csv,
    )
    artifacts = build_dataset_artifacts(dataset_name=dataset_name, output_dir=output_dir)
    processing_pcap = artifacts.sanitized_pcap
    prepare_nfstream: dict[str, object] | None = None
    if extract_nfstream_after_prepare:
        total_flows = extract_nfstream_csv(processing_pcap, artifacts.nfstream_csv)
        prepare_nfstream = {
            "pcap": str(Path(processing_pcap).expanduser().resolve()),
            "nfstream_csv": str(Path(artifacts.nfstream_csv).expanduser().resolve()),
            "flows": int(total_flows),
        }
    if prepare_only:
        return {
            "prepare": prepare_results,
            "prepare_nfstream": prepare_nfstream,
            "zeek": None,
            "pipeline": None,
        }

    zeek_stage: dict[str, str] | None = None
    resolved_zeek_log_dir: str | Path | None = zeek_log_dir
    if run_zeek:
        if not zeek_available():
            raise FileNotFoundError(
                "zeek binary not found on PATH. Provide --zeek-log-dir/--zeek-csv-dir or run on a host with Zeek installed."
            )
        resolved_zeek_log_dir = artifacts.zeek_log_dir
        zeek_stage = run_zeek_on_pcap(processing_pcap, resolved_zeek_log_dir)

        existing = Path(artifacts.provenance_json).expanduser().resolve()
        payload = existing.read_text(encoding="utf-8")
        # Reuse the tracked provenance list and append the Zeek stage.
        import json
        data = json.loads(payload)
        data["entries"].append({
            "stage": "zeek_logs",
            "path": str(Path(resolved_zeek_log_dir).expanduser().resolve()),
            "sha256": "",
            "size_bytes": 0,
            "parent_path": str(Path(processing_pcap).expanduser().resolve()),
            "source_url": source_url,
            "source_rel_path": source_rel_path,
            "tool": "zeek",
            "tool_version": zeek_stage["tool_version"],
            "command": zeek_stage["command"],
            "notes": "Zeek log directory generated from the sanitized malicious capture.",
        })
        existing.write_text(json.dumps(data, indent=2), encoding="utf-8")

    pipeline_results = run_dataset_pipeline(
        dataset_name=dataset_name,
        output_dir=output_dir,
        pcap=processing_pcap,
        nfstream_csv=None,
        zeek_log_dir=resolved_zeek_log_dir,
        zeek_csv_dir=zeek_csv_dir,
        extract_nfstream=True,
        convert_zeek=resolved_zeek_log_dir is not None and zeek_csv_dir is None,
        all_zeek_logs=False,
        merge_tolerance_sec=merge_tolerance_sec,
        protocol_filter="encrypted_only",
        near_const_threshold=near_const_threshold,
        corr_threshold=corr_threshold,
        allow_quality_failures=allow_quality_failures,
        min_merge_match_rate=min_merge_match_rate,
        max_unmatched_uid_rate=max_unmatched_uid_rate,
        max_non_tls_quic_rate=max_non_tls_quic_rate,
        max_duplicate_flow_rate=max_duplicate_flow_rate,
        max_duplicate_uid_rate=max_duplicate_uid_rate,
    )

    return {
        "prepare": prepare_results,
        "zeek": zeek_stage,
        "pipeline": pipeline_results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare and run the malicious capture pipeline end to end")
    parser.add_argument("--dataset-name", required=True)
    parser.add_argument("--input-pcap", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--display-filter", default="tls or quic")
    parser.add_argument("--source-url", default=None)
    parser.add_argument("--source-rel-path", default=None)
    parser.add_argument("--manifest-csv", default=None, help="Optional downloader manifest used to infer source provenance")
    parser.add_argument("--zeek-log-dir", default=None, help="Reuse an existing malicious Zeek log directory")
    parser.add_argument("--zeek-csv-dir", default=None, help="Reuse an existing malicious Zeek CSV directory")
    parser.add_argument("--skip-zeek", action="store_true", help="Skip running Zeek locally")
    parser.add_argument("--prepare-only", action="store_true", help="Only sanitize, filter, and record provenance")
    parser.add_argument("--extract-nfstream-after-prepare", action="store_true")
    parser.add_argument("--allow-quality-failures", action="store_true")
    args = parser.parse_args(argv)

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
    )
    for section, payload in results.items():
        print(f"[{section}]")
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
