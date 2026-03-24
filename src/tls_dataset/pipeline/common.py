"""Shared helpers for dataset pipeline orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DatasetArtifacts:
    dataset_name: str
    output_dir: Path
    raw_pcap: Path
    sanitized_pcap: Path
    filtered_pcap: Path
    zeek_log_dir: Path
    quality_report_json: Path
    provenance_json: Path
    zeek_csv_dir: Path
    nfstream_csv: Path
    merged_csv: Path
    all_merged_csv: Path
    tls_csv: Path
    quic_csv: Path
    ml_ready_csv: Path
    ml_no_constant_csv: Path
    ml_no_constant_novar_csv: Path
    ml_pruned_csv: Path
    ml_final_csv: Path

    def as_dict(self) -> dict[str, str]:
        return {
            "dataset_name": self.dataset_name,
            "output_dir": str(self.output_dir),
            "raw_pcap": str(self.raw_pcap),
            "sanitized_pcap": str(self.sanitized_pcap),
            "filtered_pcap": str(self.filtered_pcap),
            "zeek_log_dir": str(self.zeek_log_dir),
            "quality_report_json": str(self.quality_report_json),
            "provenance_json": str(self.provenance_json),
            "zeek_csv_dir": str(self.zeek_csv_dir),
            "nfstream_csv": str(self.nfstream_csv),
            "merged_csv": str(self.merged_csv),
            "all_merged_csv": str(self.all_merged_csv),
            "tls_csv": str(self.tls_csv),
            "quic_csv": str(self.quic_csv),
            "ml_ready_csv": str(self.ml_ready_csv),
            "ml_no_constant_csv": str(self.ml_no_constant_csv),
            "ml_no_constant_novar_csv": str(self.ml_no_constant_novar_csv),
            "ml_pruned_csv": str(self.ml_pruned_csv),
            "ml_final_csv": str(self.ml_final_csv),
        }


def build_dataset_artifacts(dataset_name: str, output_dir: str | Path) -> DatasetArtifacts:
    out_dir = Path(output_dir).expanduser().resolve()

    return DatasetArtifacts(
        dataset_name=dataset_name,
        output_dir=out_dir,
        raw_pcap=out_dir / f"{dataset_name}_raw.pcapng",
        sanitized_pcap=out_dir / f"{dataset_name}_sanitized.pcapng",
        filtered_pcap=out_dir / f"{dataset_name}_filtered_tls_quic.pcapng",
        zeek_log_dir=out_dir / f"{dataset_name}_zeek_logs",
        quality_report_json=out_dir / f"{dataset_name}_quality_report.json",
        provenance_json=out_dir / f"{dataset_name}_provenance.json",
        zeek_csv_dir=out_dir / f"{dataset_name}_zeek_csv",
        nfstream_csv=out_dir / f"{dataset_name}_nfstream.csv",
        merged_csv=out_dir / f"{dataset_name}_merged.csv",
        all_merged_csv=out_dir / f"{dataset_name}_all_merged.csv",
        tls_csv=out_dir / f"{dataset_name}_tls.csv",
        quic_csv=out_dir / f"{dataset_name}_quic.csv",
        ml_ready_csv=out_dir / f"{dataset_name}_ml_ready.csv",
        ml_no_constant_csv=out_dir / f"{dataset_name}_ml_no_constant.csv",
        ml_no_constant_novar_csv=out_dir / f"{dataset_name}_ml_no_constant_novar.csv",
        ml_pruned_csv=out_dir / f"{dataset_name}_ml_pruned.csv",
        ml_final_csv=out_dir / f"{dataset_name}_ml_final.csv",
    )
