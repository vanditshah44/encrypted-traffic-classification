"""Data-quality gates for pre-feature-generation validation."""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

TRUNCATION_MARKERS = (
    "appears to have been cut short",
    "cut short in the middle of a packet",
    "middle of a packet",
)

FLOW_KEY_COLUMNS = (
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "bidirectional_first_seen_ms",
)

TLS_SIGNAL_COLUMNS = ("version", "cipher", "server_name", "ja3", "ja3s")
QUIC_SIGNAL_TOKENS = ("quic", "cid", "scid", "dcid", "h3", "http3")


@dataclass(frozen=True)
class GateOutcome:
    name: str
    status: str
    message: str
    metrics: dict[str, object] = field(default_factory=dict)


@dataclass
class QualityReport:
    dataset_name: str
    outcomes: list[GateOutcome] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(outcome.status == "fail" for outcome in self.outcomes)

    def add(self, outcome: GateOutcome) -> None:
        self.outcomes.append(outcome)

    def to_dict(self) -> dict[str, object]:
        return {
            "dataset_name": self.dataset_name,
            "failed": self.failed,
            "outcomes": [asdict(outcome) for outcome in self.outcomes],
        }

    def write(self, output_path: str | Path) -> None:
        target = Path(output_path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


def is_truncation_warning(stderr_text: str) -> bool:
    lowered = stderr_text.lower()
    return any(marker in lowered for marker in TRUNCATION_MARKERS)


def _is_present(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower()
    return normalized not in ("", "nan", "none", "null")


def row_has_encrypted_signal(row: Mapping[str, str], fieldnames: Iterable[str]) -> bool:
    if any(_is_present(row.get(column)) for column in TLS_SIGNAL_COLUMNS):
        return True

    for fieldname in fieldnames:
        lowered = fieldname.lower()
        if any(token in lowered for token in QUIC_SIGNAL_TOKENS) and _is_present(row.get(fieldname)):
            return True
    return False


def check_pcap_health(pcap_path: str | Path) -> GateOutcome:
    path = Path(pcap_path).expanduser().resolve()
    if not path.exists():
        return GateOutcome("pcap_health", "fail", f"PCAP file does not exist: {path}")

    capinfos = shutil.which("capinfos")
    if capinfos is None:
        return GateOutcome("pcap_health", "warn", "capinfos is not available; truncation check skipped", {"pcap": str(path)})

    result = subprocess.run(
        [capinfos, "-Tm", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    truncated = is_truncation_warning(result.stderr)
    metrics: dict[str, object] = {"pcap": str(path), "capinfos_returncode": result.returncode}

    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) >= 2:
        reader = csv.DictReader(lines)
        first_row = next(reader, None)
        if first_row is not None:
            for key in ("Number of packets", "Capture duration (seconds)", "File size (bytes)"):
                if key in first_row:
                    metrics[key] = first_row[key]

    if truncated:
        return GateOutcome("pcap_health", "fail", "PCAP appears truncated according to capinfos", metrics)
    if result.returncode != 0:
        return GateOutcome("pcap_health", "warn", "capinfos returned a non-zero status without a truncation marker", metrics)
    return GateOutcome("pcap_health", "pass", "PCAP passed truncation checks", metrics)


def check_zeek_outputs(zeek_csv_dir: str | Path) -> GateOutcome:
    path = Path(zeek_csv_dir).expanduser().resolve()
    required = {"conn.csv"}
    encrypted_evidence = {"ssl.csv", "tls.csv", "quic.csv"}

    if not path.exists():
        return GateOutcome("zeek_outputs", "fail", f"Zeek CSV directory does not exist: {path}")

    present = {child.name for child in path.glob("*.csv")}
    missing_required = sorted(required - present)
    has_encrypted_evidence = bool(encrypted_evidence & present)
    metrics = {
        "zeek_csv_dir": str(path),
        "present_files": sorted(present),
        "missing_required": missing_required,
    }

    if missing_required:
        return GateOutcome("zeek_outputs", "fail", "Required Zeek CSV files are missing", metrics)
    if not has_encrypted_evidence:
        return GateOutcome("zeek_outputs", "fail", "None of ssl.csv, tls.csv, or quic.csv is present", metrics)
    return GateOutcome("zeek_outputs", "pass", "Required Zeek CSV files are present", metrics)


def check_nfstream_csv(
    nfstream_csv: str | Path,
    *,
    max_duplicate_flow_rate: float = 0.0,
) -> GateOutcome:
    path = Path(nfstream_csv).expanduser().resolve()
    if not path.exists():
        return GateOutcome("nfstream_csv", "fail", f"NFStream CSV does not exist: {path}")

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        missing_columns = [column for column in FLOW_KEY_COLUMNS if column not in fieldnames]
        if missing_columns:
            return GateOutcome(
                "nfstream_csv",
                "fail",
                "NFStream CSV is missing required columns",
                {"nfstream_csv": str(path), "missing_columns": missing_columns},
            )

        total_rows = 0
        duplicate_rows = 0
        seen_keys: set[tuple[str, ...]] = set()
        for row in reader:
            total_rows += 1
            flow_key = tuple(row[column] for column in FLOW_KEY_COLUMNS)
            if flow_key in seen_keys:
                duplicate_rows += 1
            else:
                seen_keys.add(flow_key)

    duplicate_rate = (duplicate_rows / total_rows) if total_rows else 0.0
    metrics = {
        "nfstream_csv": str(path),
        "rows": total_rows,
        "duplicate_flow_rows": duplicate_rows,
        "duplicate_flow_rate": duplicate_rate,
    }
    if duplicate_rate > max_duplicate_flow_rate:
        return GateOutcome("nfstream_csv", "fail", "NFStream CSV contains duplicate flow keys", metrics)
    return GateOutcome("nfstream_csv", "pass", "NFStream CSV passed duplicate-flow checks", metrics)


def check_merged_dataset(
    merged_csv: str | Path,
    *,
    min_match_rate: float = 0.90,
    max_unmatched_uid_rate: float = 0.10,
    max_non_tls_quic_rate: float = 0.05,
    max_duplicate_uid_rate: float = 0.0,
) -> GateOutcome:
    path = Path(merged_csv).expanduser().resolve()
    if not path.exists():
        return GateOutcome("merged_dataset", "fail", f"Merged CSV does not exist: {path}")

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        if "uid" not in fieldnames:
            return GateOutcome("merged_dataset", "fail", "Merged CSV does not contain a uid column", {"merged_csv": str(path)})

        total_rows = 0
        matched_rows = 0
        unmatched_rows = 0
        non_encrypted_rows = 0
        uid_counts: dict[str, int] = {}

        for row in reader:
            total_rows += 1
            uid_value = row.get("uid", "")
            if _is_present(uid_value):
                matched_rows += 1
                uid_counts[uid_value] = uid_counts.get(uid_value, 0) + 1
            else:
                unmatched_rows += 1

            if not row_has_encrypted_signal(row, fieldnames):
                non_encrypted_rows += 1

    duplicate_uid_rows = sum(count - 1 for count in uid_counts.values() if count > 1)
    match_rate = (matched_rows / total_rows) if total_rows else 0.0
    unmatched_rate = (unmatched_rows / total_rows) if total_rows else 0.0
    non_encrypted_rate = (non_encrypted_rows / total_rows) if total_rows else 0.0
    duplicate_uid_rate = (duplicate_uid_rows / total_rows) if total_rows else 0.0

    metrics = {
        "merged_csv": str(path),
        "rows": total_rows,
        "matched_rows": matched_rows,
        "unmatched_rows": unmatched_rows,
        "match_rate": match_rate,
        "unmatched_uid_rate": unmatched_rate,
        "non_tls_quic_rows": non_encrypted_rows,
        "non_tls_quic_rate": non_encrypted_rate,
        "duplicate_uid_rows": duplicate_uid_rows,
        "duplicate_uid_rate": duplicate_uid_rate,
    }

    failures: list[str] = []
    if match_rate < min_match_rate:
        failures.append(f"match_rate<{min_match_rate}")
    if unmatched_rate > max_unmatched_uid_rate:
        failures.append(f"unmatched_uid_rate>{max_unmatched_uid_rate}")
    if non_encrypted_rate > max_non_tls_quic_rate:
        failures.append(f"non_tls_quic_rate>{max_non_tls_quic_rate}")
    if duplicate_uid_rate > max_duplicate_uid_rate:
        failures.append(f"duplicate_uid_rate>{max_duplicate_uid_rate}")

    if failures:
        return GateOutcome("merged_dataset", "fail", "Merged dataset failed quality gates: " + ", ".join(failures), metrics)
    return GateOutcome("merged_dataset", "pass", "Merged dataset passed join and leakage checks", metrics)


def raise_for_failed_gates(report: QualityReport) -> None:
    if not report.failed:
        return
    failing = [f"{outcome.name}: {outcome.message}" for outcome in report.outcomes if outcome.status == "fail"]
    raise RuntimeError("Quality gates failed: " + " | ".join(failing))
