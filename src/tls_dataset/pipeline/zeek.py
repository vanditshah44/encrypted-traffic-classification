#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path

LOGS_OF_INTEREST = ["conn.log", "ssl.log", "tls.log", "x509.log", "quic.log", "http.log"]

def sniff_format(log_path: Path) -> str:
    """
    Returns: "json", "zeek_tsv", or "unknown"
    """
    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for _ in range(50):
            line = f.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            if line.startswith("#fields") or line.startswith("#separator"):
                return "zeek_tsv"
            if line.startswith("{") and line.endswith("}"):
                return "json"
            # Zeek TSV data lines are tab-separated, but header is #fields
            # If we haven't seen headers yet, keep reading.
    return "unknown"

def convert_json_lines_to_csv(log_path: Path, out_csv: Path):
    # First pass: collect keys (columns) safely (cap to avoid insane memory)
    keys = []
    keys_set = set()

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if not (line.startswith("{") and line.endswith("}")):
                continue
            obj = json.loads(line)
            for k in obj.keys():
                if k not in keys_set:
                    keys_set.add(k)
                    keys.append(k)
            # If you want a hard cap, uncomment:
            # if len(keys) > 500: break

    if not keys:
        print(f"[WARN] No JSON objects found in {log_path.name}")
        return

    with out_csv.open("w", newline="", encoding="utf-8") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=keys)
        writer.writeheader()

        with log_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if not (line.startswith("{") and line.endswith("}")):
                    continue
                obj = json.loads(line)
                writer.writerow(obj)

def parse_zeek_tsv_header(log_path: Path):
    """
    Parses Zeek default log format and returns:
      separator (str), fields (list[str])
    """
    separator = "\t"
    fields = None

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#separator"):
                # Example: "#separator \x09"
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    sep_token = parts[1]
                    # Zeek writes \x09 for tab
                    if "\\x09" in sep_token:
                        separator = "\t"
                    else:
                        # fallback: try literal
                        separator = sep_token.encode("utf-8").decode("unicode_escape")
            elif line.startswith("#fields"):
                parts = line.split()
                fields = parts[1:]
                break

    return separator, fields

def convert_zeek_tsv_to_csv(log_path: Path, out_csv: Path):
    sep, fields = parse_zeek_tsv_header(log_path)
    if not fields:
        print(f"[WARN] Could not find #fields in {log_path.name}")
        return

    with out_csv.open("w", newline="", encoding="utf-8") as out_f:
        writer = csv.writer(out_f)
        writer.writerow(fields)

        with log_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                row = line.split(sep)
                # Some lines may have fewer columns; pad
                if len(row) < len(fields):
                    row += [""] * (len(fields) - len(row))
                writer.writerow(row[:len(fields)])

def convert_zeek_logs(
    zeek_dir: str | Path,
    out_dir: str | Path,
    *,
    all_logs: bool = False,
) -> list[str]:
    zeek_dir = Path(zeek_dir).expanduser().resolve()
    out_dir = Path(out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not zeek_dir.exists():
        raise FileNotFoundError(f"Zeek directory not found: {zeek_dir}")

    if all_logs:
        log_files = sorted(zeek_dir.glob("*.log"))
    else:
        log_files = [zeek_dir / name for name in LOGS_OF_INTEREST]

    log_files = [p for p in log_files if p.exists()]

    if not log_files:
        print("[ERROR] No .log files found to convert.")
        return

    print(f"Zeek dir : {zeek_dir}")
    print(f"Out dir  : {out_dir}")
    print(f"Files    : {len(log_files)}")
    print("-" * 40)

    written_files: list[str] = []
    for p in log_files:
        fmt = sniff_format(p)
        out_csv = out_dir / (p.stem + ".csv")
        print(f"Converting {p.name} -> {out_csv.name} (format={fmt})")

        try:
            if fmt == "json":
                convert_json_lines_to_csv(p, out_csv)
            elif fmt == "zeek_tsv":
                convert_zeek_tsv_to_csv(p, out_csv)
            else:
                print(f"[WARN] Unknown format, skipping: {p.name}")
                continue
        except Exception as e:
            print(f"[ERROR] Failed converting {p.name}: {e}")
            continue
        written_files.append(str(out_csv))

    print("\nDone. CSVs are in:", out_dir)
    return written_files

def main(argv: list[str] | None = None):
    ap = argparse.ArgumentParser(description="Convert Zeek .log files (JSON or default TSV) to CSV")
    ap.add_argument("--zeek-dir", required=True, help="Folder containing Zeek .log files")
    ap.add_argument("--out-dir", required=True, help="Output folder for CSV files")
    ap.add_argument("--all", action="store_true",
                    help="Convert ALL .log files in the directory (not just conn/ssl/x509/quic/http)")
    args = ap.parse_args(argv)

    written_files = convert_zeek_logs(args.zeek_dir, args.out_dir, all_logs=args.all)
    print(f"written_files={len(written_files)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
