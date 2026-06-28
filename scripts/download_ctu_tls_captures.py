#!/usr/bin/env python3
"""
Download additional CTU-Malware botnet PCAP captures known to contain TLS traffic.

These captures supplement the existing malicious source to provide multiple distinct
capture sessions (needed for capture-aware cross-validation and honest generalization).

Usage:
    python scripts/download_ctu_tls_captures.py --out data/mcfp_malicious/ --list-only
    python scripts/download_ctu_tls_captures.py --out data/mcfp_malicious/

After downloading, add each capture as a new source in configs/canonical_sources.yaml
and re-run the malicious pipeline, then re-run the canonical builder.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from tls_dataset.pipeline.download import main as _downloader_main

# CTU-Malware PCAP captures known to produce TLS/HTTPS traffic from C&C botnet activity.
# These capture numbers were selected based on published CTU dataset descriptions that
# list TLS/HTTPS as the primary C&C protocol.
#
# Reference: https://mcfp.felk.cvut.cz/publicDatasets/
#
# NOTE: Verify each capture before adding to canonical_sources.yaml:
#   1. Run through malicious pipeline
#   2. Check zeek output — if ssl.csv exists, quality_status=ok
#   3. If only conn.csv, the capture uses non-standard TLS (still usable but note it)
KNOWN_TLS_BOTNET_DIRS = [
    "CTU-Malware-Capture-Botnet-34",   # Ramnit: HTTPS C&C
    "CTU-Malware-Capture-Botnet-36",   # Ramnit variant: HTTPS
    "CTU-Malware-Capture-Botnet-37",   # Ramnit variant: HTTPS
    "CTU-Malware-Capture-Botnet-44",   # Virut: HTTPS C&C
    "CTU-Malware-Capture-Botnet-52",   # Mixed TLS/HTTP botnet
    "CTU-Malware-Capture-Botnet-53",   # TLS C&C exfil
    "CTU-Malware-Capture-Botnet-54",   # TLS exfiltration
    "CTU-Malware-Capture-Botnet-110",  # Recent HTTPS botnet
    "CTU-Malware-Capture-Botnet-111",  # Recent HTTPS botnet
    "CTU-Malware-Capture-Botnet-112",  # Recent HTTPS botnet
]


def build_argv(out_dir: str, list_only: bool) -> list[str]:
    # argparse only keeps the last --include-dirs value, so join into one regex
    include_pattern = "|".join(re.escape(d) for d in KNOWN_TLS_BOTNET_DIRS)
    argv = [
        "--base-url", "https://mcfp.felk.cvut.cz/publicDatasets/",
        "--out", out_dir,
        "--sleep", "0.5",
        "--include-dirs", include_pattern,
    ]
    if list_only:
        argv.append("--list-only")
    return argv


def main() -> int:
    parser = argparse.ArgumentParser(description="Download CTU malware PCAP captures with TLS traffic")
    parser.add_argument("--out", default="data/mcfp_malicious", help="Output directory for downloaded PCAPs")
    parser.add_argument("--list-only", action="store_true", help="Dry-run: list files without downloading")
    args = parser.parse_args()

    out_path = Path(args.out).expanduser().resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    print(f"Target captures: {', '.join(KNOWN_TLS_BOTNET_DIRS)}")
    print(f"Output directory: {out_path}")
    if args.list_only:
        print("DRY RUN — listing only, no download")
    print()

    sys.argv = ["download"] + build_argv(str(out_path), args.list_only)
    return _downloader_main()


if __name__ == "__main__":
    raise SystemExit(main())
