#!/usr/bin/env python3
"""NFStream extraction utilities."""

from __future__ import annotations

import argparse
from pathlib import Path

from nfstream import NFStreamer


def extract_nfstream_csv(
    pcap_file: str | Path,
    output_csv: str | Path,
    *,
    decode_tunnels: bool = True,
    bpf_filter: str | None = None,
    statistical_analysis: bool = True,
    splt_analysis: int = 20,
    n_meters: int = 4,
) -> int:
    source = Path(pcap_file).expanduser().resolve()
    output = Path(output_csv).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    streamer = NFStreamer(
        source=str(source),
        decode_tunnels=decode_tunnels,
        bpf_filter=bpf_filter,
        statistical_analysis=statistical_analysis,
        splt_analysis=splt_analysis,
        n_meters=n_meters,
    )

    total_flows = streamer.to_csv(str(output))
    return int(total_flows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract NFStream features from a PCAP file")
    parser.add_argument("--pcap", required=True, help="Input PCAP/PCAPNG file")
    parser.add_argument("--output", required=True, help="Output NFStream CSV path")
    parser.add_argument("--bpf-filter", default=None, help="Optional BPF filter")
    parser.add_argument("--no-decode-tunnels", action="store_true", help="Disable tunnel decoding")
    parser.add_argument("--no-statistical-analysis", action="store_true", help="Disable statistical analysis")
    parser.add_argument("--splt-analysis", type=int, default=20, help="SPLT analysis depth")
    parser.add_argument("--n-meters", type=int, default=4, help="Number of NFStream meters")
    args = parser.parse_args(argv)

    total_flows = extract_nfstream_csv(
        pcap_file=args.pcap,
        output_csv=args.output,
        decode_tunnels=not args.no_decode_tunnels,
        bpf_filter=args.bpf_filter,
        statistical_analysis=not args.no_statistical_analysis,
        splt_analysis=args.splt_analysis,
        n_meters=args.n_meters,
    )

    print(f"Extraction completed: {Path(args.output).expanduser().resolve()}")
    print(f"Total flows: {total_flows}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
