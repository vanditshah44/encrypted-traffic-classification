#!/usr/bin/env python3
import argparse
from pathlib import Path
from scapy.utils import RawPcapReader, RawPcapNgReader, PcapWriter

PCAP_EXTS = {".pcap", ".pcapng", ".cap"}

def iter_packets(pcap_path: Path):
    ext = pcap_path.suffix.lower()

    if ext in {".pcap", ".cap"}:
        reader = RawPcapReader(str(pcap_path))
    elif ext == ".pcapng":
        reader = RawPcapNgReader(str(pcap_path))
    else:
        raise ValueError(f"Unsupported file: {pcap_path}")

    try:
        for pkt, meta in reader:
            yield pkt
    finally:
        reader.close()

def merge_pcaps(
    input_dir: str | Path,
    output_pcap: str | Path,
    *,
    delete_source: bool = False,
) -> dict[str, str | int]:
    input_dir = Path(input_dir).expanduser().resolve()
    output_pcap = Path(output_pcap).expanduser().resolve()

    if not input_dir.exists():
        raise FileNotFoundError(input_dir)

    # ✅ Recursive search
    pcaps = sorted([p for p in input_dir.rglob("*") if p.is_file() and p.suffix.lower() in PCAP_EXTS])

    if not pcaps:
        raise RuntimeError(f"No PCAP files found under: {input_dir}")

    print(f"Found {len(pcaps)} PCAP files")
    for p in pcaps[:30]:
        print("  -", p.relative_to(input_dir))
    if len(pcaps) > 30:
        print(f"  ... and {len(pcaps) - 30} more")

    # Ensure output directory exists
    output_pcap.parent.mkdir(parents=True, exist_ok=True)

    # Write output
    writer = PcapWriter(str(output_pcap), append=False, sync=True)

    total_packets = 0

    try:
        for idx, pcap in enumerate(pcaps, 1):
            print(f"[{idx}/{len(pcaps)}] Merging {pcap.relative_to(input_dir)}")

            file_packets = 0
            for pkt in iter_packets(pcap):
                writer.write(pkt)
                total_packets += 1
                file_packets += 1

            print(f"    -> merged packets: {file_packets}")

            # ✅ Delete only after successfully finishing this file
            if delete_source:
                try:
                    pcap.unlink()
                    print(f"    -> deleted: {pcap.relative_to(input_dir)}")
                except Exception as e:
                    print(f"    [WARN] Could not delete {pcap}: {e}")

    finally:
        writer.close()

    print("\nMerge completed")
    print(f"Output file : {output_pcap}")
    print(f"Packets     : {total_packets}")
    return {
        "input_dir": str(input_dir),
        "output_pcap": str(output_pcap),
        "pcap_files": int(len(pcaps)),
        "total_packets": int(total_packets),
    }

def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="Merge multiple PCAP/PCAPNG files into one PCAP")
    parser.add_argument("--input-dir", required=True, help="Directory containing pcaps (nested allowed)")
    parser.add_argument("--output", required=True, help="Output merged pcap file")
    parser.add_argument("--delete-source", action="store_true",
                        help="Delete each source pcap after it is merged successfully")
    args = parser.parse_args(argv)

    merge_pcaps(args.input_dir, args.output, delete_source=args.delete_source)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
