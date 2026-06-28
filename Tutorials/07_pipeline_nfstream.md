# Tutorial 07 — NFStream Feature Extraction (`pipeline/nfstream.py`)

## Prerequisites

- Tutorial 03 (`common.py`) — you know about `DatasetArtifacts` and the artifact path
  `nfstream_csv`
- Tutorial 04 (`filtering.py`) — you know the pipeline produces a filtered PCAP at
  `artifacts.filtered_pcap`
- Tutorial 05 & 06 (Zeek) — you know what Zeek extracts. NFStream is the complementary source.

---

## 1. Why Does This File Exist? The Two-Source Philosophy

The thesis project extracts features from PCAPs using **two completely different tools** that do
fundamentally different things:

| Tool | What it sees | What it extracts | Output |
|------|-------------|-----------------|--------|
| **Zeek** | Individual packets, protocol dissection | TLS metadata: cipher, SNI, JA3, certificates | Per-connection logs keyed by `uid` |
| **NFStream** | Bidirectional flows (grouped packets) | Statistical summaries: byte counts, timing, inter-arrival times, payload length distributions | One row per flow |

**The key insight:** Zeek and NFStream are *complementary*, not redundant.

- Zeek tells you **what** was negotiated in the TLS handshake (cipher suite, SNI, JA3 hash).
- NFStream tells you **how** the connection behaved over time (how fast did packets arrive? how much data? was the flow long or short? was it bursty?).

Malicious traffic often has distinctive *behavioral* patterns even if the TLS handshake looks
legitimate. A C2 (command-and-control) beacon checking in every 60 seconds has a very different
inter-arrival time profile from a human browsing a website — NFStream captures exactly that.

**Why not just Zeek for everything?**

Zeek is a protocol analyser. It understands TLS structures deeply. But it does NOT compute:
- Standard deviation of packet sizes across a flow
- Mean inter-arrival time between packets
- Kurtosis of the payload length distribution
- Packet length sequences for the first N packets

These are time-series statistical features that require buffering all packets in a flow and
computing summaries. NFStream does this efficiently.

**Why not just NFStream for everything?**

NFStream does not parse TLS protocol fields. It cannot extract the SNI, cipher suite, JA3
fingerprint, or certificate details. Those require deep protocol dissection. Zeek does that.

**The formal decision is in ADR 0001** (`docs/adr/0001-feature-extraction-stack.md`):
> "The official production extraction stack is: Zeek as the authoritative source for TLS 1.3 and
> QUIC protocol-aware metadata; NFStream as the authoritative source for bidirectional statistical
> flow features."

The project formally rejected CICFlowMeter (a Java-based flow extractor commonly used in academic
network ML papers) in favour of NFStream because:
1. NFStream is Python-native — no JVM dependency
2. NFStream is actively maintained and handles modern protocols including QUIC
3. NFStream integrates nDPI for application-level protocol identification
4. The existing pipeline scripts were already built on NFStream

---

## 2. What is a Network Flow? (The Concept NFStream Operates On)

Before understanding NFStream, you must understand what a **network flow** is, because it is a
fundamentally different unit than a **packet**.

### Packet vs Flow

```
Timeline (wireshark view of a single TLS connection):
  t=0.000  [SYN]            src: 192.168.1.5:54321  dst: 1.2.3.4:443  len=60
  t=0.001  [SYN-ACK]        src: 1.2.3.4:443        dst: 192.168.1.5:54321  len=60
  t=0.002  [ACK]            src: 192.168.1.5:54321  dst: 1.2.3.4:443  len=54
  t=0.003  [TLS ClientHello] src: 192.168.1.5:54321  dst: 1.2.3.4:443  len=517
  t=0.012  [TLS ServerHello] src: 1.2.3.4:443        dst: 192.168.1.5:54321  len=1448
  ...
  t=5.342  [FIN]            src: 192.168.1.5:54321  dst: 1.2.3.4:443  len=54
  t=5.343  [FIN-ACK]        src: 1.2.3.4:443        dst: 192.168.1.5:54321  len=54

A FLOW is all these packets collapsed into ONE summary row:
  src_ip = 192.168.1.5
  dst_ip = 1.2.3.4
  src_port = 54321
  dst_port = 443
  protocol = TCP (6)
  bidirectional_first_seen_ms = 0
  bidirectional_last_seen_ms = 5343
  bidirectional_duration_ms = 5343
  bidirectional_packets = 12
  bidirectional_bytes = 23450
  src2dst_packets = 7       ← packets from client to server
  dst2src_packets = 5       ← packets from server to client
  src2dst_bytes = 8200
  dst2src_bytes = 15250
  bidirectional_mean_ps = 1954.2   ← mean packet size
  bidirectional_stddev_ps = 432.1  ← std dev of packet sizes
  ...
```

A flow is defined by its **5-tuple**:
1. Source IP
2. Destination IP
3. Source port
4. Destination port
5. Transport protocol (TCP=6, UDP=17)

All packets sharing the same 5-tuple (in either direction) belong to the same **bidirectional
flow**. NFStream monitors the PCAP, groups packets by 5-tuple, and emits one row per flow when the
flow terminates (FIN/RST for TCP, or an idle timeout for UDP).

### Why Bidirectional Matters

A unidirectional flow only sees one direction. NFStream is bidirectional — it sees packets going
in both directions as part of the same record. This is critical because:

- The **ratio** of src2dst vs dst2src bytes reveals protocol behaviour. A file download has
  massive dst2src (server → client) bytes. A C2 beacon has small bidirectional bytes with nearly
  equal byte counts in both directions.
- **Inter-arrival times** measured bidirectionally capture the full rhythmic pattern of the
  connection.

---

## 3. What is NFStream? (The Library)

NFStream is an open-source Python library (`pip install nfstream`) that:

1. **Reads PCAPs** (or live network interfaces) using low-level packet capture
2. **Groups packets** into bidirectional flows using 5-tuple matching
3. **Identifies the application** using nDPI (deep packet inspection) — nDPI can identify 300+
   protocols including TLS, QUIC, HTTP/2, BitTorrent, Zoom, Netflix, etc.
4. **Computes statistical features** over the packet sequence of each flow
5. **Exports** flows as a pandas DataFrame or CSV

### nDPI — What It Is

**nDPI** (ntopng Deep Packet Inspection) is a C library that inspects packet payloads to
identify the application protocol. It uses:
- Port-based heuristics (port 443 → likely TLS)
- Protocol fingerprints (looking at packet content patterns)
- Hostname extraction from TLS SNI
- Flow behaviour patterns

NFStream embeds nDPI and runs it on every flow, adding columns like:
- `application_name` — e.g., `"TLS.Google"`, `"QUIC.YouTube"`, `"DNS"`
- `application_category_name` — e.g., `"Web"`, `"Media"`, `"Network"`
- `application_is_guessed` — boolean; whether nDPI is certain or guessing

### NFStreamer — The Core Object

The entire NFStream API is exposed through one class: `NFStreamer`.

```python
from nfstream import NFStreamer

streamer = NFStreamer(
    source="path/to/capture.pcap",  # PCAP file or interface name like "eth0"
    decode_tunnels=True,             # unwrap GRE/VXLAN/etc tunnels
    bpf_filter=None,                 # kernel-level BPF filter
    statistical_analysis=True,       # compute packet size/timing statistics
    splt_analysis=20,                # SPLT: capture first 20 packet lengths
    n_meters=4,                      # parallel processing threads
)

# Iterate flows:
for flow in streamer:
    print(flow.src_ip, flow.bidirectional_bytes)

# Or dump to CSV directly:
total = streamer.to_csv("output.csv")
print(f"Wrote {total} flows")
```

---

## 4. The Complete Feature Set NFStream Produces

NFStream produces a rich set of columns. Understanding every column category is critical for
interviews. Here is a complete breakdown:

### Category 1: Flow Identity (5-tuple + metadata)

| Column | Type | Description |
|--------|------|-------------|
| `src_ip` | string | Source IP address |
| `src_mac` | string | Source MAC address (if available) |
| `src_oui` | string | Organizationally Unique Identifier of src MAC (identifies NIC vendor) |
| `dst_ip` | string | Destination IP address |
| `dst_mac` | string | Destination MAC address |
| `dst_oui` | string | OUI of destination NIC |
| `src_port` | int | Source port number (0–65535) |
| `dst_port` | int | Destination port number |
| `protocol` | int | IP protocol number: 6=TCP, 17=UDP, 1=ICMP |
| `ip_version` | int | 4 = IPv4, 6 = IPv6 |
| `vlan_id` | int | VLAN tag (0 if no VLAN) |
| `tunnel_id` | int | Tunnel identifier for encapsulated flows |
| `bidirectional_first_seen_ms` | int64 | Unix timestamp of first packet in flow (milliseconds) |
| `bidirectional_last_seen_ms` | int64 | Unix timestamp of last packet in flow (milliseconds) |
| `bidirectional_duration_ms` | int64 | Duration: `last_seen - first_seen` in milliseconds |
| `expiration_id` | int | Why the flow was terminated: 0=idle, 1=active timeout, 2=TCP RST/FIN, 3=end of file |

### Category 2: Packet and Byte Counts

NFStream tracks three "directions": bidirectional (both), src2dst (client→server), dst2src
(server→client).

| Column | Description |
|--------|-------------|
| `bidirectional_packets` | Total packets in both directions |
| `src2dst_packets` | Packets from source to destination |
| `dst2src_packets` | Packets from destination to source |
| `bidirectional_bytes` | Total bytes in both directions |
| `src2dst_bytes` | Bytes from source to destination |
| `dst2src_bytes` | Bytes from destination to source |

### Category 3: Statistical Features (`statistical_analysis=True`)

When `statistical_analysis=True` (the default in this project), NFStream computes descriptive
statistics over the sequence of **packet sizes** (ps = packet size) and **inter-arrival times**
(piat = packet inter-arrival time) for the entire flow.

For each of the three directions (bidirectional, src2dst, dst2src), NFStream computes 8
statistics:

| Statistic suffix | What it measures |
|-----------------|-----------------|
| `_mean_ps` | Arithmetic mean of packet sizes |
| `_stddev_ps` | Standard deviation of packet sizes |
| `_variance_ps` | Variance (= stddev²) |
| `_skew_from_gaussian_ps` | Skewness — how asymmetric the distribution is |
| `_kurtosis_ps` | Kurtosis — how heavy the tails are |
| `_mean_piat_ms` | Mean inter-arrival time between consecutive packets (ms) |
| `_stddev_piat_ms` | Std dev of inter-arrival times |
| `_variance_piat_ms` | Variance of inter-arrival times |
| `_skew_from_gaussian_piat_ms` | Skewness of inter-arrival times |
| `_kurtosis_piat_ms` | Kurtosis of inter-arrival times |

Applied to all three directions:
```
bidirectional_mean_ps, src2dst_mean_ps, dst2src_mean_ps
bidirectional_stddev_ps, src2dst_stddev_ps, dst2src_stddev_ps
bidirectional_variance_ps, src2dst_variance_ps, dst2src_variance_ps
bidirectional_skew_from_gaussian_ps, src2dst_skew_from_gaussian_ps, dst2src_skew_from_gaussian_ps
bidirectional_kurtosis_ps, src2dst_kurtosis_ps, dst2src_kurtosis_ps
bidirectional_mean_piat_ms, src2dst_mean_piat_ms, dst2src_mean_piat_ms
bidirectional_stddev_piat_ms, src2dst_stddev_piat_ms, dst2src_stddev_piat_ms
bidirectional_variance_piat_ms, src2dst_variance_piat_ms, dst2src_variance_piat_ms
bidirectional_skew_from_gaussian_piat_ms, src2dst_skew_from_gaussian_piat_ms, dst2src_skew_from_gaussian_piat_ms
bidirectional_kurtosis_piat_ms, src2dst_kurtosis_piat_ms, dst2src_kurtosis_piat_ms
```

That is **30 statistical columns** total (10 stats × 3 directions).

**Why skewness and kurtosis matter for malware detection:**

A legitimate HTTPS session has a natural packet size distribution: TLS record headers are small
(~5 bytes), data records vary widely. The kurtosis and skew of packet sizes for C2 traffic are
often very different because C2 heartbeats tend to be uniform, small, and highly periodic.
Regular browsing has high variance and positive skew (many small ACKs, occasional large data
bursts).

### Category 4: SPLT — Sequence of Packet Lengths and Times (`splt_analysis=20`)

SPLT (Sequence of Packet Length and Time) records the raw sequence of the first N packets in the
flow — not a statistic but the actual sequence.

With `splt_analysis=20`, NFStream adds these columns:
```
splt_direction     ← list of 20 packet directions (0=src2dst, 1=dst2src)
splt_ps            ← list of 20 packet sizes (bytes)
splt_piat_ms       ← list of 20 inter-arrival times (ms)
```

These are stored as arrays (serialized to strings in CSV format). For example:
```
splt_ps = "[517, 1448, 54, 384, 1448, 1448, 54, ...]"
```

**Why SPLT matters:**

The first N packets of a flow carry a disproportionate amount of signal. For TLS:
- Packet 1: TCP SYN (~60 bytes)
- Packet 3: TLS ClientHello (~300–600 bytes)
- Packet 4: TLS ServerHello + Certificate (~1400+ bytes, often multiple packets)
- Packet 7+: Application data

Malicious flows have characteristic early-packet signatures. DGA (domain-generation algorithm)
malware calling home has very distinctive SPLT patterns. The SPLT sequence is essentially a
lightweight traffic fingerprint.

`splt_analysis=20` means capture the first 20 packets. This project uses 20, matching academic
literature recommendations for TLS classification tasks.

### Category 5: nDPI Application Labels

| Column | Type | Description |
|--------|------|-------------|
| `application_name` | string | nDPI-identified protocol, e.g., `TLS.Google`, `QUIC.YouTube`, `HTTP` |
| `application_category_name` | string | Category, e.g., `Web`, `Media`, `VPN`, `Malware` |
| `application_is_guessed` | int | 0 = confident, 1 = best-guess identification |
| `requested_server_name` | string | SNI extracted by nDPI from TLS ClientHello |
| `client_fingerprint` | string | Client TLS fingerprint (similar to JA3 but nDPI-computed) |
| `server_fingerprint` | string | Server TLS fingerprint |

Note: `requested_server_name` in NFStream is the same as Zeek's `server_name` in ssl.log — both
extract SNI. Having both is useful for cross-validation.

---

## 5. The Source Code — `pipeline/nfstream.py`

```python
#!/usr/bin/env python3
"""NFStream extraction utilities."""

from __future__ import annotations

import argparse
from pathlib import Path

from nfstream import NFStreamer
```

### Imports explained

**`from __future__ import annotations`**

This is a Python 3.10+ compatibility shim for type hints. Without it, writing `str | Path` in a
function signature would fail on Python 3.9. With this import, all annotations are treated as
strings (lazily evaluated), so `str | Path` is valid even on older versions.

You will see this in every `pipeline/*.py` file. It is a standard practice when you want to use
modern union type syntax (`X | Y`) while maintaining backward compatibility.

**`from nfstream import NFStreamer`**

`nfstream` is a third-party library (in `requirements.lock` as `nfstream==6.5.3`). `NFStreamer`
is its single main class — the entire public API.

---

## 6. `extract_nfstream_csv()` — Line by Line

```python
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
```

### Parameter design

**`pcap_file: str | Path`**

Accepts either a string path or a `Path` object. The `str | Path` union type means callers are
not forced to construct a `Path` object — they can pass the string from argparse directly.

**`output_csv: str | Path`**

Where to write the CSV. The parent directory will be created automatically (see below).

**`*` (keyword-only separator)**

All parameters after `*` must be passed as keyword arguments. You cannot write:
```python
extract_nfstream_csv("in.pcap", "out.csv", True, None, True, 20, 4)
```
You must write:
```python
extract_nfstream_csv("in.pcap", "out.csv", decode_tunnels=True, bpf_filter=None, ...)
```
This is a deliberate API safety measure — `extract_nfstream_csv("in.pcap", "out.csv", False)`
would silently disable tunnel decoding if positional. Keyword-only forces explicit intent.

**`decode_tunnels: bool = True`**

Whether NFStream should unwrap tunnelled protocols. Tunnelling protocols:
- **GRE** (Generic Routing Encapsulation) — used by VPNs and routers
- **VXLAN** — used in cloud virtual networks
- **MPLS** — used in ISP backbone networks
- **GTP** — used in mobile/LTE networks

When `decode_tunnels=True`, NFStream looks inside these wrappers and analyses the inner packets
as if they were not encapsulated. For a thesis dataset capturing real network traffic, tunnels
may be present (e.g., if the capture was taken on a machine inside a VPN). Setting `True` ensures
we see the actual application-level traffic, not just the outer tunnel packets.

**`bpf_filter: str | None = None`**

An optional BPF (Berkeley Packet Filter) string that filters which packets NFStream reads. This is
a kernel-level filter applied before NFStream even sees the packets.

Examples:
- `"tcp port 443"` — only analyse TLS/HTTPS traffic
- `"not port 22"` — skip SSH
- `None` — no filter, analyse all packets (the default)

In this project, BPF filtering in `tshark` was already done in `filtering.py` (Tutorial 04). By
the time NFStream receives the PCAP, it is already a filtered TLS/QUIC capture. So `bpf_filter`
defaults to `None` here — double filtering would be redundant.

**`statistical_analysis: bool = True`**

Enables computation of the 30 statistical feature columns (mean, std, variance, skew, kurtosis for
packet sizes and inter-arrival times across three directions). Setting this to `False` reduces
NFStream's computational work and output columns significantly.

This project always uses `True` because these statistical features are core to the ML detection
model — they capture behavioural patterns that Zeek does not.

**`splt_analysis: int = 20`**

Number of packets from which to capture the raw SPLT sequence. Setting to `0` disables SPLT.
Setting to `20` means: for the first 20 packets in the flow, record the direction, size, and
inter-arrival time.

The value `20` is chosen to match empirical research showing that the first ~20 packets of a TLS
flow contain most of the distinguishing information for traffic classification.

**`n_meters: int = 4`**

Number of parallel processing threads (NFStream calls them "meters"). Higher values allow NFStream
to process multiple flows concurrently.

- `4` is the default, balancing speed against CPU usage for a research workstation
- On a production server with many cores, you might increase this to 8 or 16
- On a resource-constrained environment, you might set it to 1

---

### Body of `extract_nfstream_csv()`

```python
    source = Path(pcap_file).expanduser().resolve()
    output = Path(output_csv).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
```

**`Path(pcap_file).expanduser().resolve()`**

The same path resolution pattern used throughout the pipeline:
- `Path(pcap_file)` — converts string to Path object
- `.expanduser()` — expands `~` to home directory
- `.resolve()` — converts to absolute path, resolves symlinks

This is called on both the input PCAP and the output CSV. Having absolute paths ensures that when
`NFStreamer` is constructed, there is no ambiguity about which file to read.

**`output.parent.mkdir(parents=True, exist_ok=True)`**

`output.parent` is the directory containing the output CSV. For example, if `output =
/data/benign/benign_nfstream.csv`, then `output.parent = /data/benign/`. 

- `parents=True` — creates all intermediate directories if they don't exist (like `mkdir -p`)
- `exist_ok=True` — does not raise an error if the directory already exists

This is important because `DatasetArtifacts` generates paths like
`/data/output/benign_nfstream.csv` and the output directory might not exist yet at the time
`extract_nfstream_csv()` is called.

---

```python
    streamer = NFStreamer(
        source=str(source),
        decode_tunnels=decode_tunnels,
        bpf_filter=bpf_filter,
        statistical_analysis=statistical_analysis,
        splt_analysis=splt_analysis,
        n_meters=n_meters,
    )
```

**`source=str(source)`**

`NFStreamer` expects a string path, not a Path object (as of nfstream 6.5.3). We use `str(source)`
to convert our resolved `Path` back to a string. This is a common pattern when third-party
libraries haven't added `os.PathLike` support.

**Why not `source=str(pcap_file)` directly?**

We use `str(source)` (the resolved Path) not `str(pcap_file)` (the raw input) because:
- `pcap_file` might be a relative path like `"./captures/benign.pcap"`
- `source` is the resolved absolute path like `"/data/captures/benign.pcap"`
- NFStream opens the file relative to the process working directory; an absolute path is
  unambiguous regardless of where the Python process was started

---

```python
    total_flows = streamer.to_csv(str(output))
    return int(total_flows)
```

**`streamer.to_csv(str(output))`**

This is where all the work happens. `to_csv()`:
1. Opens the PCAP file
2. Reads packets one by one (streaming, not loading everything into memory at once)
3. Groups packets into bidirectional flows
4. When a flow expires (TCP FIN/RST or idle timeout), writes one row to the CSV
5. Returns the total number of flows written

`to_csv()` returns the count as a numeric type. `int(total_flows)` converts it to a Python `int`
for consistent return type regardless of the NFStream version's exact numeric type.

**Memory efficiency of the streaming approach:**

NFStream is fundamentally a streaming processor. Even a 10GB PCAP with millions of packets
requires only flow-state memory (one entry per active concurrent flow) plus write buffering. The
CSV is written incrementally — not all at once. This is why `nfstream.py` can handle very large
PCAP files without running out of RAM.

**What the CSV looks like:**

After `to_csv()`, the output CSV has one row per bidirectional flow with all the feature columns
described in Section 4. For a 1-hour TLS capture with 5,000 connections, the CSV has 5,000 rows
and roughly 100–120 columns.

---

## 7. `main()` — The CLI Entry Point

```python
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
```

### Flag design decisions

**`--no-decode-tunnels` (action="store_true")**

This is an "inverted flag" pattern. The function parameter is `decode_tunnels` (positive, default
True). But the CLI flag is `--no-decode-tunnels` (negative). This is idiomatic CLI design:

- When you provide the flag: `args.no_decode_tunnels = True` → `decode_tunnels = not True = False`
- When you omit the flag: `args.no_decode_tunnels = False` → `decode_tunnels = not False = True`

The default behaviour (tunnel decoding ON) requires no flags. The non-default behaviour (tunnel
decoding OFF) requires an explicit opt-out. This matches user expectations: you should have to ask
to disable a feature, not to enable it.

The same pattern applies to `--no-statistical-analysis`.

**`--bpf-filter` (hyphen in flag → underscore in `args`)**

argparse automatically converts hyphens in flag names to underscores in the `args` namespace.
`--bpf-filter` → `args.bpf_filter`. This is standard argparse behaviour.

**`--splt-analysis type=int`**

Without `type=int`, argparse reads all arguments as strings. `type=int` tells argparse to
convert the string input to an integer before storing it. If the user passes a non-integer (e.g.,
`--splt-analysis foo`), argparse raises an error immediately with a helpful message.

---

```python
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
```

`main()` is a thin wrapper that translates CLI arguments to function call arguments and prints a
human-readable completion summary. The actual logic is entirely in `extract_nfstream_csv()`.

**`Path(args.output).expanduser().resolve()`**

The completion message shows the absolute path to the output CSV. This is helpful when the user
passed a relative path — seeing the full absolute path confirms exactly where the file landed.

### The `extract-nfstream.py` root script

The project root contains `extract-nfstream.py`:

```python
# extract-nfstream.py
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from tls_dataset.pipeline.nfstream import main

if __name__ == "__main__":
    raise SystemExit(main())
```

This is the convenience entry point for running NFStream extraction without a full package
install. It manually adds `src/` to `sys.path` (the PYTHONPATH trick explained in Tutorial 01)
and then delegates to the same `main()` function.

**Usage:**
```bash
python extract-nfstream.py \
    --pcap /data/benign/benign_filtered.pcap \
    --output /data/benign/benign_nfstream.csv
```

Or via the installed package entry point (defined in `pyproject.toml`):
```bash
tls-nfstream --pcap ... --output ...
```

---

## 8. Where NFStream Fits in the Pipeline

NFStream runs on the **filtered PCAP** (from `filtering.py`), not the raw or sanitized PCAP:

```
Original PCAP
    │
    ▼ filtering.py (sanitize_pcap + filter_encrypted_pcap)
Filtered PCAP (TLS+QUIC only)  ◄── NFStream reads THIS
    │                                     │
    │                          nfstream.py produces:
    │                          benign_nfstream.csv (one row per flow)
    │
    ▼ zeek_runner.py (runs on SANITIZED pcap, not filtered)
Zeek logs → zeek.py → benign_zeek_csvs/
    │
    ▼ merge_features.py
    (joins nfstream.csv + conn.csv on 5-tuple + timestamp tolerance)
    │
    ▼ benign_merged.csv  (NFStream features + Zeek features in one row)
```

**Key architectural point:** NFStream runs on the **filtered** PCAP (only TLS+QUIC packets), while
Zeek runs on the **sanitized** PCAP (all traffic, including non-TLS). This was a deliberate
design:

- NFStream's feature statistics should only include encrypted traffic — running it on all traffic
  would mix TCP/HTTP features into the TLS dataset
- Zeek needs the full TCP context (SYN/ACK handshakes, connection state) to correctly populate
  `conn.log`, which is why it runs on the sanitized (not filtered) PCAP

### DatasetArtifacts fields involved

```python
@dataclass(frozen=True)
class DatasetArtifacts:
    filtered_pcap: Path       # ← nfstream.py reads THIS
    nfstream_csv: Path        # ← nfstream.py writes HERE
```

In `orchestration.py`:
```python
extract_nfstream_csv(
    pcap_file=artifacts.filtered_pcap,   # /data/benign/benign_filtered.pcap
    output_csv=artifacts.nfstream_csv,   # /data/benign/benign_nfstream.csv
)
```

---

## 9. What the NFStream CSV Looks Like (Concrete Example)

For a row from a TLS 1.3 connection to google.com:

```
src_ip                          = 192.168.1.5
dst_ip                          = 142.250.80.46
src_port                        = 55043
dst_port                        = 443
protocol                        = 6
ip_version                      = 4
bidirectional_first_seen_ms     = 1633046400123
bidirectional_last_seen_ms      = 1633046405891
bidirectional_duration_ms       = 5768
bidirectional_packets           = 23
src2dst_packets                 = 11
dst2src_packets                 = 12
bidirectional_bytes             = 38420
src2dst_bytes                   = 9340
dst2src_bytes                   = 29080
bidirectional_mean_ps           = 1670.43
bidirectional_stddev_ps         = 591.22
bidirectional_variance_ps       = 349541.0
bidirectional_skew_from_gaussian_ps  = 0.83
bidirectional_kurtosis_ps       = -0.41
bidirectional_mean_piat_ms      = 264.9
bidirectional_stddev_piat_ms    = 312.7
...
application_name                = TLS.Google
application_category_name       = Web
application_is_guessed          = 0
requested_server_name           = www.google.com
client_fingerprint              = (JA3-like hash)
splt_direction                  = [0,1,0,0,1,1,0,1,0,0,1,1,0,0,1,1,0,1,0,1]
splt_ps                         = [60,60,54,517,1448,1448,54,384,54,54,...]
splt_piat_ms                    = [1,2,0,5,10,0,3,8,1,2,...]
```

That one row (plus the corresponding Zeek columns from ssl.log / x509.log) becomes a training
sample for the ML model.

---

## 10. Design Decisions and Why

### Decision 1: Run NFStream on filtered PCAP, not raw

Running NFStream on the raw PCAP would include HTTP, DNS, SMTP, and other unencrypted traffic.
This would pollute the feature statistics with non-TLS traffic. The filtering step (Tutorial 04)
ensures NFStream only sees TLS/QUIC flows, keeping the feature space clean.

### Decision 2: Always enable statistical_analysis

The `statistical_analysis=True` default adds ~30 columns but these are among the most
discriminating features for detecting C2 and botnet traffic. Academic literature on network
anomaly detection consistently shows inter-arrival time statistics as high-importance features.
Disabling them would significantly degrade ML performance.

### Decision 3: `splt_analysis=20` not `0` or `100`

- `0` would lose all SPLT features — throwing away potentially critical early-packet signatures
- `100` would add 3 × 100 = 300 columns mostly filled with zeros (most flows are <20 packets)
  and would significantly inflate the feature space with sparse, noisy data
- `20` captures the TLS handshake and first application data exchange for virtually every flow
  (TLS 1.3 completes in ~5–7 packets; TLS 1.2 takes ~10–12)

### Decision 4: NFStream instead of CICFlowMeter (ADR 0001)

CICFlowMeter is the most-cited flow extractor in academic network intrusion detection papers. The
formal decision NOT to use it was made because:
1. CICFlowMeter requires Java — a heavyweight dependency for a Python project
2. CICFlowMeter has known bugs where packet size calculations differ from ground truth (documented
   in reproducibility studies by Engelen et al., 2021)
3. CICFlowMeter does not support QUIC protocol flows
4. NFStream computes the same categories of features with correct implementations
5. The existing scripts were already using NFStream

---

## 11. Interview Q&A

**Q: What is NFStream and what does it produce?**

NFStream is a Python library that reads PCAP files and groups packets into bidirectional network
flows. For each flow (defined by the 5-tuple: src IP, dst IP, src port, dst port, protocol), it
produces one row of features including: byte/packet counts, timing duration, statistical summaries
of packet sizes and inter-arrival times (mean, std, variance, skewness, kurtosis), SPLT sequences
(raw first-N packet lengths), and nDPI application identification labels. In this project,
`to_csv()` writes these features directly to a CSV file.

---

**Q: What is SPLT analysis and why does the project use 20 packets?**

SPLT (Sequence of Packet Lengths and Times) records the raw packet sizes, directions, and
inter-arrival times for the first N packets in a flow. It is not a statistic — it is the actual
sequence. 20 packets covers the TLS 1.3 handshake (which completes in ~5–7 packets) and the
first application data exchange, capturing the most discriminating early-flow behaviour. Fewer
than 20 would miss post-handshake patterns; more than 20 adds sparse, uninformative data for
most flows.

---

**Q: Why does NFStream run on the filtered PCAP while Zeek runs on the sanitized PCAP?**

NFStream runs on the filtered PCAP (TLS+QUIC only) because its statistical features should reflect
only encrypted traffic. Running it on all traffic would mix HTTP, DNS, and other protocol
statistics into the TLS feature vectors, polluting the training data.

Zeek runs on the sanitized PCAP (all traffic, post-editcap) because Zeek needs complete TCP
connection context — including SYN/SYN-ACK handshakes — to correctly populate `conn.log`. If
Zeek only saw TLS application-data packets (with SYN packets filtered out), it would produce
incomplete connection records and miss many flows entirely.

---

**Q: What is nDPI and what does it add?**

nDPI (ntopng Deep Packet Inspection) is a C library embedded in NFStream that identifies the
application-level protocol of a flow by inspecting packet payloads, port numbers, and protocol
fingerprints. It adds columns like `application_name` (e.g., `"TLS.Google"`, `"QUIC.YouTube"`),
`application_category_name` (e.g., `"Web"`, `"Media"`), and `requested_server_name` (the SNI
extracted from TLS ClientHello). These labels are useful for stratified analysis (e.g., comparing
malware behaviour within the same application category as benign traffic).

---

**Q: What does `decode_tunnels=True` do and why is it the default?**

`decode_tunnels=True` tells NFStream to unwrap encapsulation protocols like GRE, VXLAN, MPLS, and
GTP and analyse the inner payload as if the tunnel did not exist. Without this, a packet tunnelled
over GRE would appear as a "GRE" flow rather than as the TLS or HTTP flow it actually carries.
For a thesis dataset that may include enterprise network captures or cloud traffic, tunnels may be
present. Decoding them ensures the feature extraction sees the actual application traffic.

---

**Q: Why is `n_meters=4` the default?**

`n_meters` controls how many parallel processing threads NFStream uses. 4 is a conservative
default that works well on a development laptop (4-core CPU) without monopolising system resources.
The value is exposed as a parameter so it can be tuned: increase for faster extraction on a
powerful machine; decrease if other processes are competing for CPU.

---

**Q: How does the merge step connect NFStream's output to Zeek's output?**

NFStream produces `nfstream_csv` with columns: `src_ip`, `dst_ip`, `src_port`, `dst_port`,
`protocol`, `bidirectional_first_seen_ms`. Zeek produces `conn.csv` with columns: `id.orig_h`
(src IP), `id.resp_h` (dst IP), `id.orig_p` (src port), `id.resp_p` (dst port), `proto`, `ts`
(timestamp). The merge step (`merge_features.py`, Tutorial 08) converts NFStream's millisecond
timestamp to seconds, converts Zeek's string protocol to a number, and uses `pd.merge_asof()` to
join the two datasets on the 5-tuple + timestamp with a 2-second tolerance window. The matched
rows get Zeek's `uid`, which is then used to join `ssl.csv` and `x509.csv` for TLS-specific
features.

---

**Q: What happens to flows that NFStream finds but Zeek does not?**

After the merge, some NFStream rows will have no matching Zeek `uid` — the `uid` column will be
NaN. These are "unmatched flows." The quality gate in `quality.py` checks the match rate and flags
failure if more than 10% of flows are unmatched. Unmatched flows are still kept in the dataset
but have NaN for all Zeek-derived features (TLS version, cipher, SNI, JA3, etc.). This is handled
during ML preprocessing where NaN values are imputed.

---

*Next: Tutorial 08 — `pipeline/merge_features.py`: How NFStream and Zeek outputs are joined on
the 5-tuple with timestamp tolerance, the bidirectional orientation problem, and x509
aggregation.*
