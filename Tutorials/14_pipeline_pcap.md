# Tutorial 14 — PCAP Merging (`pipeline/pcap.py`)

## Prerequisites

- Understanding of what a PCAP file is: a binary file that stores captured network packets, each
  with a raw byte payload and metadata (capture timestamp, original length, captured length).
- Tutorial 04 (`filtering.py`) — you know that filtering produces a single filtered PCAP per
  capture session. This module handles the step *before* filtering when you have many raw
  PCAPs that need combining first.

---

## 1. Why This File Exists

Network traffic datasets are rarely captured as a single file. In practice you collect:

- **Time-sliced captures** — `tcpdump` rotates output every N minutes, producing
  `capture_00.pcap`, `capture_01.pcap`, `capture_02.pcap`, ...
- **Interface-split captures** — separate PCAP per network interface on a multi-NIC sensor.
- **Source-split captures** — one PCAP per traffic source (one per malware family, one per
  benign application).
- **Nested directory trees** — datasets downloaded from public repositories (CICIDS,
  CTU-Malware-Capture) often come as ZIP archives with a directory tree of PCAPs.

Before filtering (Tutorial 04) and Zeek/NFStream processing (Tutorials 05–07) can run, all these
files must be combined into a single PCAP. That is what `pcap.py` does.

The critical design constraint is **memory efficiency**: a directory of PCAPs for a single
dataset can easily be tens of gigabytes. Loading all packets into memory at once (e.g., using
Scapy's `rdpcap()` which returns a `PacketList`) would exhaust RAM. This file processes packets
one at a time using **raw readers** that never materialise the full PCAP in memory.

---

## 2. The PCAP Format Family — Why Three Extensions

```python
PCAP_EXTS = {".pcap", ".pcapng", ".cap"}
```

Three extensions because the PCAP format has two generations and one alias:

| Extension | Format | Notes |
|-----------|--------|-------|
| `.pcap` | libpcap (classic) | Original format by Van Jacobson, 1988. Fixed 24-byte global header, 16-byte per-packet header. Single link-layer type for the entire file. |
| `.cap` | libpcap (alias) | Identical binary format to `.pcap`. Different extension used by Wireshark's legacy naming and some older tools (Network Monitor, older tcpdump versions). |
| `.pcapng` | PCAP-Next Generation | Newer format (RFC-draft 2004, standardised 2020). Block-based, supports multiple interfaces per file, per-packet timestamps with nanosecond resolution, capture comments, and interface metadata. All modern Wireshark/tshark captures default to this. |

`.pcap` and `.pcapng` are **not compatible** — you cannot open a `.pcapng` file with a classic
libpcap reader, and vice versa. This is why `iter_packets` selects a different Scapy reader
class per extension.

**Why does the project use `.pcapng` as the standard pipeline format?**

Look at `common.py` (Tutorial 03): all `DatasetArtifacts` paths use `_{suffix}.pcapng` naming.
PCAPNG is preferred because:
1. Tools like `tshark`, `editcap`, and Zeek all write PCAPNG by default in modern versions.
2. PCAPNG preserves interface metadata and nanosecond timestamps — more precise for
   inter-arrival time calculations in NFStream.
3. It is what most public TLS/network datasets ship as today.

---

## 3. `iter_packets(pcap_path)` — Lines 8–22

```python
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
```

This is a **generator function** — the `yield` keyword makes it return an iterator rather than
a list. The caller gets one packet at a time; no accumulation happens in memory.

### Why `RawPcapReader` / `RawPcapNgReader` instead of Scapy's `rdpcap` or `sniff`?

Scapy has multiple ways to read PCAPs:

| API | What it returns | Memory behaviour |
|-----|----------------|-----------------|
| `rdpcap(file)` | `PacketList` — all packets decoded and in RAM | Loads the entire file into memory. 1 GB PCAP = ~3–5 GB RAM after parsing |
| `PcapReader(file)` | Iterator of decoded `Packet` objects | Streams packets, but each packet is fully decoded by Scapy's dissection engine (slow) |
| `RawPcapReader(file)` | Iterator of `(bytes, metadata)` tuples | Streams raw bytes — **no dissection**. Fastest possible read. |
| `RawPcapNgReader(file)` | Same but for PCAPNG format | Same raw-bytes approach |

`RawPcapReader` reads the packet as raw bytes without attempting to decode the Ethernet frame,
IP header, TCP header, or any layer above. For merging purposes you do not need to understand
the packet — you just need to copy its bytes from one file to another. Raw readers are the right
tool: they are an order of magnitude faster than decoded readers and use a fraction of the memory.

### The `try/finally` pattern

```python
try:
    for pkt, meta in reader:
        yield pkt
finally:
    reader.close()
```

File handles must be closed even if the caller stops consuming the generator mid-way (e.g., an
exception is raised in the caller, or the caller uses `break` in a for loop over the generator).
In a normal function, `try/finally` closes the file when the function exits. In a generator,
execution is suspended at each `yield` and resumes when the caller calls `next()` again. The
`finally` block executes when the generator is **garbage-collected or explicitly closed** —
including the case where the caller abandons iteration early.

Without `finally`, an abandoned generator would leave the PCAP file handle open until the
next garbage collection cycle — potentially holding exclusive locks on the file (Windows) or
exhausting the OS file descriptor limit on large batch merges.

### What `yield pkt` discards

`for pkt, meta in reader` unpacks each item into `pkt` (raw bytes) and `meta`
(a `RawPcapReader.PacketMetadata` namedtuple containing `sec`, `usec`, `wirelen`, `caplen` — the
per-packet header fields). The function discards `meta` and yields only `pkt`.

**Why is discarding `meta` safe here?**

`PcapWriter` (the writer in `merge_pcaps`) calls `writer.write(pkt)` with only the raw bytes.
Scapy's `PcapWriter.write()` reconstructs the per-packet header from the current system time
and the length of the bytes. For a merge operation, preserving original capture timestamps would
require passing `meta.sec` and `meta.usec` through — but this would complicate the API and is
not needed for the project's use case (Zeek and NFStream re-derive timestamps from the original
packet data, not from the PCAP per-packet header timestamp in all cases).

---

## 4. `merge_pcaps(input_dir, output_pcap, *, delete_source)` — Lines 24–87

```python
def merge_pcaps(
    input_dir: str | Path,
    output_pcap: str | Path,
    *,
    delete_source: bool = False,
) -> dict[str, str | int]:
```

`delete_source=False` by default — non-destructive unless explicitly requested. The `*` makes
it keyword-only; you cannot accidentally pass `True` positionally.

### Step 1 — Discover all PCAP files recursively (Line 37)

```python
pcaps = sorted([p for p in input_dir.rglob("*") if p.is_file() and p.suffix.lower() in PCAP_EXTS])
```

`rglob("*")` traverses the entire directory tree recursively — not just the top level. This
handles the nested-directory case (e.g., a downloaded dataset where each subdirectory represents
a traffic category):

```
input_dir/
  benign/
    browser/
      chrome_2024_01.pcap
      chrome_2024_02.pcap
    streaming/
      netflix_4k.pcapng
  malware/
    botnet_A.pcap
    botnet_B.pcapng
```

All six files are found and merged in a single call.

`sorted()` ensures **deterministic ordering** — the merged PCAP contains packets from files in
lexicographic path order. Without sorting, `rglob` order is filesystem-dependent and can vary
between runs, producing different merged files from the same inputs.

`p.suffix.lower()` normalises the extension to lowercase before checking against `PCAP_EXTS` —
handles `FILE.PCAP`, `capture.PCAPNG`, etc.

### Step 2 — Log found files (Lines 43–46)

```python
for p in pcaps[:30]:
    print("  -", p.relative_to(input_dir))
if len(pcaps) > 30:
    print(f"  ... and {len(pcaps) - 30} more")
```

Prints the first 30 file paths relative to `input_dir`. This is not vanity logging — in a
research workflow you need to verify that the right files are being merged. The 30-line cap
prevents flooding the terminal when merging hundreds of files. `relative_to(input_dir)` strips
the absolute path prefix, making output readable regardless of where the directory is on disk.

### Step 3 — Open `PcapWriter` (Line 52)

```python
writer = PcapWriter(str(output_pcap), append=False, sync=True)
```

`PcapWriter` writes a classic libpcap-format file (`.pcap` header, even if the output path ends
in `.pcapng`). Note: despite the output convention of naming artifacts `.pcapng`, Scapy's
`PcapWriter` writes classic `.pcap` format. The downstream tools (Zeek, NFStream, tshark) all
read `.pcap` format transparently regardless of file extension.

**`append=False`** — always start a new file. If the output path already exists from a previous
run, it is overwritten. This is the correct behaviour for a deterministic build pipeline: the
output is always reproducible from the inputs.

**`sync=True`** — calls `flush()` after every packet write, forcing the OS to write each packet
to the file buffer immediately rather than accumulating in Python's I/O buffer. This has a
performance cost (more system calls) but ensures that if the process is killed mid-merge, the
output file contains all packets written so far — not a truncated buffered state. For merges that
can take minutes on large datasets, this crash-safety property is worth the overhead.

### Step 4 — The merge loop (Lines 57–74)

```python
for idx, pcap in enumerate(pcaps, 1):
    print(f"[{idx}/{len(pcaps)}] Merging {pcap.relative_to(input_dir)}")

    file_packets = 0
    for pkt in iter_packets(pcap):
        writer.write(pkt)
        total_packets += 1
        file_packets += 1

    print(f"    -> merged packets: {file_packets}")

    if delete_source:
        try:
            pcap.unlink()
        except Exception as e:
            print(f"    [WARN] Could not delete {pcap}: {e}")
```

`enumerate(pcaps, 1)` starts the counter at 1 (not 0) for human-readable progress output.

The inner `for pkt in iter_packets(pcap)` drives the generator from Section 3 — one raw packet
at a time, written immediately to `writer`. At no point does more than one packet's worth of
bytes live in memory simultaneously.

**The `delete_source` safety ordering:**

```
for each source PCAP:
    [fully iterate and write all packets from this file]  ← completes first
    if delete_source:
        pcap.unlink()                                      ← deletes only after success
```

The source file is deleted **only after every packet from it has been written and flushed**
(recall `sync=True`). If `iter_packets` raises an exception mid-file (e.g., a corrupted packet
header), the exception propagates up through the outer `for` loop, hits the `finally:
writer.close()`, and the source file is **not** deleted (because the `delete_source` block
is after `iter_packets` completes).

The `except Exception` around `pcap.unlink()` handles the case where deletion fails (permissions
issue, file in use on Windows) — it logs a warning but does not crash the merge. The merged
output already contains this file's packets; a failed delete is a cleanup problem, not a data
problem.

### Step 5 — `finally: writer.close()` (Lines 76–77)

```python
finally:
    writer.close()
```

Closes `PcapWriter` even if an exception is thrown mid-merge. This writes the final bytes of
the PCAP file format (the global header was written in `PcapWriter.__init__`; no footer is
needed for classic PCAP, but the file handle must be closed to flush any remaining OS buffer).

Without this, a mid-merge crash would leave a partial, unclosed PCAP that appears valid to
tools but may be missing the last N packets (whatever was still in the OS write buffer).

---

## 5. The `main()` Function and `--delete-source` CLI Flag

```python
parser.add_argument("--delete-source", action="store_true", ...)
```

`action="store_true"` means the flag is a boolean — present = `True`, absent = `False`. No
argument value is needed:

```bash
# Non-destructive merge (default):
python -m tls_dataset.pipeline.pcap \
  --input-dir /data/captures/ \
  --output /data/merged.pcap

# Space-saving merge (deletes each source after writing):
python -m tls_dataset.pipeline.pcap \
  --input-dir /data/captures/ \
  --output /data/merged.pcap \
  --delete-source
```

`--delete-source` is the disk-space management flag for large datasets. A single CTU botnet
capture session might be 50 GB of PCAPs; after merging into `merged.pcap`, you want to free
that 50 GB rather than keeping both the originals and the merged copy.

---

## 6. Complete Data Flow

```
input_dir/ (tree of .pcap, .pcapng, .cap files)
      │
      │  rglob("*") + sorted()
      ▼
pcaps = [file1.pcap, file2.pcapng, dir/file3.pcap, ...]  (sorted, deterministic)
      │
      │  for each pcap:
      │    iter_packets() → RawPcapReader or RawPcapNgReader
      │    yield raw bytes one packet at a time
      │    PcapWriter.write(bytes) with sync=True
      │    [delete source if delete_source=True]
      ▼
output_pcap  (single merged .pcap file, all packets, deterministic order)
      │
      └──► Tutorial 04 (filtering.py) reads this as input
```

---

## 7. Interview Questions and Answers

**Q: Why use `RawPcapReader` instead of Scapy's `PcapReader` or `rdpcap`?**

A: The merge operation does not need to understand packet content — it only needs to copy bytes
from input files to the output file. `RawPcapReader` reads packets as raw byte strings without
decoding any protocol layers, making it an order of magnitude faster than Scapy's protocol
dissector and using a fraction of the memory. `rdpcap` loads the entire file into a `PacketList`
in RAM — on a 10 GB PCAP that means 30–50 GB of RAM after dissection. `RawPcapReader` keeps
memory usage flat regardless of PCAP size.

---

**Q: Why does `iter_packets` use `try/finally` around a generator's `yield`?**

A: In a generator, `finally` runs when the generator is closed or garbage-collected, not when
the `yield` expression is first reached. This guarantees the file handle is always closed even
if the caller abandons iteration early — via `break`, an exception, or simply going out of scope.
Without `finally`, abandoned generators leave file handles open until the next GC cycle, which
can exhaust OS file descriptors when processing hundreds of PCAPs in a batch.

---

**Q: Why is `sync=True` set on `PcapWriter` despite the performance cost?**

A: Merging large PCAPs can take several minutes. `sync=True` flushes each packet to the OS
buffer immediately, ensuring the output file is valid and complete up to the last written packet
if the process is killed or crashes mid-merge. Without it, the final packets live only in
Python's in-process I/O buffer and would be lost on a crash, producing a silently truncated
output file that tools can still open but is missing packets — the exact defect that
`check_pcap_health` (Tutorial 09) uses `capinfos` to detect.

---

**Q: Why does the file discovery use `rglob` rather than `glob` (non-recursive)?**

A: Public network traffic datasets (CICIDS, CTU-13, UNSW-NB15) are distributed as nested
directory trees — often one subdirectory per capture day, attack category, or victim host. A
non-recursive glob would only find PCAPs at the top level and silently miss everything in
subdirectories. `rglob("*")` ensures the full tree is traversed regardless of how deep the
nesting goes.

---

**Q: Why is `delete_source=False` the default, and what real risk does `True` carry?**

A: The default is non-destructive because a merge is a one-way transformation — once source
files are deleted there is no recovery without re-downloading or re-capturing. The risk with
`delete_source=True` is a partial merge failure: if `iter_packets` raises an exception partway
through a source file, that file is not deleted (the `unlink()` is only called after the file
fully iterates). However, if an earlier file was already deleted before the failure occurred,
those files are gone permanently. For irreplaceable captures (live sensor data, one-time
experiments), always merge without `--delete-source` first, verify the output, then delete
manually.

---

*Next: [Tutorial 15 — Provenance Tracking](15_pipeline_provenance.md)*
