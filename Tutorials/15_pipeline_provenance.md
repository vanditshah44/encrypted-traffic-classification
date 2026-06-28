# Tutorial 15 — Provenance Tracking (`pipeline/provenance.py`)

## Prerequisites

- Tutorial 03 (`common.py`) — know `DatasetArtifacts` and the `provenance_json` artifact path.
- Tutorial 13 (`orchestration.py`) — understand that `run_dataset_pipeline` returns all
  artifact paths but does not write a provenance record itself; callers like `canonical.py` do.

---

## 1. Why Provenance Tracking Exists

A machine learning dataset is the product of a chain of transformations:

```
Downloaded PCAP  →  filtered PCAP  →  Zeek CSVs  →  merged CSV  →  ml_final.csv
```

Without provenance tracking, you cannot answer any of these questions after the fact:

- **What exact PCAP produced this `ml_final.csv`?** Was it the same file you downloaded last
  month, or was it re-downloaded and silently different?
- **Did the PCAP change between two training runs?** If a file was partially overwritten by a
  failed download, you would never know — the filename is the same.
- **Which tool version produced these Zeek CSVs?** Zeek 5.0 changed TLS log field names versus
  Zeek 4.x. If your Zeek binary was upgraded, your feature schema changed silently.
- **What was the exact `tshark` command used to filter the PCAP?** The filter string determines
  which flows survived — two runs with different BPF expressions produce different datasets.

Provenance tracking answers all of these by recording, for each artifact:
- A SHA256 fingerprint of its content.
- Its size in bytes.
- The stage of the pipeline that produced it.
- What it was derived from (`parent_path`).
- What tool and command created it.

This is not bureaucratic record-keeping — it is the mechanism that makes your thesis dataset
**reproducible and auditable**. Any reviewer can verify that the `ml_final.csv` you published
was derived from the exact PCAPs you claimed, through the exact processing steps you described.

---

## 2. `ProvenanceEntry` — Lines 11–23

```python
@dataclass(frozen=True)
class ProvenanceEntry:
    stage: str
    path: str
    sha256: str
    size_bytes: int
    parent_path: str | None = None
    source_url: str | None = None
    source_rel_path: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    command: str | None = None
    notes: str | None = None
```

Every field has a specific purpose. The split between required fields (no default) and optional
fields (default `None`) reflects what is always knowable vs. what depends on context.

**Required fields — always known for any artifact:**

| Field | Type | What it records |
|-------|------|----------------|
| `stage` | str | Pipeline stage name, e.g. `"filter"`, `"zeek"`, `"merge"`, `"download"` |
| `path` | str | Absolute path of the artifact on disk at the time it was produced |
| `sha256` | str | 64-character hex SHA256 digest of the file's full byte content |
| `size_bytes` | int | File size in bytes as reported by `stat()` |

**Optional fields — context-dependent:**

| Field | Type | When populated |
|-------|------|---------------|
| `parent_path` | str | Path of the artifact this was derived from — links the lineage DAG |
| `source_url` | str | URL the PCAP was downloaded from (populated for downloaded datasets) |
| `source_rel_path` | str | Relative path within a downloaded archive (e.g., `"CICIDS2017/Monday.pcap"`) |
| `tool` | str | Tool name, e.g. `"tshark"`, `"zeek"`, `"nfstream"`, `"editcap"` |
| `tool_version` | str | Version string of the tool, e.g. `"4.2.3"` |
| `command` | str | Exact CLI command that produced this artifact |
| `notes` | str | Free-form annotation, e.g. `"contains only TLS 1.3 traffic"` |

**Why `frozen=True`?**

A provenance record describes a fact about a file at a specific moment in time — it is
immutable by definition. If the file changes, you create a new `ProvenanceEntry`; you do not
modify the existing one. `frozen=True` enforces this at the Python level: any attempt to assign
to a field after construction raises `FrozenInstanceError`. This prevents bugs where provenance
is accidentally mutated after being written to disk.

**The lineage DAG via `parent_path`:**

The `parent_path` field creates a directed acyclic graph of artifact dependencies:

```
downloaded_raw.pcap         stage="download",  parent=None,            url="https://..."
       │
       ▼
filtered_tls_quic.pcap      stage="filter",    parent=downloaded_raw.pcap,  tool="tshark"
       │
       ▼
zeek_csv/conn.csv           stage="zeek",      parent=filtered_tls_quic.pcap, tool="zeek"
       │
       ▼
merged.csv                  stage="merge",     parent=filtered_tls_quic.pcap, tool="pipeline"
       │
       ▼
ml_final.csv                stage="build",     parent=merged.csv,       tool="pipeline"
```

Following `parent_path` links from `ml_final.csv` back up the chain, you can reconstruct the
complete processing history of the dataset. This is what reproducibility means in practice.

---

## 3. `sha256_file(path, *, chunk_size)` — Lines 26–32

```python
def sha256_file(path: str | Path, *, chunk_size: int = 1024 * 1024) -> str:
    target = Path(path).expanduser().resolve()
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
```

### Why SHA256 specifically?

SHA256 (Secure Hash Algorithm 256-bit) produces a 256-bit (32-byte, 64 hex character) digest.
The choice over alternatives:

| Algorithm | Digest size | Collision resistance | Speed | Verdict |
|-----------|-------------|---------------------|-------|---------|
| MD5 | 128-bit | Broken — collisions known | Fast | Not suitable for integrity |
| SHA1 | 160-bit | Broken — SHAttered collision (2017) | Fast | Not suitable for integrity |
| SHA256 | 256-bit | No known collisions | Moderate | Current standard |
| SHA3-256 | 256-bit | No known collisions | Slower | Overkill for file integrity |

For dataset provenance the threat model is not a malicious adversary constructing a collision
— it is silent data corruption (partial download, filesystem error, accidental overwrite). MD5
would technically suffice for that. SHA256 is used because it is the current cryptographic
standard for content addressing (used by Git, Docker image layers, S3 ETags) and future-proofs
the provenance records against any future MD5/SHA1 weaknesses.

### The chunked reading idiom

```python
for chunk in iter(lambda: handle.read(chunk_size), b""):
    digest.update(chunk)
```

This is a Python idiom for reading a file in fixed-size chunks until EOF. Unpacking it:

`handle.read(chunk_size)` reads exactly `chunk_size` bytes from the current file position.
When the file is exhausted, it returns `b""` (empty bytes).

`iter(callable, sentinel)` — the two-argument form of `iter()` — calls `callable()` repeatedly
and yields each result until the result equals `sentinel`. When `handle.read(chunk_size)`
returns `b""`, iteration stops.

The `lambda: handle.read(chunk_size)` wraps the read call in a zero-argument callable because
`iter()` expects a callable, not a method call expression.

**Why chunks instead of `handle.read()` to load the whole file?**

`hashlib.sha256()` is designed for streaming — `digest.update(chunk)` incrementally feeds bytes
into the hash state. The final `hexdigest()` produces the same result as hashing the entire file
at once. The 1 MB default chunk means hashing a 1 GB PCAP uses only 1 MB of RAM at any moment.
Loading a 10 GB PCAP into memory just to hash it would be impractical.

**`chunk_size=1 * 1024 * 1024` (1 MB):**

1 MB is a standard disk I/O sweet spot — large enough to amortise system call overhead (each
`read()` is a system call), small enough to fit in CPU cache for fast hashing. The keyword-only
`*` enforces this as a named argument so callers cannot accidentally pass it positionally.

### What `hexdigest()` returns

A 64-character lowercase hex string:
```
"a3f5d1b2e9c8..."   (64 hex chars = 256 bits)
```

This is the canonical format for SHA256 — used by `sha256sum`, Git, Docker, and every standard
toolchain. Storing it as a hex string (not raw bytes) makes it directly human-readable and
JSON-serialisable without base64 encoding.

---

## 4. `build_provenance_entry(...)` — Lines 35–60

```python
def build_provenance_entry(
    *,
    stage: str,
    path: str | Path,
    parent_path: str | Path | None = None,
    source_url: str | None = None,
    source_rel_path: str | None = None,
    tool: str | None = None,
    tool_version: str | None = None,
    command: str | None = None,
    notes: str | None = None,
) -> ProvenanceEntry:
    target = Path(path).expanduser().resolve()
    return ProvenanceEntry(
        stage=stage,
        path=str(target),
        sha256=sha256_file(target),
        size_bytes=target.stat().st_size,
        parent_path=str(Path(parent_path).expanduser().resolve()) if parent_path else None,
        ...
    )
```

This function exists to separate two concerns:

1. **What the caller knows**: `stage`, `path`, `parent_path`, `tool`, `command`, etc. — all
   semantic context about *how* the artifact was produced.
2. **What must be computed from the file**: `sha256` and `size_bytes` — properties derived from
   the file's current bytes on disk.

If `ProvenanceEntry` were constructed directly by callers, every call site would need to
compute the hash and size manually. `build_provenance_entry` encapsulates that computation —
the caller passes a path and gets back a fully populated entry.

**`target.stat().st_size`:**

`Path.stat()` returns an `os.stat_result` with file metadata. `st_size` is the file size in
bytes as reported by the filesystem. This is the same value you see from `ls -l` or
`os.path.getsize()`. It is cheap (one system call, no file reading) and consistent with what
`sha256_file` hashed.

**`parent_path` resolution:**

```python
parent_path=str(Path(parent_path).expanduser().resolve()) if parent_path else None,
```

The parent path is resolved to an absolute path using the same `.expanduser().resolve()` pattern
as `path`. This ensures the lineage link is unambiguous — two entries that point to the same
file will always have the same `parent_path` string regardless of how the path was originally
specified (relative, with `~`, with symlinks). `None` is preserved as `None` for root entries
(downloaded files with no pipeline parent).

**All parameters are keyword-only (`*`):**

With 9 parameters, positional calling would be a source of hard-to-debug bugs. Keyword-only
makes every call site self-documenting:

```python
# Clear — you can read exactly what each argument means
entry = build_provenance_entry(
    stage="filter",
    path=artifacts.filtered_pcap,
    parent_path=artifacts.raw_pcap,
    tool="tshark",
    tool_version="4.2.3",
    command="tshark -r raw.pcap -w filtered.pcap -Y 'tls or quic'",
)
```

---

## 5. `write_provenance(entries, output_path)` — Lines 63–67

```python
def write_provenance(entries: list[ProvenanceEntry], output_path: str | Path) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {"entries": [asdict(entry) for entry in entries]}
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
```

**`asdict(entry)`:**

`dataclasses.asdict()` recursively converts a dataclass to a plain dict. Every field becomes a
key-value pair. For `ProvenanceEntry`, all fields are primitives (`str`, `int`, `None`), so the
result is directly JSON-serialisable with no custom encoder.

**Why `{"entries": [...]}` wrapper instead of a bare list?**

Writing a bare JSON array as the root would work technically, but wrapping in an object with a
key `"entries"` makes the file extensible. If you later add a `"schema_version"` key or a
`"dataset_name"` key to the provenance file, the wrapper object already exists — you add a key
rather than changing the root type from array to object, which would break all existing readers.

**Why `indent=2`?**

Provenance JSON is a human-auditable record. An unindented file is valid JSON but unreadable to
a human reviewer. `indent=2` produces:
```json
{
  "entries": [
    {
      "stage": "filter",
      "path": "/data/filtered.pcap",
      "sha256": "a3f5d1b2...",
      "size_bytes": 123456789,
      ...
    }
  ]
}
```

This is also diff-friendly — when a pipeline re-run produces a new provenance file, `git diff`
shows exactly which fields changed (e.g., a new `sha256` if the PCAP was updated).

**`target.write_text(..., encoding="utf-8")`:**

`Path.write_text` opens, writes, and closes the file in one call. Specifying `encoding="utf-8"`
is explicit rather than relying on the system locale default — provenance files are shared
across machines (Windows, Linux, macOS), and the UTF-8 encoding ensures consistent reading
regardless of locale settings. URLs in `source_url` may contain non-ASCII characters in
principle; UTF-8 handles them correctly.

---

## 6. How This File Is Used — The Call Pattern

`provenance.py` is a utility library — it has no `main()` function because it is never run
directly. It is called by `canonical.py` (Tutorial 17) and `malicious.py` (Tutorial 16). A
typical call sequence:

```python
from tls_dataset.pipeline.provenance import build_provenance_entry, write_provenance

entries = []

# After downloading a PCAP:
entries.append(build_provenance_entry(
    stage="download",
    path=raw_pcap_path,
    source_url="https://mcfp.felk.cvut.cz/...",
    notes="CTU-13 scenario 1, capture duration 3h",
))

# After filtering:
entries.append(build_provenance_entry(
    stage="filter",
    path=filtered_pcap_path,
    parent_path=raw_pcap_path,
    tool="tshark",
    command=f"tshark -r {raw_pcap_path} -w {filtered_pcap_path} -Y 'tls or quic'",
))

# After the full pipeline:
entries.append(build_provenance_entry(
    stage="ml_final",
    path=ml_final_csv_path,
    parent_path=merged_csv_path,
    tool="tls_dataset.pipeline",
))

write_provenance(entries, provenance_json_path)
```

Each `build_provenance_entry` call reads the file from disk and computes its SHA256. The calls
must happen **after** each stage completes and its output file is fully written. Calling it
before the file is written — or during writing — would hash a partial file and record the wrong
digest.

---

## 7. What a Provenance JSON Looks Like

```json
{
  "entries": [
    {
      "stage": "download",
      "path": "/data/captures/ctu13_s1_raw.pcapng",
      "sha256": "a3f5d1b2e9c845f7...",
      "size_bytes": 3145728000,
      "parent_path": null,
      "source_url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/...",
      "source_rel_path": "capture20110810.binetflow",
      "tool": null,
      "tool_version": null,
      "command": null,
      "notes": "CTU-13 scenario 1"
    },
    {
      "stage": "filter",
      "path": "/data/captures/ctu13_s1_filtered_tls_quic.pcapng",
      "sha256": "7b2e4c9d1f3a8...",
      "size_bytes": 245678912,
      "parent_path": "/data/captures/ctu13_s1_raw.pcapng",
      "source_url": null,
      "source_rel_path": null,
      "tool": "tshark",
      "tool_version": "4.2.3",
      "command": "tshark -r ctu13_s1_raw.pcapng -w ctu13_s1_filtered.pcapng -Y 'tls or quic'",
      "notes": null
    }
  ]
}
```

---

## 8. Interview Questions and Answers

**Q: Why is SHA256 used rather than a faster hash like MD5 or xxHash?**

A: The threat model for dataset provenance is silent data corruption — a partially downloaded
file, a filesystem error, or an accidental overwrite that changes bytes without changing the
filename. MD5 would technically detect this too. SHA256 is chosen because it is the universal
standard for content-addressing (used by Git object storage, Docker image layers, S3 object
ETags, and the `sha256sum` POSIX utility), which means provenance records can be cross-verified
by external tools without any project-specific code. SHA256 is also not collision-broken unlike
MD5 and SHA1, which makes the records more trustworthy if the provenance file is used in a
formal reproducibility audit.

---

**Q: Why does `build_provenance_entry` compute `sha256` and `size_bytes` automatically instead
of requiring the caller to pass them?**

A: Computing them requires reading the file from disk — a side-effectful operation. Keeping that
inside `build_provenance_entry` enforces a single point of truth: the hash and size are always
computed from the actual file at call time, never from a cached or pre-computed value the caller
might have gotten wrong. If callers were responsible for passing these values, you would
eventually get a bug where someone passes `size_bytes=0` or a hash computed before the file was
fully written. Encapsulating the file I/O in this function makes it impossible to record a stale
or incorrect hash.

---

**Q: What does the `parent_path` field enable that `path` alone does not?**

A: `parent_path` turns a flat list of file records into a directed acyclic graph of derivation
relationships. With only `path`, the provenance file tells you *what* artifacts exist and *when*
they were produced. With `parent_path`, you can walk the lineage backwards from any artifact to
its ultimate source — tracing `ml_final.csv` → `merged.csv` → `filtered.pcap` →
`raw.pcap` → download URL. This is the difference between a file inventory and a reproducibility
record. A thesis reviewer can follow the chain from your published `ml_final.csv` all the way
back to the publicly available source URL of the original PCAP.

---

**Q: The `sha256_file` function uses `iter(lambda: handle.read(chunk_size), b"")`. Why this
idiom rather than a `while True` loop?**

A: Both approaches are functionally equivalent, but the `iter(callable, sentinel)` idiom is
more Pythonic and eliminates a manual `break` condition. The `while True` alternative:

```python
while True:
    chunk = handle.read(chunk_size)
    if not chunk:
        break
    digest.update(chunk)
```

The `iter()` form communicates the intent more directly — "iterate until the callable returns
the sentinel value" — and removes the `if not chunk: break` that a reader must mentally parse
as the loop termination condition. It also slightly reduces the chance of accidentally writing
`if chunk is None` instead of `if not chunk`, which would miss the empty-bytes-at-EOF case.

---

**Q: Why wrap the entries in `{"entries": [...]}` rather than writing a bare JSON array?**

A: A bare JSON array as the root of a file is valid but rigid — the only information in the file
is the list of entries. Wrapping in an object with a key makes the format extensible without
breaking backward compatibility. Future additions like `"schema_version": "1"`,
`"dataset_name": "ctu13_scenario1"`, or `"pipeline_version": "0.4.2"` can be added as sibling
keys to `"entries"` without any existing reader breaking. Readers that only look for
`data["entries"]` continue to work; new readers can also read the additional keys.

---

*Next: [Tutorial 16 — Malicious Pipeline](16_pipeline_malicious.md)*
