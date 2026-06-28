# Tutorial 16 — Malicious Capture Pipeline (`pipeline/malicious.py`)

## Prerequisites

- Tutorial 04 (`filtering.py`) — `sanitize_pcap` and `filter_encrypted_pcap` are called here.
- Tutorial 05 (`zeek_runner.py`) — `run_zeek_on_pcap` and `zeek_available` are called here.
- Tutorial 13 (`orchestration.py`) — `run_dataset_pipeline` is called here. Understand every
  parameter it accepts.
- Tutorial 15 (`provenance.py`) — `build_provenance_entry` and `write_provenance` are called
  here. Provenance records are built for every stage.

---

## 1. Why This File Exists — Malicious Traffic Is Different

The general pipeline in Tutorial 13 (`orchestration.py`) assumes you already have a filtered
PCAP and pre-converted Zeek CSVs, or that you want to run NFStream/Zeek conversion in-place. It
has no concept of a *source URL*, a *manifest*, or the need to *copy a raw capture* before
processing it.

Malicious traffic introduces requirements that benign traffic does not have:

**1 — Source provenance is critical for reproducibility.**
Malicious PCAPs come from public botnet archives (CTU-13, UNSW-NB15, CICIDS, Malware Traffic
Analysis). Each has a known URL and a path within the archive. If you do not record these at
ingest time, you cannot later prove which specific capture produced your dataset.

**2 — Raw captures must be copied before modification.**
The raw malicious PCAP is the ground truth. `editcap` sanitisation (Tutorial 04) modifies
timestamps and removes malformed packets. You must preserve the original untouched copy and
process only the copy — otherwise you lose the ability to re-derive the sanitised file from
scratch.

**3 — A manifest CSV may resolve source metadata automatically.**
When processing a large batch of malicious captures downloaded by `mscp_down.py` (Tutorial 40),
the download manifest already knows each file's source URL and relative path. `malicious.py`
can look up a PCAP's provenance metadata from that manifest rather than requiring the caller to
pass it explicitly for every file.

**4 — Zeek must run locally in-pipeline (not pre-computed).**
For benign traffic you might run Zeek on a dedicated sensor. For malicious captures you are
working from an existing archive PCAP — running Zeek directly is the expected workflow.
`run_zeek_on_pcap` is called here explicitly, with a check that Zeek is actually installed
before attempting it.

This file wraps all of that into two functions: `prepare_malicious_capture` (sanitise + filter
+ provenance) and `run_malicious_pipeline` (prepare + Zeek + full pipeline).

---

## 2. `resolve_manifest_source(input_pcap, manifest_csv)` — Lines 18–42

```python
def resolve_manifest_source(
    input_pcap: str | Path,
    manifest_csv: str | Path | None,
) -> tuple[str | None, str | None]:
```

Returns `(source_url, source_rel_path)` by looking up the input PCAP in a downloader manifest
CSV. Returns `(None, None)` in all failure cases.

### What a manifest CSV looks like

`mscp_down.py` (Tutorial 40) downloads PCAPs from public repositories and writes a manifest
tracking what it downloaded:

```
local_path,rel_path,url
/data/raw/ctu13/capture20110810.pcap,CTU-13-Dataset/1/capture20110810.pcap,https://mcfp.felk.cvut.cz/...
/data/raw/ctu13/capture20110811.pcap,CTU-13-Dataset/2/capture20110811.pcap,https://mcfp.felk.cvut.cz/...
```

### The lookup logic

```python
target = Path(input_pcap).expanduser().resolve()
...
with manifest_path.open(...) as handle:
    reader = csv.DictReader(handle)
    for row in reader:
        local_path = row.get("local_path", "")
        rel_path   = row.get("rel_path", "")
        candidates = {
            Path(local_path).name if local_path else "",
            Path(rel_path).name if rel_path else "",
        }
        if target.name in candidates or str(target) == local_path:
            return row.get("url") or None, row.get("rel_path") or None
```

The lookup uses **two matching strategies**:

**Strategy 1 — Filename match:** Compares `target.name` (just the filename, e.g.
`capture20110810.pcap`) against the filenames extracted from `local_path` and `rel_path` in the
manifest. This works when the PCAP was moved to a different directory than where it was
originally downloaded — only the filename needs to match.

**Strategy 2 — Full path match:** Compares `str(target)` (the full absolute path) against
`local_path`. This is the precise match — it handles the case where two captures have identical
filenames but are from different datasets. Full path match takes precedence conceptually because
the `or` in `target.name in candidates or str(target) == local_path` evaluates left to right,
but both return the same row values if they match.

**Why a `set` for `candidates`?**

```python
candidates = {
    Path(local_path).name if local_path else "",
    Path(rel_path).name if rel_path else "",
}
```

`Path(local_path).name` gives just the filename component (e.g., `capture20110810.pcap`).
`Path(rel_path).name` does the same for the relative archive path. Using a set deduplicates them
if `local_path` and `rel_path` happen to have the same filename — `target.name in candidates`
then only needs one lookup.

**Graceful failure everywhere:**

- `manifest_csv is None` → return `(None, None)` immediately.
- Manifest file does not exist → return `(None, None)`.
- No matching row found → falls through the loop and returns `(None, None)`.
- `row.get("url") or None` — if the URL field is an empty string `""`, `"" or None` evaluates
  to `None`. This prevents storing empty strings as `source_url` in provenance records.

The function never raises — it only ever returns a two-tuple. Callers use the result with `or`
to fall back to explicitly passed values:

```python
manifest_source_url, manifest_source_rel_path = resolve_manifest_source(input_pcap, manifest_csv)
resolved_source_url = source_url or manifest_source_url
```

Explicit argument wins over manifest lookup; manifest lookup wins over `None`.

---

## 3. `_copy_raw_capture(input_pcap, output_pcap)` — Lines 45–51

```python
def _copy_raw_capture(input_pcap: str | Path, output_pcap: str | Path) -> Path:
    source = Path(input_pcap).expanduser().resolve()
    target = Path(output_pcap).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if source != target:
        shutil.copy2(source, target)
    return target
```

Copies the raw malicious PCAP to `artifacts.raw_pcap` — the managed, standardised location
inside the output directory.

**Why `shutil.copy2` instead of `shutil.copy`?**

`copy2` preserves file metadata (access time, modification time) from the source. `copy` only
copies the bytes. For provenance purposes, the modification time of the raw capture tells you
when the PCAP was originally created or last modified — useful context for correlating with
attack timelines. It also makes the copy's `stat()` consistent with the original, which matters
if any downstream tool checks modification time.

**Why the `if source != target` guard?**

If `input_pcap` already resolves to the same absolute path as `artifacts.raw_pcap` (e.g., the
caller intentionally placed the PCAP directly in the output directory with the expected name),
copying a file over itself would either fail (depending on the OS) or wastefully read/write the
same data. The guard skips the copy in that case — idempotent behaviour.

**Leading underscore `_copy_raw_capture`:**

The underscore convention marks this as module-private — not part of the public API. It is an
implementation detail of `prepare_malicious_capture` and should not be called directly by
external code.

---

## 4. `prepare_malicious_capture(...)` — Lines 54–108

```python
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
```

This function does exactly three things and records provenance for all three:

```
input_pcap (arbitrary location)
      │
      │  _copy_raw_capture()
      ▼
artifacts.raw_pcap          ← stage="raw_capture" provenance entry
      │
      │  sanitize_pcap()       (editcap: fix timestamps, remove malformed packets)
      ▼
artifacts.sanitized_pcap    ← stage="sanitized_capture" provenance entry
      │
      │  filter_encrypted_pcap() (tshark: keep only TLS/QUIC flows)
      ▼
artifacts.filtered_pcap     ← stage="filtered_capture" provenance entry
```

### Source URL resolution (Lines 66–68)

```python
manifest_source_url, manifest_source_rel_path = resolve_manifest_source(input_pcap, manifest_csv)
resolved_source_url      = source_url or manifest_source_url
resolved_source_rel_path = source_rel_path or manifest_source_rel_path
```

Priority chain: explicit argument → manifest lookup → `None`. The explicit argument always wins.
This means callers who know the source URL can pass it directly; callers processing a batch from
a manifest don't have to know the URL per-file.

### Provenance entry construction (Lines 74–100)

Each stage produces a `ProvenanceEntry`. Note what each entry captures from the *result dict*
of the stage functions:

**`raw_capture` entry:**
```python
build_provenance_entry(
    stage="raw_capture",
    path=raw_copy,
    source_url=resolved_source_url,
    source_rel_path=resolved_source_rel_path,
    notes="Original malicious source capture copied into the managed run directory.",
)
```
No `parent_path` — this is the root of the lineage DAG. No `tool` — copying is not a
transformation, just a move to managed storage.

**`sanitized_capture` entry:**
```python
build_provenance_entry(
    stage="sanitized_capture",
    path=artifacts.sanitized_pcap,
    parent_path=raw_copy,
    tool="editcap",
    tool_version=sanitize_result["tool_version"],
    command=sanitize_result["command"],
    notes=sanitize_result["stderr"] or "Sanitized with editcap.",
)
```
`tool_version` and `command` come directly from the result dict returned by `sanitize_pcap()`
(Tutorial 04). This means the provenance record contains the exact `editcap` binary version and
exact command string that was run — not a hardcoded template. If editcap is upgraded, the
provenance records the new version automatically.

`notes=sanitize_result["stderr"] or "Sanitized with editcap."` — if editcap emitted any
warnings or informational messages on stderr (e.g., "31 packets dropped because of input packet
filter"), those are recorded in the notes field. If stderr was empty, the fallback string is
used.

**`filtered_capture` entry:**
```python
build_provenance_entry(
    stage="filtered_capture",
    path=artifacts.filtered_pcap,
    parent_path=artifacts.sanitized_pcap,
    tool="tshark",
    tool_version=filter_result["tool_version"],
    command=filter_result["command"],
    notes=f"Display filter: {display_filter}",
)
```
Records the exact tshark display filter used — critical because `"tls or quic"` and
`"tls"` would produce different filtered PCAPs, and the provenance record makes this
distinction explicit.

### Why write provenance here, before Zeek and NFStream?

```python
write_provenance(provenance_entries, artifacts.provenance_json)
```

`prepare_malicious_capture` writes the initial provenance JSON with three entries. Later,
`run_malicious_pipeline` reads this file and appends the Zeek entry. This staged approach means
if the pipeline fails during Zeek (e.g., Zeek crashes), the provenance JSON still exists and
records the first three stages that did complete. Provenance accumulates rather than being
written only at the end.

---

## 5. `run_malicious_pipeline(...)` — Lines 111–218

The top-level function. It calls `prepare_malicious_capture`, optionally runs Zeek, optionally
runs early NFStream extraction, then delegates to `run_dataset_pipeline`.

### The `prepare_only` early-exit pattern (Lines 154–160)

```python
if prepare_only:
    return {
        "prepare": prepare_results,
        "prepare_nfstream": prepare_nfstream,
        "zeek": None,
        "pipeline": None,
    }
```

`prepare_only=True` stops after sanitisation and filtering. Use cases:
- **Batch inspection**: sanitise and filter a large batch of PCAPs to check they are not empty
  before committing to the full Zeek + NFStream processing.
- **Distributed processing**: prepare on one machine, copy to a Zeek-capable machine, run Zeek
  there separately.

The return dict always has the same four keys regardless of which path was taken — callers can
always do `results["zeek"]` and get `None` if Zeek was skipped, rather than getting a
`KeyError`. Consistent return shapes make callers simpler.

### The `extract_nfstream_after_prepare` flag (Lines 147–153)

```python
if extract_nfstream_after_prepare:
    total_flows = extract_nfstream_csv(processing_pcap, artifacts.nfstream_csv)
    prepare_nfstream = {
        "pcap": str(...),
        "nfstream_csv": str(...),
        "flows": int(total_flows),
    }
```

Runs NFStream on the **sanitized PCAP** before Zeek. Why might you want this? If the dataset
is large and Zeek takes a long time, you can run NFStream first (it is CPU-parallel and fast),
confirm the flow count looks reasonable, and then run Zeek. Alternatively, this flag allows
NFStream extraction to happen before any quality gates — useful for research where you want the
raw NFStream output regardless of what the quality gates say.

`processing_pcap = artifacts.sanitized_pcap` — note that NFStream processes the *sanitized*
PCAP, not the filtered one. The filtered PCAP removes non-TLS/QUIC packets, which would reduce
the flow count and lose non-encrypted context. The sanitized PCAP retains all traffic; filtering
happens inside `run_dataset_pipeline` when `extract_nfstream=True` is set.

Wait — actually looking at line 199: `extract_nfstream=True` is passed to `run_dataset_pipeline`
regardless. If `extract_nfstream_after_prepare=True`, NFStream runs *twice*: once here on the
sanitized PCAP, and again inside `run_dataset_pipeline` on the filtered PCAP. The second run
overwrites `artifacts.nfstream_csv`. This is intentional — `prepare_nfstream` in the return
dict reflects the early extraction (on sanitized PCAP), while the pipeline uses the filtered
extraction for actual ML feature generation.

### Zeek execution and provenance append (Lines 162–190)

```python
if run_zeek:
    if not zeek_available():
        raise FileNotFoundError("zeek binary not found on PATH. ...")
    resolved_zeek_log_dir = artifacts.zeek_log_dir
    zeek_stage = run_zeek_on_pcap(processing_pcap, resolved_zeek_log_dir)

    existing = Path(artifacts.provenance_json).expanduser().resolve()
    payload = existing.read_text(encoding="utf-8")
    import json
    data = json.loads(payload)
    data["entries"].append({
        "stage": "zeek_logs",
        "path": str(Path(resolved_zeek_log_dir).expanduser().resolve()),
        "sha256": "",
        "size_bytes": 0,
        ...
    })
    existing.write_text(json.dumps(data, indent=2), encoding="utf-8")
```

**`zeek_available()` check before running:**

This is a hard failure — `FileNotFoundError` — not a soft warning. If `run_zeek=True` (the
default), Zeek must be present. The error message explicitly tells the user the alternatives
(`--zeek-log-dir` or `--zeek-csv-dir` to provide pre-run results, or running on a machine with
Zeek). Hard failure is correct here because attempting the rest of the pipeline without Zeek
would produce an empty Zeek CSV directory and fail at the quality gate anyway — better to
stop immediately with a clear message.

**Why `sha256=""` and `size_bytes=0` for the Zeek entry?**

The Zeek log directory is a *directory*, not a single file. `sha256_file()` from Tutorial 15
hashes a single file. Hashing an entire directory would require hashing each file and combining
digests — a legitimate approach (Merkle tree), but not implemented here. The empty SHA256 and
zero size are honest placeholders that acknowledge the limitation rather than computing a
potentially misleading single-file hash or silently omitting the Zeek stage from provenance.

**The JSON read-modify-write pattern:**

```python
data = json.loads(payload)
data["entries"].append({...})
existing.write_text(json.dumps(data, indent=2), encoding="utf-8")
```

Instead of calling `write_provenance()` again (which would overwrite the existing entries),
this reads the existing JSON, appends to the `"entries"` list in memory, and writes the whole
document back. This is the correct approach for accumulating provenance across multiple stages
that happen in sequence — each stage adds its record to the same file rather than producing
separate provenance files.

The `import json` inside the function body is unusual — module-level imports are standard Python
style. This is likely a carry-over from iterative development; the `json` module is already
imported at the top of the file implicitly via `write_provenance`. It works correctly but would
be cleaner at the top of the module.

### The `run_dataset_pipeline` call (Lines 192–212)

```python
pipeline_results = run_dataset_pipeline(
    ...
    extract_nfstream=True,
    convert_zeek=resolved_zeek_log_dir is not None and zeek_csv_dir is None,
    ...
)
```

Two flags worth understanding:

**`extract_nfstream=True` always:**

The pipeline always re-runs NFStream, this time on the filtered PCAP. The filtered PCAP is what
`run_dataset_pipeline` knows about (via `pcap=processing_pcap`), and `extract_nfstream=True`
tells it to run NFStream on that PCAP rather than looking for a pre-existing CSV.

**`convert_zeek=resolved_zeek_log_dir is not None and zeek_csv_dir is None`:**

This conditional evaluates to `True` only when:
- Zeek log files exist (`resolved_zeek_log_dir is not None`) — either just run by this function
  or provided by the caller via `--zeek-log-dir`.
- No pre-converted CSV directory was provided (`zeek_csv_dir is None`).

If the caller already provides `zeek_csv_dir` (pre-converted Zeek CSVs), there is nothing to
convert — `convert_zeek=False`. If both `zeek_log_dir` and `zeek_csv_dir` are `None` (caller
skipped Zeek entirely with `run_zeek=False` and provided nothing), then `convert_zeek=False`
and `run_dataset_pipeline` will attempt to use the default `artifacts.zeek_csv_dir` — which
will raise `FileNotFoundError` if it doesn't exist. This is intentional: running the full
pipeline without any Zeek source should fail explicitly.

---

## 6. The `main()` CLI — Notable Flags

```python
parser.add_argument("--skip-zeek", action="store_true", ...)
...
run_zeek=not args.skip_zeek,
```

The CLI flag is `--skip-zeek` (negative framing) while the function parameter is `run_zeek`
(positive framing). The `not` inverts it. This is a common CLI design pattern where the safe
default (run Zeek) requires no flag, and the exception (skip it) requires an explicit flag. This
prevents accidental Zeek-skipping by omission.

```python
parser.add_argument("--extract-nfstream-after-prepare", action="store_true")
```

Only present in CLI if you explicitly pass it. Default is `False` — the prepare stage does not
extract NFStream separately. The full pipeline run always extracts NFStream; this flag adds an
*additional* early extraction on the sanitized PCAP.

---

## 7. Complete Execution Flow

```
input_pcap (e.g., from CTU-13 download)
      │
      │  resolve_manifest_source()     → (source_url, source_rel_path) from manifest
      │  _copy_raw_capture()           → artifacts.raw_pcap
      │  sanitize_pcap()               → artifacts.sanitized_pcap
      │  filter_encrypted_pcap()       → artifacts.filtered_pcap
      │  write_provenance(3 entries)   → artifacts.provenance_json
      │
      │  [if extract_nfstream_after_prepare]
      │    extract_nfstream_csv()      → artifacts.nfstream_csv (early, sanitized PCAP)
      │
      │  [if prepare_only] ────────────────────────────────────────────► return
      │
      │  [if run_zeek]
      │    zeek_available() check
      │    run_zeek_on_pcap()          → artifacts.zeek_log_dir/*.log
      │    read+append+write JSON      → adds zeek_logs entry to provenance_json
      │
      │  run_dataset_pipeline(
      │      extract_nfstream=True,    → re-runs NFStream on filtered_pcap
      │      convert_zeek=...,         → converts zeek_log_dir to zeek_csv_dir
      │  )
      │    → merge → build → prune → finalize → artifacts.ml_final_csv
      │
      └──► return {"prepare": ..., "zeek": ..., "pipeline": ...}
```

---

## 8. Interview Questions and Answers

**Q: Why does `prepare_malicious_capture` exist as a separate function from
`run_malicious_pipeline`? Why not just inline it?**

A: Two reasons. First, `prepare_only=True` needs a clean stopping point — it returns after
preparation without running Zeek or the full pipeline. Having a separate `prepare_malicious_capture`
function makes that boundary explicit in the code rather than hidden behind a conditional.
Second, the preparation steps (copy, sanitise, filter, write provenance) form a cohesive,
independently testable unit. A test can call `prepare_malicious_capture` without needing Zeek
installed or NFStream available — it only requires `editcap` and `tshark`. This separation
allows the preparation stage to be validated in CI environments that don't have the full tool
stack.

---

**Q: Why does the Zeek provenance entry use `sha256=""` and `size_bytes=0` instead of computing
real values?**

A: The Zeek stage produces a *directory* of log files, not a single file. Computing a meaningful
hash for a directory requires either hashing a manifest of all files (fragile — depends on file
ordering) or building a Merkle tree over all file hashes (more robust but complex to implement
and verify). Rather than implementing a complex directory hashing scheme that could produce
misleading results, the code uses explicit placeholders that honestly communicate "this is a
directory, hashing is not implemented." Anyone auditing the provenance record can see the Zeek
stage's `path` (the directory location), `tool_version`, and exact `command`, and verify the
logs manually. The hash fields are a limitation, not a silent omission.

---

**Q: What is the priority chain for resolving `source_url`, and why does explicit argument
always win over manifest?**

A: The chain is: explicit `source_url` argument → manifest lookup → `None`. Explicit argument
wins because the caller has more specific knowledge than the manifest. The manifest is a
bulk-download record — it stores the URL for each file at download time. But the caller might
be re-processing a file from a mirror, a different version of the same dataset, or a file that
was manually obtained. In all those cases, the caller's explicit URL is more authoritative than
the manifest's recorded URL. Manifest lookup is the fallback for batch processing where passing
a URL per-file would be tedious.

---

**Q: `run_dataset_pipeline` is always called with `extract_nfstream=True`. Why not respect the
pre-existing NFStream CSV from `extract_nfstream_after_prepare`?**

A: The early extraction (when `extract_nfstream_after_prepare=True`) runs NFStream on the
*sanitized* PCAP — before `tshark` filtering. The pipeline's NFStream extraction (`extract_nfstream=True`)
runs on the *filtered* PCAP — after `tshark` removes non-TLS/QUIC flows. These produce different
CSVs: the early extraction includes all flows (TCP, UDP, ICMP, everything), while the pipeline
extraction includes only TLS and QUIC flows. The pipeline needs the filtered version for correct
protocol-specific feature generation. The early extraction is a diagnostic artifact — it tells
you the total flow count before filtering, useful for understanding how much traffic was removed
by the display filter.

---

**Q: Why is `convert_zeek` a computed boolean expression rather than just `True`?**

A: `convert_zeek=resolved_zeek_log_dir is not None and zeek_csv_dir is None` covers three cases:
1. Zeek ran locally (or `--zeek-log-dir` was provided) and no CSV directory exists →
   `True`, convert the logs.
2. The caller provided `--zeek-csv-dir` directly (pre-converted CSVs) → `False`, skip
   conversion, use existing CSVs.
3. Zeek was skipped entirely and nothing was provided → `False`, `run_dataset_pipeline`
   will look for the default `artifacts.zeek_csv_dir` and fail if it does not exist.

Always passing `True` would attempt to convert Zeek logs even when only CSVs are available,
which would fail. Always passing `False` would skip conversion even when logs need converting.
The conditional expression selects the correct behaviour for all three cases without requiring
the caller to reason about it.

---

*Next: [Tutorial 17 — Canonical Dataset Builder](17_pipeline_canonical.md)*
