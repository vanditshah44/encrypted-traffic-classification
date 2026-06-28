# Tutorial 03 — Pipeline Common: `DatasetArtifacts` and `build_dataset_artifacts`

**Primary file:** `src/tls_dataset/pipeline/common.py`

**Used by:**
- `src/tls_dataset/pipeline/orchestration.py` — calls `build_dataset_artifacts` to get all paths
- `src/tls_dataset/pipeline/malicious.py` — same
- `src/tls_dataset/pipeline/build_dataset.py` — uses `artifacts.all_merged_csv`, `tls_csv`, `quic_csv`, `ml_ready_csv`
- `src/tls_dataset/pipeline/pruning.py` — uses `artifacts.ml_no_constant_csv`, `ml_no_constant_novar_csv`, `ml_pruned_csv`

**Prerequisite:** Tutorial 02 (Configuration System)

---

## 1. The Problem This File Solves

Before understanding the code, understand the problem it was designed to prevent.

Imagine you are building a pipeline with ten steps. Each step reads one file and writes
another. Without any central coordination, you might write something like this scattered
across different modules:

```python
# In zeek.py
output_path = f"{output_dir}/{dataset_name}_zeek_csv"

# In nfstream.py
csv_path = output_dir + "/" + dataset_name + "_nfstream.csv"

# In merge_features.py
merged = os.path.join(output_dir, dataset_name + "_merged.csv")

# In pruning.py
pruned_output = Path(output_dir) / f"{name}_ml_pruned.csv"
```

This is a maintenance disaster:
- Four different ways to build the same kind of path
- A typo in one place (e.g., `_nfstream` vs `_nstream`) breaks the pipeline silently
- If you want to rename a file, you have to hunt through every module
- Tests cannot reliably predict what a file will be called

The solution is to have **one single place** that declares every intermediate file path
in the entire pipeline. That is exactly what `common.py` does — it is the pipeline's
single source of truth for naming.

---

## 2. Background Concepts

### What is a `dataclass`?

A `dataclass` is a Python class where you declare fields with type annotations and Python
automatically generates `__init__`, `__repr__`, and `__eq__` for you.

Without dataclass:
```python
class DatasetArtifacts:
    def __init__(self, dataset_name, output_dir, raw_pcap, ...):
        self.dataset_name = dataset_name
        self.output_dir = output_dir
        self.raw_pcap = raw_pcap
        ...  # 17 more lines

    def __repr__(self):
        return f"DatasetArtifacts(dataset_name={self.dataset_name!r}, ...)"
```

With `@dataclass`:
```python
@dataclass
class DatasetArtifacts:
    dataset_name: str
    output_dir: Path
    raw_pcap: Path
    ...
```
Python generates all the boilerplate. You just list the fields.

### What does `frozen=True` mean on a dataclass?

`frozen=True` makes every field **immutable** after the object is created.

```python
artifacts = build_dataset_artifacts("benign", "artifacts/runs/benign")

artifacts.dataset_name = "something_else"   # raises FrozenInstanceError
artifacts.nfstream_csv = Path("/tmp/foo")   # raises FrozenInstanceError
```

This is intentional and important. The `DatasetArtifacts` object is meant to be a
**fixed contract** for a single pipeline run. Once the orchestrator creates it at the
start of `run_dataset_pipeline()`, every downstream module reads from it. If any module
could mutate it, another module might read a different path than expected, causing
silent data corruption. `frozen=True` makes this bug impossible.

### What is `pathlib.Path`?

`Path` is Python's modern object-oriented path handling library. Instead of string
concatenation, you use the `/` operator:

```python
from pathlib import Path

out_dir = Path("artifacts/runs/benign")
name = "benign"

# String approach (error-prone)
path1 = out_dir + "/" + name + "_nfstream.csv"        # TypeError if out_dir is Path
path1 = str(out_dir) + "/" + name + "_nfstream.csv"   # works but ugly

# Path approach (clean)
path2 = out_dir / f"{name}_nfstream.csv"              # Path object, cross-platform
```

`Path` also handles:
- `.expanduser()` — expands `~` to the home directory
- `.resolve()` — converts relative paths to absolute paths
- `.exists()` — checks if the file exists
- `.mkdir(parents=True, exist_ok=True)` — creates directories
- `.parent` — gets the parent directory
- `str(path)` — converts back to a string for APIs that need strings

---

## 3. The Full Source: `common.py`

```python
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
            ...
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
```

That's the **entire file**. 79 lines total. But understanding each field deeply means
understanding the whole pipeline.

---

## 4. `build_dataset_artifacts` — Line by Line

```python
def build_dataset_artifacts(dataset_name: str, output_dir: str | Path) -> DatasetArtifacts:
```

**`dataset_name: str`** — a short descriptive name for this dataset run. Examples from
the actual project: `"benign"`, `"malicious_full_v2"`, `"benign_local"`. This name
becomes the **prefix** of every file produced by the pipeline. Every artifact filename
starts with `{dataset_name}_`.

**`output_dir: str | Path`** — where all outputs land. The `str | Path` union type
means the caller can pass either a string (`"artifacts/runs/benign"`) or an already-
constructed `Path` object. Both are accepted.

**`-> DatasetArtifacts`** — return type annotation. This function always returns a
`DatasetArtifacts` instance. Never a dict, never None.

---

```python
    out_dir = Path(output_dir).expanduser().resolve()
```

This single line does three things in sequence:

1. **`Path(output_dir)`** — if `output_dir` is already a `Path`, this is a no-op.
   If it's a string like `"artifacts/runs/benign"`, it creates a `Path` object from it.

2. **`.expanduser()`** — replaces `~` with the actual home directory. If you passed
   `"~/Desktop/Projects/tls_dataset/artifacts/runs/benign"`, this becomes
   `"/home/vandit/Desktop/Projects/tls_dataset/artifacts/runs/benign"`.

3. **`.resolve()`** — converts any relative path to an absolute path, resolving any
   `..` components and symlinks. `"artifacts/runs/benign"` becomes
   `"/home/vandit/Desktop/Projects/tls_dataset/artifacts/runs/benign"`.

**Why resolve to absolute?** Every downstream module receives a `DatasetArtifacts`
object and reads paths from it. If the paths were relative, they would be resolved
relative to whatever the current working directory happens to be when the module runs.
If you `cd` into a different directory, the paths would break. Absolute paths work from
anywhere.

---

## 5. Every Field Explained — What, Why, and Which Module Uses It

Here is a concrete example with `dataset_name = "benign"` and
`output_dir = "artifacts/runs/benign"`. Every path becomes:
`/home/vandit/Desktop/Projects/tls_dataset/artifacts/runs/benign/{dataset_name}_*`

---

### `output_dir`
```python
output_dir=out_dir,
# → /home/vandit/Desktop/Projects/tls_dataset/artifacts/runs/benign
```
The root directory. All other paths are children of this. Created by `orchestration.py`
with `artifacts.output_dir.mkdir(parents=True, exist_ok=True)` at pipeline startup.

---

### `raw_pcap`
```python
raw_pcap=out_dir / f"{dataset_name}_raw.pcapng",
# → .../benign_raw.pcapng
```
A copy of the original input PCAP, stored inside the managed run directory. In
`malicious.py`, the function `_copy_raw_capture(input_pcap, artifacts.raw_pcap)` copies
the user-provided PCAP here. This preserves the original untouched while all subsequent
transformations work on copies.

**Why copy it?** Provenance. You need to know which exact bytes were the starting point.
The hash of `raw_pcap` is recorded in `provenance.json`.

**Used by:** `malicious.py`

---

### `sanitized_pcap`
```python
sanitized_pcap=out_dir / f"{dataset_name}_sanitized.pcapng",
# → .../benign_sanitized.pcapng
```
The PCAP after running through `editcap`. `editcap` fixes malformed packets, removes
truncation errors, and standardises the format. The sanitized file is what all
subsequent steps (tshark, Zeek, NFStream) actually process.

**Why sanitize?** Raw PCAPs from the internet (like CTU-13 botnet captures) sometimes
have malformed packets, out-of-order timestamps, or other issues that make tools crash
or produce incorrect output. Sanitization is a defensive first step.

**Used by:** `malicious.py` — `sanitize_pcap(raw_copy, artifacts.sanitized_pcap)`

---

### `filtered_pcap`
```python
filtered_pcap=out_dir / f"{dataset_name}_filtered_tls_quic.pcapng",
# → .../benign_filtered_tls_quic.pcapng
```
The PCAP after applying tshark's `"tls or quic"` display filter. Only packets that are
part of TLS or QUIC connections remain. All other traffic (HTTP, DNS, ARP, ICMP, etc.)
is discarded.

**Why filter before extraction?** Two reasons:
1. **Correctness** — NFStream and Zeek extract statistics for every flow, including
   non-TLS ones. If non-TLS flows contaminate the feature set, the ML model learns from
   irrelevant traffic. The quality gate `max_non_tls_quic_rate` checks for this leakage.
2. **Performance** — smaller PCAP = faster NFStream and Zeek runs.

**Used by:** `malicious.py` — `filter_encrypted_pcap(artifacts.sanitized_pcap, artifacts.filtered_pcap)`

---

### `zeek_log_dir`
```python
zeek_log_dir=out_dir / f"{dataset_name}_zeek_logs",
# → .../benign_zeek_logs/
```
A **directory** (not a file) where Zeek writes its raw log files. After running Zeek,
this directory contains:
```
benign_zeek_logs/
├── conn.log        ← every connection summary
├── ssl.log         ← TLS handshake metadata (for TLS 1.2 and 1.3)
├── tls.log         ← TLS 1.3 specific events
├── x509.log        ← certificate details
├── quic.log        ← QUIC connection metadata
├── files.log       ← transferred files metadata
└── ...
```

**Used by:** `malicious.py` → `run_zeek_on_pcap(processing_pcap, resolved_zeek_log_dir)`

---

### `quality_report_json`
```python
quality_report_json=out_dir / f"{dataset_name}_quality_report.json",
# → .../benign_quality_report.json
```
The JSON file where the quality gate results are written. Contains the result of every
check: PCAP health, Zeek outputs, merge match rate, unmatched UIDs, non-TLS leakage,
duplicates. Written twice by `orchestration.py`:
1. After initial checks (PCAP health, Zeek outputs, NFStream)
2. After the merge (with merge quality results appended)

Also read by `canonical.py` when building the canonical dataset, to populate the
`quality_status` column.

**Used by:** `orchestration.py` → `quality_report.write(artifacts.quality_report_json)`

---

### `provenance_json`
```python
provenance_json=out_dir / f"{dataset_name}_provenance.json",
# → .../benign_provenance.json
```
The JSON file where the chain of transformation is recorded. Each stage appends an
entry with:
- The stage name (e.g., `"raw_capture"`, `"sanitized_capture"`, `"filtered_capture"`)
- The SHA256 hash of the output file
- The parent file's path
- The tool used (e.g., `"editcap"`, `"tshark"`, `"zeek"`)
- The exact command that was run
- The tool version

This creates an **audit trail** from raw PCAP to ML-ready CSV. If you later question
whether a model was trained on contaminated data, you can trace every transformation.

**Used by:** `malicious.py` → `write_provenance(provenance_entries, artifacts.provenance_json)`

---

### `zeek_csv_dir`
```python
zeek_csv_dir=out_dir / f"{dataset_name}_zeek_csv",
# → .../benign_zeek_csv/
```
A **directory** where Zeek's raw log files are converted to CSV format. After running
`convert_zeek_logs()`, this directory contains:
```
benign_zeek_csv/
├── conn.csv
├── ssl.csv
├── tls.csv
├── x509.csv
└── quic.csv   (if QUIC traffic was present)
```
These CSVs are what `merge_features.py` reads for the join step.

**Used by:** `orchestration.py` → `convert_zeek_logs(zeek_dir=zeek_log_dir, out_dir=resolved_zeek_csv_dir)`

---

### `nfstream_csv`
```python
nfstream_csv=out_dir / f"{dataset_name}_nfstream.csv",
# → .../benign_nfstream.csv
```
The output of NFStream extraction. One row per bidirectional flow, with ~80-100 columns
of statistics: byte counts, packet counts, flow duration, inter-arrival times, payload
size histograms, and more.

**Example rows (abbreviated):**
```
src_ip,        dst_ip,         src_port, dst_port, protocol, bidirectional_bytes, ...
192.168.1.10,  142.250.180.14, 49312,    443,      6,        24580, ...
192.168.1.10,  172.217.14.206, 49315,    443,      6,        8192, ...
```

**Used by:**
- `orchestration.py` → `extract_nfstream_csv(pcap_file=pcap, output_csv=resolved_nfstream_csv)`
- `orchestration.py` → `check_nfstream_csv(resolved_nfstream_csv)` (quality gate)
- `orchestration.py` → `merge_nfstream_with_zeek(nfstream_csv=resolved_nfstream_csv, ...)`

---

### `merged_csv`
```python
merged_csv=out_dir / f"{dataset_name}_merged.csv",
# → .../benign_merged.csv
```
The output of joining NFStream flow statistics with Zeek log data. One row per flow,
with columns from both NFStream and Zeek combined. This is the richest intermediate
file — it has both flow-level statistics AND protocol-level metadata.

**Before merge:**
- NFStream knows: bytes, packets, duration, inter-arrival times
- Zeek knows: TLS version, cipher suite, SNI, certificate, JA3 fingerprint

**After merge:**
- One row = NFStream stats + Zeek protocol metadata

This file is what the quality gates analyse for merge match rate, unmatched UIDs, and
non-TLS leakage.

**Used by:**
- `orchestration.py` → `merge_nfstream_with_zeek(..., out_csv=artifacts.merged_csv)`
- `orchestration.py` → `check_merged_dataset(artifacts.merged_csv, ...)`
- `orchestration.py` → `build_dataset_outputs(merged_csv=artifacts.merged_csv, ...)`

---

### `all_merged_csv`
```python
all_merged_csv=out_dir / f"{dataset_name}_all_merged.csv",
# → .../benign_all_merged.csv
```
A copy of the full merged dataset including ALL rows — both TLS/QUIC and non-TLS/QUIC.
This is written for inspection and debugging. The ML-ready steps only use the
TLS/QUIC-filtered subset, but this file lets you check what the full merged data looks
like before filtering.

**Used by:** `build_dataset.py` → `df.to_csv(artifacts.all_merged_csv, index=False)`

---

### `tls_csv`
```python
tls_csv=out_dir / f"{dataset_name}_tls.csv",
# → .../benign_tls.csv
```
The merged dataset filtered to only rows identified as TLS flows. Identification uses
`detect_protocol_masks()` in `build_dataset.py`:
```python
# A row is TLS if any of these columns are non-null:
ssl_indicator_cols = [c for c in df.columns if c in ("version", "cipher", "server_name", "ja3", "ja3s")]
tls_mask = df[ssl_indicator_cols].notna().any(axis=1)
```

**Used by:** `build_dataset.py` → `df[tls_mask].to_csv(artifacts.tls_csv, index=False)`

---

### `quic_csv`
```python
quic_csv=out_dir / f"{dataset_name}_quic.csv",
# → .../benign_quic.csv
```
The merged dataset filtered to only rows identified as QUIC flows. Identification:
```python
# A row is QUIC if any QUIC-specific column is non-null:
likely_quic_cols = [c for c in df.columns if any(
    token in c.lower() for token in ("quic", "cid", "scid", "dcid", "h3", "http3")
)]
quic_mask = df[likely_quic_cols].notna().any(axis=1)
```

**Used by:** `build_dataset.py` → `df[quic_mask].to_csv(artifacts.quic_csv, index=False)`

---

### `ml_ready_csv`
```python
ml_ready_csv=out_dir / f"{dataset_name}_ml_ready.csv",
# → .../benign_ml_ready.csv
```
**The first truly ML-ready file.** This is produced by `build_ml_ready_frame()` in
`build_dataset.py`. Three transformations are applied to the TLS/QUIC-filtered merged
data:

1. **Text-to-length encoding** — string columns like `server_name`, `client_fingerprint`
   are replaced by the integer length of their value. A 30-character server name becomes
   the number 30. ML models cannot consume arbitrary strings; lengths preserve some
   information about the value.

2. **Identifier removal** — columns like `src_ip`, `dst_ip`, `src_port`, `dst_port`,
   `uid`, `ts` are dropped. An IP address is an identifier, not a feature — training
   on IPs causes catastrophic data leakage (the model memorises "this IP is malicious"
   instead of learning traffic behaviour patterns).

3. **Numeric-only selection** — `df.select_dtypes(include=[np.number])` keeps only
   columns with numeric dtype. Any remaining string or categorical columns are dropped.

**Used by:**
- `orchestration.py` → `prune_feature_dataset(input_csv=artifacts.ml_ready_csv, ...)`
- `pruning.py` (as input)

---

### `ml_no_constant_csv`
```python
ml_no_constant_csv=out_dir / f"{dataset_name}_ml_no_constant.csv",
# → .../benign_ml_no_constant.csv
```
Intermediate pruning output. After removing features with zero variance (all rows have
the same value). For example, if every flow has `vlan_id = 0`, the `vlan_id` column
adds no information and would cause sklearn's `VarianceThreshold` to flag it.

Done using sklearn's `VarianceThreshold(threshold=0.0)`:
```python
variance_filter = VarianceThreshold(threshold=0.0)
variance_filter.fit(matrix)
constant_mask = variance_filter.get_support()  # True = keep, False = constant
df_no_constant = df[df.columns[constant_mask]]
```

**Used by:** `pruning.py` → saved as intermediate checkpoint

---

### `ml_no_constant_novar_csv`
```python
ml_no_constant_novar_csv=out_dir / f"{dataset_name}_ml_no_constant_novar.csv",
# → .../benign_ml_no_constant_novar.csv
```
Intermediate pruning output. After also removing **near-constant** features — columns
where more than `near_const_threshold` (default 99.5%) of values are the same.

```python
for column in df_no_constant.columns:
    top_freq = df_no_constant[column].value_counts(normalize=True).iloc[0]
    if top_freq > 0.995:   # 99.5% of values are the same
        near_constant_dropped.append(column)
```

A feature that is 0 for 99.5% of rows and non-zero for only 0.5% adds almost no
discriminating power — it would barely affect any tree split or Gaussian distribution.
Removing it reduces noise and speeds up training.

**Used by:** `pruning.py` → saved as intermediate checkpoint

---

### `ml_pruned_csv`
```python
ml_pruned_csv=out_dir / f"{dataset_name}_ml_pruned.csv",
# → .../benign_ml_pruned.csv
```
Final pruning output. After also removing **highly correlated** features.

```python
corr = df_no_var.corr(numeric_only=True).abs()
upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
correlated_dropped = [col for col in upper.columns if (upper[col] > 0.95).any()]
```

If two features have Pearson correlation > 0.95, they carry nearly identical information.
Keeping both bloats the feature space without benefit. The upper triangle of the
correlation matrix is used to avoid double-counting pairs: if feature A is correlated
with feature B, drop B (the later one in the matrix), keep A.

**Used by:**
- `orchestration.py` → `finalize_feature_dataset(input_csv=artifacts.ml_pruned_csv, ...)`
- `finalize.py` (as input)

---

### `ml_final_csv`
```python
ml_final_csv=out_dir / f"{dataset_name}_ml_final.csv",
# → .../benign_ml_final.csv
```
**The last file in the pipeline for a single dataset.** After `finalize.py` drops any
remaining temporal columns (columns with timestamps that would cause data leakage —
e.g., `bidirectional_first_seen_ms`, `ts_zeek_ssl`, `flow_start_ms`).

This is the file that would be referenced in `canonical_sources.yaml` as the
`input_csv` for each source — though in this project, `nfstream_csv` is what's actually
referenced there (because the canonical builder handles its own filtering via
`encrypted_only`).

**Used by:** `orchestration.py` → `finalize_feature_dataset(output_csv=artifacts.ml_final_csv, ...)`

---

## 6. The `as_dict()` Method

```python
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
```

**What it does:** Converts every `Path` field to a string and returns a plain Python
dict.

**Why is this needed?** The pipeline returns its results as a `dict[str, object]`. The
`artifacts` key in that return value needs to be serialisable — printable to the
terminal and writable to JSON. `Path` objects are not JSON-serialisable by default
(`json.dumps(Path("/foo"))` raises `TypeError`). Converting to strings solves this.

**Where it's used in `orchestration.py`:**
```python
return {
    "artifacts": artifacts.as_dict(),   # ← as_dict() called here
    "quality": quality_report.to_dict(),
    "merge": merge_results,
    ...
}
```

And in `malicious.py`:
```python
return {
    "artifacts": artifacts.as_dict(),   # ← same
    "sanitize": sanitize_result,
    ...
}
```

---

## 7. How `orchestration.py` Uses `DatasetArtifacts` — The Full Flow

This is where everything connects. Read this carefully because it shows
the whole pipeline's control flow:

```python
def run_dataset_pipeline(*, dataset_name, output_dir, pcap, ...):

    # STEP 1: Build the artifacts object — sets ALL file paths in one call
    artifacts: DatasetArtifacts = build_dataset_artifacts(
        dataset_name=dataset_name,
        output_dir=output_dir
    )
    artifacts.output_dir.mkdir(parents=True, exist_ok=True)
    # From this point on, no module needs to think about naming.
    # Every path is accessed via artifacts.something

    # STEP 2: NFStream extraction (writes to artifacts.nfstream_csv)
    if extract_nfstream:
        extract_nfstream_csv(pcap_file=pcap, output_csv=resolved_nfstream_csv, ...)
    quality_report.add(check_nfstream_csv(resolved_nfstream_csv, ...))

    # STEP 3: Zeek conversion (reads from zeek_log_dir, writes to zeek_csv_dir)
    if convert_zeek:
        convert_zeek_logs(zeek_dir=zeek_log_dir, out_dir=resolved_zeek_csv_dir, ...)
    quality_report.add(check_zeek_outputs(resolved_zeek_csv_dir))

    # STEP 4: PCAP health check
    if pcap is not None:
        quality_report.add(check_pcap_health(pcap))
    quality_report.write(artifacts.quality_report_json)  # ← writes to artifacts path

    # STEP 5: Merge (reads nfstream_csv + zeek_csv_dir, writes artifacts.merged_csv)
    merge_results = merge_nfstream_with_zeek(
        nfstream_csv=resolved_nfstream_csv,
        zeek_dir=resolved_zeek_csv_dir,
        out_csv=artifacts.merged_csv,           # ← artifacts path
        tolerance_sec=merge_tolerance_sec,
    )
    quality_report.add(check_merged_dataset(artifacts.merged_csv, ...))
    quality_report.write(artifacts.quality_report_json)  # ← written again with merge results

    # STEP 6: Build ML-ready outputs (reads artifacts.merged_csv, writes ml_ready_csv etc.)
    build_results = build_dataset_outputs(
        merged_csv=artifacts.merged_csv,        # ← artifacts path as input
        output_dir=artifacts.output_dir,
        dataset_name=dataset_name,
        protocol_filter=protocol_filter,
    )
    # Inside build_dataset_outputs, it calls build_dataset_artifacts again:
    # artifacts = build_dataset_artifacts(dataset_name, output_dir)
    # Then writes: artifacts.all_merged_csv, artifacts.tls_csv, artifacts.quic_csv, artifacts.ml_ready_csv

    # STEP 7: Prune features (reads artifacts.ml_ready_csv, writes ml_pruned_csv etc.)
    prune_results = prune_feature_dataset(
        input_csv=artifacts.ml_ready_csv,       # ← artifacts path as input
        output_dir=artifacts.output_dir,
        dataset_name=dataset_name,
        ...
    )
    # Inside prune_feature_dataset, it calls build_dataset_artifacts again:
    # artifacts = build_dataset_artifacts(dataset_name, output_dir)
    # Then writes: ml_no_constant_csv, ml_no_constant_novar_csv, ml_pruned_csv

    # STEP 8: Finalize (reads artifacts.ml_pruned_csv, writes artifacts.ml_final_csv)
    finalize_results = finalize_feature_dataset(
        input_csv=artifacts.ml_pruned_csv,      # ← artifacts path as input
        output_csv=artifacts.ml_final_csv,      # ← artifacts path as output
        drop_cols=final_drop_cols or DEFAULT_DROP_COLS,
    )

    return {
        "artifacts": artifacts.as_dict(),
        "quality": quality_report.to_dict(),
        "merge": merge_results,
        "build": build_results,
        "prune": prune_results,
        "finalize": finalize_results,
        "inspect": inspect_results,
    }
```

Notice the critical pattern: `build_dataset_artifacts` is called **multiple times** in
the pipeline — once in `orchestration.py`, once inside `build_dataset.py`, once inside
`pruning.py`. Each call produces an identical `DatasetArtifacts` object because the
inputs (`dataset_name` and `output_dir`) are the same. This is safe because
`build_dataset_artifacts` is a **pure function** — same inputs always produce the same
outputs, with no side effects. The immutability (`frozen=True`) of `DatasetArtifacts`
ensures that calling it multiple times cannot cause any consistency issues.

---

## 8. Concrete File System Example

Given `dataset_name = "benign"` and `output_dir = "artifacts/runs/benign"`, here is
exactly what the output directory looks like after a full pipeline run:

```
artifacts/runs/benign/
│
├── benign_raw.pcapng                      ← raw_pcap (copy of original)
├── benign_sanitized.pcapng                ← sanitized_pcap (editcap output)
├── benign_filtered_tls_quic.pcapng        ← filtered_pcap (tshark TLS/QUIC filter)
│
├── benign_zeek_logs/                      ← zeek_log_dir (directory)
│   ├── conn.log
│   ├── ssl.log
│   ├── tls.log
│   └── x509.log
│
├── benign_zeek_csv/                       ← zeek_csv_dir (directory)
│   ├── conn.csv
│   ├── ssl.csv
│   └── tls.csv
│
├── benign_nfstream.csv                    ← nfstream_csv (NFStream output)
├── benign_merged.csv                      ← merged_csv (NFStream + Zeek join)
├── benign_all_merged.csv                  ← all_merged_csv (all rows before protocol filter)
├── benign_tls.csv                         ← tls_csv (TLS rows only)
├── benign_quic.csv                        ← quic_csv (QUIC rows only)
├── benign_ml_ready.csv                    ← ml_ready_csv (text→len, drop IDs, numeric only)
│
├── benign_ml_no_constant.csv              ← ml_no_constant_csv (zero-variance removed)
├── benign_ml_no_constant_novar.csv        ← ml_no_constant_novar_csv (near-constant removed)
├── benign_ml_pruned.csv                   ← ml_pruned_csv (correlated removed)
├── benign_ml_final.csv                    ← ml_final_csv (temporal columns removed)
│
├── benign_quality_report.json             ← quality_report_json (all gate results)
└── benign_provenance.json                 ← provenance_json (transformation audit trail)
```

This is the full footprint of one pipeline run. The naming convention is completely
systematic — `{dataset_name}_{descriptor}` — and every single name comes from
`build_dataset_artifacts`.

---

## 9. Design Decisions Worth Explaining in an Interview

### Decision 1: Why a frozen dataclass instead of a dict?

A dict would work:
```python
artifacts = {
    "nfstream_csv": Path(out_dir) / f"{name}_nfstream.csv",
    ...
}
```

But a frozen dataclass is better because:

- **Attribute access not key access:** `artifacts.nfstream_csv` vs `artifacts["nfstream_csv"]`.
  Attribute access is checked by mypy — if you typo `artifacts.nfstrem_csv`, mypy catches
  it at type-check time. A dict key typo only fails at runtime.
- **Immutability:** `frozen=True` prevents any module from accidentally modifying a path
  (e.g., `artifacts["nfstream_csv"] = "/tmp/something"` would break every downstream
  consumer that already has a reference to the dict).
- **Self-documenting:** The dataclass fields are a complete, named, typed list of every
  artifact in the pipeline — readable as documentation.
- **IDE autocomplete:** IDEs know the fields of `DatasetArtifacts` and can autocomplete
  them. They cannot autocomplete dict keys.

### Decision 2: Why call `build_dataset_artifacts` multiple times instead of passing it around?

In `orchestration.py`, the `artifacts` object is created and then passed to
`build_dataset_outputs` and `prune_feature_dataset` as `(output_dir, dataset_name)` —
not as the `DatasetArtifacts` object itself. Each of those functions calls
`build_dataset_artifacts` internally.

This is a deliberate design choice: each function is **self-contained**. It does not
depend on the caller to provide a pre-built artifacts object. This makes each function
independently callable from any context — tests, scripts, the REPL — without needing
to first build an artifacts object. The cost is minor (a few microseconds to re-create
identical Path objects). The benefit is testability and independence.

### Decision 3: Why `expanduser().resolve()` and not just `Path(output_dir)`?

Two reasons:
1. **`expanduser()`:** Users might specify paths with `~`. Without expansion, `~` would
   be treated as a literal directory name, creating a folder called `~`.
2. **`resolve()`:** Without resolving to absolute paths, two different callers working
   in different directories might produce different `str(artifacts.nfstream_csv)` values
   even with the same `output_dir` string. Absolute paths are unambiguous and safe to
   store in provenance records, pass to subprocess calls, and compare for equality.

---

## 10. The Data Flow Diagram (Single Dataset, Full Pipeline)

```
User calls: tls-dataset run-dataset-pipeline
            --dataset-name benign
            --output-dir artifacts/runs/benign
            --pcap data/benign.pcap
            --extract-nfstream
            --convert-zeek
            --zeek-log-dir data/zeek/benign
                    │
                    ▼
orchestration.py: run_dataset_pipeline()
                    │
                    ├─ build_dataset_artifacts("benign", "artifacts/runs/benign")
                    │    → DatasetArtifacts (all 17 paths pre-computed)
                    │
                    ├─ nfstream.py: extract_nfstream_csv(pcap → artifacts.nfstream_csv)
                    │    writes: benign_nfstream.csv
                    │
                    ├─ quality.py: check_nfstream_csv(artifacts.nfstream_csv)
                    │    reads: benign_nfstream.csv
                    │
                    ├─ zeek.py: convert_zeek_logs(zeek_log_dir → artifacts.zeek_csv_dir)
                    │    writes: benign_zeek_csv/conn.csv, ssl.csv, tls.csv...
                    │
                    ├─ quality.py: check_zeek_outputs(artifacts.zeek_csv_dir)
                    │    reads: benign_zeek_csv/
                    │
                    ├─ quality.py: check_pcap_health(pcap)
                    │
                    ├─ quality_report.write(artifacts.quality_report_json)
                    │    writes: benign_quality_report.json
                    │
                    ├─ merge_features.py: merge_nfstream_with_zeek(→ artifacts.merged_csv)
                    │    reads: benign_nfstream.csv + benign_zeek_csv/
                    │    writes: benign_merged.csv
                    │
                    ├─ quality.py: check_merged_dataset(artifacts.merged_csv)
                    │    reads: benign_merged.csv
                    │
                    ├─ quality_report.write(artifacts.quality_report_json)   [updated]
                    │
                    ├─ build_dataset.py: build_dataset_outputs(artifacts.merged_csv)
                    │    reads: benign_merged.csv
                    │    writes: benign_all_merged.csv, benign_tls.csv,
                    │            benign_quic.csv, benign_ml_ready.csv
                    │
                    ├─ pruning.py: prune_feature_dataset(artifacts.ml_ready_csv)
                    │    reads: benign_ml_ready.csv
                    │    writes: benign_ml_no_constant.csv,
                    │            benign_ml_no_constant_novar.csv,
                    │            benign_ml_pruned.csv
                    │
                    └─ finalize.py: finalize_feature_dataset(artifacts.ml_pruned_csv)
                         reads: benign_ml_pruned.csv
                         writes: benign_ml_final.csv
```

Every arrow in this diagram corresponds to one field of `DatasetArtifacts`. The entire
pipeline is a directed acyclic graph (DAG) of file transformations, and `DatasetArtifacts`
is the schema of that graph's nodes.

---

## 11. Interview Questions & Answers for Tutorial 03

**Q: What is `DatasetArtifacts` and why does it exist?**
> `DatasetArtifacts` is a frozen dataclass in `pipeline/common.py` that centralises
> every intermediate file path produced by the pipeline into one object. Instead of
> each module independently constructing its output paths (which leads to inconsistent
> naming, typos, and maintenance problems), they all read from the same `DatasetArtifacts`
> instance. `build_dataset_artifacts(dataset_name, output_dir)` creates it by applying
> the `{dataset_name}_{descriptor}` naming convention consistently to every artifact.

**Q: Why is `DatasetArtifacts` frozen?**
> `frozen=True` makes every field immutable after construction. The artifacts object is
> created once at the start of the pipeline and shared across multiple stages. If any
> stage could mutate it, another stage reading the same field later might see a different
> path, causing silent data corruption. Immutability makes this bug impossible by design.

**Q: What does `.expanduser().resolve()` do and why is it called?**
> `.expanduser()` expands `~` to the home directory so paths like `~/artifacts/benign`
> work correctly. `.resolve()` converts any relative path to an absolute path, resolving
> `..` components and symlinks. Both are called because the function must work correctly
> regardless of the working directory the caller is in, and regardless of how the user
> specified the path.

**Q: Why does `build_dataset_artifacts` get called multiple times (in orchestration, in
`build_dataset.py`, in `pruning.py`) instead of passing the object around?**
> Each function is designed to be self-contained and independently callable. By
> reconstructing the paths from the same `(dataset_name, output_dir)` inputs, each
> function works correctly from any calling context — tests, scripts, REPL — without
> needing the caller to pre-build an artifacts object. The reconstruction is safe because
> `build_dataset_artifacts` is a pure function: identical inputs always produce identical
> outputs.

**Q: What is the order of intermediate files from `merged.csv` to `ml_final.csv`?**
> Four steps: (1) `merged.csv` → `build_dataset.py` → `ml_ready.csv` (text-to-length,
> drop identifiers, numeric only); (2) `ml_ready.csv` → `pruning.py` →
> `ml_no_constant.csv` (drop zero-variance features); (3) → `ml_no_constant_novar.csv`
> (drop near-constant features, >99.5% same value); (4) → `ml_pruned.csv` (drop
> correlated features, Pearson >0.95); (5) `ml_pruned.csv` → `finalize.py` →
> `ml_final.csv` (drop temporal leakage columns).

**Q: What is the difference between `merged_csv` and `all_merged_csv`?**
> `merged_csv` is the direct output of the Zeek-NFStream join — all rows, all protocols.
> `all_merged_csv` is a copy saved after the merge for inspection purposes, before any
> protocol filtering. `ml_ready_csv` is built from the TLS/QUIC-only subset of the
> merged data (when `protocol_filter="encrypted_only"`). The `all_merged_csv` exists so
> developers can inspect the full merged dataset without losing the protocol-filtered
> ML-ready version.

**Q: Why is `as_dict()` needed when `DatasetArtifacts` is already a structured object?**
> `Path` objects are not JSON-serialisable — `json.dumps(Path("/foo"))` raises `TypeError`.
> `as_dict()` converts all fields to strings, making the artifacts object safe to
> include in JSON output (e.g., pipeline result dicts that get printed to the terminal
> or written to log files). It is a serialisation helper, not a primary access method.

**Q: What naming convention do all artifact files follow?**
> Every file follows `{dataset_name}_{descriptor}`. For `dataset_name="benign"`: the
> NFStream CSV is `benign_nfstream.csv`, the merged CSV is `benign_merged.csv`, the
> quality report is `benign_quality_report.json`, etc. This convention means you can
> always identify what a file is and which dataset it belongs to just by reading the
> filename.

---

*Previous: [02_configuration_system.md](02_configuration_system.md)*
*Next: [04_pipeline_filtering.md](04_pipeline_filtering.md)*
