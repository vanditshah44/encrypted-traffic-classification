# Tutorial 10 — Building the ML-Ready Dataset (`pipeline/build_dataset.py`)

## Prerequisites

- Tutorial 03 (`common.py`) — know `DatasetArtifacts` and what `all_merged_csv`, `tls_csv`,
  `quic_csv`, and `ml_ready_csv` paths are.
- Tutorial 08 (`merge_features.py`) — understand what `merged.csv` contains: one row per flow,
  with NFStream statistics + Zeek TLS/QUIC metadata, and identifier columns like `uid`, `src_ip`.
- Tutorial 09 (`quality.py`) — understand `row_has_encrypted_signal` and why non-TLS/QUIC rows
  need to be removed before ML.

---

## 1. Why Does This File Exist? The Gap Between Merged and ML-Ready

After Tutorial 08 you have `merged.csv`. That file is **rich but completely unsuitable for ML**
as-is. Here is what is wrong with it:

| Problem | Example column | Why it breaks ML |
|---------|---------------|------------------|
| Text strings | `server_name = "api.example.com"` | Scikit-learn models accept only numbers |
| Identifier columns | `uid`, `src_ip`, `src_port` | High-cardinality identifiers the model memorises but cannot generalise from |
| Timestamp columns | `ts`, `first_seen_ms` | Encodes wall-clock time — would cause data leakage (model learns "morning traffic is benign") |
| Infinity values | `inf` in some NFStream ratio columns | Crashes `np.dot` in linear algebra operations |
| NaN values | Missing TLS metadata on unmatched rows | Crashes most sklearn estimators |
| Mixed TLS + non-TLS rows | Plain TCP rows with no `cipher` or `ja3` | Dilutes the training signal for TLS classification |

`build_dataset.py` solves every one of these problems in a single function, producing a CSV that
a scikit-learn `Pipeline` can consume with no further pre-processing.

```
merged.csv                                 ml_ready.csv
(raw, text+identifiers+mixed protocols)    (numbers-only, clean, TLS/QUIC filtered)
        │                                          │
        │   build_dataset_outputs()                │
        └──────────────────────────────────────────►
                also produces:
                  all_merged.csv  (full copy, no filtering)
                  tls.csv         (rows with TLS evidence)
                  quic.csv        (rows with QUIC evidence)
```

---

## 2. Module-Level Constants — Lines 14–41

```python
TEXT_COLUMNS_TO_LENGTH = (
    "server_name",
    "requested_server_name",
    "client_fingerprint",
    "server_fingerprint",
    "user_agent",
    "content_type",
)

IDENTIFIER_COLUMNS = (
    "id", "expiration_id", "uid",
    "src_ip", "dst_ip", "src_mac", "dst_mac",
    "src_port", "dst_port",
    "vlan_id", "tunnel_id",
    "first_seen_ms", "last_seen_ms",
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
    "ts",
)
```

Understanding these two constants is half of understanding the whole file.

### `TEXT_COLUMNS_TO_LENGTH`

These six columns are **text fields that carry ML-useful signal in their length, not their
content**. Instead of dropping them, the code converts them to integer length features.

| Column | Original value | Converted to | Why length matters |
|--------|---------------|--------------|-------------------|
| `server_name` | `"api.corp.example.internal"` | `28` | Long internal SNI names differ from short CDN domains |
| `requested_server_name` | `"login.example.com"` | `18` | QUIC equivalent of SNI |
| `client_fingerprint` | `"abc123...def"` (hex) | `32` | Fixed length for known fingerprint types, unusual lengths signal anomalies |
| `server_fingerprint` | same | same | same reasoning |
| `user_agent` | `"Mozilla/5.0 (Windows…)"` | `73` | Short user-agents are unusual; absent user-agents (length 0) are a strong malware signal |
| `content_type` | `"application/octet-stream"` | `24` | Binary content types differ from text/html |

The key insight: **the string itself has too many unique values** to one-hot encode (thousands of
distinct SNIs). But the length has far fewer unique integer values and preserves a meaningful
signal. This is a form of feature engineering that reduces cardinality without losing information.

### `IDENTIFIER_COLUMNS`

These columns must be **completely removed** from ML training data. There are two distinct reasons:

**Category A — Network identifiers (IP addresses, ports, MACs):**

`src_ip`, `dst_ip`, `src_mac`, `dst_mac`, `src_port`, `dst_port`

If you train on IP addresses, the model learns that "traffic from 192.168.1.100 is benign"
because that host only appeared in the benign training PCAP. This is **spurious correlation** —
the model overfits to specific hosts rather than learning generalizable traffic patterns. At
inference time, it will fail on any IP address it has not seen before.

**Category B — Temporal identifiers (timestamps):**

`ts`, `first_seen_ms`, `last_seen_ms`, `bidirectional_first_seen_ms`, `bidirectional_last_seen_ms`

If you train on wall-clock timestamps, the model learns "traffic captured on Tuesday afternoon is
benign" (because that is when benign traffic was captured in the lab). This is a severe form of
**temporal data leakage** — the model learns *when* data was collected, not the traffic patterns
themselves.

**Category C — Opaque identifiers:**

`uid`, `id`, `expiration_id`, `vlan_id`, `tunnel_id`

These are arbitrary unique IDs or network infrastructure identifiers. They carry no transferable
signal — they are effectively random numbers from the ML model's perspective.

---

## 3. Function Walkthrough — Function by Function

### 3.1 `detect_protocol_masks(df)` — Lines 43–58

```python
def detect_protocol_masks(df: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    ssl_indicator_cols = [c for c in df.columns if c in ("version", "cipher", "server_name", "ja3", "ja3s")]
    if ssl_indicator_cols:
        tls_mask = df[ssl_indicator_cols].notna().any(axis=1)
    else:
        tls_mask = pd.Series(False, index=df.index)

    likely_quic_cols = [
        c for c in df.columns
        if any(token in c.lower() for token in ("quic", "cid", "scid", "dcid", "h3", "http3"))
    ]
    if likely_quic_cols:
        quic_mask = df[likely_quic_cols].notna().any(axis=1)
    else:
        quic_mask = pd.Series(False, index=df.index)

    return tls_mask, quic_mask
```

**What it does:** Returns two boolean pandas Series (one per row) indicating whether each row
has TLS evidence and/or QUIC evidence.

**Returns:**
- `tls_mask` — `True` for rows where at least one TLS indicator column is non-null.
- `quic_mask` — `True` for rows where at least one QUIC-related column is non-null.

**The TLS detection logic:**

```python
ssl_indicator_cols = [c for c in df.columns if c in ("version", "cipher", "server_name", "ja3", "ja3s")]
tls_mask = df[ssl_indicator_cols].notna().any(axis=1)
```

Step 1: Find which of the five TLS indicator column names are actually present in the DataFrame
(defensive — not every merged CSV will have all five, e.g., if Zeek only produced `ssl.log`
without `ja3` plugin).

Step 2: `df[ssl_indicator_cols].notna()` produces a boolean DataFrame where each cell is `True`
if the value is not NaN. `.any(axis=1)` collapses across columns — a row is `True` if *any* of
its TLS indicator cells are non-null.

**Visual example:**

```
     version  cipher  server_name  ja3    ja3s
row0  TLSv13  AES...  example.com  ab12   cd34  → notna: T T T T T → any=True  (TLS row)
row1  NaN     NaN     NaN          NaN    NaN   → notna: F F F F F → any=False (no TLS)
row2  NaN     NaN     NaN          ab12   NaN   → notna: F F F T F → any=True  (partial TLS, still TLS)
```

**The QUIC detection logic:**

```python
likely_quic_cols = [
    c for c in df.columns
    if any(token in c.lower() for token in ("quic", "cid", "scid", "dcid", "h3", "http3"))
]
quic_mask = df[likely_quic_cols].notna().any(axis=1)
```

QUIC columns are detected by searching column *names* for known QUIC tokens. This is the same
pattern as `QUIC_SIGNAL_TOKENS` in `quality.py` (Tutorial 09) — exact name matching is fragile
because Zeek versions change QUIC log field names.

**Symmetry with `quality.py`:**

`detect_protocol_masks` and `row_has_encrypted_signal` (Tutorial 09) implement the same concept
at different levels:
- `quality.py`: row-by-row CSV scan using `csv.DictReader` (memory-efficient, no pandas).
- `build_dataset.py`: vectorised pandas operation on an already-loaded DataFrame (fast, uses
  numpy under the hood via `.notna().any()`).

The logic is intentionally duplicated rather than shared because the two layers have different
constraints — quality gates must be memory-efficient, while `build_dataset.py` operates on a
DataFrame already loaded for processing.

---

### 3.2 `build_ml_ready_frame(df)` — Lines 61–74

```python
def build_ml_ready_frame(df: pd.DataFrame) -> pd.DataFrame:
    working_df = df.copy()

    # Step 1 — text → length
    for column in TEXT_COLUMNS_TO_LENGTH:
        if column in working_df.columns:
            working_df[f"{column}_len"] = working_df[column].astype("string").str.len()

    # Step 2 — drop identifier columns
    drop_cols = [column for column in IDENTIFIER_COLUMNS if column in working_df.columns]
    # Step 3 — drop remaining object (text) columns
    drop_text = [column for column in working_df.columns if working_df[column].dtype == "object"]
    ml_df = working_df.drop(columns=list(set(drop_cols + drop_text)), errors="ignore")

    # Step 4 — select only numeric columns
    ml_df = ml_df.select_dtypes(include=[np.number]).copy()

    # Step 5 — replace inf, fill NaN
    ml_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    ml_df.fillna(0, inplace=True)

    return ml_df
```

This function is the core transformation. It takes any DataFrame (already filtered to
TLS/QUIC-only rows if `protocol_filter="encrypted_only"`) and returns a numeric-only, clean
DataFrame ready for `sklearn`.

**Step by step:**

**Step 1 — Text to length (Lines 64–66):**
```python
for column in TEXT_COLUMNS_TO_LENGTH:
    if column in working_df.columns:
        working_df[f"{column}_len"] = working_df[column].astype("string").str.len()
```

For each text column in `TEXT_COLUMNS_TO_LENGTH` that exists in the DataFrame, creates a new
column `{column}_len` with integer character length. The `.astype("string")` cast is important:
it converts pandas' old `object` dtype (which can hold any Python object) to the proper
`StringDtype`, making `.str.len()` reliable even when the column contains NaN values (which
become `pd.NA` in StringDtype and produce `pd.NA` length — handled later by `fillna(0)`).

The original text column is NOT dropped here — it gets dropped in Step 2/3 below. The two-step
approach (create new → drop old) ensures `{column}_len` is in `working_df` before the drop
phase, so it survives.

**Step 2 — Drop identifier columns (Lines 68):**
```python
drop_cols = [column for column in IDENTIFIER_COLUMNS if column in working_df.columns]
```

Builds the list of identifier columns that actually exist in this DataFrame (defensive — not all
may be present in every merged CSV).

**Step 3 — Drop remaining object/text columns (Line 69):**
```python
drop_text = [column for column in working_df.columns if working_df[column].dtype == "object"]
```

After Step 1, the text columns from `TEXT_COLUMNS_TO_LENGTH` have been encoded as `_len`
integers but the original string columns still exist. This line catches those plus any other text
columns that were not in `TEXT_COLUMNS_TO_LENGTH` (e.g., Zeek's `certificate.subject` string,
NFStream's application name string).

The `set()` deduplication in the drop call:
```python
ml_df = working_df.drop(columns=list(set(drop_cols + drop_text)), errors="ignore")
```

Prevents errors if a column appears in both lists. `errors="ignore"` handles any stale column
names that might not exist.

**Step 4 — Numeric-only selection (Line 71):**
```python
ml_df = ml_df.select_dtypes(include=[np.number]).copy()
```

A final safety net after all drops. `select_dtypes(include=[np.number])` keeps only columns
whose dtype is a numpy numeric type (`int64`, `float64`, `int32`, etc.). This catches any
remaining non-numeric columns that slipped through (e.g., boolean columns from Zeek, which have
dtype `bool` rather than `object`).

The `.copy()` after `select_dtypes` is important: `select_dtypes` returns a view, not a copy.
If you later modify `ml_df` (the `inplace` operations in Step 5), you would get a
`SettingWithCopyWarning` and potentially corrupt `working_df`. The `.copy()` makes it independent.

**Step 5 — Replace infinity, fill NaN (Lines 72–73):**
```python
ml_df.replace([np.inf, -np.inf], np.nan, inplace=True)
ml_df.fillna(0, inplace=True)
```

**Infinity values** appear in NFStream features like flow rate ratios. For example:
`bytes_per_second = total_bytes / duration_seconds`. If `duration_seconds = 0` (a single-packet
flow with zero duration), this produces `inf`. sklearn models crash on `inf` because it propagates
through matrix operations.

**NaN values** remain after the merge for rows where a TLS column had no value (e.g., a flow
that matched via `conn.csv` but not `ssl.csv`). Most sklearn models cannot handle NaN.

Both are replaced with `0`. The choice of `0` over mean imputation or median imputation is
intentional at this stage:
- Mean/median imputation is handled later in the ML workflow (`ml/workflow.py`, Tutorial 19).
- Using `0` here is a conservative neutral fill — it signals "absent" without introducing
  statistical dependencies between the training and test set (which mean imputation would create
  if the mean is computed on the full dataset including the test set).

---

### 3.3 `build_dataset_outputs(...)` — Lines 77–114

```python
def build_dataset_outputs(
    merged_csv: str | Path,
    *,
    output_dir: str | Path,
    dataset_name: str,
    protocol_filter: str = "encrypted_only",
) -> dict[str, str | int]:
```

The orchestrating function. It loads the merged CSV, applies all transformations, and writes
**four output files**.

**Parameters:**

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `merged_csv` | required | Path to the merged CSV from Tutorial 08 |
| `output_dir` | required | Directory for all four output files |
| `dataset_name` | required | Used to construct output file names via `DatasetArtifacts` |
| `protocol_filter` | `"encrypted_only"` | Whether ML-ready data includes only TLS/QUIC rows or everything |

**Step 1 — Build artifact paths:**
```python
artifacts = build_dataset_artifacts(dataset_name=dataset_name, output_dir=output_dir)
```

`build_dataset_artifacts` (from `common.py`) creates a `DatasetArtifacts` frozen dataclass with
all output paths pre-computed as:
```
{output_dir}/{dataset_name}_all_merged.csv
{output_dir}/{dataset_name}_tls.csv
{output_dir}/{dataset_name}_quic.csv
{output_dir}/{dataset_name}_ml_ready.csv
```

**Step 2 — Load and validate:**
```python
df = pd.read_csv(merged_path, low_memory=False)
if "uid" not in df.columns:
    raise RuntimeError("Expected column 'uid' not found. Did feature merge succeed?")
```

Checks that the merge step ran successfully by verifying `uid` is present. If it is missing,
the merged CSV is almost certainly from a different step or was accidentally overwritten.

**Step 3 — Build protocol masks:**
```python
tls_mask, quic_mask = detect_protocol_masks(df)
encrypted_mask = tls_mask | quic_mask
```

`tls_mask | quic_mask` is a bitwise OR on boolean Series — a row is in `encrypted_mask` if it
has TLS evidence *or* QUIC evidence (or both). Rows that have neither are plain TCP flows that
the filter in Tutorial 04 missed.

**Step 4 — Apply protocol filter:**
```python
ml_source = df[encrypted_mask].copy() if protocol_filter == "encrypted_only" else df.copy()
ml_df = build_ml_ready_frame(ml_source)
```

If `protocol_filter="encrypted_only"` (the default), only TLS+QUIC rows enter `build_ml_ready_frame`.
Plain TCP rows are excluded from ML training but still written to `all_merged_csv`.

If `protocol_filter="all"`, every row (including non-TLS/QUIC rows) enters ML training. This is
used for research experiments to test whether the protocol filter improves model quality.

**Step 5 — Write four output files:**
```python
df.to_csv(artifacts.all_merged_csv, index=False)      # full merge, no filtering
df[tls_mask].to_csv(artifacts.tls_csv, index=False)   # TLS rows only (still raw/text)
df[quic_mask].to_csv(artifacts.quic_csv, index=False) # QUIC rows only (still raw/text)
ml_df.to_csv(artifacts.ml_ready_csv, index=False)     # numeric-only, clean
```

**Why four files?**

| File | Contains | Used by |
|------|---------|---------|
| `all_merged.csv` | Every row from the merge, no filtering, all columns | Debugging, manual inspection, research |
| `tls.csv` | Only TLS rows, all columns including text | Protocol-specific analysis, Zeek field inspection |
| `quic.csv` | Only QUIC rows, all columns including text | QUIC-specific research |
| `ml_ready.csv` | TLS+QUIC rows, numbers only, NaN→0 | ML training (Tutorial 19) and pruning (Tutorial 11) |

The first three files are **analysis artifacts** — they keep the raw merged columns (including
text, identifiers, timestamps) for human inspection. The fourth is the **ML artifact** — it has
undergone the transformations that make it safe for training.

**Step 6 — Return statistics:**
```python
return {
    "all_merged_csv": str(artifacts.all_merged_csv),
    "tls_csv": str(artifacts.tls_csv),
    "quic_csv": str(artifacts.quic_csv),
    "ml_ready_csv": str(artifacts.ml_ready_csv),
    "total_rows": int(len(df)),
    "tls_rows": int(tls_mask.sum()),
    "quic_rows": int(quic_mask.sum()),
    "encrypted_rows": int(encrypted_mask.sum()),
    "ml_rows": int(len(ml_df)),
    "ml_columns": int(ml_df.shape[1]),
    "protocol_filter": protocol_filter,
}
```

Exposes the row and column counts of every output artifact. Downstream (orchestration, provenance
tracking) can use this to verify expectations: e.g., if `ml_columns` suddenly drops from 200 to
20 it indicates a schema change in Zeek or NFStream output.

---

### 3.4 `main(argv)` — Lines 117–143

```python
parser.add_argument("--protocol-filter", choices=("encrypted_only", "all"), default="encrypted_only", ...)
```

The CLI exposes the `protocol_filter` choice, allowing research experiments without code changes:

```bash
# Production mode — only TLS/QUIC rows in ML training
python -m tls_dataset.pipeline.build_dataset \
  --merged artifacts/merged.csv \
  --dataset-name benign_2024 \
  --output-dir artifacts/ \
  --protocol-filter encrypted_only

# Research mode — include all flows
python -m tls_dataset.pipeline.build_dataset \
  --merged artifacts/merged.csv \
  --dataset-name benign_2024_all \
  --output-dir artifacts/ \
  --protocol-filter all
```

Output is key=value lines per result item — easy to `grep` or parse in shell scripts.

---

## 4. The Complete Transformation Chain

This diagram shows exactly what happens to the columns as a row moves through the file:

```
merged.csv row (example columns):
  uid=C3l2bD  src_ip=192.168.1.5  src_port=54321  ts=1609459203.5
  server_name=api.example.com  cipher=TLS_AES_256_GCM_SHA384  ja3=abc123
  bidirectional_bytes=4096  bidirectional_mean_ps=512.0
  x509_record_count=3  x509_certificate.not_valid_after__num_mean=1893456000.0

        │
        │  detect_protocol_masks()
        │  → tls_mask=True (cipher is present)
        │  → quic_mask=False
        │
        │  [encrypted_mask=True → row included in ml_source]
        │
        ▼
        build_ml_ready_frame():

  Step 1 — TEXT_COLUMNS_TO_LENGTH:
    server_name="api.example.com" → server_name_len=15
    (original server_name column still present for now)

  Step 2/3 — DROP:
    uid ✗  src_ip ✗  src_port ✗  ts ✗         (IDENTIFIER_COLUMNS)
    server_name ✗  cipher ✗                    (object dtype)

  Step 4 — select_dtypes(numeric):
    keeps: server_name_len, bidirectional_bytes, bidirectional_mean_ps,
           x509_record_count, x509_certificate.not_valid_after__num_mean, ja3 (if numeric)
    drops: any remaining non-numeric that survived steps 2/3

  Step 5 — replace inf → NaN → 0:
    any inf in ratio columns → 0
    any NaN in x509 columns → 0

ml_ready.csv row:
  server_name_len=15  bidirectional_bytes=4096  bidirectional_mean_ps=512.0
  x509_record_count=3  x509_certificate.not_valid_after__num_mean=1893456000.0
  [all numeric, no NaN, no inf, no identifiers, no timestamps]
```

---

## 5. How This Connects to the Artifact Path System

`build_dataset_outputs` uses `build_dataset_artifacts` from `common.py` to resolve all four
output paths. The naming convention for `dataset_name="benign_2024"` is:

```
artifacts/
  benign_2024_all_merged.csv          ← full merge, analysis use
  benign_2024_tls.csv                 ← TLS-only rows, analysis use
  benign_2024_quic.csv                ← QUIC-only rows, analysis use
  benign_2024_ml_ready.csv            ← numeric-only, ML input
  benign_2024_ml_no_constant.csv      ← after Tutorial 11 (pruning step 1)
  benign_2024_ml_no_constant_novar.csv← after Tutorial 11 (pruning step 2)
  benign_2024_ml_pruned.csv           ← after Tutorial 11 (pruning step 3)
  benign_2024_ml_final.csv            ← after Tutorial 12 (finalization)
```

`ml_ready.csv` is the **entry point** for the pruning and finalization stages (Tutorials 11
and 12). Every downstream stage reads from one artifact path and writes to the next.

---

## 6. Interview Questions and Answers

**Q: Why convert text columns to their length instead of one-hot encoding or dropping them?**

A: One-hot encoding on high-cardinality text (thousands of unique SNI hostnames, hundreds of
cipher suite strings) would produce thousands of binary columns — most of which would be nearly
zero across the training data. This causes the "curse of dimensionality" and would massively slow
down training without adding predictive value. Dropping these columns entirely would discard
information — a 200-character SNI (a long internal hostname) looks very different from a
3-character one. Length encoding preserves the information in a form that is safe for tree-based
models (which can split on "length > 20") and linear models (which can weight longer lengths more
heavily).

---

**Q: Why fill NaN with 0 rather than the column mean?**

A: This stage is intentionally conservative. The proper imputation strategy (mean, median, or
constant) should be decided in the ML workflow (`ml/workflow.py`) where the imputer is fitted on
training data only and then applied to test data. If you impute with the dataset mean here (before
the train/test split), you leak information from the test set into the training set — the mean
used to fill training NaN values incorporates test set statistics. Zero-filling at this stage is
a safe neutral placeholder that downstream imputation in the ML pipeline overrides.

---

**Q: Why are timestamps in `IDENTIFIER_COLUMNS`? Timestamps carry real information about when
a flow occurred.**

A: Yes — and that is exactly why they must be removed. The issue is **temporal data leakage**. If
benign traffic was captured on Monday and malicious traffic on Friday, a model trained on raw
timestamps will learn "Monday = benign, Friday = malicious" rather than the actual flow-level
features that distinguish them. At inference time (a Tuesday), the model will fail because the
day-of-week signal is absent. The fundamental goal is to learn protocol-level behaviour patterns,
not artefacts of when the capture was conducted.

---

**Q: What is the difference between `all_merged.csv` and `ml_ready.csv`?**

A: `all_merged.csv` is a verbatim copy of the merged CSV including all rows (TLS, QUIC, and
non-encrypted), all original text columns, identifier columns, and timestamps. It is for human
inspection, debugging, and research. `ml_ready.csv` has undergone four transformations: protocol
filtering (only TLS+QUIC rows), text-to-length encoding, identifier/text column removal, and
inf/NaN cleaning. It contains only numeric columns suitable for a scikit-learn estimator.

---

**Q: Why does `select_dtypes(include=[np.number])` run as a final step when you already dropped
text columns earlier?**

A: It is a defensive safety net. After dropping `object`-dtype columns, there may still be
non-numeric columns in the DataFrame — specifically `bool` columns (which pandas treats as a
distinct dtype from `int64`) or any `category` columns introduced by pandas' type inference
during CSV loading. `select_dtypes` guarantees the output has only numpy numeric types regardless
of what the drop steps missed. The two-step approach (explicit drops + dtype selection) is more
readable than relying solely on `select_dtypes`, because the explicit drops document *why* those
specific columns are removed.

---

**Q: `tls_mask` and `quic_mask` can both be `True` for the same row. What does that mean?**

A: It means the row has evidence of both TLS and QUIC metadata. This is theoretically possible
for flows captured during a protocol negotiation (e.g., an HTTP/3 connection that falls back to
TLS over TCP) or if Zeek logged the same flow under both `ssl.log` and `quic.log` due to a
version/plugin quirk. The row appears in both `tls.csv` and `quic.csv` — these analysis files
are not mutually exclusive. For the ML-ready dataset, the row is included once in `ml_ready.csv`
because `encrypted_mask = tls_mask | quic_mask` keeps it without duplication (OR on a boolean
Series never duplicates rows).

---

*Next: [Tutorial 11 — Feature Pruning](11_pipeline_pruning.md)*
