# Tutorial 17 — Canonical Labeled Dataset Builder (`pipeline/canonical.py`)

## Prerequisites

- Tutorial 10 (`build_dataset.py`) — the `ml_ready.csv` files produced per-capture are what
  `input_csv` points to in each `CanonicalSource`.
- Tutorial 09 (`quality.py`) — the `quality_report_json` artifact written per-capture is read
  here to annotate each row with its source's quality status.
- Tutorial 15 (`provenance.py`) — the provenance chain concept. This file is the stage that
  assembles multiple per-capture pipelines into one labeled dataset.

---

## 1. Why This File Exists — What "Canonical" Means

Every tutorial so far processes **one PCAP at a time**. After running the full pipeline for a
benign Chrome capture and a malicious CTU-13 botnet capture separately, you have:

```
artifacts/chrome_2024/chrome_2024_ml_final.csv      (label = benign)
artifacts/ctu13_s1/ctu13_s1_ml_final.csv            (label = malicious)
artifacts/ctu13_s2/ctu13_s2_ml_final.csv            (label = malicious)
```

These are three separate CSVs with no labels, no common schema guarantee, and no way to know
which rows came from which capture. A supervised ML model needs a **single labeled DataFrame**:

```
record_id | label | label_id | attack_family | window_id | ... | feature_1 | feature_2 | ...
sha256... | benign|     0    | unknown       | chrome:w0 | ... |   4096    |   0.72    | ...
sha256... |malicio|     1    | Neris          | ctu13:w0  | ... |   1024    |   0.11    | ...
```

`canonical.py` builds that single DataFrame. It:
1. Reads a YAML config that declares all input sources with their labels and metadata.
2. For each source, loads the `ml_final.csv`, adds metadata columns (label, record_id, window,
   protocol_family, quality_status, ...), and handles optional filtering.
3. Concatenates all annotated frames into one canonical CSV.
4. Writes a summary JSON with row/column counts, label distribution, and quality breakdown.

The word "canonical" means: **this is the single authoritative labeled dataset**. Everything
downstream (ML training, multi-tier detection, the backend's scoring logic) consumes this file.

---

## 2. Module-Level Constants

### `LABEL_TO_ID` — Lines 16–19

```python
LABEL_TO_ID = {
    "benign": 0,
    "malicious": 1,
}
```

Maps string labels to integers for ML. Binary classification requires numeric class labels —
sklearn estimators use 0 and 1. The convention `benign=0, malicious=1` is standard in network
security ML: the positive class (what the model is trained to detect) is malicious (1), and the
negative class is benign (0). This convention aligns with sklearn's default treatment of the
highest class value as the positive class in binary metrics like precision, recall, and AUC.

Only two labels are defined. If a source's YAML specifies any other label string, `canonicalize_source`
raises a `RuntimeError` at line 217 — there is no silent fallback.

### `BASE_METADATA_COLUMNS` — Lines 21–46

```python
BASE_METADATA_COLUMNS = [
    "record_id", "sample_id", "label", "label_id",
    "attack_family", "attack_category", "traffic_role",
    "capture_id", "protocol_family", "window_id",
    "flow_start_ms", "flow_end_ms", "window_start_ms", "window_end_ms",
    "source_dataset", "source_name", "feature_view", "source_row_index",
    "quality_status", "quality_failed", "quality_report_path",
    "provenance_path", "input_csv", "is_encrypted",
]
```

Every row in the canonical dataset carries these 23 columns **before** the actual ML features.
They split into four conceptual groups:

**Identity columns** — uniquely identify a row:

| Column | What it stores |
|--------|---------------|
| `record_id` | SHA256 of `source_dataset|capture_id|feature_view|row_index` — stable, deterministic, globally unique |
| `sample_id` | First 16 hex chars of `record_id` — a shorter human-readable identifier for display |
| `source_row_index` | Integer index of this row within its source CSV — allows tracing back to the exact original row |

**Label columns** — the supervised learning targets:

| Column | What it stores |
|--------|---------------|
| `label` | Human-readable: `"benign"` or `"malicious"` |
| `label_id` | Integer: `0` or `1` — what sklearn actually uses |
| `attack_family` | Fine-grained attack name, e.g. `"Neris"`, `"Virut"`, `"unknown"` |
| `attack_category` | Coarse attack type, e.g. `"botnet"`, `"ransomware"`, `"normal"` |
| `traffic_role` | Who generated the traffic, e.g. `"victim"`, `"attacker"`, `"benign_client"` |

**Temporal/windowing columns** — for time-aware analysis:

| Column | What it stores |
|--------|---------------|
| `capture_id` | Identifier for the capture session, e.g. `"ctu13_s1"` |
| `window_id` | Time window bucket, e.g. `"ctu13_s1:w000042"` — which 1-minute window the flow falls in |
| `flow_start_ms` | Unix epoch milliseconds of the first packet |
| `flow_end_ms` | Unix epoch milliseconds of the last packet |
| `window_start_ms` | Start of the time window bucket this flow belongs to |
| `window_end_ms` | End of the time window bucket |

**Provenance/audit columns** — for dataset integrity:

| Column | What it stores |
|--------|---------------|
| `source_dataset` | Dataset name, e.g. `"CTU-13"`, `"CICIDS2017"` |
| `source_name` | Source identifier from the YAML config |
| `feature_view` | Which feature extraction approach, e.g. `"nfstream"`, `"zeek"` |
| `quality_status` | `"pass"`, `"fail"`, or `"unknown"` — from the quality report JSON |
| `quality_failed` | `True`, `False`, or `None` — raw boolean from quality report |
| `quality_report_path` | Absolute path to the quality report JSON for this source |
| `provenance_path` | Absolute path to the provenance JSON for this source |
| `input_csv` | Absolute path to the source CSV |
| `is_encrypted` | Boolean — whether NFStream/Zeek identified this flow as TLS or QUIC |
| `protocol_family` | `"tls"`, `"quic"`, or `"other"` |

These columns come first in the output CSV. When you open the canonical dataset in a spreadsheet
or `head()` it in pandas, the first 23 columns tell you everything about where each row came
from, what class it belongs to, and how trustworthy it is — before you ever see a feature value.

---

## 3. `CanonicalSource` Dataclass — Lines 49–64

```python
@dataclass(frozen=True)
class CanonicalSource:
    name: str
    input_csv: str
    source_dataset: str
    capture_id: str
    label: str
    attack_family: str
    attack_category: str
    feature_view: str
    encrypted_only: bool
    window_size_ms: int
    traffic_role: str
    quality_report_json: str | None = None
    provenance_json: str | None = None
    extra_labels: dict[str, Any] = field(default_factory=dict)
```

One instance per YAML source entry. `frozen=True` because a source declaration is a
configuration fact — it should not be modified after loading from YAML.

The required fields (no default) must be present in every YAML source entry. The optional fields
have sensible defaults or are `None`.

**`window_size_ms`:** How wide (in milliseconds) each time window is. Default 60,000 ms = 1
minute. Flows are bucketed into windows of this size relative to the earliest flow in the
capture. This is used by the multi-tier detection engine (Tutorial 20) to group flows by time
for graph-based analysis — flows in the same time window are co-temporal and may represent
coordinated activity.

**`encrypted_only`:** If `True`, rows that `derive_protocol_family` classifies as `"other"`
(non-TLS, non-QUIC) are dropped from this source's contribution to the canonical dataset. This
mirrors the `protocol_filter="encrypted_only"` in Tutorial 13's orchestration. Default `True`
because the project is specifically about TLS/QUIC classification.

**`extra_labels`:** A free-form dict for source-specific annotation columns not in
`BASE_METADATA_COLUMNS`. For example:
```yaml
extra_labels:
  botnet_id: "neris_01"
  campaign: "2011-08-10"
```
These become additional columns in the canonical dataset, with the same value for every row from
this source. Useful for sub-categorising within the malicious class.

---

## 4. `_load_yaml` and `load_canonical_sources` — Lines 67–111

### `_load_yaml` (Lines 67–73)

```python
def _load_yaml(path: str | Path) -> dict[str, Any]:
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise RuntimeError(f"Expected a mapping in config file: {config_path}")
    return data
```

`yaml.safe_load` is used — not `yaml.load`. `safe_load` only deserialises basic YAML types
(strings, numbers, lists, dicts). `yaml.load` with the default Loader can execute arbitrary
Python constructors embedded in YAML — a code execution vulnerability. In a research pipeline
that may process config files from external sources, `safe_load` is the correct choice.

The `isinstance(data, dict)` check guards against a YAML file that is a list at the root
(which `safe_load` would return as a Python list) — fail immediately with a readable error
rather than a confusing `AttributeError` later.

### `load_canonical_sources` (Lines 76–111)

Reads the YAML config and constructs a list of `CanonicalSource` objects.

**Key design decisions:**

`default_window_size_ms = int(config.get("window_size_ms", 60_000))` — a top-level YAML
key provides a default window size for all sources. Individual sources can override it with their
own `window_size_ms`. This two-level default allows dataset-wide configuration without repeating
the value for every source entry.

```python
label = str(raw_source["label"]).lower()
```

Normalises label to lowercase before constructing `CanonicalSource`. YAML `label: Benign` and
`label: benign` are treated identically. This prevents `LABEL_TO_ID.get("Benign")` returning
`None` due to capitalisation mismatch.

```python
attack_family=str(raw_source.get("attack_family", "unknown")),
attack_category=str(raw_source.get("attack_category", "unknown")),
traffic_role=str(raw_source.get("traffic_role", label)),
```

For benign sources, `traffic_role` defaults to `"benign"` (the label value itself). For
malicious sources, you would typically set `traffic_role="victim"` or `traffic_role="attacker"`.
The label-as-default makes benign sources require zero extra YAML fields.

---

## 5. `_load_quality_failed` and `derive_quality_status` — Lines 114–130

```python
def _load_quality_failed(path: str | None) -> bool | None:
    if path is None:
        return None
    ...
    failed = payload.get("failed")
    return bool(failed) if failed is not None else None
```

Returns a **three-value type**: `True` (quality failed), `False` (quality passed), `None`
(no quality report available or report does not contain `"failed"` key).

```python
def derive_quality_status(quality_failed: bool | None) -> str:
    if quality_failed is True:  return "fail"
    if quality_failed is False: return "pass"
    return "unknown"
```

The three-value system is intentional. Using only `True`/`False` would force you to decide
whether "no report" means "pass" or "fail" — both are wrong. "No report" means the quality check
was not run for this source. The `"unknown"` status propagates to the canonical dataset, allowing
downstream consumers to filter by quality status:

```python
# Only train on sources with confirmed passing quality:
train_df = canonical_df[canonical_df["quality_status"] == "pass"]
```

Note the explicit `is True` and `is False` checks — not `==`. In Python, `bool(None) == False`
is `True`, so `if quality_failed == False` would incorrectly match `None`. The identity checks
`is True` and `is False` correctly distinguish all three states.

---

## 6. `derive_protocol_family(df)` — Lines 133–149

```python
def derive_protocol_family(df: pd.DataFrame) -> pd.Series:
    protocol_family = pd.Series("other", index=df.index, dtype="string")
    ...
```

Starts with `"other"` for every row and progressively overrides with `"tls"` or `"quic"` using
three signal sources, each applied only where the protocol is still `"other"`:

**Signal 1 — `application_name` column (NFStream's application identification via nDPI):**
```python
if "application_name" in df.columns:
    app_name = df["application_name"].fillna("").astype(str).str.upper()
    protocol_family[app_name.str.startswith("TLS")]  = "tls"
    protocol_family[app_name.str.startswith("QUIC")] = "quic"
```
NFStream's `application_name` field uses nDPI's protocol classification — values like
`"TLS.Google"`, `"TLS.Amazon"`, `"QUIC.Google"`. Checking `str.startswith("TLS")` catches all
TLS sub-protocols. This is the most reliable signal when present.

**Signal 2 — Zeek's `version` column (TLS version string from ssl.log/tls.log):**
```python
if "version" in df.columns:
    version = df["version"].fillna("").astype(str).str.upper()
    protocol_family[(protocol_family == "other") & version.str.startswith("TLS")] = "tls"
```
Applied only to rows still `"other"` — does not override the `application_name`-based
classification. Zeek's `version` field contains strings like `"TLSv13"`, `"TLSv12"`, `"TLS"`.
The `startswith("TLS")` catches all variants. No QUIC equivalent here because Zeek logs QUIC
via `quic.log` which has different column names.

**Signal 3 — QUIC-specific column presence (from quic.log merge):**
```python
for quic_column in ("client_scid", "server_scid", "quic_version"):
    if quic_column in df.columns:
        values = df[quic_column].fillna("").astype(str).str.strip()
        protocol_family[(protocol_family == "other") & values.ne("")] = "quic"
```
QUIC flows have non-empty `client_scid` (source Connection ID) or `server_scid` fields from
Zeek's `quic.log`. A non-empty value in any QUIC-specific column is strong evidence of QUIC.

The cascade matters: a flow that appears in both `ssl.log` (TLS) and `quic.log` (QUIC) due to
a parsing edge case would first be classified as `"tls"` by Signal 1 or 2, and then Signal 3
would not override it (the `protocol_family == "other"` guard). TLS classification takes
precedence over QUIC column presence in that edge case.

---

## 7. `_build_record_id(source, source_row_index)` — Lines 152–154

```python
def _build_record_id(source: CanonicalSource, source_row_index: int) -> str:
    basis = f"{source.source_dataset}|{source.capture_id}|{source.feature_view}|{source_row_index}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()
```

Produces a 64-character SHA256 hex string as a stable, deterministic row identifier.

**What the basis string encodes:**

| Component | Example | Purpose |
|-----------|---------|---------|
| `source_dataset` | `"CTU-13"` | Which public dataset this flow came from |
| `capture_id` | `"ctu13_s1"` | Which specific capture session |
| `feature_view` | `"nfstream"` | Which feature extraction method |
| `source_row_index` | `42` | Which row within that capture's CSV |

The `|` separator prevents collisions between fields — `"CTU-13|ctu13"` and `"CTU-13|ctu"` +
`"13"` would be different strings in the basis even though `|` prevents the second scenario.

**Why SHA256 here — not a UUID or sequential integer?**

UUID would be random — different every run, making the canonical dataset non-reproducible.
Sequential integer would require a global counter — fragile when sources are added or reordered.
SHA256 of the basis string is **deterministic**: given the same source configuration and row
index, it always produces the same `record_id`. This means:
- Two pipeline runs on identical inputs produce identical `record_id` values.
- A reviewer can independently recompute `record_id` from the source metadata and verify it.
- When the canonical dataset is re-built with an extra source added, existing rows keep the same
  `record_id` — they are the same records, just with new neighbours.

`sample_id = record_id[:16]` — the first 16 hex characters (64 bits) provide a shorter display
identifier. The collision probability for 16 hex chars across millions of rows is negligible for
a research dataset.

---

## 8. `_build_window_columns(...)` — Lines 157–185

Time windowing is one of the most conceptually important operations in this file. It assigns
every flow to a named time bucket so that the multi-tier detection system (Tutorial 20) can
group co-temporal flows together.

### The concept

A botnet C2 beacon fires every 60 seconds. If you look at one flow in isolation, it might look
like benign HTTPS traffic. But if you look at all flows within the same 60-second window and see
that 50 of them are from the same host to the same IP, the pattern becomes clear. Time windows
are the mechanism that enables this group-level analysis.

```python
baseline_ms   = int(valid_flow_start.min())           # earliest flow in this capture
bucket_index  = (flow_start - baseline_ms) // window_size_ms   # which bucket (floor division)
window_start  = bucket_index * window_size_ms + baseline_ms
window_end    = window_start + window_size_ms - 1
window_id     = f"{capture_id}:w{int(bucket_index):06d}"
```

**Walkthrough with numbers:**

```
baseline_ms   = 1704960000000  (first flow starts at this Unix epoch ms)
window_size_ms = 60000         (1-minute windows)

Flow A: flow_start = 1704960000000  →  bucket = (0) // 60000 = 0  →  window "ctu13_s1:w000000"
Flow B: flow_start = 1704960045000  →  bucket = (45000) // 60000 = 0  →  window "ctu13_s1:w000000"
Flow C: flow_start = 1704960072000  →  bucket = (72000) // 60000 = 1  →  window "ctu13_s1:w000001"
Flow D: flow_start = 1704960300000  →  bucket = (300000) // 60000 = 5  →  window "ctu13_s1:w000005"
```

Flows A and B are co-temporal (both within the first minute), Flow C is in the second minute,
Flow D is in the sixth minute.

**`Int64` (capital I) vs `int64` (lowercase):**

```python
flow_start = pd.to_numeric(df["bidirectional_first_seen_ms"], errors="coerce").astype("Int64")
```

`"Int64"` is pandas' **nullable integer type** — it can hold `pd.NA` for missing values.
`"int64"` (numpy's type) cannot hold `NaN` — it would convert `NaN` to a large negative integer
(`-9223372036854775808`) which would produce garbage window calculations. `"Int64"` correctly
propagates `pd.NA` through arithmetic, so rows without a timestamp produce `pd.NA` window
values rather than nonsense numbers.

**The all-NA fallback:**
```python
if flow_start.isna().all():
    window_id = pd.Series([f"{capture_id}:w000000"] * len(df), dtype="string")
    window_start = window_end = pd.Series([pd.NA] * len(df), dtype="Int64")
    return ...
```

If a source CSV has no timestamp columns (e.g., it came from a heavily pruned ML-ready CSV
that dropped timestamps), all flows are assigned to window `w000000`. This graceful fallback
prevents a crash and keeps the canonical dataset valid — the `window_id` is synthetic but the
feature data is intact.

**`bucket_index.map(lambda ...)` for `window_id`:**
```python
window_id = bucket_index.map(
    lambda value: f"{capture_id}:w{int(value):06d}"
    if value is not pd.NA and pd.notna(value)
    else f"{capture_id}:wunknown"
).astype("string")
```

The double check `value is not pd.NA and pd.notna(value)` handles both pandas `pd.NA` and numpy
`np.nan` — both can appear in nullable integer series depending on how the data was loaded.
`f"{int(value):06d}"` zero-pads the bucket index to 6 digits — `w000042` not `w42` — giving
lexicographic sort order that matches chronological order.

---

## 9. `canonicalize_source(source)` — Lines 193–265

This is the core per-source transformation. It loads one source CSV and produces a fully
annotated DataFrame with metadata prepended.

**Critical step — `reset_index(drop=True)` (Lines 209–211):**

```python
df = df[is_encrypted].copy()
...
df = df.reset_index(drop=True)
protocol_family = protocol_family.reset_index(drop=True)
is_encrypted = is_encrypted.reset_index(drop=True)
```

After filtering with `df[is_encrypted]`, the DataFrame retains the original integer index — row
42 is still index 42 even if 30 rows before it were dropped. If you then build `source_row_index
= pd.Series(range(len(df)))` and try to assign it to `metadata_df` alongside `df`, the lengths
match but the indices do not (metadata has 0–N, df has the original scattered indices). This
would cause misaligned data in `pd.concat([metadata_df, df], axis=1)`. `reset_index(drop=True)`
resets the index to 0, 1, 2, ... so all Series align correctly for the concat.

**Extra label collision check (Lines 219–222):**
```python
invalid_extra_labels = set(source.extra_labels).intersection(
    set(BASE_METADATA_COLUMNS).union(df.columns)
)
if invalid_extra_labels:
    raise RuntimeError(...)
```

If a user defines `extra_labels: {label: "custom"}` in YAML, it would collide with the
`BASE_METADATA_COLUMNS` entry `"label"`, silently creating two columns named `"label"`. This
check catches that before any data is written. The union of `BASE_METADATA_COLUMNS` and
`df.columns` covers both standard metadata and feature column names from the source CSV.

**`pd.concat([metadata_df, df], axis=1)` (Line 265):**

`axis=1` means column-wise concatenation — metadata columns are placed to the left of feature
columns in the result. Since both DataFrames have been `reset_index`-ed, they share the same
0-to-N integer index and the concat is row-aligned.

---

## 10. `build_canonical_dataset(...)` — Lines 268–313

**Stable sort (Lines 279–281):**
```python
sort_columns = [c for c in ("capture_id", "flow_start_ms", "source_row_index") if c in canonical_df.columns]
canonical_df = canonical_df.sort_values(sort_columns, kind="stable").reset_index(drop=True)
```

`kind="stable"` (a mergesort) preserves the original relative order of rows that compare
equal. When two flows from the same capture have the same `flow_start_ms` (timestamp tie),
`source_row_index` breaks the tie. When that is also equal (edge case with identical timestamps
and indices), the stable sort keeps the original concat order — benign rows before malicious
rows if they were concatenated in that order. Without `kind="stable"`, pandas defaults to
quicksort which is not stable and produces non-deterministic output for equal elements.

**Column ordering (Lines 283–286):**
```python
ordered_columns = BASE_METADATA_COLUMNS + extra_label_columns + [
    column for column in canonical_df.columns
    if column not in BASE_METADATA_COLUMNS and column not in extra_label_columns
]
canonical_df = canonical_df[ordered_columns]
```

Enforces: metadata first, extra labels second, features last. The list comprehension at the end
collects all remaining columns (the actual ML features) in their natural order. This column
ordering makes the canonical CSV human-navigable: the first N columns always tell you what a
row is (metadata), and the remaining columns are the numeric features.

**Summary JSON (Lines 292–311):**

```python
summary = {
    "rows": int(len(canonical_df)),
    "columns": int(len(canonical_df.columns)),
    "label_counts": canonical_df["label"].value_counts(dropna=False).to_dict(),
    "protocol_counts": canonical_df["protocol_family"].value_counts(dropna=False).to_dict(),
    "source_counts": canonical_df["source_name"].value_counts(dropna=False).to_dict(),
    "capture_counts": canonical_df["capture_id"].value_counts(dropna=False).to_dict(),
    "quality_status_counts": canonical_df["quality_status"].value_counts(dropna=False).to_dict(),
    ...
}
```

`value_counts(dropna=False)` — includes `NaN` in the counts. If any metadata column has null
values, they appear in the summary as `NaN: N` rather than being silently excluded. A non-zero
`NaN` count in `label_counts` would indicate a configuration bug (a source with an unrecognised
label).

The summary is also the class imbalance diagnostic — a typical canonical dataset might show
`{"benign": 45000, "malicious": 8000}`. The ML workflow (Tutorial 19) uses this imbalance to
configure class weights or resampling strategies.

---

## 11. Interview Questions and Answers

**Q: Why is `record_id` a SHA256 hash of the basis string rather than a sequential integer
or UUID?**

A: A sequential integer requires a global counter that changes every time a source is added or
rows are reordered — the same physical row gets a different ID in different dataset versions,
breaking any external references. A UUID is random — non-reproducible across pipeline runs. A
SHA256 of the basis string (`source_dataset|capture_id|feature_view|row_index`) is deterministic
and stable: the same source configuration always produces the same IDs. This means a model
trained on version N of the canonical dataset can be audited against version N+1 by matching
`record_id` — you can identify exactly which rows changed, were added, or were removed.

---

**Q: Why does `canonicalize_source` call `reset_index(drop=True)` after filtering?**

A: After `df = df[is_encrypted].copy()`, the DataFrame's integer index reflects the original
row positions in the source CSV (e.g., rows 0, 2, 5, 7, ... if odd-indexed rows were non-TLS).
When `pd.concat([metadata_df, df], axis=1)` runs, pandas aligns on index values. `metadata_df`
was built with `pd.Series(range(len(df)))` which has index 0, 1, 2, ... — it would misalign
against the scattered original index and produce NaN-filled metadata columns for most rows.
`reset_index(drop=True)` re-numbers both DataFrames 0 to N-1 before the concat, ensuring
correct row alignment.

---

**Q: What does the `window_id` enable in the detection system, and why 60-second windows?**

A: `window_id` groups flows by co-temporal proximity. The multi-tier detection system (Tutorial
20) uses these groups to build a graph where flows in the same time window that share IP,
protocol, or port characteristics form edges. Botnet C2 beacons that fire every N seconds
concentrate in specific windows and produce dense sub-graphs. Normal browsing traffic distributes
across many windows with no sub-graph concentration. 60 seconds is a round number that captures
common C2 beacon intervals (30s, 60s, 120s) in one to two consecutive windows. It is
configurable per-source because some botnet families beacon at longer intervals (300s or more)
and benefit from wider windows.

---

**Q: The `extra_labels` feature adds arbitrary columns from YAML config. What prevents it from
creating a messy, inconsistent schema across sources?**

A: `_extra_label_columns(sources)` takes the union of all extra label keys across all sources
and returns them sorted. `build_canonical_dataset` includes these in the ordered column list.
When `pd.concat(frames, ignore_index=True, sort=False)` combines frames, a source that does not
have a particular extra label key simply gets `NaN` for that column — pandas fills missing
columns with `NaN` automatically during concat. So all rows have the same schema. The sorted
union ensures the extra label columns appear in a deterministic, consistent order regardless of
which sources define them.

---

**Q: Why does `derive_protocol_family` use three separate signal sources in a cascade rather
than just one?**

A: No single signal is universally available. `application_name` is an NFStream column — not
present if the source CSV came from a Zeek-only extraction. `version` is a Zeek column — not
present if Zeek did not produce an ssl.log for this source. QUIC columns are from Zeek's
quic.log — not present for TLS-only captures. The cascade ensures the function produces a
meaningful `protocol_family` for any combination of available columns. The priority order
(application_name first, then Zeek version, then QUIC columns) reflects confidence: nDPI's
application name is the most specific classifier; Zeek's TLS version string is a direct
protocol indicator; QUIC column presence is an inference.

---

*Next: [Tutorial 18 — NFStream Inspection Utility](18_pipeline_inspect.md)*
