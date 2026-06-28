# Tutorial 12 — Final Dataset Cleanup (`pipeline/finalize.py`)

## Prerequisites

- Tutorial 08 (`merge_features.py`) — understand how `suffixes=("", "_zeek_ssl")` and
  `suffixes=("", "_zeek_quic")` rename Zeek timestamp columns during the merge.
- Tutorial 10 (`build_dataset.py`) — know exactly which columns `IDENTIFIER_COLUMNS` removes
  and which ones it does NOT cover.
- Tutorial 11 (`pruning.py`) — understand the three pruning stages and what conditions allow a
  column to survive all three.

This tutorial is deliberately detailed because the file is short but the concept it enforces —
preventing temporal data leakage — is one of the most important ML correctness guarantees in the
entire project.

---

## 1. Why Does This File Exist?

The pipeline already has two leakage-prevention layers:

- **Tutorial 10**: removes `IDENTIFIER_COLUMNS` — a hardcoded list of known identifiers and
  timestamps by their exact column names.
- **Tutorial 11**: removes statistically useless features — constant, near-constant, and
  correlated columns.

Yet **four timestamp columns survive both layers** and reach `ml_pruned.csv` still carrying
wall-clock time information. If they entered ML training, the model would learn *when* traffic
was captured rather than *what* it looks like. This is temporal data leakage — a category of
bug that causes models to pass offline evaluation but fail completely in deployment.

`finalize.py` is the last line of defence. It drops those four columns explicitly, producing
`ml_final.csv` — the file that the ML workflow in Tutorial 19 reads as its starting point.

```
ml_pruned.csv
(survived pruning, but still contains 4 timestamp columns)
      │
      │  finalize_feature_dataset()
      │  drops: src2dst_first_seen_ms, dst2src_first_seen_ms,
      │          ts_zeek_ssl, ts_zeek_quic
      ▼
ml_final.csv
(truly leakage-free — safe for ML training)
```

---

## 2. Deep Dive — Temporal Data Leakage

Before examining the code, this concept needs to be fully understood because it motivates every
design decision in this file.

### What is temporal data leakage?

A machine learning model learns patterns from training data. If those patterns are *artefacts of
when the data was collected* rather than *intrinsic properties of the traffic*, the model is
doing the wrong job.

**Concrete example:**

Suppose benign traffic was captured Monday at 09:00 and malicious (botnet) traffic was captured
Thursday at 02:00. Both are in the training set. If `bidirectional_first_seen_ms` (a Unix
timestamp in milliseconds) is a feature, the model observes:

```
Class = benign  →  bidirectional_first_seen_ms ≈ 1704960000000  (Monday 09:00 epoch ms)
Class = malware →  bidirectional_first_seen_ms ≈ 1705200000000  (Thursday 02:00 epoch ms)
```

A decision tree will find a split like `bidirectional_first_seen_ms > 1705100000000 → malware`
that achieves near-perfect accuracy on training data. But this split carries *zero information*
about the traffic itself — it just learned "traffic captured earlier is benign". On any new
dataset captured at different times, this rule is useless or actively misleading.

Cross-validation will not catch this bug because the same timestamps appear in both train and
validation folds (the split is random over rows, not over time windows). The model looks perfect
offline and fails completely in production.

### Why is this specifically "temporal" leakage?

The general term "data leakage" covers any situation where information unavailable at prediction
time enters the training features. Temporal leakage is the specific case where the leaking
information is *when* the sample was collected — a property of the experimental setup rather
than the sample itself.

The correct fix is not to "be careful" with timestamps — it is to remove them entirely from the
feature matrix so they physically cannot be learned from.

---

## 3. The Four Leaked Columns — Where They Come From and Why They Survived

Each column has a specific origin in the pipeline. Understanding the origin explains why it
escaped the earlier safeguards.

### 3.1 `src2dst_first_seen_ms`

**Origin:** NFStream output column. NFStream tracks unidirectional sub-flows within a
bidirectional flow. `src2dst_first_seen_ms` is the Unix epoch timestamp (in milliseconds) of the
first packet travelling from source to destination — the client's first byte sent.

**Why it survived Tutorial 10 (`IDENTIFIER_COLUMNS`):**

Look at Tutorial 10's `IDENTIFIER_COLUMNS`:

```python
IDENTIFIER_COLUMNS = (
    ...
    "first_seen_ms",
    "last_seen_ms",
    "bidirectional_first_seen_ms",
    "bidirectional_last_seen_ms",
    "ts",
)
```

`src2dst_first_seen_ms` is **not in this list**. Tutorial 10 removed the bidirectional variants
but missed the directional ones. This is not an oversight in the project design — it reflects how
the column list was built incrementally as the NFStream schema was explored. The finalize step
exists precisely to catch these gaps.

**Why it survived Tutorial 11 (pruning):**

- **Not constant** — every flow starts at a different wall-clock time → variance > 0 → passes
  `VarianceThreshold`.
- **Not near-constant** — each value is essentially unique → top frequency ≈ 1/N → far below
  0.995 → passes near-constant check.
- **Not highly correlated with other features** — timestamp values are large integers
  (≈ 1.7 × 10¹²) that bear no linear relationship to traffic statistics like byte counts or
  inter-arrival times → Pearson r ≪ 0.95 with all remaining features → passes correlation
  pruning.

All three pruning stages are blind to the *semantic meaning* of a column. They only see numbers.
A timestamp column looks like any other large-valued numeric column to `VarianceThreshold` and
the Pearson matrix.

---

### 3.2 `dst2src_first_seen_ms`

**Origin:** NFStream's mirror of the above — the Unix epoch timestamp (milliseconds) of the
first packet travelling from destination back to source — the server's first response byte.

**Why it survived Tutorial 10:** Same reason — not listed in `IDENTIFIER_COLUMNS`. The
bidirectional `bidirectional_first_seen_ms` was listed, but not this directional variant.

**Why it survived Tutorial 11:** Identical logic. Unique values per flow → not constant, not
near-constant. Large integers with no linear relationship to flow statistics → not correlated.

**Additional note:** `src2dst_first_seen_ms` and `dst2src_first_seen_ms` are themselves highly
correlated with *each other* (both reflect when the connection occurred, typically within
milliseconds). You might expect Phase 3 of pruning to catch one of them since their Pearson r is
close to 1.0. However, this depends on whether both columns were present in `df_no_var` at that
point — if `src2dst_first_seen_ms` was already dropped or if the correlation matrix threshold
was narrowly missed, the other survives. The explicit removal in `finalize.py` removes both
unconditionally, sidestepping this fragility.

---

### 3.3 `ts_zeek_ssl`

**Origin:** From Tutorial 08's merge step. When `ssl.csv` is joined onto the merged DataFrame:

```python
# merge_features.py line 178
merged = merged.merge(ssl, on="uid", how="left", suffixes=("", "_zeek_ssl"))
```

`ssl.csv` contains a `ts` column — Zeek's wall-clock timestamp for when it recorded the TLS
handshake (Unix epoch in fractional seconds). When this column is joined onto the DataFrame that
already has a `ts` column from `conn.csv`, pandas appends the `_zeek_ssl` suffix to avoid
collision. The result: a new column named `ts_zeek_ssl`.

**Why it survived Tutorial 10:**

Tutorial 10's `IDENTIFIER_COLUMNS` contains `"ts"` (the bare name). After the merge suffix
rename, the column is `"ts_zeek_ssl"` — a completely different string. String matching is exact;
`"ts" != "ts_zeek_ssl"`. It was never removed.

**Why it survived Tutorial 11:**

`ts_zeek_ssl` is the Zeek-side connection timestamp in fractional seconds (e.g.,
`1704960000.123456`). It is:
- Unique per connection → non-constant, non-near-constant.
- A large float with no meaningful linear correlation to flow byte counts or timing deltas →
  Pearson r below 0.95 with all behavioral features.

---

### 3.4 `ts_zeek_quic`

**Origin:** Exactly the same mechanism as `ts_zeek_ssl` but from the QUIC log merge:

```python
# merge_features.py line 183
merged = merged.merge(quic, on="uid", how="left", suffixes=("", "_zeek_quic"))
```

Zeek's `quic.csv` also contains a `ts` column. After the merge it becomes `ts_zeek_quic`.

**Why it survived Tutorial 10:** `"ts_zeek_quic" != "ts"` — same exact-match failure.

**Why it survived Tutorial 11:** Same logic. Unique per-flow timestamp, no linear relationship
to behavioral features.

**Note on NaN:** For PCAPs that contain no QUIC traffic, `ts_zeek_quic` is `NaN` for every row.
After Tutorial 10's `fillna(0)` and Tutorial 11's `fillna(0)`, it becomes all-zero — meaning it
**would** be caught by `VarianceThreshold(threshold=0.0)` in Tutorial 11's Phase 1 and removed
then. So `ts_zeek_quic` only appears in `ml_pruned.csv` for PCAPs that have at least some QUIC
traffic. `finalize.py` handles both cases correctly because `final_drop_cols` only includes
columns that are actually present (see Section 4.2 below).

---

## 4. File Walkthrough — Every Line

### 4.1 `DEFAULT_DROP_COLS` — Lines 11–16

```python
DEFAULT_DROP_COLS = [
    "src2dst_first_seen_ms",
    "dst2src_first_seen_ms",
    "ts_zeek_ssl",
    "ts_zeek_quic",
]
```

A module-level constant defining the baseline list of temporal leakage columns to drop. It is a
`list` (not a `tuple` like `IDENTIFIER_COLUMNS` and `TEXT_COLUMNS_TO_LENGTH` in earlier
tutorials) because the CLI can pass a custom list in its place — lists are more natural for
mutable-replacement patterns.

**Why a module-level constant rather than hardcoded inside the function?**

A module-level constant is:
1. **Importable** — other modules (`orchestration.py`, tests) can import `DEFAULT_DROP_COLS`
   and verify it or extend it without duplicating the string literals.
2. **Visible in documentation** — tools like `help()` or code editors show the constant at the
   top of the file.
3. **Overridable** — the function accepts a `drop_cols` parameter; the caller can pass
   `DEFAULT_DROP_COLS + ["extra_col"]` without editing the function body.

---

### 4.2 `finalize_feature_dataset(input_csv, output_csv, *, drop_cols)` — Lines 19–40

```python
def finalize_feature_dataset(
    input_csv: str | Path,
    output_csv: str | Path,
    *,
    drop_cols: list[str] | None = None,
) -> dict[str, str | int]:
```

**Parameters:**

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `input_csv` | required | `ml_pruned.csv` from Tutorial 11 |
| `output_csv` | required | `ml_final.csv` — the ML training-ready file |
| `drop_cols` | `None` | Custom drop list; if `None`, uses `DEFAULT_DROP_COLS` |

Unlike earlier pipeline functions, `output_csv` is passed directly as a path rather than derived
from `DatasetArtifacts`. This gives the caller full control over the output location — useful
when running finalization as a standalone script with custom I/O paths.

---

```python
input_path  = Path(input_csv).expanduser().resolve()
output_path = Path(output_csv).expanduser().resolve()
output_path.parent.mkdir(parents=True, exist_ok=True)
```

`.expanduser()` handles `~` in paths (e.g., `~/artifacts/`). `.resolve()` converts relative
paths to absolute. `mkdir(parents=True, exist_ok=True)` creates any missing parent directories
(e.g., if `output_csv` is `artifacts/final/dataset_ml_final.csv` and `final/` doesn't exist
yet). This combination appears throughout the pipeline — it is the standard path-preparation
idiom for pipeline output files.

---

```python
df = pd.read_csv(input_path, low_memory=False)
```

Loads the pruned CSV. `low_memory=False` is used consistently across the pipeline (see Tutorial
10) to force correct dtype inference in a single pass.

---

```python
final_drop_cols = [column for column in (drop_cols or DEFAULT_DROP_COLS) if column in df.columns]
```

This single line does two things simultaneously:

**1 — Override resolution: `drop_cols or DEFAULT_DROP_COLS`**

If `drop_cols` is `None` (the default), `None or DEFAULT_DROP_COLS` evaluates to
`DEFAULT_DROP_COLS`. If the caller passes an explicit list (even an empty list `[]`), that list
is used instead.

**Important edge case:** An empty list `[]` is falsy in Python. So `[] or DEFAULT_DROP_COLS`
would evaluate to `DEFAULT_DROP_COLS` — meaning you cannot pass an empty list to "drop nothing".
If you need to pass explicitly "drop nothing", you would need to handle that case differently.
In practice, this edge case never arises in the pipeline since you always want to drop at least
the default columns.

**2 — Defensive existence check: `if column in df.columns`**

Only include column names that actually exist in the current DataFrame. This is critical for two
reasons:

- `ts_zeek_quic` will not exist in a pure-TLS (no QUIC traffic) dataset — dropping a
  non-existent column would raise a `KeyError` without this guard.
- If a future version of Zeek or NFStream renames one of these columns, the pipeline continues
  rather than crashing — and the missing column simply is not dropped (it likely was renamed and
  is no longer a timestamp leakage source anyway).

---

```python
df_final = df.drop(columns=final_drop_cols)
df_final.to_csv(output_path, index=False)
```

`df.drop(columns=...)` returns a new DataFrame — it does not modify `df` in place. This is
correct pandas style: `drop` has an `inplace` parameter but using it on the main DataFrame is
discouraged because it can cause subtle issues with views vs. copies. Assigning to `df_final`
makes the intent clear and keeps `df` available if needed for debugging.

`index=False` — the standard pipeline convention that prevents an unnamed integer index column
from appearing in the output CSV.

---

```python
return {
    "input_csv": str(input_path),
    "output_csv": str(output_path),
    "dropped_columns": len(final_drop_cols),
    "rows": int(df_final.shape[0]),
    "columns": int(df_final.shape[1]),
}
```

The returned dict is deliberately minimal — this stage does only one thing (drop columns), so the
meaningful diagnostic is just how many columns were dropped and what the final shape is.

`dropped_columns` being 0 would be a warning sign: it means none of the `DEFAULT_DROP_COLS`
existed in the input — possibly indicating the input came from an earlier pipeline stage or a
dataset that never went through the merge step (and therefore never got `ts_zeek_ssl` added).

---

### 4.3 `main(argv)` — Lines 43–58

```python
parser.add_argument(
    "--drop-cols",
    nargs="*",
    default=None,
    help="Optional explicit list of columns to drop; defaults to the repository baseline",
)
```

`nargs="*"` means zero or more values. This allows:

```bash
# Use DEFAULT_DROP_COLS (most common):
python -m tls_dataset.pipeline.finalize \
  --input artifacts/ml_pruned.csv \
  --output artifacts/ml_final.csv

# Override with a custom list (research use):
python -m tls_dataset.pipeline.finalize \
  --input artifacts/ml_pruned.csv \
  --output artifacts/ml_final.csv \
  --drop-cols ts_zeek_ssl ts_zeek_quic my_custom_col

# Edge case — pass no columns (attempts to drop nothing, but falls back to DEFAULT_DROP_COLS
# due to the `or` logic; this would need code-level override to truly skip):
python -m tls_dataset.pipeline.finalize \
  --input artifacts/ml_pruned.csv \
  --output artifacts/ml_final.csv \
  --drop-cols
# args.drop_cols = [] (empty list, falsy) → falls back to DEFAULT_DROP_COLS
```

When `--drop-cols` is not provided at all, `args.drop_cols = None` (the `default=None`). This
is distinct from providing `--drop-cols` with no arguments (`args.drop_cols = []`). Both end up
using `DEFAULT_DROP_COLS` due to the `or` logic, but the distinction matters if you read the CLI
source and expect `[]` to mean "drop nothing explicitly".

---

## 5. The Layered Leakage Prevention System — Full Picture

Across Tutorials 10, 11, and 12, the project uses three complementary leakage-prevention layers.
Understanding why all three are needed — and why no single layer is sufficient — is essential.

```
Layer 1 — Tutorial 10 (build_dataset.py): Name-based removal
  IDENTIFIER_COLUMNS = ("uid", "src_ip", "dst_ip", "src_port", "dst_port",
                        "ts", "bidirectional_first_seen_ms", ...)
  Removes: known identifiers and primary timestamps by exact column name.
  Limitation: Cannot catch renamed variants like "ts_zeek_ssl" or
              "src2dst_first_seen_ms" (not in the hardcoded list).

Layer 2 — Tutorial 11 (pruning.py): Statistics-based removal
  VarianceThreshold + frequency check + correlation matrix.
  Removes: columns with no discriminative power — constants, near-constants, redundant.
  Limitation: Blind to semantics. A timestamp has high variance, unique values,
              and low correlation with behavioral features — all three pruning
              stages let it through.

Layer 3 — Tutorial 12 (finalize.py): Explicit targeted removal
  DEFAULT_DROP_COLS = ["src2dst_first_seen_ms", "dst2src_first_seen_ms",
                       "ts_zeek_ssl", "ts_zeek_quic"]
  Removes: the specific temporal columns that escaped Layers 1 and 2.
  Limitation: Only catches known columns; requires updating if new timestamp
              columns are added to the pipeline.
```

Each layer defends against a different class of leakage:
- Layer 1: catches identifiers and primary timestamps (known names).
- Layer 2: catches useless features regardless of name.
- Layer 3: catches semantic leakage (temporal) that is invisible to statistics.

No single layer is sufficient. Together they provide defence-in-depth: a column must evade all
three to enter ML training.

---

## 6. What `ml_final.csv` Contains — the End State

After this stage, `ml_final.csv` contains:

| Column type | Examples | Status |
|------------|---------|--------|
| NFStream statistical features | `bidirectional_bytes`, `bidirectional_mean_ps`, `bidirectional_stddev_ps`, `src2dst_packets` | Present |
| Zeek TLS length-encoded features | `server_name_len`, `cipher_len` (if those were in `TEXT_COLUMNS_TO_LENGTH`) | Present |
| X509 certificate aggregates | `x509_record_count`, `x509_certificate.not_valid_after__num_mean` | Present |
| Network identifiers | `uid`, `src_ip`, `src_port` | REMOVED (Tutorial 10) |
| Primary timestamps | `ts`, `bidirectional_first_seen_ms` | REMOVED (Tutorial 10) |
| Directional NFStream timestamps | `src2dst_first_seen_ms`, `dst2src_first_seen_ms` | REMOVED (Tutorial 12) |
| Zeek suffix timestamps | `ts_zeek_ssl`, `ts_zeek_quic` | REMOVED (Tutorial 12) |
| Constant features | `vlan_id`, `tunnel_id` (all-zero) | REMOVED (Tutorial 11 Phase 1) |
| Near-constant features | Rare protocol indicator columns | REMOVED (Tutorial 11 Phase 2) |
| Correlated features | NFStream ratio duplicates | REMOVED (Tutorial 11 Phase 3) |

The result is a clean numeric matrix — typically 60–100 columns — of behavioral features with
no identifiers, no timestamps, no NaN, no inf, and no redundant columns. This is what Tutorial 19
(`ml/workflow.py`) reads directly into a scikit-learn pipeline.

---

## 7. Interview Questions and Answers

**Q: This file is only 63 lines. Why does it deserve its own pipeline stage instead of just
adding the four columns to `IDENTIFIER_COLUMNS` in `build_dataset.py`?**

A: Three reasons. First, **origin traceability**: the four columns appear because of the merge
step's suffix renaming (`ts_zeek_ssl`) and NFStream's directional column naming
(`src2dst_first_seen_ms`). These are merge artefacts — it is cleaner to handle them in a
separate stage that explicitly acknowledges "the merge introduced new temporal columns". Mixing
them into `IDENTIFIER_COLUMNS` would hide this context. Second, **checkpoint value**: the
`ml_pruned.csv` → `ml_final.csv` boundary is the last checkpoint before ML training. Having an
explicit stage here with its own output file means you can load `ml_pruned.csv` and `ml_final.csv`
side by side and immediately see which columns were removed at the final stage. Third,
**overridability**: the `drop_cols` parameter lets the ML workflow or orchestration layer
customise which columns are removed without touching `build_dataset.py`'s core logic.

---

**Q: What is temporal data leakage and why does it specifically fool cross-validation?**

A: Temporal leakage occurs when training features encode *when* a sample was collected rather
than properties of the sample itself. It fools standard k-fold cross-validation because k-fold
splits data randomly across folds — both the training fold and the validation fold contain
samples from the same capture sessions and therefore the same time ranges. The model learns the
timestamp patterns during training and "validates" them against data from the same time window.
The validation accuracy looks excellent, but the model has learned nothing generalisable. This
would only be caught by **temporal cross-validation** (train on earlier captures, validate on
later ones) — but the correct fix is simpler: remove the timestamps so the model cannot learn
them at all.

---

**Q: Why does `ts_zeek_ssl` exist as a separate column rather than just being the same as the
`ts` column already removed in Tutorial 10?**

A: Because of pandas' merge suffix logic. In `merge_features.py`, the NFStream DataFrame already
has a `ts` column (converted from `bidirectional_first_seen_ms`). When `ssl.csv` is left-joined
onto it, `ssl.csv` also has a `ts` column (Zeek's connection timestamp). Pandas cannot have two
columns named `ts` in the same DataFrame. The `suffixes=("", "_zeek_ssl")` argument tells pandas
to keep the left side's name (`ts`) unchanged and rename the right side's column to `ts_zeek_ssl`.
Tutorial 10 removed `"ts"` from `IDENTIFIER_COLUMNS`, which correctly removed the NFStream `ts`
column. But `"ts_zeek_ssl"` is a different string — the name-based removal missed it.

---

**Q: If `ts_zeek_quic` is all-zero in a TLS-only dataset (no QUIC traffic), wouldn't Tutorial
11's `VarianceThreshold(0.0)` already drop it? Why is it in `DEFAULT_DROP_COLS`?**

A: You are correct — in a pure-TLS dataset, `ts_zeek_quic` would be all-zero after `fillna(0)`
and `VarianceThreshold` would drop it. But `DEFAULT_DROP_COLS` must be correct for mixed
TLS+QUIC datasets too. In a mixed dataset, `ts_zeek_quic` has real non-zero values (actual Zeek
QUIC timestamps) — it survives `VarianceThreshold`, survives near-constant check (unique values),
and survives correlation pruning (large integers unrelated to behavioral statistics). So for mixed
datasets it is a genuine leakage risk. `DEFAULT_DROP_COLS` must cover the worst case. The
defensive existence check (`if column in df.columns`) in the function ensures this causes no
error when the column is absent.

---

**Q: Could the project add a fourth pruning stage to `pruning.py` that detects timestamp columns
automatically (e.g., by value range — "if all values are > 1e12 they are epoch milliseconds")?**

A: In theory yes, but it would be fragile. Some legitimate behavioral features could fall in a
similar value range — for example, a flow's total byte count on a high-throughput link could
exceed 10⁹, and X509 certificate expiry timestamps (`not_valid_after`) are themselves Unix epoch
values that are intentionally kept as features. Heuristic value-range detection would create false
positives (dropping real features) or require careful tuning per-dataset. The explicit list in
`DEFAULT_DROP_COLS` is more reliable: it documents the exact columns, their origins, and the
reason they exist — making the leakage prevention auditable and reviewable rather than implicit.

---

**Q: What would happen to the trained ML model if `src2dst_first_seen_ms` were not removed?**

A: The model would achieve artificially high accuracy on the training and cross-validation sets
because it would learn to distinguish benign vs. malicious based on the capture time window.
A random forest, for example, would place `src2dst_first_seen_ms` near the top of its feature
importance ranking — not because the feature is meaningful, but because it perfectly separates
two classes that were captured at different times. When the model is deployed on new traffic
(captured at a different time), this feature would become random noise, and model performance
would collapse to near-chance. The model would be scientifically invalid and
production-worthless, despite looking excellent in offline evaluation.

---

*Next: [Tutorial 13 — Pipeline Orchestration](13_pipeline_orchestration.md)*
