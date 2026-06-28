# Tutorial 11 — Feature Pruning (`pipeline/pruning.py`)

## Prerequisites

- Tutorial 03 (`common.py`) — know `DatasetArtifacts` and the artifact chain from
  `ml_ready_csv` → `ml_no_constant_csv` → `ml_no_constant_novar_csv` → `ml_pruned_csv`.
- Tutorial 10 (`build_dataset.py`) — understand that `ml_ready.csv` is numeric-only with NaN
  filled to 0. That file is exactly what `pruning.py` reads as input.
- Basic statistics: variance, correlation coefficient, frequency distribution.

---

## 1. Why Does This File Exist? The Dimensionality Problem

After Tutorial 10 you have `ml_ready.csv`. A typical run of Zeek + NFStream on a PCAP produces
around **200–300 feature columns** in the merged CSV. After `build_dataset.py` drops identifiers
and text columns, you might still have 150–200 numeric columns left.

That sounds manageable, but most of those columns are **not useful for ML**. Here is why:

| Problem | Example | Why it hurts ML |
|---------|---------|----------------|
| **Constant features** | A column that is `0` for every single row | Provides zero discriminative power. Some models (SVM, linear regression) cannot train on them at all (divide-by-zero in normalisation). All models waste memory and compute on them. |
| **Near-constant features** | A column that is `0` for 99.7% of rows and `1` for 0.3% | Barely any discriminative power. Tree-based models waste splits trying to use them. Creates class-imbalance artefacts in some splits. |
| **Highly correlated features** | `bidirectional_bytes` and `bidirectional_mean_ps * bidirectional_duration_ms` (essentially the same thing) | Multicollinearity. In linear models it inflates coefficients and causes numerical instability. In tree models it means the same information is split across multiple near-identical features, diluting feature importance scores — the true driver gets half the importance it deserves. |

`pruning.py` removes all three categories in a **three-stage sequential pipeline**, each stage
writing its own checkpoint CSV so you can inspect what was removed at every step.

```
ml_ready.csv
      │
      │  Stage 1: VarianceThreshold(threshold=0.0)
      ▼
ml_no_constant.csv          (constant features removed)
      │
      │  Stage 2: value_counts top frequency > 0.995
      ▼
ml_no_constant_novar.csv    (near-constant features also removed)
      │
      │  Stage 3: upper-triangle Pearson |r| > 0.95
      ▼
ml_pruned.csv               (correlated features also removed)
```

The order matters: you remove exact constants first (cheap operation), then near-constants
(slightly more expensive), then correlations (expensive — requires computing an N×N matrix).
Running correlation analysis on constant columns would produce NaN in the correlation matrix,
which breaks the upper-triangle logic.

---

## 2. The Single Function: `prune_feature_dataset(...)` — Lines 16–69

```python
def prune_feature_dataset(
    input_csv: str | Path,
    *,
    output_dir: str | Path,
    dataset_name: str,
    near_const_threshold: float = 0.995,
    corr_threshold: float = 0.95,
) -> dict[str, str | int]:
```

**Parameters:**

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `input_csv` | required | Path to `ml_ready.csv` from Tutorial 10 |
| `output_dir` | required | Directory for the three checkpoint CSVs |
| `dataset_name` | required | Used to build file names via `DatasetArtifacts` |
| `near_const_threshold` | `0.995` | A column is near-constant if its most frequent single value appears in ≥ 99.5% of rows |
| `corr_threshold` | `0.95` | A feature pair is "too correlated" if absolute Pearson r ≥ 0.95 |

The `*` in the signature forces all parameters after it to be keyword-only — you cannot call
`prune_feature_dataset("file.csv", "out/", "name")` by position; you must write
`prune_feature_dataset("file.csv", output_dir="out/", dataset_name="name")`. This prevents
accidental argument transposition in a function with several path-like arguments.

---

### Phase 0 — Load and Sanitise (Lines 28–33)

```python
df = pd.read_csv(input_path, low_memory=False)
df = df.apply(pd.to_numeric, errors="coerce")
df.replace([np.inf, -np.inf], np.nan, inplace=True)
total_nans = int(df.isna().sum().sum())
df.fillna(0, inplace=True)
duplicate_rows = int(df.duplicated().sum())
```

**Why re-sanitise here when Tutorial 10 already did this?**

Defensive programming. The input CSV may not always come from `build_dataset.py` — you might
run `prune_feature_dataset` directly on a manually prepared CSV, or the CSV may have been
modified between steps. Re-applying the same sanitisation guarantees this function's preconditions
are always met regardless of how the input was produced.

**Line by line:**

`df.apply(pd.to_numeric, errors="coerce")` — attempts to convert every column to a numeric
dtype. Columns that contain any non-numeric strings become `NaN` for those cells. This is
`apply` on the whole DataFrame, which calls `pd.to_numeric` on each column Series in turn.

`df.replace([np.inf, -np.inf], np.nan, inplace=True)` — converts both positive and negative
infinity to `NaN`. The list `[np.inf, -np.inf]` is passed as a single replacement source.

`total_nans = int(df.isna().sum().sum())` — double `.sum()`: first `.sum()` gives a Series of
NaN counts per column; second `.sum()` sums that Series into a single integer. This count goes
into the returned stats dict as a diagnostic — a high NaN count before filling suggests the
input data had structural problems.

`df.fillna(0, inplace=True)` — zero-fills all NaN. At this point the DataFrame is a clean
float64 matrix of shape (n_flows, n_features) with no NaN and no inf.

`duplicate_rows = int(df.duplicated().sum())` — counts rows that are identical across all
columns. Logged for diagnostics but not acted upon here (duplicates are not removed because
legitimate identical flows can exist in TLS traffic — e.g., two connections to the same server
with the same statistical properties).

---

### Phase 1 — Constant Feature Removal (Lines 35–41)

```python
matrix = df.to_numpy(dtype=float)
variance_filter = VarianceThreshold(threshold=0.0)
variance_filter.fit(matrix)
constant_mask = variance_filter.get_support()
constant_dropped = df.columns[~constant_mask].tolist()
df_no_constant = df[df.columns[constant_mask]].copy()
df_no_constant.to_csv(artifacts.ml_no_constant_csv, index=False)
```

**What `VarianceThreshold` does:**

`VarianceThreshold` is a scikit-learn feature selector. It computes the **variance** of every
column and discards columns whose variance is at or below the given threshold.

Variance of a column = average squared deviation from the mean:

```
Var(X) = (1/N) * Σ (xᵢ - x̄)²
```

If every value in a column is identical (constant), `x̄ = xᵢ` for all `i`, so every squared
deviation is zero, and `Var(X) = 0`.

`threshold=0.0` means: keep only columns with variance **strictly greater than zero** — i.e.,
drop only the perfectly constant columns.

**Why convert to numpy first (`df.to_numpy(dtype=float)`)?**

`VarianceThreshold` operates on a numpy array, not a pandas DataFrame. Passing the DataFrame
directly works in newer sklearn versions but may trigger warnings or dtype conversion overhead.
Explicit conversion makes the operation clear and avoids any ambiguity about how sklearn handles
the DataFrame index.

**`get_support()` and the mask:**

After `.fit(matrix)`, `variance_filter.get_support()` returns a boolean numpy array of length
`n_features` — `True` for columns that passed (variance > 0), `False` for constant columns.

```python
constant_mask   = [True, True, False, True, False, ...]
df.columns       = ["bidirectional_bytes", "src2dst_packets", "vlan_id", "ja3_len", "tunnel_id", ...]
                              ↓ constant_mask=False means constant
constant_dropped = ["vlan_id", "tunnel_id", ...]    ← were all-zero in this PCAP
```

`~constant_mask` inverts the boolean array (True ↔ False) to identify the dropped columns.
`df.columns[~constant_mask].tolist()` extracts their names for the returned stats dict so you
can audit exactly which columns were removed.

**Typical constant columns in this project:**

Columns like `vlan_id`, `tunnel_id`, and various NFStream plugin output columns are often all
zero because the PCAP contains no VLAN-tagged or tunnelled traffic. These are legitimately
constant for a given capture but would have non-zero variance in other captures. They are
correctly removed here because they provide no signal for this specific dataset.

---

### Phase 2 — Near-Constant Feature Removal (Lines 43–49)

```python
near_constant_dropped: list[str] = []
for column in df_no_constant.columns:
    top_freq = df_no_constant[column].value_counts(normalize=True, dropna=False).iloc[0]
    if top_freq > near_const_threshold:
        near_constant_dropped.append(column)
df_no_var = df_no_constant.drop(columns=near_constant_dropped)
df_no_var.to_csv(artifacts.ml_no_constant_novar_csv, index=False)
```

**Why not just lower the `VarianceThreshold`?**

You might think: "Why not set `VarianceThreshold(threshold=0.001)` instead of a separate stage?"

Variance and frequency are different concepts. Consider a column that is `0.0` for 99.6% of
rows and `1000.0` for the remaining 0.4%. Its variance is:

```
x̄ ≈ 4.0
Var ≈ (0.996 * (0 - 4)²) + (0.004 * (1000 - 4)²)
    = (0.996 * 16) + (0.004 * 992016)
    ≈ 15.9 + 3968.1
    = 3984
```

This column has high variance (~3984) despite being 99.6% the same value! A variance threshold
would not catch it. But it is near-constant — dominated by a single value — and provides almost
no useful discriminative power.

**How `value_counts` detects this:**

```python
top_freq = df_no_constant[column].value_counts(normalize=True, dropna=False).iloc[0]
```

`value_counts(normalize=True)` returns the relative frequency of each unique value, sorted
descending. `.iloc[0]` picks the most frequent value's frequency.

```
Column A: [0, 0, 0, 0, 0, 0, 0, 0, 0, 1]   → top_freq = 0.9  → keep (below 0.995)
Column B: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    → top_freq = 0.997 → DROP (above 0.995)
           0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
```

`dropna=False` includes NaN values in the count. Since all NaN were filled to 0 in Phase 0,
this has no effect here — but it makes the function robust if someone calls it with un-filled
data.

**The 0.995 threshold — why this specific value?**

0.995 means: drop any column where one value dominates 99.5% or more of all rows. This is a
deliberately aggressive threshold. The reasoning:
- If a feature has one dominant value in 99.5% of rows, it will split the data at best into
  a 99.5/0.5 partition — almost never useful.
- Tree models can find these splits but they produce highly imbalanced nodes that generalise
  poorly.
- The remaining 0.5% may be real signal, but that 0.5% is better captured by other non-constant
  features that are correlated with it.

The threshold is tunable via the `--near-constant-threshold` CLI argument for cases where you
want to be more or less aggressive.

---

### Phase 3 — Correlated Feature Removal (Lines 51–55)

```python
corr = df_no_var.corr(numeric_only=True).abs()
upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
correlated_dropped = [column for column in upper.columns if (upper[column] > corr_threshold).any()]
df_pruned = df_no_var.drop(columns=correlated_dropped)
df_pruned.to_csv(artifacts.ml_pruned_csv, index=False)
```

This is the most mathematically complex stage. Understanding it requires knowing what the
Pearson correlation matrix is and what the upper triangle represents.

**What is the Pearson correlation coefficient?**

For two features X and Y measured across N flows:

```
r(X, Y) = Σ((xᵢ - x̄)(yᵢ - ȳ)) / (N * σX * σY)
```

Where `σX` and `σY` are the standard deviations of X and Y. The result is always in [-1, 1]:

| r value | Meaning |
|---------|---------|
| +1.0 | Perfect positive linear correlation (X increases → Y increases proportionally) |
| 0.0 | No linear correlation |
| -1.0 | Perfect negative linear correlation (X increases → Y decreases proportionally) |

The code uses `.abs()` to take the absolute value — it treats strong negative correlation
(`r = -0.97`) the same as strong positive correlation (`r = +0.97`). Both mean the features
carry redundant information.

**Step 1 — Build the correlation matrix:**

```python
corr = df_no_var.corr(numeric_only=True).abs()
```

`df.corr()` computes the full N×N correlation matrix where N is the number of feature columns.
Every cell `corr[i][j]` = |r(feature_i, feature_j)|.

The diagonal is always 1.0 (a feature perfectly correlates with itself). The matrix is
**symmetric** — `corr[i][j] == corr[j][i]`.

For 150 columns this produces a 150×150 matrix (22,500 cells). For 300 columns: 90,000 cells.
This is why correlated feature removal is run last — it is the most memory-intensive step.

**Step 2 — Extract the upper triangle:**

```python
upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
```

This is the key mathematical trick. Let us unpack it:

`np.ones(corr.shape)` — creates a matrix of all 1s, same shape as `corr` (N×N).

`np.triu(..., k=1)` — keeps only the **strictly upper triangle** (above the main diagonal):

```
Full correlation matrix (4×4 example):
  A     B     C     D
A [1.0,  0.97, 0.12, 0.88]
B [0.97, 1.0,  0.43, 0.21]
C [0.12, 0.43, 1.0,  0.76]
D [0.88, 0.21, 0.76, 1.0 ]

np.triu(ones, k=1) mask:
  A     B     C     D
A [F,    T,    T,    T  ]
B [F,    F,    T,    T  ]
C [F,    F,    F,    T  ]
D [F,    F,    F,    F  ]

upper triangle of corr:
  A     B     C     D
A [NaN,  0.97, 0.12, 0.88]
B [NaN,  NaN,  0.43, 0.21]
C [NaN,  NaN,  NaN,  0.76]
D [NaN,  NaN,  NaN,  NaN ]
```

`k=1` means "one step above the main diagonal" — this excludes the diagonal itself (which is
always 1.0 and would cause every feature to consider itself correlated with itself).

`corr.where(mask)` keeps values where mask is `True` and replaces the rest with `NaN`.

**Why only the upper triangle?**

The correlation matrix is symmetric: `corr[A][B] == corr[B][A]`. If you used the full matrix,
every correlated pair (A, B) would appear **twice** — once as (A, B) and once as (B, A). You
would add both A and B to the drop list, losing both features in the pair instead of just one.
The upper triangle contains each pair exactly once.

**Step 3 — Identify and drop correlated columns:**

```python
correlated_dropped = [column for column in upper.columns if (upper[column] > corr_threshold).any()]
```

For each column in the upper triangle matrix, check: does this column have any row value above
0.95? If yes, this column is "highly correlated with at least one other feature" — add it to the
drop list.

**Critical insight — what this actually drops:**

Consider features A, B, C where B is highly correlated with both A (r=0.97) and C (r=0.96):

```
Upper triangle:
     A     B     C
A   NaN   0.97  0.12
B   NaN   NaN   0.96
C   NaN   NaN   NaN

Column A: max upper value = 0.97 > 0.95 → DROP A?  No — (upper[A]).any() asks if column A
          has any value > 0.95. Column A in the upper triangle is [NaN, NaN, NaN] (column A
          has no upper-triangle values since upper triangle keeps columns to the right).

Wait — let me re-read the logic carefully:
correlated_dropped = [col for col in upper.columns if (upper[col] > corr_threshold).any()]

upper[col] is the *column* of the upper triangle. For a 4-column example:
  upper["B"] = [0.97, NaN, NaN, NaN]  ← only row A has a value (A-B correlation)
  upper["C"] = [0.12, 0.43, NaN, NaN] ← rows A and B have values (A-C and B-C correlations)
  upper["D"] = [0.88, 0.21, 0.76, NaN]

For threshold=0.95:
  upper["A"].any() → column A upper triangle is empty → False → keep A
  upper["B"].any() → [0.97] > 0.95 → True → DROP B
  upper["C"].any() → [0.12, 0.43] → max 0.43 not > 0.95 → keep C
  upper["D"].any() → [0.88, 0.21, 0.76] → max 0.88 not > 0.95 → keep D
```

The logic drops the **right-hand column** of each highly-correlated pair. In the upper triangle,
the earlier column (left) is the row and the later column (right) is the column. So the code
implicitly keeps the "earlier" feature (by column index) and drops the "later" one when they are
highly correlated. The choice of which feature in a correlated pair to keep is arbitrary — what
matters is removing the redundancy, not which specific one survives.

**Why 0.95 as the threshold?**

0.95 means features must explain at least 1 - 0.95² ≈ 10% of each other's variance uniquely to
both be kept. In practice this means:
- Two features that are near-perfect proxies for each other (r=0.98) → one is dropped.
- Two features that are moderately correlated (r=0.80, common in network flow data) → both kept.
- Features derived from the same NFStream base metric (e.g., `bytes_total` and `bytes_per_ms`)
  are often at r=0.99+ → one dropped.

---

## 3. Returned Statistics Dictionary (Lines 57–69)

```python
return {
    "input_csv": str(input_path),
    "ml_no_constant_csv": str(artifacts.ml_no_constant_csv),
    "ml_no_constant_novar_csv": str(artifacts.ml_no_constant_novar_csv),
    "ml_pruned_csv": str(artifacts.ml_pruned_csv),
    "rows": int(df_pruned.shape[0]),
    "columns": int(df_pruned.shape[1]),
    "total_nans_before_fill": total_nans,
    "duplicate_rows": duplicate_rows,
    "constant_features_dropped": len(constant_dropped),
    "near_constant_features_dropped": len(near_constant_dropped),
    "correlated_features_dropped": len(correlated_dropped),
}
```

Every count tells a diagnostic story:

| Key | If unexpectedly high | Likely cause |
|-----|---------------------|-------------|
| `total_nans_before_fill` | Very high NaN count | Zeek metadata missing for most flows — merge quality problem |
| `constant_features_dropped` | > 50 features | PCAP lacked certain traffic types (no VLAN, no tunnelling, no QUIC) — normal |
| `near_constant_features_dropped` | > 30 features | NFStream plugin output mostly zeros — plugin not applicable to this traffic type |
| `correlated_features_dropped` | > 40 features | Many NFStream derived metrics (ratios, products) are linear combinations of base metrics — expected |
| `columns` at the end | < 20 columns | Over-pruned — thresholds may be too aggressive for this traffic type |

---

## 4. The Three Checkpoint CSVs — Why They Exist

Each stage writes its own CSV file:

```
ml_ready.csv                → input (from Tutorial 10)
ml_no_constant.csv          → after Phase 1 (constant features removed)
ml_no_constant_novar.csv    → after Phase 2 (near-constant features also removed)
ml_pruned.csv               → after Phase 3 (correlated features also removed)
```

**Why not just write the final output?**

The checkpoints allow you to:
1. **Debug why a feature was removed** — was it constant? near-constant? correlated with what?
   You can load `ml_no_constant.csv` and `ml_no_constant_novar.csv` and compare column lists.
2. **Restart from mid-pipeline** — if the correlation step fails (e.g., out-of-memory on a
   huge dataset), you can resume from `ml_no_constant_novar.csv` without rerunning the earlier
   stages.
3. **Compare different threshold settings** — run with `corr_threshold=0.90` vs `0.95` and
   compare `ml_pruned.csv` column counts without rerunning the constant/near-constant stages.

---

## 5. Complete Data Flow Through the Function

```
ml_ready.csv  (e.g., 180 columns, 50,000 rows)
      │
      │  Phase 0: pd.to_numeric, replace inf, fillna(0)
      │  → 180 columns (unchanged), 50,000 rows, all float64, no NaN, no inf
      │
      │  Phase 1: VarianceThreshold(0.0)
      │  → drops e.g., 35 constant columns (all-zero NFStream plugin fields,
      │    vlan_id, tunnel_id, etc.)
      │  → 145 columns remain
      ▼
ml_no_constant.csv  (145 columns)
      │
      │  Phase 2: value_counts top_freq > 0.995
      │  → drops e.g., 20 near-constant columns (features present in < 0.5%
      │    of flows, like rare NFStream application protocol indicators)
      │  → 125 columns remain
      ▼
ml_no_constant_novar.csv  (125 columns)
      │
      │  Phase 3: upper-triangle Pearson |r| > 0.95
      │  → drops e.g., 45 correlated columns (NFStream byte/packet ratio
      │    features that are linear combinations of base byte/packet counts)
      │  → 80 columns remain
      ▼
ml_pruned.csv  (80 columns, 50,000 rows)
      │
      └──► Tutorial 12 (finalize.py) reads ml_pruned.csv → ml_final.csv
```

---

## 6. How This Connects to Tutorial 12 and the ML Workflow

`ml_pruned.csv` is not the final ML input. Tutorial 12 (`finalize.py`) performs one more pass —
removing any **temporal leakage** columns that survived pruning (columns that encode flow timing
information indirectly). After finalization, `ml_final.csv` is what the ML workflow in Tutorial
19 reads.

The three pruning thresholds (`near_const_threshold=0.995`, `corr_threshold=0.95`) are exposed
as parameters so the ML workflow or the orchestration layer can tune them per-dataset. For
example, a QUIC-heavy capture might need a lower correlation threshold because QUIC flow
statistics are more densely correlated than TCP statistics.

---

## 7. Interview Questions and Answers

**Q: Why does the code use `VarianceThreshold` from scikit-learn instead of just computing
variance with pandas?**

A: `VarianceThreshold` is a proper scikit-learn transformer — it implements `.fit()`,
`.transform()`, and `.get_support()`. This means it can be slotted into a scikit-learn `Pipeline`
object later if the pruning step is ever refactored into the ML pipeline. Using it here also makes
the intent explicit: this is a feature selection step using a standard, well-tested algorithm, not
a custom one-off pandas operation. `get_support()` returns the boolean mask in a documented,
stable API — more reliable than manually computing variance and applying a threshold.

---

**Q: Why does near-constant removal use frequency rather than variance?**

A: Variance and frequency detect different problems. A column with 99.6% zeros and 0.4% large
values (e.g., 1000.0) has **high variance** because of those outlier values, but is dominated by
one value — the zero. A pure variance threshold would keep this column because its variance is
high. Frequency analysis correctly identifies it as near-constant because 99.6% of rows have the
same value. The two methods are complementary: Phase 1 (variance) catches columns that are
literally all-the-same; Phase 2 (frequency) catches columns that are almost-all-the-same but
with rare outliers that inflate variance.

---

**Q: In the upper-triangle correlation logic, which feature in a correlated pair is kept and
which is dropped?**

A: The code drops the **later column** (higher column index) in each correlated pair. The upper
triangle matrix stores `corr[row_col][column_col]` where `column_col` is always to the right of
`row_col`. The list comprehension iterates over columns and drops any column that appears in the
upper triangle with a correlation value above the threshold. This means: when A and B are
correlated (A appears in a row, B appears as the column), B is dropped and A is kept. The choice
is arbitrary in terms of ML quality — what matters is eliminating the redundancy, not which
feature survives. If you wanted to keep the feature with higher variance (the more informative
one), you would need a more sophisticated selection strategy, but the default (keep earlier,
drop later) is sufficient for this project.

---

**Q: What happens if all features in a dataset are highly correlated with each other?**

A: All but the first column (index 0) would be dropped, leaving a single-feature dataset. This
would be a degenerate case indicating that the dataset is essentially one-dimensional — the
entire traffic behaviour is captured by a single metric. In practice this cannot happen with
real TLS+NFStream+Zeek data because Zeek and NFStream measure fundamentally different aspects of
traffic (protocol metadata vs. timing statistics) that are not linearly related.

---

**Q: Why is `duplicate_rows` counted but not acted upon?**

A: Duplicate rows in the ML-ready CSV are diagnostically interesting (they suggest the same
flow appeared twice in the capture) but removing them is a policy decision that belongs in the
orchestration layer, not in the pruning function. The pruning function's responsibility is
feature selection, not sample selection. The count is surfaced in the return dict so the
orchestration layer can log it or the quality gate can check it. Removing duplicate rows here
would couple two concerns — feature pruning and data deduplication — that are conceptually
separate.

---

**Q: Why run the correlation step on `df_no_var` (after near-constant removal) rather than on
`df` (the original DataFrame)?**

A: Three reasons. First, constant and near-constant features produce degenerate correlations:
a constant column has zero standard deviation, so the Pearson formula divides by zero, producing
`NaN` throughout the row/column in the correlation matrix. This would break the upper-triangle
logic. Second, it is wasteful to compute an N×N matrix for columns you are about to drop anyway.
Third, removing redundant features before correlation analysis produces a cleaner, more
interpretable correlation structure — the surviving features' correlations are not diluted by
hundreds of near-zero-variance columns that correlate weakly with everything.

---

*Next: [Tutorial 12 — Final Dataset Cleanup](12_pipeline_finalize.md)*
