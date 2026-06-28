# Tutorial 31 — Reporting Snapshot (`reporting/snapshot.py`)

## Prerequisites

- Tutorial 17 (`pipeline/canonical.py`) — the canonical CSV and its summary JSON are the
  primary inputs. The metadata columns (`protocol_family`, `window_id`, `capture_id`,
  `label`, etc.) built there are the columns queried here.
- Tutorial 20 (`detection/multitier.py`) — `tiered_flow_scores.csv`, `suspicious_clusters.csv`,
  `graph_nodes.csv`, `graph_edges.csv` are outputs of the multi-tier run read here.
- Tutorial 26 (`backend/registry.py`) — `resolve_model_bundle_dir` is called to locate the
  active model bundle's feature importance CSVs.
- Tutorial 22 (`backend/models.py`) — `ProcessingJob.status` is queried for the job status
  counts section of the dashboard.

---

## 1. Why This File Exists

Once the multi-tier detection run completes, the results live in several separate CSV and JSON
files. A dashboard or static site needs a single, consistently shaped JSON snapshot to render
charts, tables, and graphs. `snapshot.py` reads all those files, assembles them into a
structured dict, and provides three query functions:

- `build_dashboard_summary` — the full snapshot: overview counts, protocol trends, alert
  timelines, feature importance, graph overview, top alerts.
- `query_flow_explorer` — paginated, filtered query over `tiered_flow_scores.csv` for an
  interactive flow browser.
- `build_graph_view` — graph topology for a specific suspicious cluster, capped at a node
  limit for rendering.

None of these functions write anything. They are read-only aggregators.

---

## 2. `DashboardArtifacts` (lines 19–25)

```python
@dataclass(frozen=True)
class DashboardArtifacts:
    canonical_csv: Path
    canonical_summary_json: Path
    model_bundle_dir: Path
    multi_tier_dir: Path
```

Four paths, frozen. `resolve_dashboard_artifacts` builds this once per call and passes it to
every sub-query. Centralising path resolution here means a change in where artifacts live
requires only changing `resolve_dashboard_artifacts`, not every function that reads files.

---

## 3. Utility Helpers (lines 27–174)

### `_read_json` and `_read_csv` (lines 27–36)

Both return safe empty defaults (`{}` and `pd.DataFrame()`) when the file does not exist. Every
caller uses `.get()` or `.empty` checks rather than guarding against `FileNotFoundError`. A
missing file is not an error in the snapshot context — it means a component hasn't run yet, and
the dashboard should show zeros rather than crash.

### `_json_safe_value` (lines 39–64)

The most complex helper. It converts any Python/NumPy/pandas value into a JSON-serialisable
Python primitive. The check order is deliberate:

```python
if value is None:                           # 1. explicit None
    return None
if isinstance(value, Path):                 # 2. Path → str
    return str(value)
if isinstance(value, dict):                 # 3. recurse into dicts
    ...
if isinstance(value, (list, tuple)):        # 4. recurse into sequences
    ...
if hasattr(value, "item") and not isinstance(value, (str, bytes)):   # 5. NumPy scalar
    value = value.item()
try:
    if pd.isna(value):                      # 6. NaN / NaT / pd.NA → None
        return None
except Exception:
    pass
if isinstance(value, bool):                # 7. bool BEFORE int
    return value
if isinstance(value, int):                  # 8. int
    return int(value)
if isinstance(value, float):               # 9. float
    return float(value)
return value                               # 10. fallback (str, etc.)
```

**Step 5 — NumPy scalar conversion**: `hasattr(value, "item")` detects NumPy scalar types
(`np.int64`, `np.float32`, `np.bool_`, etc.). Calling `.item()` converts them to the
corresponding Python primitive. Without this, `json.dumps` raises `TypeError: Object of type
int64 is not JSON serializable`. The `not isinstance(value, (str, bytes))` guard prevents
calling `.item()` on string types, which also have an `item`-like attribute in some versions.

**Step 6 — `pd.isna` wrapped in try/except**: `pd.isna` raises `ValueError` when passed a
non-scalar array-like value (e.g., a DataFrame). The `try/except` makes the check safe for
any value type.

**Step 7 — `bool` before `int`**: In Python, `bool` is a subclass of `int`.
`isinstance(True, int)` is `True`. If the `int` branch came first, `True` would become `int(True)` = `1` — a valid integer but wrong semantically. The JSON distinction between `true` and `1`
matters to JavaScript clients.

### `_bool_series` (lines 99–105)

```python
def _bool_series(df: pd.DataFrame, column: str) -> pd.Series:
    if column not in df.columns:
        return pd.Series(False, index=df.index)
    series = df[column]
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    return series.astype(str).str.lower().isin({"true", "1", "yes"})
```

Boolean columns written to CSV and read back arrive in one of three forms:

| Stored value | CSV representation | `read_csv` dtype | Handled by |
|---|---|---|---|
| Python `True`/`False` | `True`/`False` | bool | `is_bool_dtype` branch |
| NumPy `True`/`False` | `True`/`False` | bool | `is_bool_dtype` branch |
| String after mixed types | `"True"`/`"False"` | object | `str.lower().isin(...)` branch |
| Integer 1/0 | `1`/`0` | int64 or object | `"1"` is in the set |

The `isin({"true", "1", "yes"})` set covers all common truthy string representations. The
guard `if column not in df.columns` returns a Series of `False` — a missing boolean column
is treated as "all rows are False" rather than raising `KeyError`.

### `_top_values` (lines 108–115)

```python
def _top_values(series: pd.Series, limit: int = 5) -> list[str]:
    cleaned = series.dropna().astype(str).str.strip()
    cleaned = cleaned[cleaned.ne("")]
    return cleaned.value_counts().head(limit).index.tolist()
```

`series.dropna().astype(str).str.strip()` — drops `NaN`, converts to string, strips whitespace.
`cleaned.ne("")` — removes empty strings left after stripping. `value_counts().head(limit).index`
— the most frequent non-empty, non-null values. Used for `top_requested_server_names` in
`protocol_breakdown`.

### `_window_sort_frame` (lines 118–123)

Sorts a windowed DataFrame by `window_start_ms` (numeric millisecond timestamps) when
available, falling back to lexicographic `window_id` sort. The numeric sort ensures windows
appear chronologically in the chart even if `window_id` strings sort differently. `kind="stable"`
preserves the relative order of rows with equal sort keys — important for reproducible output.

### `_job_status_counts` (lines 138–144)

```python
rows = session.execute(
    select(ProcessingJob.status, func.count()).group_by(ProcessingJob.status)
).all()
return {str(status): int(count) for status, count in rows}
```

A single `SELECT status, COUNT(*) FROM processing_jobs GROUP BY status` query. Returns a dict
like `{"queued": 2, "running": 1, "succeeded": 14, "failed": 1}`. The `session: Session | None`
parameter makes this optional — if no session is passed, the function returns `{}`. This
allows `build_dashboard_summary` to be called without a live DB connection for static site
export (Tutorial 32).

### `_collect_quality_reports` (lines 147–174)

```python
paths = sorted(
    runs_root.rglob("*_quality_report.json"),
    key=lambda path: path.stat().st_mtime,
    reverse=True,
)
for path in paths[:8]:
    ...
```

Finds all quality report JSON files anywhere under `artifacts/runs/`, sorts them by filesystem
modification time (newest first), and reads the 8 most recent. `reverse=True` is critical —
without it the oldest reports would be shown. `[:8]` caps at 8 to avoid reading hundreds of
reports on a large dataset.

For each report, `failed_gates` extracts only the gate names that failed:
`outcome.get("status", "").lower() == "fail"`. This gives the dashboard a concise list like
`["merge_match_rate", "non_tls_leakage"]` without embedding the full gate report.

---

## 4. `resolve_dashboard_artifacts` (lines 88–96)

```python
def resolve_dashboard_artifacts(settings: BackendSettings | None = None) -> DashboardArtifacts:
    resolved_settings = settings or get_backend_settings()
    project_root = resolved_settings.project_root
    return DashboardArtifacts(
        canonical_csv=(project_root / "artifacts" / "canonical" / "canonical_labeled_flows.csv").resolve(),
        canonical_summary_json=(...).resolve(),
        model_bundle_dir=resolve_model_bundle_dir(settings=resolved_settings),
        multi_tier_dir=_resolve_multi_tier_dir(project_root),
    )
```

Canonical paths are hardcoded relative to `project_root`. This is intentional: these artifacts
are always in the same place relative to the project (Tutorial 17). The model bundle and
multi-tier dir use the same `latest/` convention and discovery fallback as the backend registry
(Tutorial 26).

`_resolve_multi_tier_dir` mirrors `resolve_model_bundle_dir`: prefers `artifacts/multi_tier/latest/`,
falls back to lexicographic discovery among `artifacts/multi_tier/*/` subdirectories, raises
`FileNotFoundError` if nothing is found.

---

## 5. `build_dashboard_summary` (lines 177–415)

The function loads eight source files and assembles ten output sections. Each section is
explained below by what is non-obvious.

### File loading (lines 185–192)

All reads go through `_read_csv` and `_read_json`, which return empty defaults. The function
never raises on a missing file — it produces a dashboard with zeros and empty lists instead.
This is correct behaviour: a fresh project with no training run yet should show an empty
dashboard, not a crash.

### Overview counts (lines 204–221)

```python
dataset_mode = "benchmark_corpus" if len(label_counts) >= 2 else "single_label_corpus"
quality_signal = "quality_caveat_present" if quality_status_counts.get("fail", 0) else "quality_clear"
```

`dataset_mode` — if the canonical dataset has at least two distinct labels (`benign`,
`malicious`), it is a full benchmark corpus. If only one label exists (e.g., benign-only or
malicious-only), it is a single-label corpus. The distinction matters for how results are
interpreted: a single-label model cannot be evaluated for false-positive rate.

`quality_signal` — a single string that summarises whether any quality gates failed across the
canonical dataset. The frontend can display a warning banner if `quality_caveat_present`.

### Protocol trend (lines 223–253)

```python
grouped = canonical_df.groupby(["window_id", "protocol_family"], dropna=False).size().rename("count").reset_index()
pivot = grouped.pivot_table(index="window_id", columns="protocol_family", values="count", fill_value=0, aggfunc="sum").reset_index()
```

`groupby` counts flows per `(window_id, protocol_family)` pair. `pivot_table` reshapes the
long format to wide: each row is a window, each column is a protocol. `fill_value=0` fills
windows that have no flows of a given protocol with zero rather than NaN.

The subsequent `merge` with `window_meta` attaches `window_start_ms` (the minimum timestamp
within each window) to each pivot row. After `_window_sort_frame`, the output is a
chronologically ordered list of `{"window_id", "window_start_ms", "tls": N, "quic": M}` dicts
ready for a D3.js time series chart.

### Alert timeline (lines 255–287)

```python
grouped["high_alerts"] = (
    timeline.groupby("window_id", dropna=False)["alert_level"]
    .apply(lambda values: int(pd.Series(values).astype(str).eq("high").sum()))
    .values
    if "alert_level" in timeline.columns
    else 0
)
```

`groupby(...).apply(lambda values: ...)` — for each window, counts rows where `alert_level ==
"high"`. `.values` at the end extracts the numpy array of per-window counts, which is assigned
back to a new column on the grouped DataFrame. The `int(pd.Series(values).astype(str)...)`
chain normalises the `alert_level` values (which may be strings or numpy strings) before
comparison.

### Feature importance (lines 309–326)

```python
importance_path = model_dir / "feature_importance_native.csv"
if not importance_path.exists():
    importance_path = model_dir / "feature_importance_permutation.csv"
...
value_column = "importance" if "importance" in importance_df.columns else "importance_mean"
```

Two fallbacks:
1. File fallback: native importance first, permutation importance second. GaussianNB has no
   native feature importance (the attribute doesn't exist for NB), so it only has the
   permutation file. RF and GradientBoosting have both; native is used for display because it
   is faster to compute and consistent across runs.
2. Column name fallback: `"importance"` for native (a single float per feature), `"importance_mean"`
   for permutation (the mean over permutation iterations). Both files have a `"feature"` column.

### Top endpoints (lines 333–350)

```python
ranking = nodes_df.sort_values(
    ["suspicious_flow_count", "unique_neighbors", "max_incident_score"],
    ascending=[False, False, False],
    kind="stable",
)
for _, row in ranking.head(8).iterrows():
    ...
```

Three-column sort: primary by `suspicious_flow_count` (most suspicious first), tiebreak by
`unique_neighbors` (endpoints with more connections are higher risk), tiebreak by
`max_incident_score` (highest single-flow risk score). This ranking surfaces the most impactful
suspicious endpoints regardless of whether they appear in many low-probability flows or fewer
high-probability ones.

---

## 6. `query_flow_explorer` (lines 418–508)

A paginated, filtered query over `tiered_flow_scores.csv` entirely in pandas — no SQL.

### Filter chain (lines 439–462)

```python
if protocol_family and "protocol_family" in working.columns:
    working = working[working["protocol_family"].astype(str).str.lower() == protocol_family.lower()]
if alert_level and "alert_level" in working.columns:
    working = working[working["alert_level"].astype(str).str.lower() == alert_level.lower()]
if only_suspicious:
    working = working[working["tier2_pass"]]
if search:
    haystack = working[search_columns].fillna("").astype(str).agg(" ".join, axis=1).str.lower()
    working = working[haystack.str.contains(lowered, na=False)]
```

Each filter narrows `working` in place. The `astype(str).str.lower()` pattern normalises
both the column values and the filter argument for case-insensitive comparison.

The `search` implementation concatenates all searchable columns into a single string per row,
then does `str.contains`. `working[search_columns].fillna("").astype(str).agg(" ".join, axis=1)`
produces a Series like `["abc123 capture1 192.168.1.1 ..."]` — one entry per row. `str.contains`
then applies the search across all fields in one vectorised operation. This is O(n × columns)
but avoids a loop and is fast enough for CSV sizes up to tens of thousands of rows.

### Pagination (lines 469–508)

```python
total = int(len(working))
page = working.iloc[offset : offset + limit][display_columns].copy()
```

`total` is computed before pagination so the client knows how many rows match the filters.
`iloc[offset : offset + limit]` is offset-based pagination. `[display_columns]` strips down to
only the columns the frontend needs, reducing payload size.

`display_columns` is built dynamically — only columns that exist in `working` are included:

```python
display_columns = [column for column in (...) if column in working.columns]
```

This guards against `tiered_flow_scores.csv` from different pipeline runs having different
column sets. A column like `requested_server_name` might be absent from some runs; the guard
prevents `KeyError`.

---

## 7. `build_graph_view` (lines 511–569)

Loads graph data for a specific cluster and prepares it for a frontend graph renderer (D3, Cytoscape, etc.).

### Cluster selection (lines 525–536)

```python
selected_cluster_id = cluster_id or str(clusters_df.iloc[0]["cluster_id"])
nodes = nodes_df[nodes_df["cluster_id"].astype(str) == selected_cluster_id].copy()
edges = edges_df[edges_df["cluster_id"].astype(str) == selected_cluster_id].copy()
```

`cluster_id or str(clusters_df.iloc[0]["cluster_id"])` — if no cluster is specified, the first
cluster in `suspicious_clusters.csv` is used as the default. The file is written by
`build_graph_enrichment` (Tutorial 20) with clusters ordered by suspiciousness, so `iloc[0]`
is the most suspicious cluster.

`astype(str)` on both sides of the comparison — `cluster_id` values may be integers in the
CSV (parsed as `int64` by `read_csv`) while the passed `cluster_id` parameter is a string.
`astype(str)` normalises both sides to prevent silent mismatches.

### Node cap and edge filtering (lines 538–557)

```python
selected = nodes.head(max_nodes).copy()
selected_endpoints = set(selected["endpoint"].astype(str))
filtered_edges = edges[
    edges["endpoint_a"].astype(str).isin(selected_endpoints)
    & edges["endpoint_b"].astype(str).isin(selected_endpoints)
].copy()
```

`nodes` is pre-sorted by `[suspicious_flow_count, unique_neighbors, max_incident_score]`
descending, so `head(max_nodes)` takes the most suspicious nodes. Edges are then filtered to
keep only those where **both** endpoints are in the selected node set. An edge between a
selected node and a dropped node would reference a node the frontend does not have — rendering
would produce dangling edges or silently drop them.

### Fallback when edge filtering empties (lines 550–557)

```python
if filtered_edges.empty and not edges.empty:
    filtered_edges = edges.sort_values(...).head(max_nodes * 2)
    selected_endpoints = set(filtered_edges["endpoint_a"]...).union(...)
    selected = nodes[nodes["endpoint"].astype(str).isin(selected_endpoints)].copy()
```

If the node-first selection leaves no edges (possible when node IDs in the edges don't match
node IDs in the nodes DataFrame, e.g., data consistency issue), the fallback switches to an
edge-first approach: select the top edges by score, then select the nodes that appear in those
edges. This ensures the frontend always receives a connected subgraph rather than isolated nodes.

---

## 8. What Makes This "Snapshot" Not "Live Query"

`build_dashboard_summary` is not a live query engine. It reads static CSV and JSON files
written by the multi-tier detection run and the training workflow. The results reflect the state
at the time those runs completed. If new scoring jobs have run since then, their results are
NOT reflected in the dashboard until a new multi-tier run writes updated CSVs.

The `session` parameter is the only live element: `_job_status_counts` queries the DB for
current job queue health. Everything else is filesystem-based. This design makes the snapshot
cheap to generate (no ML computation, no pipeline re-run) and trivially exportable as a static
file (Tutorial 32) by simply not passing a session.

---

## 9. Interview Questions and Answers

**Q: Why does `_json_safe_value` check `isinstance(value, bool)` before `isinstance(value, int)`?**

A: In Python, `bool` is a subclass of `int`. `isinstance(True, int)` returns `True`, so if the
`int` branch came first, `True` would be passed to `int(True)` = `1`. JSON serialisation would
then send `1` instead of `true` to the client. A JavaScript client checking `if (value === true)`
would fail because `1 === true` is `false` in strict comparison. The `bool` check must precede
the `int` check to preserve the semantic distinction between booleans and integers.

---

**Q: Why does `_bool_series` need to handle both `bool` dtype and string representations of
boolean values?**

A: When a pandas DataFrame with boolean columns is written to CSV with `df.to_csv()`, the
values are serialised as the strings `"True"` and `"False"`. When `pd.read_csv` reads the file
back, it may infer the column as `bool` dtype (if the column is clean) or as `object` dtype
(if the column has mixed types or was cast via another operation). Because `tiered_flow_scores.csv`
is produced by scoring runs that may be older or come from different pipeline versions, the
dtype is not guaranteed. `_bool_series` handles both cases so callers can use the result as a
boolean Series regardless of how the CSV was written.

---

**Q: Why is the search in `query_flow_explorer` implemented by concatenating columns into a
single string rather than doing a column-by-column search?**

A: A column-by-column search would require multiple passes over the DataFrame — one `str.contains`
per searchable column — and then combining the results with `|`. Concatenating all columns into
one string per row with `.agg(" ".join, axis=1)` reduces the search to a single vectorised
`str.contains` call. For a DataFrame of tens of thousands of rows and ~7 search columns, the
single-pass approach is roughly 7× faster. The trade-off is that a search term might match a
substring that spans two adjacent column values (e.g., the end of `src_ip` and the start of
`dst_ip`), producing a false positive. For a research dashboard this is acceptable.

---

**Q: Why does `build_graph_view` use an edge-first fallback when the node-first selection
produces empty edges?**

A: The node-first selection (take the top-N suspicious nodes, keep edges between them) can
fail when the graph is sparse: the most suspicious nodes may not be directly connected to each
other but connected only through dropped lower-suspicion nodes. In that case the edge set is
empty even though the cluster has real structure. The edge-first fallback selects the highest-
scoring edges and derives the node set from them, guaranteeing the frontend receives a connected
subgraph. Rendering an empty edge set would show isolated nodes with no visible relationships
— the fallback preserves the graph's explanatory value.

---

*Next: [Tutorial 32 — Static Site Export](32_static_site_export.md)*
