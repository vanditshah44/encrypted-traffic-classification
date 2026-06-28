# Tutorial 20 — Multi-Tier Detection (`detection/multitier.py`)

## Prerequisites

- Tutorial 17 (`canonical.py`) — the canonical dataset this file reads, specifically the
  `record_id`, `capture_id`, `window_id`, and `protocol_family` columns that appear throughout.
- Tutorial 19 (`ml/workflow.py`) — the model bundle this file loads: `model.joblib`,
  `threshold_summary.json`, and `feature_manifest.json`.
- Tutorial 09 (`quality.py`) — `GateOutcome` / `QualityReport` concepts; the same "read first,
  decide second" phasing used here.

---

## 1. Why This File Exists

Tutorial 19 trains models and stores them on disk. That's offline work. `multitier.py` is the
**online scoring path** — it takes new data, runs it through the saved models, and produces an
actionable alert structure.

But "run the model and threshold" isn't enough for a detection system. Two additional problems
exist:

**Problem 1 — Speed vs accuracy tradeoff.** GaussianNB is fast because it makes a conditional
independence assumption that is almost always wrong. It mislabels complex traffic. RF and GB are
slow but accurate. Running RF + GB on 50,000 flows per second is expensive. The solution: run
GNB first as a *screener*. Only flows that pass GNB's threshold get promoted to RF + GB. Most
benign flows are eliminated cheaply; only the suspicious minority pays the heavier cost.

**Problem 2 — Flow-level scores don't tell you what's coordinating.** A C2 beacon from a botnet
doesn't look like a single suspicious flow — it looks like 20 flows between the same two IPs
over 10 minutes, all with similar scores. A flow-level score misses the campaign structure.
Graph enrichment finds this by building a connectivity graph of suspicious endpoints, running BFS
to find connected components (clusters), and annotating every flow with its cluster's statistics.

This file implements both: two-tier scoring (§4–§7), then graph enrichment (§8–§9).

---

## 2. Utility Functions — Lines 29–55

### `_load_yaml` (lines 29–35)

```python
def _load_yaml(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).expanduser().resolve()
    with config_path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected mapping config at {config_path}")
    return payload
```

`yaml.safe_load` raises nothing if the YAML file is empty — it returns `None`. The `isinstance`
check turns that silent bad case into an explicit error. `safe_load` (not `load`) is always
correct here: `yaml.load` with no Loader can execute arbitrary Python via `!!python/object`
tags; `safe_load` disallows all such constructors.

### `_json_default` (lines 38–49)

```python
def _json_default(value: Any) -> Any:
    if isinstance(value, (np.integer,)):   return int(value)
    if isinstance(value, (np.floating,)):  return float(value)
    if isinstance(value, (np.bool_,)):     return bool(value)
    if isinstance(value, Path):            return str(value)
    if pd.isna(value):                     return None
    raise TypeError(...)
```

`json.dumps` fails on numpy scalar types because they are not Python builtins even though they
look identical. `np.int64(3)` is not `int(3)` — the default JSON encoder does not know about
NumPy. This function is passed as `default=_json_default` to `json.dumps`, which calls it only
when the normal encoder fails, so it acts as a fallback for NumPy types only. The `pd.isna` line
handles `np.nan` and `pd.NA` → `None` (JSON `null`). The final `raise TypeError` is intentional:
if an unhandled type appears, fail loudly rather than silently producing wrong output.

### `save_json` (lines 52–55)

```python
def save_json(payload: dict[str, Any], output_path: str | Path) -> None:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")
```

`indent=2` produces human-readable JSON. `write_text` is atomic at the OS level on most
filesystems — it opens, writes, and closes in one call. A crash mid-write may produce a partial
file, but the previous version is never overwritten until the write completes, which is sufficient
for this use case.

---

## 3. `MultiTierConfig` — Lines 58–82

```python
@dataclass(frozen=True)
class MultiTierConfig:
    dataset_csv: str
    model_bundle_dir: str
    output_dir: str
    target_column: str | None       # only present during evaluation; None in production
    label_column: str | None        # human-readable label; optional
    record_id_column: str           # from canonical.py — "record_id"
    src_ip_column: str              # from canonical.py — "src_ip"
    dst_ip_column: str              # from canonical.py — "dst_ip"
    src_port_column: str
    dst_port_column: str
    capture_id_column: str          # from canonical.py — "capture_id"
    window_id_column: str           # from canonical.py — "window_id"
    protocol_family_column: str     # from canonical.py — "protocol_family"
    requested_server_name_column: str  # TLS SNI field
    tier1_model_name: str           # default "gaussian_nb"
    tier1_threshold: float | None   # None = use saved threshold from bundle
    deep_model_names: tuple[str, ...]  # immutable sequence of Tier 2 model names
    deep_model_weights: dict[str, float]  # per-model weight in consensus
    deep_consensus_threshold: float    # weighted score above which = pass
    min_deep_model_passes: int         # how many individual deep models must also pass
    use_optimized_thresholds: bool     # True = use CV-optimized thresholds from §19
    cluster_min_suspicious_flows: int  # minimum flows on an edge to be graphed
```

`frozen=True` makes all fields immutable after construction — the config object can be passed
between functions without risk of accidental mutation. `target_column: str | None` exposes the
asymmetry between evaluation mode (you have ground truth and want metrics) and production mode
(you don't). When `target_column` is `None`, `run_multitier_detection` skips the metrics block
entirely. This is safer than checking `if target_column in scored.columns` — the `None` case
forces the caller to be explicit about evaluation intent.

`deep_model_names: tuple[str, ...]` — a list would be mutable; in a frozen dataclass, using a
list for a field that should not change after creation is technically permitted (frozen only
prevents field reassignment, not mutation of a list in place). Using `tuple` makes the intent
unambiguous and prevents `config.deep_model_names.append(...)` from silently corrupting state.

---

## 4. `LoadedModel` (lines 84–88) and `load_model` (lines 127–140)

```python
@dataclass(frozen=True)
class LoadedModel:
    name: str
    pipeline: Any        # sklearn Pipeline object
    threshold: float     # decision boundary for this model
```

The threshold lives on the `LoadedModel` object, not the sklearn pipeline. This is a deliberate
design: sklearn's `predict` uses 0.5 internally; the CV-optimized threshold from Tutorial 19 is
stored in `threshold_summary.json` separately. `LoadedModel` binds the two together so downstream
code never has to look up the threshold separately — it always comes with the model.

```python
def load_model(model_bundle_dir, model_name, *, use_optimized_thresholds, threshold_override=None):
    bundle_dir = Path(model_bundle_dir).expanduser().resolve() / model_name
    pipeline = joblib.load(bundle_dir / "model.joblib")
    threshold_payload = json.loads((bundle_dir / "threshold_summary.json").read_text(...))
    threshold = float(threshold_payload["threshold"]) if use_optimized_thresholds else 0.5
    if threshold_override is not None:
        threshold = float(threshold_override)
    return LoadedModel(name=model_name, pipeline=pipeline, threshold=threshold)
```

Three-way threshold priority (highest wins):
1. `threshold_override` — caller forces a specific value (e.g., tuning a single model)
2. `use_optimized_thresholds=True` — use the CV-optimized value from `threshold_summary.json`
3. `use_optimized_thresholds=False` — fall back to 0.5 (sklearn default)

`joblib.load` is used instead of `pickle.load` because joblib handles large NumPy arrays more
efficiently (memory-mapped when possible) and is the standard sklearn serialization format.

---

## 5. Feature Alignment — `align_inference_frame` (lines 143–148)

```python
def align_inference_frame(df: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    X = df.reindex(columns=feature_columns).copy()
    bool_columns = [column for column in X.columns if pd.api.types.is_bool_dtype(X[column])]
    if bool_columns:
        X[bool_columns] = X[bool_columns].astype(int)
    return X
```

`df.reindex(columns=feature_columns)` does three things simultaneously:
1. **Selects** the 80 feature columns from the canonical dataset (drops all metadata columns)
2. **Orders** them in exactly the training order (required: RandomForest feature importance
   is positional)
3. **Fills** missing columns with `NaN` — if inference data lacks a column that was present at
   training time, the imputer inside the sklearn Pipeline handles the NaN safely

`bool_columns → astype(int)` is necessary because scikit-learn's imputer and tree models do
not always handle bool dtype consistently across versions — converting to 0/1 int is safe and
unambiguous.

---

## 6. Tier 1 and Tier 2 Scoring — `run_multitier_detection` lines 450–494

### Stage 1: GNB screener

```python
tier1_probability = predict_model_probability(tier1_model, X)
tier1_pass = pd.Series(tier1_probability >= tier1_model.threshold, index=df.index)
```

All 50,000 rows go through GNB. Because GNB is essentially a product of univariate Gaussian
likelihoods, `predict_proba` is fast even on large frames. `tier1_pass` is a boolean Series
aligned on `df.index` — this alignment is critical for the selective stage-2 scoring below.

### Stage 2: Selective deep model scoring

```python
stage2_index = scored.index[scored["tier1_pass"]]
if len(stage2_index):
    X_stage2 = X.loc[stage2_index]
else:
    X_stage2 = X.iloc[0:0]  # empty but correct-shaped frame
```

`X.loc[stage2_index]` extracts only the rows that passed Tier 1. The RF and GB models run only
on this subset. If GNB passes 500 rows out of 50,000, RF and GB do 1% of the work they would
otherwise do. The `X.iloc[0:0]` branch produces an empty DataFrame with the correct column
schema — if you used `X.iloc[[]]` you'd get the same result, but `0:0` slice is more readable.

```python
for model in deep_models:
    probabilities = pd.Series(np.nan, index=scored.index, dtype="float64")
    if len(stage2_index):
        probabilities.loc[stage2_index] = predict_model_probability(model, X_stage2)
    scored[score_column] = probabilities
```

`pd.Series(np.nan, index=scored.index)` pre-fills every row with NaN. Then only the stage-2
rows are filled with real scores. This means rows that failed Tier 1 have `NaN` for all deep
model scores — a downstream reader seeing `NaN` in `random_forest_probability` immediately knows
that row was eliminated at Tier 1 without needing to read `tier1_pass`.

### Consensus score

```python
deep_score_frame = scored.loc[stage2_index, deep_score_columns].copy()
deep_weights = {model_name + "_probability": config.deep_model_weights.get(model_name, 1.0) ...}
deep_consensus_subset = weighted_mean_scores(deep_score_frame, deep_weights)
```

`weighted_mean_scores` (lines 157–165) vectorizes the weighted average:

```python
effective_weights = np.array([weights.get(column, 1.0) for column in score_frame.columns])
weighted_values = score_frame.to_numpy(dtype=float) * effective_weights   # broadcast
return pd.Series(weighted_values.sum(axis=1) / weight_sum, index=score_frame.index)
```

`weights.get(column, 1.0)` — if a model has no configured weight, it defaults to 1.0 (equal
weight). This is forgiving: you can add a new model to `deep_model_names` without updating
`deep_model_weights` and it will participate equally. The `weight_sum <= 0` guard is paranoia
against misconfiguration where all weights are 0.

### Tier 2 pass logic

```python
required_deep_passes = min(config.min_deep_model_passes, len(deep_models))
scored["tier2_pass"] = scored["tier1_pass"] & (
    (scored["tier2_pass_count"] >= required_deep_passes) | scored["tier2_consensus_pass"].fillna(False)
)
```

Two paths to a Tier 2 pass:
- **Count path**: at least `min_deep_model_passes` individual models agreed (each exceeding its
  own threshold)
- **Consensus path**: the weighted average score exceeds `deep_consensus_threshold`

The `|` (OR) between them is intentional. A flow where one high-weight model gives 0.95 and a
low-weight model gives 0.40 might not satisfy `min_deep_model_passes=2` (since only one model
passed its threshold), but the consensus score could be 0.75 if the high-weight model dominates.
The OR allows the weighted evidence to carry a Tier 2 pass even when no single majority exists.

Both paths require `tier1_pass` (the `&` at the start) — Tier 2 can never pass without Tier 1.

---

## 7. `assign_alert_level` — Lines 168–182

```python
def assign_alert_level(*, tier1_pass, tier2_pass, deep_pass_count, deep_model_total, deep_consensus_score):
    alert_level = pd.Series("none", index=tier1_pass.index, dtype="string")
    alert_level[tier1_pass] = "candidate"
    medium_mask = tier2_pass
    alert_level[medium_mask] = "medium"
    high_mask = tier2_pass & (deep_pass_count >= deep_model_total) & (deep_consensus_score >= 0.9)
    alert_level[high_mask] = "high"
    return alert_level
```

Four alert levels built by progressive overwriting:

| Level | Condition | Meaning |
|---|---|---|
| `none` | default | benign at Tier 1 |
| `candidate` | Tier 1 pass | GNB flagged it; pending deep review |
| `medium` | Tier 2 pass | RF+GB consensus confirmed it |
| `high` | Tier 2 pass + **all** deep models passed + consensus ≥ 0.9 | unanimous high-confidence |

The `high` condition checks `deep_pass_count >= deep_model_total` — *all* configured deep
models, not just a majority. If you have RF + GB and both must pass for "high", this is equivalent
to requiring unanimous agreement. The 0.9 consensus threshold is hardcoded as the "high" bar
regardless of `deep_consensus_threshold` (which only controls the Tier 2 pass). These are
intentionally different: Tier 2 pass at 0.5 consensus is already suspicious; "high" requires
near-certainty.

`keyword-only arguments (*)` — every parameter is keyword-only. A caller cannot write
`assign_alert_level(a, b, c, d, e)` positionally and accidentally swap `tier2_pass` with
`deep_pass_count`. For a function that controls alert levels in a detection system, argument-order
bugs would be silent and dangerous.

---

## 8. `build_connected_components` — Lines 218–239

```python
def build_connected_components(pairs: list[tuple[str, str]]) -> dict[str, str]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    for left, right in pairs:
        adjacency[left].add(right)
        adjacency[right].add(left)          # undirected graph

    assignments: dict[str, str] = {}
    cluster_index = 0
    for node in sorted(adjacency):          # deterministic iteration order
        if node in assignments:
            continue
        cluster_id = f"cluster_{cluster_index:04d}"
        queue: deque[str] = deque([node])
        assignments[node] = cluster_id
        while queue:
            current = queue.popleft()       # BFS, not DFS
            for neighbor in adjacency[current]:
                if neighbor not in assignments:
                    assignments[neighbor] = cluster_id
                    queue.append(neighbor)
        cluster_index += 1
    return assignments
```

This is textbook BFS-based connected components. The inputs are IP endpoint pairs from suspicious
edges. Two IPs are in the same cluster if they share any suspicious flow (directly or through
intermediate hops).

**Why BFS not DFS?** For network security, clusters can be large (a C2 server talking to 1000
bots). Recursive DFS would hit Python's default recursion limit (~1000) and raise
`RecursionError`. BFS with an explicit deque has no recursion depth limit.

**Why `sorted(adjacency)`?** Python `dict` iteration order is insertion order (CPython 3.7+), and
insertion order depends on which flows were processed first. Sorting ensures that `cluster_0000`
always refers to the same cluster across runs, making the output deterministic and diff-friendly.

**`f"cluster_{cluster_index:04d}"`** — `:04d` zero-pads to 4 digits. `cluster_0000`,
`cluster_0001`, ... `cluster_0099`. Without zero-padding, `cluster_10` sorts before `cluster_2`
lexicographically, breaking any downstream sort-by-cluster-ID.

---

## 9. `build_graph_enrichment` — Lines 249–409

This is the most complex function in the codebase. It takes the `tier2_pass` suspicious flows
and produces five DataFrames: `suspicious_flows`, `nodes`, `edges`, `clusters`, `windows`.

### Step 1 — Canonical edge direction (lines 276–277)

```python
working["endpoint_a"] = working[[src_ip_column, dst_ip_column]].astype(str).min(axis=1)
working["endpoint_b"] = working[[src_ip_column, dst_ip_column]].astype(str).max(axis=1)
```

A flow from 192.168.1.1 → 10.0.0.5 and a flow from 10.0.0.5 → 192.168.1.1 are the same edge.
Without canonicalization, they'd be two separate edges. `.min(axis=1)` and `.max(axis=1)` across
the two IP columns ensures the lexicographically smaller IP is always `endpoint_a`. The groupby
that follows uses `(endpoint_a, endpoint_b)` as the key, so both directions of a flow map to the
same edge.

### Step 2 — Edge aggregation (lines 279–299)

```python
edge_group = working.groupby(["endpoint_a", "endpoint_b"], dropna=False)
edges = edge_group.agg(
    suspicious_flow_count=("record_id", "count"),
    mean_consensus_score=("tier2_consensus_score", "mean"),
    max_consensus_score=("tier2_consensus_score", "max"),
    unique_captures=(capture_id_column, "nunique"),
    unique_windows=(window_id_column, "nunique"),
).reset_index()
edges = edges[edges["suspicious_flow_count"] >= min_suspicious_flows].copy()
```

`dropna=False` in `groupby` preserves rows where `endpoint_a` or `endpoint_b` might be NaN
(e.g., a flow with a missing IP). This prevents silently dropping suspicious flows with
incomplete IP data — they appear as a NaN-keyed group rather than vanishing.

`min_suspicious_flows` filters edges with too few flows to be credible. An edge with 1 flow
could be coincidence. An edge with 50 flows across 3 capture windows is almost certainly a C2
channel. The threshold is configurable.

`"nunique"` on `capture_id` — if the same edge appears in multiple independent capture sessions
(different PCAPs), that is a much stronger signal than if it only appears in one session.

After filtering, `_top_string_values` extracts the most frequent protocol families and SNI names
per edge:

```python
edge_top_protocols = edge_group[protocol_family_column].apply(_top_string_values).rename(...).reset_index()
edges = edges.merge(edge_top_protocols, on=["endpoint_a", "endpoint_b"], how="left")
```

`apply(_top_string_values)` runs the function on each group's Series. The result is a Series of
lists (one per group). `.reset_index()` turns the group keys back into regular columns so it can
be merged. `how="left"` preserves all edges even if they had no protocol family recorded.

### Step 3 — Connected components (lines 312–313)

```python
component_pairs = list(edges[["endpoint_a", "endpoint_b"]].itertuples(index=False, name=None))
cluster_lookup = build_connected_components(component_pairs)
edges["cluster_id"] = edges["endpoint_a"].map(cluster_lookup)
```

`itertuples(index=False, name=None)` produces plain tuples, which is faster than `iterrows`
(which produces dicts/Series) and avoids the overhead of named tuples. `cluster_lookup` maps
each IP to its cluster ID. Assigning via `edges["endpoint_a"].map(cluster_lookup)` works because
both IPs on the same edge are in the same cluster — either can be used for the lookup.

### Step 4 — Node aggregation (lines 316–348)

```python
for endpoint, edge_rows in endpoint_groups.items():
    suspicious_flow_count = int(sum(int(edge_row["suspicious_flow_count"]) for edge_row in edge_rows))
    ...
    node_records.append({
        "endpoint": endpoint,
        "cluster_id": ...,
        "is_private": safe_ip_private(endpoint),
        "edge_count": len(edge_rows),
        "unique_neighbors": len(neighbors),
        "suspicious_flow_count": suspicious_flow_count,
        "mean_incident_score": float(np.mean(mean_scores)),
        "max_incident_score": float(np.max(max_scores)),
        "risk_mass": float(sum(mean_scores)),       # total risk, not average
    })
```

`risk_mass = sum(mean_scores)` vs `mean_incident_score = mean(mean_scores)`: a node with 10
edges at 0.8 average score has `risk_mass = 8.0` and a node with 1 edge at 0.82 has
`risk_mass = 0.82`. The node with 10 edges is far more suspicious even though its per-edge score
is slightly lower. `mean_incident_score` and `risk_mass` together let analysts filter by either
dimension.

`safe_ip_private` (lines 211–215):
```python
def safe_ip_private(value: str) -> bool | None:
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return None
```

Real-world IPs from network captures can be malformed, truncated (e.g., "192.168"), or IPv6
scoped addresses that `ipaddress` rejects. Returning `None` on failure instead of raising means
the graph enrichment never crashes on a bad IP string — the `is_private` field becomes nullable.

### Step 5 — Flow back-annotation (lines 389–401)

```python
working["cluster_endpoint_count"] = working["cluster_id"].map(cluster_map["endpoint_count"])
working["src_endpoint_degree"] = working[src_ip_column].astype(str).map(node_map["edge_count"])
working["dst_endpoint_degree"] = working[dst_ip_column].astype(str).map(node_map["edge_count"])
...
```

Every suspicious flow row gets 13 new columns describing its cluster and its source/destination
endpoints. This back-annotation is what makes `suspicious_flows.csv` useful for an analyst: you
can sort by `cluster_suspicious_flow_count` descending to find the highest-risk campaigns, then
by `src_endpoint_degree` to find the most active C2 servers in that cluster.

`node_map = nodes.set_index("endpoint")[["edge_count", ...]]` builds an index-aligned lookup
table. `working[src_ip_column].astype(str).map(node_map["edge_count"])` performs a vectorized
lookup — faster than `apply(lambda x: node_map.loc[x, "edge_count"])` by roughly 10×.

---

## 10. `compute_stage_metrics` — Lines 185–208

```python
tn, fp, fn, tp = confusion_matrix(y_true_series, y_pred_series, labels=[0, 1]).ravel()
metrics = {
    "accuracy": ...,
    "precision": ...,
    "recall": ...,
    "f1": ...,
    "specificity": float(tn / (tn + fp)) if (tn + fp) else 0.0,  # hand-computed
    "balanced_accuracy": ...,
    "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
}
if y_score is not None and len(pd.Series(y_true_series).unique()) == 2:
    metrics["roc_auc"] = ...
    metrics["average_precision"] = ...
```

`specificity = TN / (TN + FP)` — also called True Negative Rate. sklearn does not have a
`specificity_score` function (it provides `recall_score` for the positive class only). Hand-
computing from the confusion matrix ravel is the standard workaround. In a detection context,
specificity is as important as recall: a system with 99% recall and 1% specificity will flag
every benign flow as suspicious.

`labels=[0, 1]` in `confusion_matrix` forces the output order to always be `[TN, FP, FN, TP]`
regardless of which label appears first in the data. Without this, if a batch of test data
happens to have no label-0 rows, `.ravel()` would return a 1×1 matrix and the unpacking would
fail or produce garbage.

The AUC guard `len(pd.Series(y_true_series).unique()) == 2` prevents `roc_auc_score` from
raising when a batch has only one class present — this can legitimately happen if you run the
detection on a small clean dataset where all flows are benign.

---

## 11. Output Artifacts

`run_multitier_detection` writes 8 files to `output_dir`:

| File | What it contains |
|---|---|
| `tiered_flow_scores.csv` | Every row from the input, with all scoring columns appended |
| `tier1_candidates.csv` | Rows where `tier1_pass=True` (GNB flagged) |
| `suspicious_flows.csv` | Rows where `tier2_pass=True` + 13 graph annotation columns |
| `graph_nodes.csv` | One row per suspicious IP endpoint with degree/risk statistics |
| `graph_edges.csv` | One row per suspicious IP pair with flow count and scores |
| `suspicious_clusters.csv` | One row per connected component (campaign) |
| `cluster_window_summary.csv` | Cluster × time-window cross-tab |
| `graph_bundle.json` | Nodes + edges + clusters as JSON for visualization tools |
| `stage_metrics.json` | Tier 1 and Tier 2 performance metrics (empty if no ground truth) |
| `workflow_summary.json` | Row counts, rates, top 10 clusters, metrics pointer |

`tiered_flow_scores.csv` is the complete audit trail. Every input row is present; nothing is
dropped. This makes the file large but means an analyst can always go back and ask "why did this
flow get a 0.23 GNB score?"

---

## 12. The Full Scoring Pipeline

```
canonical_dataset.csv  (N rows, 80 features + metadata)
         │
         ▼
align_inference_frame   ← reindex to feature_manifest.json columns, NaN fill, bool→int
         │
         ▼
GaussianNB.predict_proba[:, 1] ≥ tier1_threshold
         │
    ┌────┴────┐
  pass      fail  → alert_level="none", no Tier 2 scoring
    │
    ▼ (subset, typically 1–10% of rows)
RF.predict_proba[:, 1]  ┐
GB.predict_proba[:, 1]  ┘ → weighted_mean_scores → tier2_consensus_score
         │
         ├── consensus_score ≥ deep_consensus_threshold → tier2_consensus_pass
         └── count(model_pass) ≥ min_deep_model_passes → tier2_pass_count pass
                  │
             tier2_pass = tier1_pass AND (count_pass OR consensus_pass)
                  │
             assign_alert_level → "candidate" / "medium" / "high"
                  │
                  ▼ (tier2_pass rows only)
         build_graph_enrichment
              ├── canonical edges → build_connected_components (BFS)
              ├── cluster statistics
              └── back-annotate suspicious_flows with 13 cluster/node columns
```

---

## 13. Interview Questions and Answers

**Q: Why does Tier 1 use GaussianNB rather than a threshold on a single feature?**

A: A threshold on a single feature (e.g., `dst2src_bytes > 10MB`) is brittle — malware adapts.
GaussianNB uses all features simultaneously, modeling the joint probability under a Gaussian
assumption. It is wrong about feature independence but surprisingly effective as a screener
because it requires the flow to look benign *across all dimensions simultaneously*. A single
suspicious feature dimension shifts the posterior enough to pass the threshold even if 79 other
features look normal.

---

**Q: Why is `tier2_consensus_score` NaN for rows that fail Tier 1, rather than 0?**

A: NaN semantically means "not computed" — the model was never run on this row. 0 means
"computed and the score is 0 (very benign)." If you set NaN to 0, a downstream query like
`suspicious_flows[suspicious_flows["tier2_consensus_score"] > 0.3]` would correctly return no
Tier-1-failed rows, but a statistical summary (mean, histogram) of `tier2_consensus_score`
across all rows would be polluted by 45,000 artificial zeros. Keeping NaN ensures that any
summary computed on `tier2_consensus_score` reflects only the population it was actually scored
on.

---

**Q: What does `min_suspicious_flows` in `build_graph_enrichment` actually control?**

A: It is the edge-level filter: an edge (IP pair) must have at least N suspicious flows to be
included in the graph. Setting it to 1 (the default) includes all edges, including coincidental
single flows. Setting it to 5 removes noise edges and makes the graph represent only persistent
communication channels. Critically, this filter is applied *before* the BFS — edges below the
threshold are excluded from the connectivity graph entirely, so a low-flow noisy edge does not
bridge two otherwise-disconnected clusters. This is the difference between "any IP pair that
appeared once" and "persistent channels that warrant investigation."

---

**Q: Why does `build_connected_components` sort the adjacency dictionary before iterating?**

A: Python dict insertion order is deterministic within a run but depends on the order flows were
read from the CSV. If two analysts run the same detection on the same data but in a different
row order (e.g., after a shuffle), they would get different cluster IDs without sorting —
`cluster_0000` in one run and `cluster_0003` in another for the same campaign. Sorting by
endpoint IP string before BFS makes cluster IDs reproducible across runs, which matters for
alerting systems that track cluster IDs over time.

---

**Q: What is `risk_mass` and when do you prefer it over `mean_incident_score`?**

A: `risk_mass = sum(mean_consensus_scores across all edges involving this node)`. It is the total
accumulated suspicious evidence at an endpoint, not the average. Consider two nodes:
- Node A: 1 edge, mean score 0.92
- Node B: 20 edges, mean score 0.71

Node A has higher `mean_incident_score` (0.92 vs 0.71), but Node B has higher `risk_mass`
(14.2 vs 0.92). Node B is a hub in a large botnet even though any single edge looks less
suspicious. `mean_incident_score` helps you find high-confidence individual connections;
`risk_mass` helps you find coordinated campaigns with many moderate-confidence flows.

---

*Next: [Tutorial 21 — FastAPI Backend](21_api_backend.md)*
