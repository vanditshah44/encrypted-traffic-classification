# Tutorial 28 — Scoring Function (`backend/scoring.py`)

## Prerequisites

- Tutorial 16 (`pipeline/malicious.py`) — `run_malicious_pipeline` is the first stage called by
  `run_pcap_scoring_job`. Its return dict structure (`pipeline.artifacts.merged_csv` etc.) is
  parsed here.
- Tutorial 17 (`pipeline/canonical.py`) — `BASE_METADATA_COLUMNS`, `_build_window_columns`,
  `_load_quality_failed`, `derive_protocol_family`, `derive_quality_status` are all imported
  here. `build_scoring_dataset` is the inference-time twin of canonical dataset construction.
- Tutorial 20 (`detection/multitier.py`) — every function imported from `multitier` is called
  inside `run_multitier_inference`. If you understand Tutorial 20, `run_multitier_inference`
  is the glue that drives those functions against a real inference dataset.
- Tutorial 29 (`backend/worker.py`) — the caller of `run_pcap_scoring_job`. The worker passes
  `ScoringRunResult.summary` directly into `job.summary_payload`.

---

## 1. Why This File Exists

The pipeline (Part 3, Tutorials 3–18) and the ML layers (Tutorials 19–20) were built for
batch dataset construction and training. At inference time the data flow is different: a single
uploaded PCAP must be processed, turned into a properly formatted dataset, scored, and its
results packaged for the API — all in one call from a worker process.

`scoring.py` bridges those two worlds. It contains no ML logic and no pipeline logic of its
own; it composes them in the order required for inference:

```
PCAP
 └─ run_malicious_pipeline   → merged Zeek+NFStream CSV
     └─ build_scoring_dataset  → metadata-augmented inference CSV
         └─ run_multitier_inference → tiered scores + graph bundle
             └─ run_pcap_scoring_job returns ScoringRunResult
```

---

## 2. `ScoringDatasetResult` and `ScoringRunResult` (lines 34–49)

```python
@dataclass(frozen=True)
class ScoringDatasetResult:
    dataset_csv: Path
    summary_json: Path
    summary: dict[str, Any]

@dataclass(frozen=True)
class ScoringRunResult:
    dataset_name: str
    workspace_dir: Path
    pipeline_output_dir: Path
    inference_output_dir: Path
    scoring_dataset_csv: Path
    platform_summary_json: Path
    summary: dict[str, Any]
```

Both are `frozen=True` receipts — immutable records of what was produced and where. `summary`
is the full parsed dict rather than just a path, because the worker needs to write it to
`ProcessingJob.summary_payload` without re-reading the file.

`ScoringRunResult.summary` is the `platform_summary` dict assembled at the end of
`run_pcap_scoring_job`. The worker stores it verbatim as `job.summary_payload`, which is then
serialised into `JobResponse.summary` by the services layer. The three count fields the worker
extracts (`tier2_suspicious_rows`, `tier1_candidate_rows`, `cluster_count`) are all inside this
dict under `inference_summary`.

---

## 3. `_record_id` (lines 52–54)

```python
def _record_id(dataset_name: str, source_row_index: int) -> str:
    basis = f"inference|{dataset_name}|{source_row_index}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()
```

Generates a deterministic, unique ID for each flow row in an inference dataset. The basis
string encodes three facts:

- `"inference"` — namespaces these IDs away from training `record_id` values. A training row
  from `canonical.py` uses `"canonical|capture_id|index"` as its basis. The namespace prevents
  any collision between training record IDs and inference record IDs.
- `dataset_name` — ties the ID to the specific submitted PCAP.
- `source_row_index` — the row's position in the filtered inference DataFrame.

Why SHA256 rather than a UUID? Determinism. If the same PCAP is submitted twice (e.g., a
re-score), the same flows get the same `record_id` values. This makes it possible to detect
duplicate scoring runs and to cross-reference flows across multiple submissions of the same
capture. A UUID would be different every run with no way to correlate.

---

## 4. `build_scoring_dataset` (lines 57–137)

This function does for inference what `pipeline/canonical.py` does for training: it takes a raw
merged CSV (Zeek + NFStream columns) and produces a fully-formed dataset with all the metadata
columns the multi-tier inference layer expects.

### Why this function must exist

`align_inference_frame` (Tutorial 20) selects only `feature_manifest.json`'s
`training_feature_columns` from the input DataFrame. But the full inference DataFrame also needs
metadata columns (`record_id`, `capture_id`, `protocol_family`, `window_id`, etc.) for:
- Graph enrichment: `src_ip`, `dst_ip`, `src_port`, `dst_port` are used by `build_graph_enrichment`
- Provenance: `quality_status`, `quality_report_path` allow the API to flag unreliable results
- Reporting: `protocol_family`, `window_id` appear in the scoring summary
- Deduplication and traceability: `record_id` is the stable per-flow identifier

Without this function, the output of `run_malicious_pipeline` would be fed directly to
`run_multitier_inference`, which would fail on missing columns.

### Protocol filtering (lines 72–76)

```python
    protocol_family = derive_protocol_family(df)
    is_encrypted = protocol_family.isin(["tls", "quic"])
    working = df[is_encrypted].copy().reset_index(drop=True)
    protocol_family = protocol_family[is_encrypted].reset_index(drop=True)
    is_encrypted = is_encrypted[is_encrypted].reset_index(drop=True)
```

Only TLS and QUIC flows are scored. Non-TLS/QUIC flows in the merged CSV (if any slipped
through the quality gates) are dropped here. The three `reset_index(drop=True)` calls are
critical: after boolean-indexing a DataFrame, the resulting index retains the original row
numbers (e.g., `[0, 2, 5, 7, ...]`). If left as-is, `source_row_index = pd.Series(range(len(working)))`
would produce `[0, 1, 2, 3, ...]` while `working.index` would still be `[0, 2, 5, 7, ...]`,
causing alignment errors when the metadata DataFrame is concatenated with `working`. Resetting
all three to `[0, 1, 2, ...]` ensures consistent row alignment.

### Metadata construction (lines 78–116)

```python
    quality_failed = _load_quality_failed(str(quality_report_json)) if quality_report_json else None
    quality_status = derive_quality_status(quality_failed)
    source_row_index = pd.Series(range(len(working)), dtype="int64")
    record_ids = [_record_id(dataset_name, int(index)) for index in source_row_index]
```

`_load_quality_failed` parses the quality report JSON written by `pipeline/quality.py`. If no
quality report exists (the pipeline ran with `allow_quality_failures=True` and produced no
report), `quality_failed` is `None` and `quality_status` becomes a series of `"unknown"`.

`record_ids` is a list comprehension over `source_row_index`. Each flow gets a deterministic
SHA256-based ID. The `int(index)` cast ensures `source_row_index` values are Python `int` when
passed to `_record_id`, not NumPy `int64` objects (which would produce a different `str()`
representation on some platforms).

```python
    "label": "",
    "label_id": pd.Series([pd.NA] * len(working), dtype="Int64"),
    "attack_family": "unknown",
    "attack_category": "unknown",
    "traffic_role": traffic_role,   # default "inference"
```

`label: ""` and `label_id: pd.NA` — the flow is unlabeled. This dataset will be passed to
the ML model for prediction, not for training. The model does not need a label; the label
columns are in the output only to match the schema expected by `align_inference_frame` and
downstream reporting. Using `pd.NA` rather than `-1` or `0` makes the absence of a label
explicit and avoids any risk of the model treating `0` as "benign" when scanning for
`label_id` values.

`dtype="Int64"` — pandas nullable integer type (capital I). Unlike `int64`, it supports `pd.NA`
as a missing value. Standard `int64` does not support `NA`; it would raise a `ValueError` when
constructing a series with `pd.NA`.

`traffic_role: "inference"` — distinguishes this data from training data (`"benign"` or
`"malicious"`). If inference output is ever mixed back into a training pipeline for active
learning or retraining, the `traffic_role` column identifies which rows came from live scoring.

### Column ordering and output (lines 117–137)

```python
    ordered_columns = BASE_METADATA_COLUMNS + [column for column in working.columns if column not in BASE_METADATA_COLUMNS]
    scored_df = pd.concat([metadata_df, working], axis=1)[ordered_columns]
```

`pd.concat([metadata_df, working], axis=1)` — horizontal concatenation. `metadata_df` has only
the metadata columns; `working` has the raw Zeek+NFStream feature columns. The concat produces
a DataFrame with both sets of columns side by side. The `[ordered_columns]` selector then
reorders: metadata columns first, then feature columns that aren't already in metadata. This
matches the column order of the canonical training dataset from Tutorial 17, which is required
for any tooling that reads both datasets by column position.

```python
    summary = {
        ...
        "quality_status": quality_status,
        ...
    }
```

`quality_status` here is the pandas Series, which `json.dumps` would fail on. But the summary
is written with `json.dumps(summary, indent=2)` — the `quality_status` field is assigned the
Series object directly to the dict. This would raise `TypeError: Object of type Series is not
JSON serializable` at `summary_path.write_text(json.dumps(...))`. Looking carefully at the
code, `quality_status` in the summary dict is the Series from `derive_quality_status(quality_failed)`.
This suggests that in practice `quality_report_json` is usually `None` (no quality report for
inference runs), making `quality_failed = None`, `quality_status = derive_quality_status(None)`.
`derive_quality_status(None)` returns a Series of `"unknown"` strings, but a Series is not
JSON serializable. The `summary` dict's `quality_status` field would fail. This is a minor bug
in the code — the summary field should be `quality_status.value_counts().to_dict()` or similar.
In practice, the `summary` is only used for the `ScoringDatasetResult.summary` field which is
embedded in `platform_summary`, and the worker stores the whole `platform_summary` in the DB
as a JSON column. The JSON serialization happens at `save_json(platform_summary, ...)` which
uses the same `json.dumps` call chain. If `quality_status` is a Series it would fail there.
The only safe path is if `quality_report_json` is always `None` for inference (making
`quality_failed = None` and `quality_status = derive_quality_status(None)` return a uniform
`"unknown"` Series), and the `summary` dict just stores the Series which is not actually
JSON-serialized in the `scoring_dataset_summary` path due to how `save_json` handles it.
Regardless, the `scored_df` is correctly written; the summary file path is separate.

---

## 5. `run_multitier_inference` (lines 140–273)

This function drives the multi-tier detection pipeline (Tutorial 20) end-to-end against a
single inference dataset. It mirrors what the `multi_tier_workflow.yaml` config drives in
batch mode, but directly in Python rather than through a config-driven runner.

### Feature alignment (lines 161–168)

```python
    df = pd.read_csv(dataset_path, low_memory=False)
    feature_columns = load_feature_columns(bundle_dir)
    X = align_inference_frame(df, feature_columns)
```

`load_feature_columns(bundle_dir)` reads `feature_manifest.json["training_feature_columns"]` —
the 53 features the model was trained on (from the actual manifest: `src_port`, `dst_port`,
`bidirectional_duration_ms`, etc.). `align_inference_frame` selects exactly those columns from
`df` and fills any missing columns with zeros. `X` is the feature matrix used by all models;
`df` is kept for metadata columns needed in output CSVs and graph enrichment.

### Tier 1 scoring (lines 170–178)

```python
    tier1_model = load_model(bundle_dir, tier1_model_name, use_optimized_thresholds=use_optimized_thresholds)
    tier1_probability = predict_model_probability(tier1_model, X)
    tier1_pass = pd.Series(tier1_probability >= tier1_model.threshold, index=df.index)
```

GaussianNB (the tier-1 model by default) scores all flows. `tier1_model.threshold` is the
CV-optimized threshold from `threshold_summary.json` when `use_optimized_thresholds=True`
(Tutorial 20). Flows where the probability exceeds this threshold are tier-1 candidates and
proceed to tier 2. All flows get `tier1_probability` and `tier1_pass` columns added to `scored`.

### Tier 2 scoring — only tier-1 candidates (lines 180–198)

```python
    stage2_index = scored.index[scored["tier1_pass"]]
    X_stage2 = X.loc[stage2_index] if len(stage2_index) else X.iloc[0:0]
```

`stage2_index` contains only the row indices that passed tier 1. If zero rows passed
(`len(stage2_index) == 0`), `X.iloc[0:0]` is an empty DataFrame with the same columns as `X`.
This defensive empty-frame assignment avoids calling `predict_model_probability` with an empty
index — while the prediction itself would return an empty array, having a typed empty DataFrame
ensures the subsequent `.loc[stage2_index]` operations behave predictably.

```python
        probabilities = pd.Series(np.nan, index=scored.index, dtype="float64")
        if len(stage2_index):
            probabilities.loc[stage2_index] = predict_model_probability(model, X_stage2)
        scored[score_column] = probabilities
```

Pre-filling with `np.nan` is the correct approach for a two-stage filter. Rows that did not
pass tier 1 are explicitly NOT scored by tier 2 — their probability should be `NaN`, not `0.0`.
A probability of `0.0` would imply the model scored the flow as "definitely benign", which is
wrong: the model was never run on those rows. `NaN` correctly signals "not evaluated".
Downstream, `scored[deep_pass_columns].fillna(False)` treats unscored rows as "did not pass",
which is the correct interpretation.

### Tier-2 consensus logic (lines 200–216)

```python
    required_deep_passes = min(min_deep_model_passes, len(deep_model_names)) if deep_model_names else 0
    scored["tier2_pass"] = scored["tier1_pass"] & (
        (scored["tier2_pass_count"] >= required_deep_passes) | scored["tier2_consensus_pass"].fillna(False)
    )
```

`min(min_deep_model_passes, len(deep_model_names))` — `min_deep_model_passes` defaults to 2,
meaning "require at least 2 deep models to agree". If only 1 deep model is available,
`min(2, 1) = 1`, so the requirement adjusts automatically. Without the `min()`, a bundle with
only 1 model would never produce `tier2_pass=True` because `pass_count >= 2` can never be true
with one model.

A flow is `tier2_pass` if AND ONLY IF:
1. It passed tier 1 (`scored["tier1_pass"]`), AND
2. Either enough individual models flagged it (`pass_count >= required_deep_passes`) OR the
   weighted mean consensus score exceeded `deep_consensus_threshold` (default 0.5)

The OR in condition 2 means a flow can pass tier 2 even if one model voted against it, as long
as the weighted average score exceeds the threshold. This prevents a single model from
single-handedly blocking a suspicious flow. The AND with `tier1_pass` means tier-2 suspicious
is always a strict subset of tier-1 candidates.

### Output files written (lines 225–253)

| File | Contents |
|---|---|
| `tiered_flow_scores.csv` | All flows with all tier scores and pass flags |
| `tier1_candidates.csv` | Only tier-1-passing rows |
| `suspicious_flows.csv` | Only tier-2-passing rows, with graph cluster annotations |
| `graph_nodes.csv` | IP/port nodes in the suspicion graph |
| `graph_edges.csv` | Connections between nodes |
| `suspicious_clusters.csv` | BFS-identified suspicious host clusters |
| `cluster_window_summary.csv` | Cluster activity per time window |
| `graph_bundle.json` | Nodes + edges + clusters as a single JSON for the frontend |
| `stage_metrics.json` | Empty dict `{}` — a placeholder for future per-stage metrics |
| `workflow_summary.json` | Counts, rates, cluster summary |

`save_json({}, target_dir / "stage_metrics.json")` — writes an empty JSON object. This file
exists so consumers of the output directory always find a `stage_metrics.json`, even before
per-stage metrics are implemented. A missing file causes `KeyError` in code that expects it;
an empty dict causes no error and returns `None` on `.get()` lookups.

### Summary construction (lines 256–272)

```python
    summary = {
        ...
        "tier1_candidate_rows": int(scored["tier1_pass"].sum()),
        "tier2_suspicious_rows": int(scored["tier2_pass"].sum()),
        "tier1_candidate_rate": float(scored["tier1_pass"].mean()) if len(scored) else 0.0,
        "tier2_suspicious_rate": float(scored["tier2_pass"].mean()) if len(scored) else 0.0,
        "required_deep_passes": int(required_deep_passes),
        "cluster_count": int(len(graph_outputs["clusters"])),
        "top_clusters": graph_outputs["clusters"].head(10).to_dict(orient="records"),
        ...
    }
```

`int(scored["tier1_pass"].sum())` — `.sum()` on a boolean Series returns a NumPy integer.
`int()` converts to a plain Python int, which is JSON-serialisable. Without the cast,
`json.dumps` would raise `TypeError` because NumPy integers are not JSON-serialisable by the
standard library encoder.

`if len(scored) else 0.0` — guards against division-by-zero when `scored` is empty (zero
TLS/QUIC flows in the PCAP). `.mean()` on an empty Series returns `NaN`, which is also not
JSON-serialisable.

`top_clusters` embeds the top 10 clusters inline in the summary so the API can display them
without the client needing to fetch the full `suspicious_clusters.csv`. `orient="records"`
produces `[{"cluster_id": 1, "size": 4, ...}, ...]`.

---

## 6. `run_pcap_scoring_job` (lines 276–343)

The top-level entry point called by the worker. Three stages in sequence:

### Stage 1 — Pipeline (lines 290–303)

```python
    pipeline_results = run_malicious_pipeline(
        dataset_name=dataset_name,
        input_pcap=input_pcap,
        output_dir=pipeline_output_dir,
        display_filter=display_filter,
        run_zeek=True,
        allow_quality_failures=allow_quality_failures,
    )
    nested_pipeline = pipeline_results.get("pipeline")
    if not isinstance(nested_pipeline, dict):
        raise RuntimeError("Pipeline stage did not return the expected artifact payload")
    artifacts = nested_pipeline.get("artifacts")
    if not isinstance(artifacts, dict) or "merged_csv" not in artifacts:
        raise RuntimeError("Pipeline results are missing merged_csv and artifact metadata")
```

`run_malicious_pipeline` (Tutorial 16) runs the full PCAP processing pipeline: editcap
sanitisation, tshark filtering, Zeek, NFStream, merge, quality gates. It returns a nested dict;
the actual artifact paths live under `results["pipeline"]["artifacts"]`.

The two `isinstance` guards validate the structure explicitly. If `run_malicious_pipeline`
returns an unexpected shape (e.g., a pipeline stage failed silently and returned `None`), the
error is surfaced immediately with a clear message rather than propagating as an `AttributeError`
deep inside `build_scoring_dataset`. The worker's `except` block catches this `RuntimeError`
and records it in `job.error_message`.

`"merged_csv" not in artifacts` — the minimum required artifact. Without the merged CSV, no
inference is possible. Other artifacts (`quality_report_json`, `provenance_json`) are optional
and accessed with `.get()` rather than direct key lookup.

### Stage 2 — Build inference dataset (lines 305–312)

```python
    scoring_dataset = build_scoring_dataset(
        merged_csv=artifacts["merged_csv"],
        output_csv=workspace / "scoring_dataset.csv",
        output_summary_json=workspace / "scoring_dataset_summary.json",
        dataset_name=dataset_name,
        quality_report_json=artifacts.get("quality_report_json"),
        provenance_json=artifacts.get("provenance_json"),
    )
```

The merged CSV from stage 1 becomes the input. `quality_report_json` and `provenance_json`
are passed through so the inference dataset records quality status and provenance lineage.
Both default to `None` if absent in the artifacts dict — `build_scoring_dataset` handles
`None` for each.

### Stage 3 — Multi-tier inference (lines 313–317)

```python
    inference_summary = run_multitier_inference(
        dataset_csv=scoring_dataset.dataset_csv,
        model_bundle_dir=model_bundle_dir,
        output_dir=inference_output_dir,
    )
```

All parameters use their defaults: `tier1_model_name="gaussian_nb"`,
`deep_model_names=("random_forest", "gradient_boosting")`, etc. The model bundle directory
is the one resolved by `resolve_model_bundle_dir` in the services layer before the job was
queued.

### Platform summary (lines 319–343)

```python
    platform_summary = {
        "dataset_name": dataset_name,
        "input_pcap": str(Path(input_pcap).expanduser().resolve()),
        ...
        "pipeline_quality_failed": bool(nested_pipeline.get("quality", {}).get("failed", False)),
        "pipeline_artifacts": artifacts,
        "scoring_dataset_summary": scoring_dataset.summary,
        "inference_summary": inference_summary,
    }
    summary_path = workspace / "platform_summary.json"
    save_json(platform_summary, summary_path)
```

`platform_summary` is the single authoritative record of what happened during this scoring
run. It nests the pipeline artifact paths, the scoring dataset summary, and the inference
summary. The worker stores it as `job.summary_payload`; the API exposes it as
`JobResponse.summary`. A consumer can reconstruct the full scoring history from this one dict.

`pipeline_quality_failed` is extracted with two `.get()` calls to avoid `KeyError` if the
`quality` key is absent. `bool(...)` ensures it is a JSON-serialisable Python bool rather than
a NumPy bool or `None`.

`str(Path(input_pcap).expanduser().resolve())` — canonicalises the input PCAP path to an
absolute resolved string for the summary. The worker may have passed a relative path or a path
with `~`; the summary always records the real, absolute path.

---

## 7. Workspace Directory Layout

After `run_pcap_scoring_job` completes, `workspace_dir` contains:

```
workspace_dir/
├── pipeline/               ← pipeline_output_dir
│   ├── filtered.pcap
│   ├── zeek_output/
│   ├── nfstream_output/
│   ├── merged.csv          ← artifacts["merged_csv"]
│   ├── quality_report.json
│   └── provenance.json
├── scoring/                ← inference_output_dir
│   ├── tiered_flow_scores.csv
│   ├── tier1_candidates.csv
│   ├── suspicious_flows.csv
│   ├── graph_nodes.csv
│   ├── graph_edges.csv
│   ├── suspicious_clusters.csv
│   ├── cluster_window_summary.csv
│   ├── graph_bundle.json
│   ├── stage_metrics.json
│   └── workflow_summary.json
├── scoring_dataset.csv     ← inference-ready dataset
├── scoring_dataset_summary.json
└── platform_summary.json   ← job.summary_payload
```

`upload_output_artifacts` (Tutorial 27) walks this entire workspace recursively and uploads
every file to object storage, except for the files under `pipeline/` — only `workspace / "run"`
is passed as `output_root` in the worker, not the full workspace. This means the raw pipeline
intermediates (filtered PCAP, Zeek logs, etc.) are not uploaded by default, keeping artifact
storage lean.

---

## 8. Interview Questions and Answers

**Q: Why does `build_scoring_dataset` exist rather than feeding the merged CSV directly to
`run_multitier_inference`?**

A: `run_multitier_inference` calls `align_inference_frame`, which selects only the feature
columns from `feature_manifest.json`. But the scoring pipeline also needs metadata columns —
`src_ip`, `dst_ip`, `capture_id`, `window_id`, `record_id` — for graph enrichment, reporting,
and provenance. The merged CSV from `run_malicious_pipeline` has these as raw Zeek/NFStream
columns but lacks the canonical metadata structure (windowing, `record_id`, `quality_status`,
`traffic_role`). `build_scoring_dataset` adds that metadata layer, producing a dataset whose
column schema exactly matches the canonical training data and which is safe to pass to any code
expecting that schema.

---

**Q: Why are tier-2 model probabilities pre-filled with `np.nan` rather than `0.0` for rows
that did not pass tier 1?**

A: `0.0` would imply the model evaluated the flow and assigned it a zero probability of being
malicious — "definitely benign." That is incorrect: those rows were never evaluated. `np.nan`
correctly represents "not evaluated". Downstream, `fillna(False)` treats them as "did not
pass," which is the right interpretation. If `0.0` were used and the consensus threshold were
very low, rows that bypassed tier 1 could accidentally accumulate a non-zero `tier2_consensus_score`
from the `fillna(0.0)` that would happen in some downstream aggregations.

---

**Q: What guarantees that `tier2_pass` is always a strict subset of `tier1_pass`?**

A: The expression `scored["tier2_pass"] = scored["tier1_pass"] & (...)`. The `&` with
`tier1_pass` makes `tier2_pass` logically impossible to be `True` for any row where
`tier1_pass` is `False`. This is by design: tier 2 is a deeper investigation of candidates,
not an independent parallel filter. A flow that GaussianNB rates as "probably benign" is not
worth the computation cost of RF and GradientBoosting.

---

**Q: Why are the two `isinstance` checks in `run_pcap_scoring_job` important, and what would
happen without them?**

A: `run_malicious_pipeline` can return partial results if a stage fails silently (e.g., quality
gate failures when `allow_quality_failures=True`). Without the `isinstance` checks, accessing
`nested_pipeline.get("artifacts")` on a non-dict value would raise `AttributeError: 'NoneType'
object has no attribute 'get'`, and `artifacts["merged_csv"]` on a missing dict would raise
`KeyError`. Both errors would be caught by the worker's `except Exception as exc` block and
recorded in `job.error_message`, but the message would be cryptic. The explicit
`RuntimeError("Pipeline results are missing merged_csv...")` provides a diagnostic message
that tells the operator exactly what went wrong.

---

**Q: Why does `_record_id` namespace with `"inference|"` rather than letting the hash stand
alone?**

A: The canonical pipeline (Tutorial 17) also generates `record_id` hashes for training data,
using a similar basis string. Without a namespace prefix, a training flow with
`("my_capture", 42)` and an inference flow with the same `dataset_name` and `source_row_index`
would produce identical `record_id` hashes. Mixing training and inference records with identical
IDs in any downstream store or analytics layer would create silent data corruption. The
`"inference|"` prefix is a namespace that guarantees the two ID spaces never overlap.

---

*Next: [Tutorial 29 — Worker Process](29_backend_worker.md)*
