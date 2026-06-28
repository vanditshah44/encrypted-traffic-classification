# Tutorial 02 — Configuration System

**Primary files:**
- `configs/base.yaml`
- `configs/dev.yaml`
- `configs/prod.yaml`
- `configs/canonical_sources.yaml`
- `configs/ml_workflow.yaml`
- `configs/multi_tier_workflow.yaml`
- `configs/backend.env.example`

**Code that reads configs:**
- `src/tls_dataset/pipeline/canonical.py` — reads `canonical_sources.yaml`
- `src/tls_dataset/ml/workflow.py` — reads `ml_workflow.yaml`
- `src/tls_dataset/detection/multitier.py` — reads `multi_tier_workflow.yaml`
- `src/tls_dataset/backend/config.py` — reads environment variables from `.env`

**Prerequisite:** Tutorial 01 (Setup & Installation)

---

## 1. How Configuration Is Structured in This Project

There are **two separate configuration systems** in this project. Understanding which
one applies where is the first thing to get right:

```
System 1: YAML files (configs/*.yaml)
─────────────────────────────────────
Used by: Pipeline, ML workflow, multi-tier detection
Read by: yaml.safe_load() inside each module
Passed via: --config argument on the CLI
Scope: offline batch work — data processing, training, scoring

System 2: Environment variables (configs/backend.env.example → .env)
──────────────────────────────────────────────────────────────────────
Used by: Backend platform (FastAPI, worker, queue, storage)
Read by: os.environ.get() inside backend/config.py
Passed via: shell environment or a .env file loaded at startup
Scope: online service work — the live API and worker
```

These two systems never overlap. The YAML files are for the pipeline.
The environment variables are for the backend service.

---

## 2. The YAML Hierarchy: `base`, `dev`, `prod`

### `configs/base.yaml` — Environment-Agnostic Defaults

```yaml
project:
  name: tls-dataset
  environment: base
```

**What it is:** The root configuration — values that are true regardless of whether
you're developing locally or running in production.

**`project.name`** — the logical name of the project. Not used programmatically in code
(the package name comes from `pyproject.toml`), but provides a self-describing label
in the config file and in any tooling that reads it.

**`project.environment`** — marks which environment this config belongs to. Here it's
`base`, meaning "not yet environment-specific". `dev.yaml` overrides this to `dev`,
`prod.yaml` overrides it to `prod`.

---

```yaml
architecture:
  official_extraction_stack:
    protocol_metadata: zeek
    flow_statistics: nfstream
  legacy_research_only:
    - cicflowmeter
  rationale:
    - Zeek is the authoritative source for TLS 1.3 and QUIC protocol-aware metadata.
    - NFStream is the authoritative source for bidirectional flow statistics and SPLT-style features.
    - CICFlowMeter is excluded from the production path to avoid thesis-code drift and duplicate extraction pipelines.
```

**This block is documentation-as-config.** No Python code reads
`config["architecture"]["rationale"]` to make a decision. Its purpose is to encode the
architecture decision (ADR 0001) directly inside the configuration file so that anyone
who opens this file — not just the code — understands what tools are official.

This mirrors the same decision in:
- `src/tls_dataset/technical_direction.py` (Python code)
- `docs/adr/0001-feature-extraction-stack.md` (prose)
- `README.md` (user-facing)

Three representations of the same fact. Redundancy is intentional here — it makes the
decision impossible to miss.

---

```yaml
paths:
  raw_data_dir: data/raw
  processed_data_dir: data/processed
  models_dir: artifacts/models
  reports_dir: artifacts/reports
  metrics_dir: artifacts/metrics
  temp_dir: artifacts/tmp
```

**Declared base paths.** These are reference paths — where raw data lives, where
processed data goes, where models are saved. Individual pipeline runs use more specific
paths built from `DatasetArtifacts` (covered in Tutorial 03), but this block
establishes the top-level directory conventions.

**Note:** In practice, the pipeline overrides these via CLI arguments (`--output-dir`).
These base paths matter most if a future configuration loader merges `base.yaml` with
`dev.yaml` or `prod.yaml` and applies the merged result — for now they serve as
documented conventions.

---

```yaml
logging:
  level: INFO
  structured: true
```

- **`level: INFO`** — the base log verbosity. `INFO` means only informational messages
  and above (WARNING, ERROR, CRITICAL) are shown. Debug-level messages are suppressed.
- **`structured: true`** — signals that logs should be emitted as structured data
  (e.g., JSON lines) rather than human-readable plain text. Structured logs are
  parseable by log aggregators (Splunk, Elasticsearch, Grafana Loki).

**`dev.yaml` overrides this** to `level: DEBUG` and `structured: false` — because
developers need verbose plain-text logs, not machine-readable JSON.

---

```yaml
pipeline:
  protocols:
    - tls13
    - quic
  extractors:
    - zeek
    - nfstream
  join_tolerance_seconds: 2.0
  min_packets_per_flow: 3
  min_duration_ms: 1
```

**`protocols`** — the target protocols. Only TLS 1.3 and QUIC flows are relevant to
the project. This list documents which protocols are in scope.

**`extractors`** — mirrors the architecture decision. Both Zeek and NFStream are used.
The order matters conceptually: Zeek first (protocol metadata), NFStream second
(flow statistics).

**`join_tolerance_seconds: 2.0`** — **this is the most operationally important value
in the pipeline.** When merging Zeek logs with NFStream output (Tutorial 08), the merge
key is the 4-tuple `(src_ip, dst_ip, src_port, dst_port)` plus a timestamp. Zeek
timestamps and NFStream timestamps are both millisecond-precision, but they can differ
slightly because:
- Zeek timestamps the connection when it *detects* the session
- NFStream timestamps the flow when the *first packet* is seen

A 2-second tolerance window means: if the timestamps differ by less than 2 seconds,
they are treated as the same flow for join purposes. Too tight → legitimate flows go
unmatched. Too loose → wrong flows get merged together.

The CLI `--merge-tolerance-sec` argument overrides this at runtime with a default of
`2.0`, matching this config.

**`min_packets_per_flow: 3`** — flows with fewer than 3 packets are discarded. A
1-packet flow has no bidirectional statistics and is likely a probe or handshake
fragment, not a real session.

**`min_duration_ms: 1`** — flows under 1 millisecond are discarded. Sub-millisecond
flows are noise.

---

```yaml
modeling:
  primary_metric: f1
  cross_validation_folds: 5
  random_seed: 42
```

**`primary_metric: f1`** — the F1 score is the primary metric for model selection and
threshold optimisation. F1 is the harmonic mean of precision and recall. It is chosen
over accuracy because the dataset is imbalanced (30,172 malicious vs 18,986 benign) —
a model that predicts "malicious" for everything would have high accuracy but zero
utility.

**`cross_validation_folds: 5`** — 5-fold stratified cross-validation. The training set
is split into 5 equal parts; the model trains on 4 and validates on 1, rotating 5
times. This gives a robust estimate of generalisation performance without touching the
test set.

**`random_seed: 42`** — the random seed for train/test splitting, model initialisation,
and cross-validation shuffling. Using a fixed seed makes results reproducible — running
the workflow twice gives identical results. `42` is conventional (a reference to
*The Hitchhiker's Guide to the Galaxy*), but the actual number doesn't matter as long
as it's consistent.

---

### `configs/dev.yaml` — Development Overrides

```yaml
project:
  environment: dev

logging:
  level: DEBUG
  structured: false

pipeline:
  sample_mode: true
```

**`project.environment: dev`** — overrides `base`. Code that checks the environment
(e.g., to decide whether to use SQLite vs PostgreSQL) sees `dev`.

**`logging.level: DEBUG`** — overrides `INFO`. In development you want to see every
debug message — each step the pipeline takes, each file it reads, each quality check
it runs.

**`logging.structured: false`** — overrides `true`. In a terminal during development,
structured JSON logs are unreadable. Plain human-readable text is far more useful.

**`pipeline.sample_mode: true`** — a flag signalling that the pipeline should operate
on a subset of data rather than the full dataset. Useful during development to get
fast feedback without waiting for full-dataset extraction. **However, in the current
implementation this flag is declared in the config but pipeline code reads `sample_mode`
only if explicitly implemented — it is a design placeholder for future development.**

---

### `configs/prod.yaml` — Production Overrides

```yaml
project:
  environment: prod

logging:
  level: INFO
  structured: true

pipeline:
  sample_mode: false
```

**`project.environment: prod`** — production environment. The backend `config.py` uses
`TLS_BACKEND_ENV` (not this YAML) to determine environment, but this file provides a
YAML-level signal for any pipeline code that checks environment.

**`logging.level: INFO`** — matches the base. In production you don't want debug noise.

**`logging.structured: true`** — matches the base. Production logs go to a log
aggregator that expects structured JSON.

**`pipeline.sample_mode: false`** — full dataset, no sampling. Production processes
all data.

---

## 3. `configs/canonical_sources.yaml` — The Dataset Builder Config

This is the most operationally critical YAML file. It is the only place where the
pipeline is told **which CSVs contain which data and what labels to assign them**.

```yaml
version: 1
window_size_ms: 60000
```

**`version: 1`** — a schema version number. If the config format ever changes
incompatibly, bumping this allows the code to detect old configs and fail gracefully
with a clear message instead of silently misbehaving.

**`window_size_ms: 60000`** — the default time window size in milliseconds. 60,000 ms
= **60 seconds = 1 minute**. Flows are grouped into 1-minute windows for time-series
analysis and graph enrichment. The `canonical.py` code uses this to compute `window_id`
columns: each flow is assigned to the 1-minute bucket it falls into relative to the
earliest flow in that capture.

**How window IDs are computed (from `canonical.py:_build_window_columns`):**
```python
baseline_ms = int(valid_flow_start.min())   # earliest flow timestamp
bucket_index = (flow_start - baseline_ms) // window_size_ms
window_id = f"{capture_id}:w{bucket_index:06d}"
```

A flow at minute 0 gets `w000000`, at minute 1 gets `w000001`, etc. This creates
time-stamped buckets for both training and detection visualisations.

---

```yaml
sources:
  - name: benign_lab_nfstream
    input_csv: benign_process_csv/benign_nfstream.csv
    source_dataset: hdbw_lab_benign
    capture_id: benign_filtered_primary
    label: benign
    attack_family: benign
    attack_category: none
    traffic_role: user_activity
    feature_view: nfstream
    encrypted_only: true
    extra_labels:
      environment: lab
      collection_origin: thesis_workspace
```

Each entry in `sources` becomes a `CanonicalSource` dataclass instance in
`canonical.py`. Here is every field:

| Field | Value | Meaning |
|-------|-------|---------|
| `name` | `benign_lab_nfstream` | A unique identifier for this source entry. Used as `source_name` in the output CSV. Must be unique across all sources. |
| `input_csv` | `benign_process_csv/benign_nfstream.csv` | Path to the NFStream CSV to load. Resolved relative to the project root. This is the pre-processed benign traffic NFStream output. |
| `source_dataset` | `hdbw_lab_benign` | A logical dataset name that groups multiple captures under the same study/origin. Becomes the `source_dataset` column in the canonical CSV. |
| `capture_id` | `benign_filtered_primary` | A unique ID for this specific capture. Used in `window_id` construction: `benign_filtered_primary:w000042`. |
| `label` | `benign` | The ground-truth class label. Mapped to `label_id=0` by `LABEL_TO_ID` dict in `canonical.py`. Only `benign` and `malicious` are currently supported. |
| `attack_family` | `benign` | Sub-classification of the attack type. For benign traffic this is also `benign`. For malicious traffic it could be `botnet`, `ransomware`, etc. |
| `attack_category` | `none` | Even finer-grained classification: `none` for benign, `c2_exfil` (command-and-control / data exfiltration) for the malicious source. |
| `traffic_role` | `user_activity` | Semantic role description — `user_activity` for benign, `adversarial_activity` for malicious. |
| `feature_view` | `nfstream` | Which extractor produced this CSV. Currently always `nfstream` for both sources (NFStream is the feature source; Zeek contributes via the merge step). |
| `encrypted_only` | `true` | If `true`, `canonicalize_source()` filters the loaded DataFrame to only rows where `protocol_family` is `tls` or `quic`. Removes any residual non-encrypted flows that survived the pipeline's tshark filter. |
| `extra_labels` | `{environment: lab, collection_origin: thesis_workspace}` | Arbitrary key-value pairs appended as extra columns to every row from this source. Used to add source-specific metadata without modifying the base schema. |

---

```yaml
  - name: malicious_ctu_nfstream
    input_csv: artifacts/runs/malicious_full_v2/malicious_full_v2_nfstream.csv
    source_dataset: ctu_botnet_tls_filtered
    capture_id: malicious_ready_primary
    label: malicious
    attack_family: botnet
    attack_category: c2_exfil
    traffic_role: adversarial_activity
    feature_view: nfstream
    encrypted_only: true
    quality_report_json: artifacts/runs/malicious_full_v2/malicious_full_v2_quality_report.json
    provenance_json: artifacts/runs/malicious_full_v2/malicious_full_v2_provenance.json
    extra_labels:
      environment: public_dataset
      collection_origin: ctu_botnet
```

The malicious source has two additional fields:

**`quality_report_json`** — path to the quality gate report JSON generated by the
malicious pipeline run. `canonical.py` reads this file and checks the `"failed"` key
to set the `quality_status` column (`pass`, `fail`, or `unknown`). This provides
transparency: a row from a capture that failed quality gates is flagged so downstream
users know its provenance is questionable.

**`provenance_json`** — path to the provenance record (SHA256 hashes, tool versions,
source URLs). Stored as the `provenance_path` column in the canonical CSV. Not read
at build time — just the path is stored so analysts can trace any row back to its
origin.

**`attack_category: c2_exfil`** — command-and-control exfiltration. The CTU-13
dataset contains botnet traffic where infected hosts communicate with a C2 server and
exfiltrate data over TLS-encrypted channels.

**`source_dataset: ctu_botnet_tls_filtered`** — the CTU-13 dataset, filtered to TLS
traffic.

---

### How `canonical.py` consumes this config — the call chain

```
build_canonical_dataset(config_path=..., output_csv=..., output_summary_json=...)
    │
    ├── load_canonical_sources(config_path)
    │       reads YAML → default_window_size_ms
    │       iterates sources list → builds CanonicalSource dataclass per entry
    │
    ├── for each source: canonicalize_source(source)
    │       reads input_csv into DataFrame
    │       derive_protocol_family(df) → classifies each row as tls/quic/other
    │       if encrypted_only: filter to tls/quic rows only
    │       _load_quality_failed(quality_report_json) → reads quality report
    │       LABEL_TO_ID[source.label] → 0 or 1
    │       _build_window_columns(df, capture_id, window_size_ms)
    │           → flow_start_ms, flow_end_ms, window_id, window_start_ms, window_end_ms
    │       _build_record_id(source, row_index) → SHA256 hash of source+row
    │       assembles metadata_df with all BASE_METADATA_COLUMNS
    │       appends extra_labels columns
    │       pd.concat([metadata_df, df], axis=1) → one row = metadata + features
    │
    ├── pd.concat(all frames) → single DataFrame
    ├── sort by (capture_id, flow_start_ms, source_row_index)
    ├── reorder columns: BASE_METADATA_COLUMNS first, then extra_labels, then features
    ├── write to output_csv
    └── write summary JSON if requested
```

---

### `BASE_METADATA_COLUMNS` — the fixed schema (from `canonical.py`)

```python
BASE_METADATA_COLUMNS = [
    "record_id",         # SHA256 of source_dataset|capture_id|feature_view|row_index
    "sample_id",         # first 16 hex chars of record_id (shorter display ID)
    "label",             # "benign" or "malicious"
    "label_id",          # 0 (benign) or 1 (malicious)
    "attack_family",     # "benign", "botnet", etc.
    "attack_category",   # "none", "c2_exfil", etc.
    "traffic_role",      # "user_activity", "adversarial_activity"
    "capture_id",        # "benign_filtered_primary" or "malicious_ready_primary"
    "protocol_family",   # "tls", "quic", or "other"
    "window_id",         # "benign_filtered_primary:w000042"
    "flow_start_ms",     # epoch ms of first packet in flow
    "flow_end_ms",       # epoch ms of last packet in flow
    "window_start_ms",   # epoch ms of window bucket start
    "window_end_ms",     # epoch ms of window bucket end
    "source_dataset",    # "hdbw_lab_benign" or "ctu_botnet_tls_filtered"
    "source_name",       # "benign_lab_nfstream" or "malicious_ctu_nfstream"
    "feature_view",      # "nfstream"
    "source_row_index",  # original row number in the input CSV
    "quality_status",    # "pass", "fail", or "unknown"
    "quality_failed",    # True / False / None
    "quality_report_path", # path to quality report JSON
    "provenance_path",   # path to provenance JSON
    "input_csv",         # absolute path to the source CSV
    "is_encrypted",      # True if TLS or QUIC flow
]
```

Every row in `canonical_labeled_flows.csv` starts with these 23 columns, followed by
any `extra_labels` columns, followed by the actual NFStream feature columns.

---

## 4. `configs/ml_workflow.yaml` — The ML Training Config

```yaml
version: 1

dataset_csv: artifacts/canonical/canonical_labeled_flows.csv
output_dir: artifacts/ml_workflow/latest
target_column: label_id
label_column: label
record_id_column: record_id
positive_label: 1
test_size: 0.2
random_state: 42
cv_folds: 5
threshold_metric: f1
top_k_feature_importance: 20
extra_excluded_columns:
  - collection_origin
  - environment
```

**`version: 1`** — schema version, same convention as canonical sources.

**`dataset_csv`** — the input to the ML workflow. Always the canonical labeled CSV.

**`output_dir: artifacts/ml_workflow/latest`** — where trained models and metrics land.
The `latest/` convention means you always know where the most recent run's artifacts
are. If you wanted to keep history, you'd name runs with timestamps instead.

**`target_column: label_id`** — the column the model learns to predict. `label_id` is
numeric (0 or 1). The ML code needs a number, not the string "benign"/"malicious" — that
is why both columns exist in the canonical CSV.

**`label_column: label`** — the human-readable version of the target. Used for display
in classification reports and plots (shows "benign"/"malicious" labels instead of 0/1).

**`record_id_column: record_id`** — the unique identifier for each row. Excluded from
features (you cannot train on an ID — it would be pure data leakage).

**`positive_label: 1`** — which value of `label_id` is the "positive" (malicious) class.
This matters for precision, recall, F1, and ROC-AUC computations — sklearn needs to know
which class is "positive" to compute these correctly.

**`test_size: 0.2`** — 20% of the dataset is held out for final evaluation. 80% is used
for training and cross-validation. With 49,158 rows: 9,832 test rows, 39,326 training
rows.

**`random_state: 42`** — the random seed for `train_test_split` and cross-validation.
Same value as `base.yaml`. Makes every run produce the exact same train/test split.

**`cv_folds: 5`** — 5-fold stratified cross-validation on the training set.
Stratified means each fold has the same class ratio (roughly 38% benign / 62% malicious)
as the original dataset.

**`threshold_metric: f1`** — the metric used to find the optimal decision threshold.
After training, the workflow sweeps decision thresholds from 0 to 1 and picks the one
that maximises F1 on the cross-validation predictions. This is stored in
`threshold_summary.json` and used by the multi-tier detector.

**`top_k_feature_importance: 20`** — report the top 20 most important features.
Both native feature importance (from tree models) and permutation importance are
computed and stored. The top 20 are printed and saved to JSON.

**`extra_excluded_columns`:**
```yaml
extra_excluded_columns:
  - collection_origin
  - environment
```
These are the `extra_labels` columns from `canonical_sources.yaml`. They are excluded
from model features because:
- `collection_origin` is `thesis_workspace` for benign and `ctu_botnet` for malicious
- `environment` is `lab` for benign and `public_dataset` for malicious

If the model trained on these columns it would learn "ctu_botnet → malicious" and
"lab → benign" — perfect label leakage. The model would fail completely on any new
PCAP that doesn't come from CTU or the thesis lab.

**How `workflow.py` builds the `WorkflowConfig` from this YAML:**

```python
def load_workflow_config(config_path: str | Path) -> WorkflowConfig:
    payload = _load_yaml(config_path)
    permutation = payload.get("permutation_importance", {}) or {}
    models = payload.get("models", {}) or {}
    return WorkflowConfig(
        dataset_csv=str(payload["dataset_csv"]),
        output_dir=str(payload["output_dir"]),
        target_column=str(payload.get("target_column", "label_id")),   # default if missing
        positive_label=int(payload.get("positive_label", 1)),
        test_size=float(payload.get("test_size", 0.2)),
        random_state=int(payload.get("random_state", 42)),
        cv_folds=int(payload.get("cv_folds", 5)),
        threshold_metric=str(payload.get("threshold_metric", "f1")),
        extra_excluded_columns=tuple(str(v) for v in payload.get("extra_excluded_columns", [])),
        ...
    )
```

Notice the pattern: `payload.get("key", default)` — every field has a fallback.
The YAML file is optional in the sense that if you omit a key, the code uses a sensible
default. The only required key is `dataset_csv` (used as `payload["dataset_csv"]`
with no default, so it raises `KeyError` if missing).

---

```yaml
permutation_importance:
  n_repeats: 5
  scoring: roc_auc
  max_samples: 4000
```

Permutation importance works by: randomly shuffling one feature column, measuring how
much the model's score drops, then restoring it. Features that cause a big drop when
shuffled are important. Features whose shuffling barely changes the score are unimportant
(or redundant with other features).

**`n_repeats: 5`** — shuffle each feature 5 times and average the importance. Multiple
repeats reduce variance in the estimate.

**`scoring: roc_auc`** — the metric used to measure the score drop. ROC-AUC is better
than accuracy for imbalanced datasets.

**`max_samples: 4000`** — permutation importance is expensive (n_features × n_repeats
model evaluations). Limit to 4,000 samples from the test set to keep it fast. With
`scikit-learn`'s `permutation_importance(max_samples=4000)`, a random 4,000-row subset
of the test set is used instead of all 9,832 test rows.

---

```yaml
models:
  gaussian_nb: {}
  random_forest:
    n_estimators: 300
    random_state: 42
    n_jobs: -1
    class_weight: balanced_subsample
  gradient_boosting:
    n_estimators: 200
    learning_rate: 0.05
    max_depth: 3
    random_state: 42
```

Each key under `models` corresponds to a model name. The value is a dict of
hyperparameters passed directly to the sklearn constructor.

**`gaussian_nb: {}`** — no hyperparameters. GaussianNB has very few tunable parameters.
It assumes features follow a Gaussian (normal) distribution within each class. It is
fast, interpretable, and gives probability outputs — ideal for Tier 1 screening.

**`random_forest`:**

| Param | Value | Why |
|-------|-------|-----|
| `n_estimators` | 300 | 300 decision trees in the ensemble. More trees → more stable predictions, slower training. 300 is a common balance. |
| `random_state` | 42 | Reproducibility. Random forest builds each tree on a random sample of data. |
| `n_jobs` | -1 | Use ALL CPU cores. `-1` in sklearn means "use all available processors." Random forest is embarrassingly parallelisable — 300 trees can be built on 300 threads simultaneously. |
| `class_weight` | `balanced_subsample` | Adjusts sample weights to compensate for class imbalance. `balanced_subsample` computes weights per bootstrap sample (each tree's training set) rather than globally. This helps the forest give equal attention to the minority class (benign, 38% of data). |

**`gradient_boosting`:**

| Param | Value | Why |
|-------|-------|-----|
| `n_estimators` | 200 | 200 boosting stages. Each stage adds one tree that corrects the errors of the previous stage. More stages → lower bias but higher overfitting risk. |
| `learning_rate` | 0.05 | How much each new tree's contribution is shrunk. Small learning rate (0.05) means you need more trees but get better generalisation. Standard trade-off: lower learning_rate → higher n_estimators. |
| `max_depth` | 3 | Each individual tree in the ensemble is limited to depth 3 (at most 8 leaf nodes). Shallow trees are "weak learners" — individually bad, but powerful when boosted. |
| `random_state` | 42 | Reproducibility. |

**How `workflow.py` builds models from these params:**

```python
def build_model_specs(config: WorkflowConfig) -> list[ModelSpec]:
    params = config.model_params   # dict from YAML
    specs = []
    if "gaussian_nb" in params:
        specs.append(ModelSpec(name="gaussian_nb", estimator=GaussianNB(**params["gaussian_nb"])))
    if "random_forest" in params:
        specs.append(ModelSpec(name="random_forest", estimator=RandomForestClassifier(**params["random_forest"])))
    if "gradient_boosting" in params:
        specs.append(ModelSpec(name="gradient_boosting", estimator=GradientBoostingClassifier(**params["gradient_boosting"])))
    return specs
```

The `**params["gaussian_nb"]` syntax unpacks the YAML dict as keyword arguments to the
sklearn constructor. For GaussianNB this is `GaussianNB()` (empty dict). For RandomForest
this is `RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1, class_weight="balanced_subsample")`.

---

## 5. `configs/multi_tier_workflow.yaml` — The Detection Config

```yaml
version: 1

dataset_csv: artifacts/canonical/canonical_labeled_flows.csv
model_bundle_dir: artifacts/ml_workflow/latest
output_dir: artifacts/multi_tier/latest
```

**`dataset_csv`** — the canonical labeled CSV. The multi-tier detector scores these
rows using the trained models.

**`model_bundle_dir: artifacts/ml_workflow/latest`** — the directory containing trained
model bundles. Each subdirectory (`gaussian_nb/`, `random_forest/`, `gradient_boosting/`)
must contain `model.joblib` and `feature_manifest.json`.

**`output_dir: artifacts/multi_tier/latest`** — where detection results land:
`graph_bundle.json`, `stage_metrics.json`, `alert_summary.json`.

---

```yaml
target_column: label_id
label_column: label
record_id_column: record_id
src_ip_column: src_ip
dst_ip_column: dst_ip
src_port_column: src_port
dst_port_column: dst_port
capture_id_column: capture_id
window_id_column: window_id
protocol_family_column: protocol_family
requested_server_name_column: requested_server_name
```

**Column name declarations.** The multi-tier detector needs to know which columns
contain which information. Rather than hardcoding column names inside Python functions,
they are externalised here so the system can be adapted to different CSV schemas without
code changes.

| Column key | Column name | Used for |
|-----------|-------------|---------|
| `target_column` | `label_id` | Ground-truth label for evaluation metrics |
| `label_column` | `label` | Human-readable label for display |
| `record_id_column` | `record_id` | Unique row identifier |
| `src_ip_column` | `src_ip` | Source IP address — used in graph node building |
| `dst_ip_column` | `dst_ip` | Destination IP address — used in graph node building |
| `src_port_column` | `src_port` | Source port |
| `dst_port_column` | `dst_port` | Destination port |
| `capture_id_column` | `capture_id` | Which capture this flow came from |
| `window_id_column` | `window_id` | Time window this flow belongs to |
| `protocol_family_column` | `protocol_family` | TLS / QUIC / other |
| `requested_server_name_column` | `requested_server_name` | SNI (TLS Server Name Indication) — the hostname the client wanted to connect to, extracted by Zeek |

---

```yaml
tier1_model_name: gaussian_nb
tier1_threshold: null
```

**`tier1_model_name: gaussian_nb`** — the Tier 1 fast screener uses GaussianNB. It is
deliberately the weakest model because Tier 1's job is high recall (don't miss any
malicious flow), not high precision (it's OK to flag some benign flows as suspicious
here — Tier 2 will filter them out).

**`tier1_threshold: null`** — `null` in YAML becomes `None` in Python. When `None`, the
code uses the **optimised threshold** found during the ML workflow (stored in
`threshold_summary.json` inside the model bundle). You can override this with an explicit
float (e.g., `0.3`) to use a custom threshold regardless of the optimised value.

---

```yaml
deep_model_names:
  - random_forest
  - gradient_boosting
deep_model_weights:
  random_forest: 1.0
  gradient_boosting: 1.0
deep_consensus_threshold: 0.5
min_deep_model_passes: 2
use_optimized_thresholds: true
```

**`deep_model_names`** — the two Tier 2 models. Both are loaded from the model bundle
directory. Their probability outputs are combined via weighted averaging.

**`deep_model_weights`** — both models have weight `1.0`. The weighted average score is:
```
score = (1.0 × rf_prob + 1.0 × gb_prob) / (1.0 + 1.0)
      = (rf_prob + gb_prob) / 2
```
If you trusted one model more, you could set its weight higher.

**`deep_consensus_threshold: 0.5`** — the threshold applied to the weighted average
score. A flow is flagged by Tier 2 if the average probability exceeds 0.5.

**`min_deep_model_passes: 2`** — **this is the most important safety parameter.** A
flow must be flagged by **at least 2 deep models** to be marked suspicious by Tier 2.
With 2 models, this means **both** must agree. This setting was added after the first
version produced one false positive — one benign flow was flagged by only the random
forest. Requiring consensus from both models eliminated that false positive.

How it works in code (`multitier.py`):
```python
# For each deep model, check if it individually exceeds its threshold
model_passes = sum(
    1 for model in deep_models
    if model_probability[model.name] >= model.threshold
)
# A flow is suspicious only if enough models agree
is_suspicious = (weighted_avg_score >= deep_consensus_threshold) and (model_passes >= min_deep_model_passes)
```

**`use_optimized_thresholds: true`** — use the optimised per-model thresholds from the
ML workflow (from `threshold_summary.json`). When `false`, use 0.5 for all models.

---

```yaml
cluster_min_suspicious_flows: 1
```

**`cluster_min_suspicious_flows: 1`** — a cluster in the endpoint graph must contain at
least 1 suspicious flow to be reported. Setting this to 1 means every cluster with any
suspicious flow is reported. Raising it to (say) 10 would only report clusters with
significant suspicious activity — useful for suppressing noise in production.

---

### How `multitier.py` builds `MultiTierConfig` from this YAML

```python
def load_multitier_config(config_path: str | Path) -> MultiTierConfig:
    payload = _load_yaml(config_path)
    deep_model_names = tuple(
        str(v) for v in payload.get("deep_model_names", ["random_forest", "gradient_boosting"])
    )
    return MultiTierConfig(
        dataset_csv=str(payload["dataset_csv"]),       # required, no default
        model_bundle_dir=str(payload["model_bundle_dir"]),  # required
        output_dir=str(payload["output_dir"]),              # required
        tier1_model_name=str(payload.get("tier1_model_name", "gaussian_nb")),
        tier1_threshold=float(payload["tier1_threshold"]) if payload.get("tier1_threshold") is not None else None,
        deep_consensus_threshold=float(payload.get("deep_consensus_threshold", 0.5)),
        min_deep_model_passes=int(payload.get("min_deep_model_passes", 1)),   # default is 1
        use_optimized_thresholds=bool(payload.get("use_optimized_thresholds", True)),
        cluster_min_suspicious_flows=int(payload.get("cluster_min_suspicious_flows", 1)),
        ...
    )
```

Note: `min_deep_model_passes` defaults to `1` in code but the YAML config sets it to
`2`. The YAML wins because the YAML value is explicitly set. If you deleted
`min_deep_model_passes` from the YAML, the code would fall back to `1` — a less safe
default. **This is a subtle but important difference between code defaults and config
values.**

---

## 6. `configs/backend.env.example` — The Backend Platform Config

This file is a **template**, not a real config. When deploying the backend, you copy
it to `.env` (which is gitignored) and fill in real values.

```bash
TLS_BACKEND_ENV=dev
```

**Environment name.** Read by `backend/config.py` as:
```python
environment=os.environ.get("TLS_BACKEND_ENV", "dev")
```
Default: `dev`. In production, set to `prod`.

---

```bash
TLS_BACKEND_DATABASE_URL=postgresql+psycopg://tls_dataset:tls_dataset@postgres:5432/tls_dataset
```

**SQLAlchemy database connection URL.** Format: `dialect+driver://user:password@host:port/database`.

- `postgresql+psycopg` — PostgreSQL database, accessed via the `psycopg` v3 driver
- `tls_dataset:tls_dataset` — username:password
- `postgres:5432` — hostname `postgres` (Docker Compose service name), port 5432
- `/tls_dataset` — database name

**Development default** (from `config.py` when this env var is missing):
```python
f"sqlite:///{(project_root / 'artifacts' / 'backend.sqlite3').as_posix()}"
```
SQLite file at `artifacts/backend.sqlite3`. No server needed — great for local
development without Docker.

---

```bash
TLS_BACKEND_QUEUE_BACKEND=rq
TLS_BACKEND_QUEUE_NAME=pcap_scoring
TLS_BACKEND_REDIS_URL=redis://redis:6379/0
```

**`TLS_BACKEND_QUEUE_BACKEND=rq`** — which queue backend to use.
- `rq` → Redis Queue (production). Jobs are enqueued in Redis, consumed by a worker
  process. Fully asynchronous.
- `inline` (dev default when env var absent) → jobs run synchronously in the same
  process as the API. No Redis needed. Useful for local testing.

**`TLS_BACKEND_QUEUE_NAME=pcap_scoring`** — the name of the Redis queue. The worker
listens on this queue. Multiple queues could exist (e.g., `high_priority`, `batch`).

**`TLS_BACKEND_REDIS_URL=redis://redis:6379/0`** — Redis connection URL.
- `redis://` — protocol
- `redis` — hostname (Docker Compose service name)
- `6379` — Redis default port
- `/0` — database index 0 (Redis supports multiple databases 0-15)

---

```bash
TLS_BACKEND_OBJECT_STORE_BACKEND=s3
TLS_BACKEND_OBJECT_STORE_BUCKET=tls-dataset
TLS_BACKEND_S3_ENDPOINT_URL=http://minio:9000
TLS_BACKEND_S3_REGION=us-east-1
TLS_BACKEND_S3_ACCESS_KEY_ID=minioadmin
TLS_BACKEND_S3_SECRET_ACCESS_KEY=minioadmin
```

**`TLS_BACKEND_OBJECT_STORE_BACKEND=s3`** — which storage backend.
- `s3` → S3-compatible (works with AWS S3 or MinIO). Used in Docker Compose stack.
- `local` (default when env var absent) → stores files in `artifacts/object_store/`
  on the local filesystem. No object storage server needed.

**`TLS_BACKEND_OBJECT_STORE_BUCKET=tls-dataset`** — the bucket name where artifacts
are stored. In MinIO, you create this bucket manually or via Docker init scripts.

**`TLS_BACKEND_S3_ENDPOINT_URL=http://minio:9000`** — the S3 API endpoint.
AWS S3 doesn't need this (it's the default). MinIO does because it's a custom server.
`minio` is the Docker Compose service name, `9000` is MinIO's S3-compatible API port.

**`TLS_BACKEND_S3_REGION=us-east-1`** — AWS region. For MinIO this is a dummy value
(MinIO doesn't use regions), but the boto3 client requires it.

**`TLS_BACKEND_S3_ACCESS_KEY_ID=minioadmin`** and
**`TLS_BACKEND_S3_SECRET_ACCESS_KEY=minioadmin`** — credentials for MinIO. These are
MinIO's default admin credentials for development. **In production, these should be
strong random values stored in a secrets manager, never in a config file.**

---

```bash
TLS_BACKEND_MODEL_BUNDLE_ROOT=/app/artifacts/ml_workflow
TLS_BACKEND_DEFAULT_MODEL_BUNDLE_DIR=/app/artifacts/ml_workflow/latest
```

**`TLS_BACKEND_MODEL_BUNDLE_ROOT`** — the root directory where trained model bundles
live. The registry (`backend/registry.py`) scans subdirectories of this path for
`model.joblib` + `feature_manifest.json` pairs.

**`TLS_BACKEND_DEFAULT_MODEL_BUNDLE_DIR`** — the specific bundle used when the API
caller doesn't specify a model. Points to `latest/` which contains the most recently
trained GaussianNB, RandomForest, and GradientBoosting bundles.

Note: `/app/...` is the Docker container path. The `Dockerfile` sets `WORKDIR /app` and
copies the project there.

---

```bash
TLS_BACKEND_JOB_RUN_ROOT=/app/artifacts/backend_jobs
```

**Where temporary job working directories are created.** Each scoring job gets its own
subdirectory: `/app/artifacts/backend_jobs/{job_id}/`. The pipeline runs there, and
outputs are uploaded to object storage from there.

---

```bash
TLS_BACKEND_SCORING_ALLOW_QUALITY_FAILURES=true
TLS_BACKEND_PCAP_DISPLAY_FILTER=tls or quic
```

**`TLS_BACKEND_SCORING_ALLOW_QUALITY_FAILURES=true`** — when scoring a user-uploaded
PCAP, should the pipeline continue even if quality gates fail? `true` in the example
because production uploaded PCAPs might not meet strict quality requirements (e.g.,
captures taken without controlled conditions). Setting to `false` would cause scoring
jobs to fail on poor-quality PCAPs.

The helper `_env_bool` in `config.py` parses this:
```python
def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
```
Accepts: `1`, `true`, `yes`, `on` (any case) as truthy. Anything else is falsy.

**`TLS_BACKEND_PCAP_DISPLAY_FILTER=tls or quic`** — the tshark display filter applied
to uploaded PCAPs before feature extraction. Keeps only TLS or QUIC packets. This is
the same filter used in the pipeline's `filtering.py`.

---

```bash
ZEEK_BIN=/opt/zeek/bin/zeek
```

**`ZEEK_BIN`** — full path to the Zeek binary. Zeek is not a Python package — it's an
external tool installed on the system. The pipeline's `zeek_runner.py` uses this to
find the Zeek executable. Without it, the runner falls back to searching `PATH` for
`zeek` or `zeek-runner`.

---

### How `backend/config.py` reads all of this — `get_backend_settings()`

```python
@lru_cache(maxsize=1)
def get_backend_settings() -> BackendSettings:
    project_root = Path(__file__).resolve().parents[3]
    ...
    return BackendSettings(
        environment=os.environ.get("TLS_BACKEND_ENV", "dev"),
        database_url=os.environ.get(
            "TLS_BACKEND_DATABASE_URL",
            f"sqlite:///{(project_root / 'artifacts' / 'backend.sqlite3').as_posix()}",
        ),
        queue_backend=os.environ.get("TLS_BACKEND_QUEUE_BACKEND", "rq"),
        ...
    )
```

**`@lru_cache(maxsize=1)`** — the settings object is computed once and cached. Every
call to `get_backend_settings()` after the first returns the exact same `BackendSettings`
instance. This means environment variables are read only once at startup — changing an
env var after the server starts has no effect.

**`clear_backend_settings_cache()`** — exists so tests can reset the cache between test
cases. A test might set `os.environ["TLS_BACKEND_DATABASE_URL"] = "sqlite:///:memory:"`,
call `clear_backend_settings_cache()`, and then get a fresh `BackendSettings` pointing
to the in-memory SQLite database.

**`BackendSettings` is a frozen dataclass:**
```python
@dataclass(frozen=True)
class BackendSettings:
    environment: str
    database_url: str
    ...
```

`frozen=True` means no field can be changed after creation. This prevents any code from
accidentally mutating the settings object at runtime — the configuration is immutable
once read.

---

## 7. Complete Config Map — What Each File Controls

```
configs/
│
├── base.yaml          Pipeline defaults: join_tolerance_seconds=2.0,
│                      cv_folds=5, random_seed=42, logging level, protocols
│
├── dev.yaml           Override: DEBUG logging, sample_mode=true
├── prod.yaml          Override: INFO logging, sample_mode=false
│
├── canonical_sources.yaml   ─────── read by pipeline/canonical.py
│                              Declares: which CSVs → which labels
│                              Controls: window_size_ms, encrypted_only,
│                                        attack_family, extra_labels
│
├── ml_workflow.yaml   ─────────────── read by ml/workflow.py
│                              Declares: train/test split, CV folds, threshold_metric
│                              Controls: which models, their hyperparameters,
│                                        which columns to exclude
│
├── multi_tier_workflow.yaml  ──────── read by detection/multitier.py
│                              Declares: tier1 model, tier2 models + weights
│                              Controls: consensus threshold, min_deep_model_passes,
│                                        cluster_min_suspicious_flows
│
└── backend.env.example  ────────────── read by backend/config.py via os.environ
                               Declares: database URL, Redis URL, S3 credentials,
                                         model paths, scoring behaviour
```

---

## 8. Interview Questions & Answers for Tutorial 02

**Q: Why are there two separate configuration systems (YAML files vs environment
variables) instead of one?**
> The YAML files configure offline batch work — data pipelines, ML training, detection
> runs — which have no runtime process. Environment variables configure the backend
> service — a running API server and worker — because services conventionally read their
> configuration from the environment (twelve-factor app principle). Environment variables
> are easy to override in Docker Compose, Kubernetes, and CI/CD without editing files.
> YAML is better for structured hierarchical config with comments, which suits
> complex pipeline parameters.

**Q: What is `min_deep_model_passes: 2` and why does it matter?**
> It requires that BOTH deep models (RandomForest and GradientBoosting) independently
> flag a flow as suspicious before Tier 2 marks it malicious. The first version used
> `min_deep_model_passes: 1` and produced one false positive — a benign flow flagged
> only by RandomForest. Raising it to 2 (requiring consensus from both models) eliminated
> that false positive entirely. It's the difference between "any model votes suspicious"
> and "all models agree."

**Q: What does `window_size_ms: 60000` control?**
> It groups flows into 60-second time windows for time-series analysis and graph
> enrichment. Each flow is assigned a `window_id` like `benign_filtered_primary:w000042`
> — the 42nd 60-second window since the capture started. This enables the graph
> enrichment layer to analyse suspicious activity across time windows, not just
> individual flows.

**Q: Why is `collection_origin` excluded from ML features?**
> Because it is `thesis_workspace` for benign traffic and `ctu_botnet` for malicious
> traffic — a perfect predictor of the label that has nothing to do with the actual
> network behaviour. A model trained on this feature would learn "if it came from CTU,
> it's malicious" — pure data leakage. The model would fail completely on any real-world
> PCAP that isn't from CTU or the thesis lab.

**Q: What is `@lru_cache(maxsize=1)` on `get_backend_settings()`?**
> `lru_cache` memoises the function result. With `maxsize=1`, the settings object is
> computed exactly once and cached. Every subsequent call returns the cached object
> without re-reading environment variables. This is a thread-safe singleton pattern.
> `clear_backend_settings_cache()` exists so tests can invalidate the cache and get
> fresh settings after changing environment variables.

**Q: What happens if you delete `min_deep_model_passes` from `multi_tier_workflow.yaml`?**
> The `load_multitier_config()` function uses `payload.get("min_deep_model_passes", 1)`
> — a default of `1`. The system would fall back to requiring only one deep model to
> pass, which was the original behaviour that produced the false positive. The YAML
> config explicitly sets it to `2` to override this less-safe default.

**Q: What is `tier1_threshold: null` and what does `null` become in Python?**
> In YAML, `null` maps to Python's `None`. When `tier1_threshold` is `None`, the
> multi-tier code uses the optimised threshold from the ML workflow's
> `threshold_summary.json` — the threshold that maximised F1 during cross-validation.
> Setting an explicit float (e.g., `0.3`) overrides the optimised value and uses a
> manual threshold instead.

**Q: Why does `join_tolerance_seconds: 2.0` exist in `base.yaml`?**
> Zeek and NFStream both timestamp flows, but their timestamps differ slightly — Zeek
> timestamps when it detects the session, NFStream timestamps when it sees the first
> packet. A 2-second window means: if the timestamps of a Zeek record and an NFStream
> flow match on the 4-tuple (src_ip, dst_ip, src_port, dst_port) AND their timestamps
> are within 2 seconds, they are the same flow. Too tight = missed matches; too loose =
> wrong flows merged together.

---

*Previous: [01_setup_and_installation.md](01_setup_and_installation.md)*
*Next: [03_pipeline_common.md](03_pipeline_common.md)*
