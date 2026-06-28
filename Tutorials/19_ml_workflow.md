# Tutorial 19 — Full ML Workflow (`ml/workflow.py`)

## Prerequisites

- Tutorial 17 (`canonical.py`) — `ml/workflow.py` reads the canonical labeled CSV. Every
  metadata column name (`BASE_METADATA_COLUMNS`) is imported from `canonical.py`.
- Tutorial 09 (`quality.py`) — quality status columns in the canonical dataset influence the
  dataset risk warnings produced here.
- Solid understanding of: sklearn Pipeline, cross-validation, confusion matrices, ROC/PR curves,
  and what "threshold" means in binary classification.

---

## 1. What This File Does

This is the end of the data pipeline. Every tutorial from 04 through 18 was about producing
`ml_final.csv` and assembling it into the canonical dataset. This file trains three binary
classifiers on that dataset, cross-validates them, optimises their decision thresholds, evaluates
them on a held-out test set, computes feature importance two ways, and writes every artifact
(models, metrics, plots, manifests) to an output directory.

It trains three models simultaneously — GaussianNB, RandomForest, GradientBoosting — and
produces a unified comparison table so you can select the best one for the multi-tier detection
system (Tutorial 20).

---

## 2. Module-Level Setup

### Matplotlib backend (Lines 14–16)

```python
os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "tls_dataset_mplconfig"))
import matplotlib
matplotlib.use("Agg")
```

These three lines run at import time, before any function is called. Two problems are solved:

**`MPLCONFIGDIR`:** Matplotlib tries to create a config directory in `$HOME/.config/matplotlib`.
In Docker containers, CI environments, or when running as a non-standard user, `$HOME` may not
be writable. `os.environ.setdefault` sets the config directory to the system temp directory only
if it is not already set — `setdefault` never overwrites an existing value. This prevents
`matplotlib` from crashing at import with a permissions error.

**`matplotlib.use("Agg")`:** The Agg backend renders plots to PNG files without requiring any
display server (X11, Wayland, macOS CoreGraphics). In a server environment, a Docker container,
or a headless CI runner, there is no display. If you use the default interactive backend, any
`plt.show()` call hangs waiting for a display. The Agg backend must be set **before** importing
`pyplot` — which is why it appears at module level before `from matplotlib import pyplot as plt`.

### Constants (Lines 50–74)

```python
DEFAULT_EXCLUDED_FEATURE_COLUMNS = ("id", "expiration_id")

ABSOLUTE_TIME_COLUMNS = (
    "ts", "flow_start_ms", "flow_end_ms", "window_start_ms", "window_end_ms",
)
ABSOLUTE_TIME_SUFFIXES = (
    "_first_seen_ms", "_last_seen_ms",
)

COMPARISON_METRIC_COLUMNS = (
    "accuracy", "precision", "recall", "f1", "specificity",
    "balanced_accuracy", "roc_auc", "average_precision",
)
```

This is the **third leakage guard** in the project. Tutorial 10 removed identifiers by name.
Tutorial 12 removed four specific suffix-renamed timestamp columns. This layer catches anything
that survived both — using three independent strategies:

- **`DEFAULT_EXCLUDED_FEATURE_COLUMNS`**: absolute identifiers not in `BASE_METADATA_COLUMNS`.
- **`ABSOLUTE_TIME_COLUMNS`**: exact-name timestamp columns from the canonical dataset.
- **`ABSOLUTE_TIME_SUFFIXES`**: pattern-matching on column name endings — any column ending in
  `_first_seen_ms` or `_last_seen_ms` is a timestamp regardless of its prefix. This catches
  NFStream directional variants (e.g., `src2dst_first_seen_ms`) if they somehow survived earlier
  stages.

Defence-in-depth: three independent exclusion mechanisms mean a timestamp column must evade
name-based removal (Tutorial 10 and 12) and suffix-pattern matching (here) to enter training.

---

## 3. `WorkflowConfig` — Lines 77–94

```python
@dataclass(frozen=True)
class WorkflowConfig:
    dataset_csv: str
    output_dir: str
    target_column: str          # "label_id" — the integer 0/1 column sklearn trains on
    label_column: str           # "label" — the human-readable string column for reports
    record_id_column: str       # "record_id" — for the split manifest
    positive_label: int         # 1 — which integer label is "malicious"
    test_size: float            # 0.2 — 20% held out
    random_state: int           # 42 — seeds all random operations
    cv_folds: int               # 5 — stratified k-fold splits
    threshold_metric: str       # "f1" — metric to optimise the decision threshold against
    top_k_feature_importance: int  # 20 — top features to show in importance plots
    extra_excluded_columns: tuple[str, ...]
    permutation_n_repeats: int  # 5 — how many shuffles per feature in permutation importance
    permutation_scoring: str    # "roc_auc" — metric used during permutation importance
    permutation_max_samples: int  # 4000 — max test rows for permutation importance
    model_params: dict[str, dict[str, Any]]  # per-model hyperparameter overrides
```

`random_state=42` seeds every stochastic operation: `train_test_split`, `StratifiedKFold`,
`RandomForestClassifier`, `GradientBoostingClassifier`, permutation importance, and stratified
sampling. With the same `random_state`, every run on the same dataset produces identical splits,
trained models, and metrics — making results reproducible and comparable across machines.

---

## 4. `build_model_specs` — Lines 136–151

Three models are trained:

| Model | sklearn class | Why it is here |
|-------|--------------|----------------|
| `GaussianNB` | `GaussianNB` | Extremely fast at inference. Used as Tier 1 in the multi-tier detection system (Tutorial 20) — it screens traffic at line rate before the expensive Tier 2 models run |
| `RandomForestClassifier` | `RandomForestClassifier` | Ensemble of decision trees, high accuracy, handles mixed-scale features naturally, produces native feature importance via `feature_importances_` |
| `GradientBoostingClassifier` | `GradientBoostingClassifier` | Sequential boosted trees, often highest accuracy on tabular data, complements RF in the Tier 2 consensus vote |

These are not arbitrary choices — they map directly to the roles they play in Tutorial 20's
multi-tier detection. Training all three here means Tutorial 20 can load any of their saved
`model.joblib` files.

Hyperparameters come from `config.model_params` — a dict loaded from the YAML config. If a
model has no entry in the YAML, `params.get("random_forest", {})` returns `{}` and sklearn
uses its defaults.

---

## 5. `select_feature_columns` and `is_excluded_feature_column` — Lines 159–206

```python
def is_excluded_feature_column(column, *, target_column, extra_excluded_columns) -> str | None:
    metadata_columns = set(BASE_METADATA_COLUMNS).union(extra_excluded_columns)
    if column == target_column:         return "target_column"
    if column in metadata_columns:      return "metadata"
    if column in DEFAULT_EXCLUDED_FEATURE_COLUMNS: return "identifier"
    if column in ABSOLUTE_TIME_COLUMNS: return "absolute_time"
    if any(column.endswith(suffix) for suffix in ABSOLUTE_TIME_SUFFIXES):
        return "absolute_time"
    return None
```

Returns a string reason if the column should be excluded, `None` if it should be kept as a
feature. The reason string is stored in the `excluded_columns` dict and written to
`feature_manifest.json` — so you can audit exactly why every column was or was not used.

`select_feature_columns` then adds one more filter:

```python
if not (pd.api.types.is_numeric_dtype(df[column]) or pd.api.types.is_bool_dtype(df[column])):
    excluded[column] = "non_numeric"
    continue
```

Even after `is_excluded_feature_column` passes a column, it must be numeric or boolean. This
is the final dtype safety net — any text column that survived all prior stages is excluded here
with a clear `"non_numeric"` reason in the manifest. Boolean columns are allowed and later
converted to `int` (line 546) — sklearn cannot train on Python booleans but handles `0`/`1`
integers correctly.

---

## 6. `build_model_pipeline` — Lines 209–215

```python
def build_model_pipeline(estimator: Any) -> Pipeline:
    return Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("model", estimator),
    ])
```

Every model is wrapped in a two-step sklearn `Pipeline`:

**Step 1 — `SimpleImputer(strategy="median")`:**

Despite Tutorial 10's `fillna(0)` and Tutorial 11's sanitisation, the canonical dataset can
reintroduce `NaN` values. When rows from sources with different feature schemas are concatenated
in `canonical.py`, a column present in one source's CSV but absent in another's becomes `NaN`
for all rows from the source without it. The imputer fills these with the training-set median,
computed during `.fit()` and applied consistently during `.transform()`.

**Why median not mean?**

Network flow statistics are right-skewed — a few very high-bandwidth flows inflate the mean far
above the typical value. The median is resistant to these outliers. `SimpleImputer(strategy="median")`
fills missing values with the 50th percentile of the training data, which is a better estimate
of "typical" for skewed distributions.

**Why a Pipeline and not separate fit/transform calls?**

The `Pipeline` encapsulates the imputer + model as a single object. `cross_val_predict(pipeline, ...)`
fits the imputer **on the training fold** and applies it to the validation fold — correctly
preventing imputation values (the median) from being contaminated by the validation fold's data.
If you imputed the full dataset before splitting, the test fold's medians would influence the
training fold's imputation, introducing leakage.

---

## 7. `compute_binary_metrics` — Lines 224–247

The full set of metrics computed for every threshold evaluation:

| Metric | Formula | What it means for malware detection |
|--------|---------|-------------------------------------|
| `accuracy` | (TP+TN)/(TP+TN+FP+FN) | Overall correct rate — misleading when classes are imbalanced |
| `precision` | TP/(TP+FP) | Of all flows flagged malicious, how many actually are — controls false alarm rate |
| `recall` | TP/(TP+FN) | Of all actual malicious flows, how many are caught — controls missed detections |
| `f1` | 2·P·R/(P+R) | Harmonic mean of precision and recall — the threshold optimisation target by default |
| `specificity` | TN/(TN+FP) | Of all benign flows, how many are correctly passed — recall for the negative class |
| `balanced_accuracy` | (recall+specificity)/2 | Mean recall across both classes — good for imbalanced datasets |
| `roc_auc` | Area under ROC curve | Rank-ordering quality: probability that a random malicious flow scores higher than a random benign flow |
| `average_precision` | Area under PR curve | Summary of PR curve — preferred over ROC AUC when classes are imbalanced (benign >> malicious) |

`specificity` is computed manually from the confusion matrix because sklearn does not have a
`specificity_score` function — `recall_score(pos_label=0)` gives it (recall of the negative
class = specificity), but computing it from `tn/(tn+fp)` directly from the confusion matrix is
more explicit and readable.

`zero_division=0` on precision, recall, and F1 prevents `ZeroDivisionError` when a model
predicts only one class at extreme thresholds (e.g., threshold=1.0 means nothing is ever
predicted positive — TP=FP=0, making precision undefined).

---

## 8. `evaluate_thresholds` and `select_best_threshold` — Lines 250–277

### Why threshold optimisation?

A probabilistic classifier outputs `predict_proba(X)[:, 1]` — a float between 0 and 1 for each
sample. The standard decision boundary is 0.5: `label = 1 if score >= 0.5 else 0`. But 0.5 is
not special — it is just the midpoint of the probability scale. The actual optimal threshold
depends on the class balance and the relative cost of false positives vs false negatives.

For malware detection:
- A false negative (missed malware) is costly — an undetected C2 beacon keeps operating.
- A false positive (benign flagged as malicious) is also costly — security teams get alert fatigue.

The optimal threshold that maximises F1 (harmonic mean of precision and recall) balances these
two costs. At threshold 0.3, recall is high but precision may be low (too many false alarms).
At threshold 0.7, precision is high but recall drops (too many missed threats).

### The sweep

```python
threshold_values = np.linspace(0.0, 1.0, 201)  # 201 thresholds: 0.000, 0.005, 0.010, ...
for threshold in threshold_values:
    y_pred = (y_score >= threshold).astype(int)
    metrics = compute_binary_metrics(y_true, y_pred, y_score, threshold=float(threshold))
```

201 evenly-spaced thresholds gives 0.5% granularity — fine enough for practical purposes
without being computationally heavy. `np.linspace(0, 1, 201)` gives exactly 201 points
including both endpoints.

### Critical: threshold is optimised on CV predictions, NOT on the test set

```python
# On training data, using cross-validation predictions:
cv_probabilities = cross_val_predict(pipeline, X_train, y_train, cv=cv, method="predict_proba", ...)[:, positive_label]
threshold_frame = evaluate_thresholds(y_train, cv_probabilities)
threshold_summary = select_best_threshold(threshold_frame, config.threshold_metric)

# Then on test data, using the already-chosen threshold:
test_probabilities = pipeline.predict_proba(X_test)[:, config.positive_label]
optimized_predictions = (test_probabilities >= threshold_summary["threshold"]).astype(int)
```

`cross_val_predict` generates out-of-fold predictions — for each fold, the model is trained on
the other folds and predicts on this fold. The result is a full set of predictions for every
training row, but each prediction was made by a model that had not seen that row during training.
This is the correct dataset for threshold selection: the threshold is chosen based on how the
model performs on data it has not seen during fitting.

If threshold were selected on the test set, you would be using the test set to make a modelling
decision (choosing the threshold), which constitutes test set leakage — the reported optimized
test metrics would be optimistically biased.

### `select_best_threshold` — the multi-column stable sort

```python
sort_columns = [metric, "precision", "balanced_accuracy", "recall"]
ranked = threshold_frame.sort_values(sort_columns, ascending=[False, False, False, False], kind="stable")
```

Primary sort: the configured metric (default `"f1"`) descending. Multiple thresholds may achieve
the same best F1. Tie-breaking: higher precision first (fewer false alarms), then higher balanced
accuracy, then higher recall. `kind="stable"` ensures that if all four values are tied, the
lower threshold (appearing earlier in the sweep frame) is retained — a conservative choice that
flags fewer flows as malicious rather than more.

---

## 9. The Training Loop — Key Steps in `run_ml_workflow`

### Feature selection and bool conversion (Lines 538–547)

```python
X = df[feature_columns].copy()
bool_columns = [column for column in X.columns if pd.api.types.is_bool_dtype(X[column])]
if bool_columns:
    X[bool_columns] = X[bool_columns].astype(int)
y = df[config.target_column].astype(int)
```

Bool-to-int conversion is necessary because sklearn's `SimpleImputer` and most estimators do
not support Python's `bool` dtype. `True`/`False` become `1`/`0` — semantically identical for
ML purposes.

### Stratified train/test split (Lines 563–570)

```python
X_train, X_test, y_train, y_test, records_train, records_test = train_test_split(
    X, y, record_frame,
    test_size=config.test_size,
    random_state=config.random_state,
    stratify=y,
)
```

`stratify=y` ensures each split contains the same proportion of class labels as the full
dataset. Without it, a random split on an imbalanced dataset (e.g., 90% benign / 10% malicious)
could put all malicious rows in the train set by chance. Three DataFrames are split together
(X, y, record_frame) with the same indices — `record_frame` tracks `record_id`, `capture_id`,
and `quality_status` per row so the split manifest (written to `dataset_split_manifest.csv`)
shows exactly which rows went into which split.

### Post-split constant column removal (Lines 572–577)

```python
constant_columns = [column for column in X_train.columns if X_train[column].nunique(dropna=False) <= 1]
all_missing_columns = [column for column in X_train.columns if X_train[column].isna().all()]
```

This runs **after** the split, not before. A column may have non-zero variance in the full
dataset but be constant within the training fold (e.g., a feature that has only one unique value
among the 80% of data selected for training). A constant column would cause issues in GaussianNB
(zero variance → division by zero in the Gaussian PDF). Checking on `X_train` and applying the
same drop to `X_test` ensures train and test have identical column schemas.

### `feature_manifest.json` — what it is and why it matters

```python
feature_manifest = {
    "dataset_csv": str(dataset_path),
    "total_columns": int(len(df.columns)),
    "candidate_numeric_columns": int(len(feature_columns)),
    "training_feature_columns": list(X_train.columns),
    "excluded_columns": excluded_columns,
    "dropped_training_columns": dropped_training_columns,
}
save_json(feature_manifest, output_dir / "feature_manifest.json")
```

This JSON is the bridge between training and inference. When the backend scoring system
(Tutorial 28) applies a saved model to a new PCAP, it must extract exactly the same feature
columns in the same order that the model was trained on. `feature_manifest.json` contains
`training_feature_columns` — the authoritative ordered list of columns the model expects. The
backend reads this file and aligns the new PCAP's features to it before calling
`pipeline.predict_proba()`.

---

## 10. `build_native_feature_importance` — Lines 356–380

Two models (RF, GB) have a `feature_importances_` attribute from sklearn — the mean decrease in
impurity across all trees. GaussianNB does not have this attribute. For GaussianNB, the function
computes a proxy:

```python
if hasattr(model, "theta_") and hasattr(model, "var_"):
    theta = np.asarray(model.theta_, dtype=float)   # class means: shape (2, n_features)
    var   = np.asarray(model.var_,   dtype=float)   # class variances: shape (2, n_features)
    importance = np.abs(theta[1] - theta[0]) / np.sqrt(var.mean(axis=0) + 1e-9)
```

**What this computes:**

`theta[1]` = mean of each feature in the malicious class.
`theta[0]` = mean of each feature in the benign class.
`|theta[1] - theta[0]|` = absolute mean difference between classes per feature.
`sqrt(var.mean(axis=0))` = average standard deviation across both classes per feature
(pooled spread).

The ratio is a **normalised mean separation** — how many standard deviations apart the two
class means are for each feature. This is equivalent to a simplified Cohen's d effect size.
A feature with high mean separation and low variance is the most discriminative under a
Gaussian assumption.

The `1e-9` additive term prevents division by zero for zero-variance features (which should
have been removed by the constant-column check, but the guard is defensive).

The return is `("gaussian_mean_gap_over_std", frame)` — the method name is stored so the
feature importance plot title and `model_summary.json` correctly describe what was computed.

---

## 11. `build_permutation_importance` — Lines 398–429

Native feature importance measures how much each feature contributes to the training process.
Permutation importance measures something more robust: **how much does model performance drop
when a feature's values are randomly shuffled?**

```python
result = permutation_importance(
    pipeline,       # the full fitted pipeline including imputer
    sampled_X,      # test data (not training data)
    sampled_y,
    scoring=scoring,        # "roc_auc" by default
    n_repeats=n_repeats,    # 5 — shuffle each feature 5 times, take mean
    random_state=random_state,
)
```

Shuffling a feature breaks its relationship with the target. If the model's ROC AUC drops
significantly after shuffling feature X, feature X was genuinely important. If it barely
changes, the model does not rely on that feature (perhaps another correlated feature carries the
same information).

**Why test data, not training data?**

A model can memorise training data. Measuring permutation importance on training data reflects
what the model memorised, not what it generalises. Test data importance measures the feature's
contribution to generalisation — a more honest answer.

**`stratified_sample` for efficiency:**

```python
if len(X) <= max_samples:
    return X, y
splitter = StratifiedShuffleSplit(n_splits=1, train_size=max_samples, random_state=random_state)
selected_indices, _ = next(splitter.split(X, y))
```

Permutation importance runs `n_repeats` full model evaluations per feature. On 10,000 test rows
and 80 features, that is 80 × 5 = 400 full predictions. Capping at `max_samples=4000` rows keeps
this tractable while `StratifiedShuffleSplit` preserves the class ratio in the sample.

---

## 12. `analyze_dataset_risks` — Lines 453–473

Three warnings that appear in `workflow_summary.json`:

**Warning 1 — Quality-failed sources:**
```python
if quality_counts.get("fail", 0) > 0:
    warnings.append("The canonical dataset includes rows from at least one quality-failed source...")
```
Models trained on quality-failed data may have learned from flows that did not pass the
quality gates in Tutorial 09. This warning surfaces in the summary so it is never silently
ignored.

**Warning 2 — Single capture per class:**
```python
if any(count < 2 for count in capture_counts.values()):
    warnings.append("At least one class is represented by fewer than two distinct captures...")
```
If all malicious rows come from a single CTU-13 capture, a random row-level train/test split
still exposes both train and test to the same capture's patterns. The model may learn capture
artefacts (specific IPs, ports, timing patterns from that one session) rather than class-level
generalisable features. Correct evaluation requires **capture-level splitting** — all rows from
a capture go to either train or test, never both.

**Warning 3 — Class imbalance:**
```python
if label_counts.max() / max(label_counts.min(), 1) > 1.5:
    warnings.append("The current dataset is class-imbalanced, so threshold optimization and PR metrics matter more than raw accuracy.")
```
A 1.5× ratio triggers this warning — even a mild imbalance changes which metrics are meaningful.
A model that predicts "benign" for everything achieves 90% accuracy on a 90/10 dataset but 0%
recall. This warning redirects attention to F1, balanced accuracy, and average precision.

---

## 13. Output Artifacts — Complete List

Per model (`output_dir/{model_name}/`):

| File | What it contains |
|------|-----------------|
| `model.joblib` | Fitted sklearn `Pipeline` (imputer + estimator) — used by Tutorial 20 and Tutorial 28 |
| `feature_importance_native.csv/png` | Native importances (RF/GB) or mean-gap-over-std (GNB) |
| `feature_importance_permutation.csv/png` | Permutation importances on test set |
| `cv_scores.csv` | Per-fold metric values from 5-fold CV |
| `cv_summary.json` | Mean ± std of every CV metric |
| `threshold_sweep.csv/png` | Precision/recall/F1/balanced_accuracy vs threshold |
| `threshold_summary.json` | Best threshold and metrics at that threshold |
| `holdout_metrics.json` | Default (0.5) and optimised threshold metrics on test set |
| `classification_report.json` | Per-class precision/recall/F1 at both thresholds |
| `test_predictions.csv` | Per-row: `record_id`, `y_true`, `probability_malicious`, both predictions |
| `confusion_matrix_default/optimized.csv/png` | Confusion matrices at both thresholds |
| `roc_curve.csv/png` | ROC curve data and plot |
| `pr_curve.csv/png` | Precision-recall curve data and plot |
| `model_summary.json` | Summary of all of the above |

At `output_dir/` level:

| File | What it contains |
|------|-----------------|
| `feature_manifest.json` | Exact columns used for training — loaded by the backend at inference time |
| `dataset_split_manifest.csv` | Every row with its split assignment (train/test) and record_id |
| `model_comparison.csv` | Side-by-side comparison of all three models |
| `roc_curve_comparison.png` | Overlay of all three ROC curves |
| `pr_curve_comparison.png` | Overlay of all three PR curves |
| `workflow_summary.json` | Dataset shape, label distribution, quality status, warnings |

---

## 14. Interview Questions and Answers

**Q: Why is the decision threshold optimised on cross-validation predictions rather than on the
test set?**

A: The test set must remain completely unused during all modelling decisions — including
threshold selection. Using the test set to pick a threshold constitutes test set leakage: the
reported test metrics would reflect performance on data that was used to make the threshold
decision, not truly unseen data. `cross_val_predict` generates out-of-fold predictions for
every training row — each row is predicted by a model that was trained without seeing it. The
resulting probability array has the same statistical properties as new data with respect to the
fitted model, making it the correct dataset for threshold selection.

---

**Q: Why use `SimpleImputer(strategy="median")` inside the sklearn Pipeline instead of filling
NaN before training?**

A: Imputation must be fitted on training data only. If you compute the median on the full
dataset and fill NaN before the train/test split, the training set's imputed values are
influenced by the test set's data distribution — leakage. The sklearn `Pipeline` encapsulates
this correctly: during `cross_validate`, the imputer's `fit_transform` runs on the training
fold and `transform` runs on the validation fold using the training fold's medians. During final
training, the imputer is fitted on all of `X_train` and applied to `X_test` consistently.

---

**Q: What is the difference between native feature importance (RF) and permutation importance,
and when does each mislead you?**

A: RF native importance (mean decrease in impurity) is computed during training and reflects
how much each feature reduces the Gini impurity across all splits in all trees. It is fast but
has known biases: it over-rates high-cardinality features (many unique values create many
possible splits) and correlated features (importance is split between correlated features,
underestimating both). Permutation importance is computed post-training by shuffling each
feature's values on test data and measuring AUC drop. It is model-agnostic, directly measures
generalisation contribution, and correctly handles correlated features (each is measured
independently). The weakness of permutation importance is instability on small test sets and
high runtime (one full evaluation per feature per repeat). The workflow computes both so you can
cross-reference them — if a feature ranks high in native importance but low in permutation
importance, it may be a high-cardinality artefact rather than a genuine discriminator.

---

**Q: Why train three different model types instead of just the best-performing one?**

A: The three models serve different roles in the downstream multi-tier detection system (Tutorial
20). GaussianNB is trained here specifically because it is fast enough to run at line rate as
a first-pass screener. Random Forest and Gradient Boosting are trained for the more accurate
second tier. Training all three in one workflow also produces the comparison table that justifies
the architectural choice — you can show empirically which model achieves the best F1/AUC and
which is fast enough for tier-1 screening. Training only the "best" model would make that
argument invisible in the artifacts.

---

**Q: What does the `analyze_dataset_risks` warning about single-capture-per-class mean for
evaluation validity?**

A: If all benign rows come from one Chrome capture and all malicious rows come from one botnet
capture, then even a stratified row-level split mixes rows from the same capture in both train
and test. The model can learn capture-level artefacts — specific IP addresses, port numbers, or
timing patterns unique to that capture session — rather than class-level behavioural patterns.
A correctly independent evaluation requires all rows from a given capture to be in either train
or test, never both. This is called capture-level or subject-level cross-validation. The warning
does not stop training (the workflow runs either way) but it is recorded in `workflow_summary.json`
so the limitation is explicitly documented in the thesis output.

---

*Next: [Tutorial 20 — Multi-Tier Detection](20_detection_multitier.md)*
