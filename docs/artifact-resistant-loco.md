# Artifact-Resistant LOCO Experiment

This experiment tests whether EncFlow is learning malware behavior or capture/source artifacts.

## Hypothesis

If the classifier relies heavily on source-specific artifacts, then removing the most source-predictive feature groups should change LOCO behavior sharply. Two outcomes are informative:

- Generalization improves or remains stable: source leakage was reduced while preserving malware signal.
- Generalization collapses: removed groups carried real malware signal, or the model was dependent on artifact-aligned shortcuts.

## Method

1. Train a capture-source predictor using the same numeric feature-selection rules as the main ML workflow.
2. Aggregate Random Forest source-prediction importance by predefined feature groups.
3. Rank feature groups by source predictiveness.
4. Create cumulative variants:
   - baseline: no source-predictive groups removed
   - remove top 1 source-predictive group
   - remove top 2 source-predictive groups
   - remove top 3 source-predictive groups
5. Rerun single-capture LOCO and paired malicious+benign LOCO for each variant.
6. Report deltas versus baseline for paired LOCO F1 and ROC-AUC.

## Command

```bash
PYTHONPATH=src .venv/bin/python -m tls_dataset.ml.artifact_resistant \
  --config configs/ml_workflow_v2.yaml \
  --output artifacts/artifact_resistant/latest \
  --max-groups 3 \
  --source-scope within_label \
  --models random_forest,xgboost
```

The main runner also executes this phase:

```bash
bash scripts/run_v2_experiment.sh
```

## Outputs

| File | Purpose |
|---|---|
| `source_predictive_group_ranking.csv` | Ranked feature groups by capture-source predictiveness |
| `source_predictive_feature_importance.csv` | Per-feature source-prediction importance |
| `artifact_resistant_loco_summary.csv` | Per-model LOCO summary for baseline and cumulative removal variants |
| `artifact_resistant_loco_summary.json` | Machine-readable manifest and output paths |
| `<variant>/loco_results.csv` | Full LOCO rows for each variant |
| `<variant>/model_summary.csv` | Per-variant aggregate model summary |

## Paper Interpretation

Use `artifact_resistant_loco_summary.csv` as the main table source. The most important columns are:

- `variant`
- `removed_groups`
- `removed_columns`
- `model`
- `f1_mean`
- `f1_mean_delta_vs_baseline`
- `roc_auc_mean`
- `roc_auc_mean_delta_vs_baseline`
- `worst_f1`
- `worst_f1_split`

For WTMC, this should be discussed as a leakage-resistance stress test, not as a replacement for the main model table. The strongest claim is not “we removed all artifacts”; the defensible claim is that the model was evaluated under a progressively stricter source-artifact removal protocol.

## Observed Results: May 17, 2026

Corrected within-label source-ranking run:

```text
artifacts/artifact_resistant/within_label_top1/
```

The source predictor is trained separately within benign captures and within
malicious captures, then the group importances are averaged. This avoids the
label-confounding error where malware-vs-benign signal is treated as capture
source leakage.

The corrected within-label capture-source ranking is:

| Rank | Feature group | Source importance | Interpretation |
|---:|---|---:|---|
| 1 | Timing/IAT | 0.351 | Strongest within-label capture fingerprint |
| 2 | Packet size | 0.329 | Strong source signal, especially within malicious captures |
| 3 | TCP flags | 0.124 | Source-predictive but also carries malware signal |
| 4 | Volume/duration | 0.119 | Moderate source signal |
| 5 | Port/protocol | 0.076 | Lower source signal |
| 6 | nDPI application confidence | 0.0004 | Negligible source signal |

Paired malicious+benign LOCO results:

| Removed groups | RF F1 | RF AUC | XGB F1 | XGB AUC | Interpretation |
|---|---:|---:|---:|---:|---|
| None | 0.445 | 0.718 | 0.402 | 0.767 | Baseline paired LOCO is much harder than the fixed held-out pair |
| Timing/IAT | 0.487 | 0.806 | 0.405 | 0.759 | Removing the strongest within-label source artifact improves RF AUC strongly |
| Timing/IAT + packet size | 0.569 | 0.828 | 0.439 | 0.792 | Best RF/AUC point; candidate artifact-resistant feature view |
| Timing/IAT + packet size + TCP flags | 0.380 | 0.576 | 0.426 | 0.605 | Removing TCP flags discards genuine malware signal |

The top-2 and top-3 rows remove the same column sets as the earlier complete
run in `artifacts/artifact_resistant/latest/`; only the top-1 row changed
after correcting the source-ranking scope. For final camera-ready evidence,
rerun the full corrected command above so all rows live in one authoritative
directory.

Paper claim:

The result is mixed in the right way for a serious measurement paper. It shows that timing and packet-size features are partly source-artifact carriers, but TCP flags should not be mechanically removed despite source predictiveness. The defensible conclusion is selective artifact resistance, not blanket source-feature removal.
