# Artifact Index

This index points to the main generated evidence artifacts produced so far.

## Canonical Dataset

Primary outputs:

- `artifacts/canonical/canonical_labeled_flows.csv`
- `artifacts/canonical/canonical_labeled_flows_summary.json`

What it contains:

- the unified labeled dataset used for model training and later reporting
- stable metadata such as labels, capture identifiers, protocol family, and time-window identifiers

## Malicious Pipeline Evidence

Key run:

- `artifacts/runs/malicious_full_v2/`

Important files:

- `artifacts/runs/malicious_full_v2/malicious_full_v2_quality_report.json`
- `artifacts/runs/malicious_full_v2/malicious_full_v2_nfstream.csv`
- `artifacts/runs/malicious_full_v2/malicious_full_v2_zeek_csv/conn.csv`
- `artifacts/runs/malicious_full_v2/malicious_full_v2_zeek_logs/weird.log`

What it shows:

- sanitized malicious capture passed PCAP health
- NFStream extraction succeeded
- Zeek did not emit TLS/SSL/QUIC protocol logs for the local malicious source

## ML Workflow

Primary run:

- `artifacts/ml_workflow/latest/`

Top-level files:

- `artifacts/ml_workflow/latest/model_comparison.csv`
- `artifacts/ml_workflow/latest/workflow_summary.json`
- `artifacts/ml_workflow/latest/roc_curve_comparison.png`
- `artifacts/ml_workflow/latest/pr_curve_comparison.png`
- `artifacts/ml_workflow/latest/dataset_split_manifest.csv`
- `artifacts/ml_workflow/latest/feature_manifest.json`

Per-model folders:

- `artifacts/ml_workflow/latest/gaussian_nb/`
- `artifacts/ml_workflow/latest/random_forest/`
- `artifacts/ml_workflow/latest/gradient_boosting/`

Each model folder contains:

- `model.joblib`
- `model_summary.json`
- `holdout_metrics.json`
- `classification_report.json`
- `cv_scores.csv`
- `cv_summary.json`
- `threshold_summary.json`
- `threshold_sweep.csv`
- `threshold_sweep.png`
- confusion matrices as CSV and PNG
- ROC and PR curves as CSV and PNG
- feature importance as CSV and PNG
- `test_predictions.csv`

## Multi-Tier Detection

Primary refined run:

- `artifacts/multi_tier/latest/`

Key files:

- `artifacts/multi_tier/latest/workflow_summary.json`
- `artifacts/multi_tier/latest/stage_metrics.json`
- `artifacts/multi_tier/latest/tiered_flow_scores.csv`
- `artifacts/multi_tier/latest/tier1_candidates.csv`
- `artifacts/multi_tier/latest/suspicious_flows.csv`
- `artifacts/multi_tier/latest/graph_nodes.csv`
- `artifacts/multi_tier/latest/graph_edges.csv`
- `artifacts/multi_tier/latest/suspicious_clusters.csv`
- `artifacts/multi_tier/latest/cluster_window_summary.csv`
- `artifacts/multi_tier/latest/graph_bundle.json`

What it contains:

- tier-by-tier scoring outputs
- suspicious-flow evidence
- graph-ready endpoint and cluster data for downstream reporting

## Backend Platform Outputs

Platform runtime locations:

- `artifacts/backend.sqlite3` or the configured backend database
- `artifacts/object_store/` or the configured S3-compatible bucket
- `artifacts/backend_jobs/`

What they contain:

- API-submitted input PCAP artifacts
- worker-produced output bundles
- queued job workspaces and job summaries during processing

Notes:

- the exact backend artifact location is environment-dependent
- in Compose, the metadata source of truth is Postgres and the artifact source of truth is MinIO

## Reporting Snapshot Helpers

Primary implementation:

- `src/tls_dataset/reporting/snapshot.py`
- `src/tls_dataset/static_site/export_static_snapshot.py`

What they provide:

- aggregated artifact summaries across canonical, ML, and multi-tier outputs
- flow-explorer and graph snapshot helpers for local presentation exports

## Supporting Repo-Level Files

Configuration:

- `configs/canonical_sources.yaml`
- `configs/ml_workflow.yaml`
- `configs/multi_tier_workflow.yaml`

Implementation:

- `src/tls_dataset/pipeline/`
- `src/tls_dataset/ml/workflow.py`
- `src/tls_dataset/detection/multitier.py`

Decision record:

- `docs/adr/0001-feature-extraction-stack.md`
