# TLS Dataset

Privacy-preserving encrypted traffic analytics platform for TLS 1.3 and QUIC.

This repository is being upgraded from a thesis prototype into a production-oriented software project. The original research assets remain in place for reference, while all new implementation work will move into a clean package structure under `src/`.

## Current Status

- `src/` contains the new application package that will replace one-off scripts over time.
- `tests/` contains the automated test suite for the new codebase.
- `configs/` contains environment-specific configuration files.
- `artifacts/` is the home for generated models, reports, metrics, and temporary outputs.
- The thesis PDF and existing root-level scripts are preserved as legacy inputs and evidence.

## Repository Layout

```text
.
├── Thesis/
├── artifacts/
├── configs/
├── docker/
├── src/
│   └── tls_dataset/
├── tests/
├── Dockerfile
├── docker-compose.yaml
├── pyproject.toml
└── requirements.lock
```

## Quick Start

1. Create a virtual environment with Python 3.12.
2. Install the pinned dependencies from `requirements.lock`.
3. Install the package in editable mode with `pip install -e .`.
4. Run `python -m tls_dataset info` to confirm the scaffold is wired correctly.

## Pipeline Usage

The repository now provides one parameterized pipeline package for both benign and malicious datasets.

- High-level run: `python -m tls_dataset run-dataset-pipeline ...`
- Step-by-step modules live under `src/tls_dataset/pipeline/`
- Legacy root scripts are now thin wrappers around the package modules, not separate implementations

Example orchestration flow:

```bash
PYTHONPATH=src python3 -m tls_dataset run-dataset-pipeline \
  --dataset-name benign \
  --output-dir artifacts/runs/benign_local \
  --pcap data/raw/benign_filtered.pcap \
  --zeek-log-dir data/zeek/benign \
  --extract-nfstream \
  --convert-zeek
```

This gives benign and malicious datasets the same execution path with different inputs instead of different scripts.

By default, the orchestration command now runs data-quality gates before feature generation and fails fast on:

- truncated PCAPs
- missing required Zeek outputs
- duplicate NFStream flow keys
- poor NFStream to Zeek join rates
- unmatched UIDs
- non-TLS/QUIC leakage in merged outputs

Each run writes a JSON quality report into the chosen output directory.

## Malicious Pipeline

The repository also includes a malicious-capture preparation path that:

- copies the raw sample into a managed run directory
- sanitizes truncated or malformed captures with `editcap`
- filters encrypted traffic consistently with `tshark`
- records provenance for the raw, sanitized, and filtered artifacts
- can extract NFStream immediately, and can run the full Zeek + NFStream pipeline on hosts where Zeek is installed
- auto-detects Zeek from `PATH`, `ZEEK_BIN`, or common install paths like `/opt/zeek/bin/zeek`
- runs Zeek and NFStream on the sanitized full capture so protocol analyzers keep full session context; the filtered PCAP is retained as an inspection artifact

Example:

```bash
.venv/bin/python -m tls_dataset run-malicious-pipeline \
  --dataset-name malicious_ready \
  --input-pcap BotnetCapture/malicious_filtered.pcap \
  --output-dir artifacts/runs/malicious_ready \
  --manifest-csv BotnetCapture/manifest.csv \
  --prepare-only \
  --extract-nfstream-after-prepare
```

## Canonical Dataset

The repository now supports a single canonical labeled dataset layer for training and reporting workflows.

- `configs/canonical_sources.yaml` declares the trusted source inputs
- `python -m tls_dataset build-canonical-dataset ...` materializes the unified CSV
- each row gets stable metadata such as `label`, `attack_family`, `capture_id`, `protocol_family`, `window_id`, and `source_dataset`
- time windows are built from flow start timestamps, so the same dataset can drive both model training and timeline analytics
- source-level labels can be extended through `extra_labels` in the config without changing code

Example:

```bash
.venv/bin/python -m tls_dataset build-canonical-dataset \
  --config configs/canonical_sources.yaml \
  --output-csv artifacts/canonical/canonical_labeled_flows.csv \
  --output-summary-json artifacts/canonical/canonical_labeled_flows_summary.json
```

## ML Workflow

The repository now includes a full supervised ML workflow for the thesis model family:

- trains `GaussianNB`, `RandomForestClassifier`, and `GradientBoostingClassifier`
- uses a stratified train/test split plus stratified cross-validation
- saves fold metrics, holdout metrics, confusion matrices, ROC curves, PR curves, threshold sweeps, predictions, and feature importance
- writes model comparison artifacts so reporting and evidence workflows can use the same outputs

Example:

```bash
.venv/bin/python -m tls_dataset run-ml-workflow \
  --config configs/ml_workflow.yaml
```

## Multi-Tier Detection

The repository now supports a multi-tier detection pass on top of the trained models:

- Tier 1 uses a lightweight filter to cheaply narrow the candidate set
- Tier 2 runs deeper model inference on those candidates and produces a consensus suspiciousness score
- Tier 3 builds a suspicious endpoint graph and enriches flows with cluster, node, and window-level context

Example:

```bash
.venv/bin/python -m tls_dataset run-multi-tier \
  --config configs/multi_tier_workflow.yaml
```

Saved outputs include:

- `tiered_flow_scores.csv`
- `tier1_candidates.csv`
- `suspicious_flows.csv`
- `graph_nodes.csv`
- `graph_edges.csv`
- `suspicious_clusters.csv`
- `cluster_window_summary.csv`
- `stage_metrics.json`
- `workflow_summary.json`

## Backend Platform

The repository now includes a backend scoring platform instead of only offline workflows.

Backend capabilities:

- `FastAPI` API for health, model-bundle discovery, PCAP submission, and job tracking
- `Postgres`-compatible metadata layer for batches, jobs, and artifact references
- local or S3-compatible object storage for uploaded inputs and produced outputs
- `Redis + RQ` worker queue for asynchronous PCAP scoring
- worker-driven PCAP processing that reuses the standardized pipeline and multi-tier scoring logic

Main implementation:

- `src/tls_dataset/backend/app.py`
- `src/tls_dataset/backend/worker.py`
- `src/tls_dataset/backend/scoring.py`
- `configs/backend.env.example`

The Compose stack now includes:

- `api`
- `worker`
- `postgres`
- `redis`
- `minio`

Local backend verification in this sandbox is test-based. The code and tests passed, but binding a live HTTP port was blocked by the sandboxed execution environment here.

## Project Direction

The implementation roadmap is intentionally stronger than the written thesis:

- fully reproducible data pipelines
- malicious and benign dataset parity
- model training and evaluation with saved evidence
- production packaging, observability, and deployment support

## Official Extraction Stack

The production feature-extraction stack for this repository is:

- `Zeek` for protocol-aware TLS 1.3 and QUIC metadata, connection logs, and protocol evidence
- `NFStream` for flow statistics, bidirectional timing, packet-size distributions, and SPLT-style features

`CICFlowMeter` is explicitly treated as thesis-era legacy only. It may still be referenced in the written document, but it is not part of the forward production path for this codebase.

Why this decision was made:

- the current scripts already align much more closely with Zeek + NFStream
- Zeek provides richer TLS/QUIC visibility than the current prototype would get from CICFlowMeter alone
- NFStream covers the flow-statistics role without introducing a parallel JVM-based extraction track
- one official stack prevents reproducibility drift between research claims and production implementation

The formal decision record lives in `docs/adr/0001-feature-extraction-stack.md`.

## Documentation

The implementation journey and findings are now documented in:

- `docs/README.md`
- `docs/backend-platform.md`
- `docs/project-journey.md`
- `docs/findings-register.md`
- `docs/artifact-index.md`

## Notes

- Large PCAPs, generated CSVs, and local artifacts are ignored by git on purpose.
- Docker assets are included as source files even though the local Docker CLI is not installed in this environment.
- The repository now standardizes on Zeek + NFStream as the production extraction direction.
