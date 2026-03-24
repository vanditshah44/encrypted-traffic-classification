# Attack Detection in Encrypted TLS 1.3 / QUIC Traffic

Production-grade implementation of a privacy-preserving encrypted traffic analytics and scoring platform for malicious activity detection in TLS 1.3 and QUIC environments.

This repository operationalizes the thesis work into a structured software project with reproducible data pipelines, supervised ML workflows, multi-tier detection, graph enrichment, and a backend scoring platform.

## Overview

The project is built around one core idea: detect malicious behavior in encrypted traffic without decrypting payloads.

It does that by combining:

- `Zeek` for protocol-aware TLS 1.3 and QUIC evidence
- `NFStream` for bidirectional flow statistics
- a canonical labeled dataset for training and scoring
- supervised models including `GaussianNB`, `RandomForest`, and `GradientBoosting`
- staged detection logic with graph-based endpoint enrichment
- a backend platform for batch PCAP scoring and artifact tracking

## Core Capabilities

- Parameterized benign and malicious data pipelines under `src/tls_dataset/pipeline/`
- Built-in data-quality gates for truncated captures, missing Zeek outputs, bad joins, duplicate flows, unmatched UIDs, and encrypted-traffic leakage
- Provenance-aware malicious capture preparation with sanitization and consistent encrypted-traffic filtering
- Canonical labeled dataset generation with stable metadata such as `label`, `attack_family`, `capture_id`, `protocol_family`, `window_id`, and `source_dataset`
- Full ML workflow with train/test splits, stratified cross-validation, threshold optimization, confusion matrices, ROC/PR curves, feature importance, saved models, and comparison artifacts
- Multi-tier detection flow with lightweight screening, deep-model consensus, and suspicious-cluster graph construction
- Backend scoring platform with API, metadata persistence, object storage support, and queue-driven batch processing

## Official Extraction Stack

The production feature-extraction stack in this repository is:

- `Zeek`
- `NFStream`

`CICFlowMeter` is treated as legacy thesis-era context only and is not part of the forward implementation path for this codebase.

The formal architecture decision is recorded in [ADR 0001](docs/adr/0001-feature-extraction-stack.md).

## Repository Layout

```text
.
├── Thesis/
├── artifacts/
├── configs/
├── docker/
├── docs/
├── src/
│   └── tls_dataset/
├── tests/
├── Dockerfile
├── docker-compose.yaml
├── pyproject.toml
└── requirements.lock
```

Key areas:

- `src/tls_dataset/pipeline/`: extraction, merging, dataset building, provenance, and quality gates
- `src/tls_dataset/ml/`: supervised ML workflow and saved evaluation evidence
- `src/tls_dataset/detection/`: multi-tier detection and suspicious-cluster enrichment
- `src/tls_dataset/backend/`: scoring platform API, worker, storage, queue, and job services
- `src/tls_dataset/reporting/`: artifact snapshot helpers used by offline reporting/export workflows
- `src/tls_dataset/static_site/`: static analytical site export pipeline
- `configs/`: pipeline, model, multi-tier, and backend configuration
- `docs/`: architecture notes, findings, artifact index, and implementation journey

## Quick Start

1. Create a Python 3.12 virtual environment.
2. Install the pinned dependencies from `requirements.lock`.
3. Install the package in editable mode.
4. Confirm the package wiring.

```bash
python3 -m venv .venv
. .venv/bin/activate
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install -e .
PYTHONPATH=src .venv/bin/python -m tls_dataset info
```

## Main Workflows

### 1. Run the standardized dataset pipeline

```bash
PYTHONPATH=src .venv/bin/python -m tls_dataset run-dataset-pipeline \
  --dataset-name benign \
  --output-dir artifacts/runs/benign_local \
  --pcap data/raw/benign_filtered.pcap \
  --zeek-log-dir data/zeek/benign \
  --extract-nfstream \
  --convert-zeek
```

### 2. Prepare and process malicious captures

```bash
PYTHONPATH=src .venv/bin/python -m tls_dataset run-malicious-pipeline \
  --dataset-name malicious_ready \
  --input-pcap BotnetCapture/malicious_filtered.pcap \
  --output-dir artifacts/runs/malicious_ready \
  --manifest-csv BotnetCapture/manifest.csv \
  --prepare-only \
  --extract-nfstream-after-prepare
```

### 3. Build the canonical labeled dataset

```bash
PYTHONPATH=src .venv/bin/python -m tls_dataset build-canonical-dataset \
  --config configs/canonical_sources.yaml \
  --output-csv artifacts/canonical/canonical_labeled_flows.csv \
  --output-summary-json artifacts/canonical/canonical_labeled_flows_summary.json
```

### 4. Train and evaluate the ML workflow

```bash
PYTHONPATH=src .venv/bin/python -m tls_dataset run-ml-workflow \
  --config configs/ml_workflow.yaml
```

### 5. Run multi-tier scoring and graph enrichment

```bash
PYTHONPATH=src .venv/bin/python -m tls_dataset run-multi-tier \
  --config configs/multi_tier_workflow.yaml
```

### 6. Export the static analytical site bundle

```bash
PYTHONPATH=src .venv/bin/python -m tls_dataset export-static-dashboard \
  --output-dir showcase
```

## Backend Scoring Platform

The backend exposes a scoring-oriented API rather than a notebook-style workflow.

Main capabilities:

- job intake for PCAP scoring
- batch tracking and metadata persistence
- model-bundle discovery
- local or S3-compatible object storage support
- queue-backed worker processing
- artifact registration for produced outputs

Main modules:

- `src/tls_dataset/backend/app.py`
- `src/tls_dataset/backend/worker.py`
- `src/tls_dataset/backend/scoring.py`
- `src/tls_dataset/backend/services.py`
- `src/tls_dataset/backend/storage.py`

Environment template:

- `configs/backend.env.example`

Compose stack:

- `api`
- `worker`
- `postgres`
- `redis`
- `minio`

Start the platform stack with:

```bash
docker compose up --build
```

## Verification

Run the test suite with:

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests
```

## Documentation

Project documentation lives in:

- [docs/README.md](docs/README.md)
- [docs/backend-platform.md](docs/backend-platform.md)
- [docs/project-journey.md](docs/project-journey.md)
- [docs/findings-register.md](docs/findings-register.md)
- [docs/artifact-index.md](docs/artifact-index.md)

## Notes

- Large PCAPs, generated artifacts, and local presentation assets are intentionally ignored by Git.
- The thesis PDF is preserved in `Thesis/` as the academic reference point for the implementation.
- The static site output under `showcase/` is local-only and is not intended for repository publication.
