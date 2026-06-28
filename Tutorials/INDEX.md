# TLS Dataset Project — Tutorial Index

Complete file-by-file, function-by-function learning guide for the `tls_dataset` thesis
project. Every tutorial explains the **what**, **why**, and **how** so you can speak about
every design decision confidently in a defense or interview.

Work through the tutorials in order — they follow the natural data flow of the system.

---

## Part 0 — Orientation

| # | File | What you will learn |
|---|------|---------------------|
| 00 | [00_project_overview.md](00_project_overview.md) | High-level goal, architecture diagram, technology stack, end-to-end data flow, how every layer connects |

---

## Part 1 — Project Setup

| # | File | What you will learn |
|---|------|---------------------|
| 01 | [01_setup_and_installation.md](01_setup_and_installation.md) | `pyproject.toml`, `requirements.lock`, virtual env setup, editable install, CLI entry-point wiring |

---

## Part 2 — Configuration System

| # | File | What you will learn |
|---|------|---------------------|
| 02 | [02_configuration_system.md](02_configuration_system.md) | Both config systems (YAML files + env vars); every key in `base.yaml`, `dev.yaml`, `prod.yaml`, `canonical_sources.yaml`, `ml_workflow.yaml`, `multi_tier_workflow.yaml`, `backend.env.example` |

---

## Part 3 — Data Pipeline

| # | File | Source file | What you will learn |
|---|------|-------------|---------------------|
| 03 | [03_pipeline_common.md](03_pipeline_common.md) | `pipeline/common.py` | `DatasetArtifacts` — centralised path management; why every intermediate file path lives in one dataclass |
| 04 | [04_pipeline_filtering.md](04_pipeline_filtering.md) | `pipeline/filtering.py` | `editcap` sanitisation, `tshark` display filters, how only TLS/QUIC packets survive |
| 05 | [05_pipeline_zeek_runner.md](05_pipeline_zeek_runner.md) | `pipeline/zeek_runner.py` | Finding the Zeek binary, subprocess execution, log directory management |
| 06 | [06_pipeline_zeek_parser.md](06_pipeline_zeek_parser.md) | `pipeline/zeek.py` | Zeek log format detection (TSV vs JSON), parsing `ssl.log`, `tls.log`, `quic.log`, `conn.log`; every column |
| 07 | [07_pipeline_nfstream.md](07_pipeline_nfstream.md) | `pipeline/nfstream.py` | What NFStream does, bidirectional flow statistics, SPLT features, the extraction wrapper |
| 08 | [08_pipeline_merge.md](08_pipeline_merge.md) | `pipeline/merge_features.py` | Joining Zeek + NFStream on 4-tuple + timestamp tolerance; inner vs outer join; unmatched UIDs |
| 09 | [09_pipeline_quality_gates.md](09_pipeline_quality_gates.md) | `pipeline/quality.py` | Every quality gate: PCAP health, Zeek validation, merge match-rate, UID leakage, non-TLS/QUIC, duplicates |
| 10 | [10_pipeline_build_dataset.md](10_pipeline_build_dataset.md) | `pipeline/build_dataset.py` | Raw merged features → ML-ready: text encoding, identifier removal, numeric selection |
| 11 | [11_pipeline_pruning.md](11_pipeline_pruning.md) | `pipeline/pruning.py` | Near-constant removal, high-correlation removal; the statistical thresholds and why |
| 12 | [12_pipeline_finalize.md](12_pipeline_finalize.md) | `pipeline/finalize.py` | Final cleanup: dropping temporal leakage columns before training |
| 13 | [13_pipeline_orchestration.md](13_pipeline_orchestration.md) | `pipeline/orchestration.py` | `run_dataset_pipeline()` — chaining all stages, argument flow, error propagation |
| 14 | [14_pipeline_pcap.md](14_pipeline_pcap.md) | `pipeline/pcap.py` | Scapy-based PCAP merging, `RawPcapReader`/`PcapWriter`, why raw readers beat high-level APIs |
| 15 | [15_pipeline_provenance.md](15_pipeline_provenance.md) | `pipeline/provenance.py` | SHA-256 fingerprinting, artifact lineage tracking, why reproducibility matters in ML |
| 16 | [16_pipeline_malicious.md](16_pipeline_malicious.md) | `pipeline/malicious.py` | Specialised pipeline for botnet captures: preparation, manifest resolution, provenance recording |
| 17 | [17_pipeline_canonical.md](17_pipeline_canonical.md) | `pipeline/canonical.py` | Building a labeled dataset from multiple sources: `CanonicalSource`, YAML config, time windows, `record_id` hashing |
| 18 | [18_pipeline_inspect.md](18_pipeline_inspect.md) | `pipeline/inspect.py` | Flow inspection utility: per-column statistics, protocol distribution |

---

## Part 4 — Machine Learning

| # | File | Source file | What you will learn |
|---|------|-------------|---------------------|
| 19 | [19_ml_workflow.md](19_ml_workflow.md) | `ml/workflow.py` | Feature selection, imputation, stratified split, 5-fold CV, threshold optimisation, permutation importance, all output artifacts |

---

## Part 5 — Multi-Tier Detection

| # | File | Source file | What you will learn |
|---|------|-------------|---------------------|
| 20 | [20_detection_multitier.md](20_detection_multitier.md) | `detection/multitier.py` | Tier-1 (GaussianNB fast pass), Tier-2 (RF + GB weighted consensus), BFS graph clustering, alert level assignment |

---

## Part 6 — Backend Platform

| # | File | Source file | What you will learn |
|---|------|-------------|---------------------|
| 21 | [21_backend_config.md](21_backend_config.md) | `backend/config.py` | Environment-driven configuration: database URL, Redis, S3/MinIO, model paths; how `pydantic-settings` works |
| 22 | [22_backend_models_db.md](22_backend_models_db.md) | `backend/models.py`, `backend/db.py` | SQLAlchemy ORM: `JobBatch`, `ProcessingJob`, `JobArtifact`; engine/session factory; SQLite vs PostgreSQL |
| 23 | [23_backend_schemas.md](23_backend_schemas.md) | `backend/schemas.py` | Every Pydantic request/response model; what each API payload looks like |
| 24 | [24_backend_storage.md](24_backend_storage.md) | `backend/storage.py` | `LocalObjectStorage` and `S3ObjectStorage`; the abstraction interface; artifact movement |
| 25 | [25_backend_queue.md](25_backend_queue.md) | `backend/queue.py` | `InlineQueueBackend` (dev) vs `RQQueueBackend` (prod); job enqueueing and consumption |
| 26 | [26_backend_registry.md](26_backend_registry.md) | `backend/registry.py` | Model bundle discovery: scanning for `model.joblib` + `feature_manifest.json`; listing and loading |
| 27 | [27_backend_services.md](27_backend_services.md) | `backend/services.py` | Business logic: job creation, batch management, status updates, API serialisation |
| 28 | [28_backend_scoring.md](28_backend_scoring.md) | `backend/scoring.py` | Core scoring: runs malicious pipeline on uploaded PCAP, applies multi-tier detection, packages output |
| 29 | [29_backend_worker.md](29_backend_worker.md) | `backend/worker.py` | RQ worker: polling Redis queue, executing jobs, uploading results, updating job status |
| 30 | [30_backend_app.md](30_backend_app.md) | `backend/app.py` | FastAPI application: every route, request/response cycle, dependency injection, CORS, health check |

---

## Part 7 — Reporting and Static Site

| # | File | Source file | What you will learn |
|---|------|-------------|---------------------|
| 31 | [31_reporting_snapshot.md](31_reporting_snapshot.md) | `reporting/snapshot.py` | Read-only aggregator: `build_dashboard_summary`, `query_flow_explorer`, `build_graph_view`; `_json_safe_value`, `_bool_series` |
| 32 | [32_static_site_export.md](32_static_site_export.md) | `static_site/export_static_snapshot.py` | Presenter/decorator layer over snapshot.py; endpoint catalog; `data.json` vs `data.js`; `.nojekyll`; privacy masking |

---

## Part 8 — CLI and Entry Points

| # | File | Source file | What you will learn |
|---|------|-------------|---------------------|
| 33 | [33_cli_and_entry_points.md](33_cli_and_entry_points.md) | `cli.py`, `__main__.py`, `technical_direction.py`, `__init__.py` | All seven subcommands, lazy imports, `[project.scripts]` entry point, `__main__.py` module invocation, `TECHNICAL_DIRECTION` as frozen ADR |

---

## Part 9 — Data Acquisition

| # | File | Source file | What you will learn |
|---|------|-------------|---------------------|
| 34 | [34_pcap_downloader.md](34_pcap_downloader.md) | `pipeline/download.py` | Apache index crawler, resumable download with HTTP Range requests, path traversal prevention, download budget, progressive manifest writing |

---

## Part 10 — Root-Level Convenience Scripts

| # | File | Source files | What you will learn |
|---|------|-------------|---------------------|
| 35 | [35_root_shim_scripts.md](35_root_shim_scripts.md) | `zeektocsv.py`, `extract-nfstream.py`, `merge-pcaps.py`, `combineCSV.py`, `freeze_benign.py`, `sanityChecks-basic.py`, `clean.py`, `flows.py`, `mscp_down.py` | The shim wrapper pattern; `sys.path.insert(0, ...)` vs append; naming-to-module mapping; when to use scripts vs CLI |

---

## Part 11 — Test Suite

| # | File | Source files | What you will learn |
|---|------|-------------|---------------------|
| 36 | [36_test_suite.md](36_test_suite.md) | `tests/` (all 12 files) | `unittest.TestCase` rationale; `tempfile.TemporaryDirectory`, `patch.dict(os.environ)`, `clear_backend_settings_cache` patterns; fixture design; fake runner pattern; privacy assertions |

---

## Part 12 — Docker and Deployment

| # | File | What you will learn |
|---|------|---------------------|
| 37 | [37_docker.md](37_docker.md) | `Dockerfile`, `docker-compose.yaml`, `docker/` — every service, volume, port, build step, Zeek in container, MinIO/Redis/PostgreSQL wiring |

---

## Part 13 — Project Documentation

| # | File | What you will learn |
|---|------|---------------------|
| 38 | [38_docs.md](38_docs.md) | `docs/adr/`, `docs/findings-register.md`, `docs/project-journey.md`, `docs/artifact-index.md`, `docs/backend-platform.md` — architectural decisions, findings log, project history |

---

## Part 14 — Interview Preparation

| # | File | What you will learn |
|---|------|---------------------|
| 39 | [39_interview_cheatsheet.md](39_interview_cheatsheet.md) | Consolidated Q&A across all 38 tutorials: architecture, ML, networking, design decisions — every answer backed by actual code locations |

---

## Series complete at Tutorial 39

All source files in `src/tls_dataset/`, all tests, all configs, Docker deployment, and
project documentation are covered. Tutorial 39 is the final synthesis for interview and
defense preparation.

---

*Start with [00_project_overview.md](00_project_overview.md)*
