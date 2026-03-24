# Project Journey

This repository has been transformed from a thesis-era script collection into a structured, testable, evidence-producing software project.

## Phase 1: Repository Foundation

We first turned the workspace into a real software repository with a clean package layout, configuration files, tests, Docker assets, and dependency manifests.

Implemented foundation:

- `src/tls_dataset/` as the application package
- `tests/` for automated validation
- `configs/` for pipeline and workflow settings
- `artifacts/` for generated evidence outputs
- `README.md`, `pyproject.toml`, `requirements.lock`, `.gitignore`, `.dockerignore`, `Dockerfile`, and `docker-compose.yaml`

Why it mattered:

- the original project was not organized as a reproducible software repo
- there was no stable place for package code, configs, tests, or generated outputs
- production delivery requires traceable structure before it requires more features

## Phase 2: Technical Direction Standardization

The thesis text and the codebase were not aligned on the extraction stack, so we formally standardized the production direction around Zeek + NFStream.

Implemented decision:

- [ADR 0001](adr/0001-feature-extraction-stack.md) records Zeek + NFStream as the official production extraction stack
- `src/tls_dataset/technical_direction.py` provides a code-level source of truth
- the main README now reflects the same decision

Why it mattered:

- it removed ambiguity between thesis claims and code reality
- it prevented the project from drifting into parallel unsupported extraction paths
- it gave us one forward-compatible feature-extraction story for production

## Phase 3: Parameterized Pipeline Refactor

The original workflow was driven by one-off scripts with hardcoded filenames and dataset-specific assumptions. We refactored that work into a parameterized pipeline package so benign and malicious traffic follow the same execution path.

Implemented pipeline modules:

- shared artifact and path handling under `src/tls_dataset/pipeline/common.py`
- orchestration under `src/tls_dataset/pipeline/orchestration.py`
- modular steps for PCAP handling, Zeek conversion, NFStream extraction, feature merging, pruning, and dataset finalization
- legacy root scripts kept only as thin wrappers so they no longer contain separate business logic

Why it mattered:

- benign and malicious processing now share one implementation path
- the code is testable and reusable instead of tied to a single notebook-era run
- future API and reporting layers can call package code instead of shelling out to ad hoc scripts

## Phase 4: Data-Quality Gates

Before allowing feature generation to continue, we inserted explicit quality gates into the pipeline.

Implemented checks:

- truncated PCAP detection
- missing required Zeek outputs
- duplicate NFStream flow-key detection
- bad NFStream-to-Zeek join quality
- unmatched UID rate checks
- non-TLS/QUIC leakage detection
- duplicate UID checks after merge

Why it mattered:

- the old pipeline could silently produce invalid training inputs
- bad joins and off-target traffic would otherwise contaminate modeling and reporting
- failing fast gives us evidence-backed trust boundaries instead of assumptions

## Phase 5: Environment and Real Pipeline Execution

Once the package structure existed, we installed the working environment and executed the real pipeline against available data.

Important outcomes:

- the benign pipeline completed and produced ML-ready outputs
- the benign quality gate exposed a major leakage problem in merged data before encrypted-only filtering
- the malicious PCAP was confirmed to be truncated in its original state
- NFStream extraction worked on the malicious source, but full Zeek evidence did not

This phase gave us a crucial truth: the code could run, but the data itself still required careful curation.

## Phase 6: Malicious Pipeline Rebuild

We then rebuilt the malicious path as a first-class workflow rather than a sidecar hack.

Implemented malicious workflow:

- managed run directories
- raw, sanitized, and TLS/QUIC-filtered artifact preservation
- provenance tracking for each transformation step
- Zeek auto-detection and local Zeek execution support
- NFStream extraction on the sanitized full capture so session context is preserved

Key evidence:

- the sanitized malicious capture passed PCAP health checks
- NFStream extraction produced 30,220 flows with zero duplicate-flow rows
- Zeek still emitted only `conn.csv` for the available malicious source, not `tls.csv`, `ssl.csv`, or `quic.csv`

Interpretation:

- this is no longer an implementation gap
- it is a source-data limitation in the locally available malicious capture

## Phase 7: Canonical Labeled Dataset

We created one canonical labeled dataset to serve as the only truth for training and reporting.

Implemented dataset layer:

- canonical builder in `src/tls_dataset/pipeline/canonical.py`
- source declarations in `configs/canonical_sources.yaml`
- stable metadata fields including `label`, `attack_family`, `capture_id`, `protocol_family`, `window_id`, and `source_dataset`
- extra production-oriented labels such as `record_id`, `sample_id`, `quality_status`, `provenance_path`, and `input_csv`

Current canonical result:

- rows: `49,158`
- columns: `115`
- benign rows: `18,986`
- malicious rows: `30,172`
- TLS rows: `47,759`
- QUIC rows: `1,399`

Why it mattered:

- training, analytics, and later API responses now have a single shared schema
- time-window metadata enables both model training and timeline/cluster analytics
- downstream workflows no longer have to reinterpret raw source files differently

## Phase 8: Full ML Workflow

We implemented the supervised modeling workflow promised by the thesis and strengthened it with reproducible evidence outputs.

Implemented workflow:

- `GaussianNB`, `RandomForestClassifier`, and `GradientBoostingClassifier`
- stratified train/test split
- stratified 5-fold cross-validation
- threshold optimization
- holdout metrics
- confusion matrices
- ROC and PR curves
- native and permutation feature importance
- saved models and predictions

Current ML evidence summary:

- `RandomForest` achieved perfect holdout metrics on the current dataset
- `GradientBoosting` was effectively perfect as well
- `GaussianNB` remained much weaker, with optimized holdout F1 around `0.7973` and ROC-AUC around `0.6024`

Interpretation:

- the workflow is implemented correctly and producing strong evidence bundles
- the tree-model results are likely too optimistic because the current dataset has limited capture diversity and includes quality-failed malicious-source rows

This phase produced the right kind of proof: working code plus honest scientific warnings.

## Phase 9: Multi-Tier Detection

After the base models were stable, we implemented the thesis-style multi-tier logic and extended it with graph-based enrichment.

Implemented detection flow:

- Tier 1 lightweight filter with `GaussianNB`
- Tier 2 deeper inference using `RandomForest` and `GradientBoosting`
- weighted consensus scoring
- configurable deep-model agreement gate
- Tier 3 endpoint graph construction and suspicious-cluster enrichment

Important refinement:

- the first version allowed one deep model to pass a flow, which left one benign false positive
- the workflow was tightened to require both deep models by default: `min_deep_model_passes: 2`

Current multi-tier result:

- total rows scored: `49,158`
- Tier 1 candidates: `44,776`
- Tier 2 suspicious flows: `29,898`
- Tier 2 precision: `1.0`
- Tier 2 recall: `0.9909`
- Tier 2 F1: `0.9954`
- suspicious graph clusters: `1`
- graph nodes: `1,846`
- graph edges: `1,845`

Top cluster observation:

- the dominant suspicious cluster centers on internal host `10.0.2.109`
- it fans out to `1,844` public peers
- the cluster spans `2` time windows

Why it mattered:

- this moved the project beyond simple classification into analyst-oriented enrichment
- it created the exact type of evidence a future reporting surface can visualize
- it also revealed a remaining design issue: Tier 1 still drops 274 malicious flows before deeper analysis can recover them

## Phase 10: Backend Scoring Platform

We then started turning the repository into an operational platform instead of leaving it as a research pipeline plus offline scripts.

Implemented platform pieces:

- a FastAPI backend under `src/tls_dataset/backend/app.py`
- SQLAlchemy metadata models for batches, jobs, and artifacts
- Postgres-compatible persistence through `src/tls_dataset/backend/db.py`
- object-storage adapters for local and S3-compatible backends
- Redis + RQ queue integration for asynchronous PCAP scoring
- a worker process in `src/tls_dataset/backend/worker.py`
- a scoring path that turns merged PCAP outputs into inference-ready datasets and runs the multi-tier detector
- Docker Compose services for API, worker, Postgres, Redis, and MinIO

Why it mattered:

- it moved the system from “run scripts manually” toward a real service platform
- uploaded PCAPs can now become tracked jobs with preserved input/output artifact lineage
- the same project can now support future reporting surfaces, analyst APIs, and automation workflows

Verification outcome:

- backend metadata and artifact flows are covered by automated tests
- the full repository suite now passes with `38` tests
- live port binding could not be verified in this sandbox because the execution environment would not bind local ports, but the platform code itself compiled and the backend tests passed

## Phase 11: Finalization And Hardening

In the final cleanup pass, we removed the backend-served dashboard surface and returned the FastAPI service to a focused scoring-platform role.

Implemented hardening:

- removed the FastAPI-served dashboard routes and static UI assets
- moved artifact-snapshot aggregation into a neutral reporting module instead of coupling it to the backend web layer
- tightened the repository documentation so publishable materials reflect the final platform rather than intermediate UI iterations
- added ignore rules for local-only presentation assets that should not ship in the repository

Why it mattered:

- the backend now has a cleaner production boundary: API, queueing, metadata, storage, and scoring
- the repository no longer mixes operational services with temporary presentation surfaces
- the published project structure is closer to what a production scoring platform should look like

## What The Journey Has Established

The project is no longer just a thesis prototype. It now has:

- a structured package layout
- a formal technical direction
- parameterized pipelines
- quality gates
- provenance-aware malicious processing
- a canonical labeled dataset
- a full ML evidence workflow
- a multi-tier detection and graph-enrichment layer
- a backend scoring platform with metadata, object storage, and queued execution

Just as importantly, it has an honest record of what still needs work:

- the locally available malicious source is not yet fully Zeek-validated
- current tree-model performance is likely inflated by dataset limitations
- Tier 1 recall still needs tuning before this becomes a confident production detector
- live service smoke testing should be repeated outside this sandboxed runtime
