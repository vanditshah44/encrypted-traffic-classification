# Findings Register

This document captures the main technical findings from the implementation work completed so far. It is intended to be updated as new phases land.

## Confirmed Improvements

### 1. The project now has a reproducible software structure

Finding:

- the original workspace was a thesis prototype with scattered scripts and no dependable project layout
- the current repository now has package code, tests, configs, Docker assets, and artifact directories

Evidence:

- `src/tls_dataset/`
- `tests/`
- `configs/`
- `artifacts/`

Impact:

- the project can now be evolved as software rather than as a one-time research run

### 2. Production direction is no longer ambiguous

Finding:

- the thesis and code initially disagreed on the extraction stack
- the implementation now formally standardizes on Zeek + NFStream for production

Evidence:

- [ADR 0001](adr/0001-feature-extraction-stack.md)
- `src/tls_dataset/technical_direction.py`

Impact:

- the pipeline, model layer, and later reporting work now have one official feature-extraction story

### 3. Benign and malicious processing now share one pipeline path

Finding:

- the old project depended on one-off scripts and hardcoded filenames
- the refactor moved this into a parameterized pipeline package

Impact:

- dataset parity is stronger
- behavior is easier to test
- future automation can invoke the same code paths for both classes

## Data Findings

### 4. Benign merged data previously leaked non-encrypted traffic

Finding:

- the quality-gate run on the benign pipeline exposed substantial non-TLS/QUIC leakage in merged outputs before canonical filtering was enforced

Impact:

- this would have contaminated training and analytics if left unchecked
- it validated the decision to add explicit encrypted-traffic filtering and quality gates

### 5. The malicious source currently available in the workspace is not fully Zeek-usable

Finding:

- the malicious pipeline rebuild successfully sanitized the local capture and extracted NFStream features
- Zeek still produced only `conn.csv`, not `ssl.csv`, `tls.csv`, or `quic.csv`

Evidence:

- [malicious_full_v2_quality_report.json](../artifacts/runs/malicious_full_v2/malicious_full_v2_quality_report.json)
- `artifacts/runs/malicious_full_v2/malicious_full_v2_zeek_csv/conn.csv`
- `artifacts/runs/malicious_full_v2/malicious_full_v2_zeek_logs/weird.log`

Interpretation:

- the code path is implemented
- the remaining issue is the available source capture quality and completeness

### 6. The canonical dataset is usable but not yet fully trustworthy for strong generalization claims

Current canonical summary:

- rows: `49,158`
- columns: `115`
- benign rows: `18,986`
- malicious rows: `30,172`
- TLS rows: `47,759`
- QUIC rows: `1,399`

Finding:

- all malicious rows currently carry `quality_status=fail`
- benign rows currently carry `quality_status=unknown`

Evidence:

- [canonical_labeled_flows_summary.json](../artifacts/canonical/canonical_labeled_flows_summary.json)

Impact:

- the canonical dataset is suitable for workflow development and evidence generation
- it is not yet a strong final dataset for high-confidence deployment claims

## ML Findings

### 7. The full thesis model family is now implemented and producing evidence bundles

Finding:

- the ML workflow now trains and evaluates `GaussianNB`, `RandomForestClassifier`, and `GradientBoostingClassifier`
- it saves model files, predictions, plots, confusion matrices, threshold sweeps, and feature-importance outputs

Evidence:

- [latest](../artifacts/ml_workflow/latest)

Impact:

- the project can now reproduce and extend the thesis modeling story with saved, inspectable outputs

### 8. Tree-model performance is extremely strong on the current data and should be treated with caution

Observed results:

- `RandomForest` holdout metrics: perfect
- `GradientBoosting` holdout metrics: effectively perfect
- `GaussianNB` optimized holdout F1: `0.7973`
- `GaussianNB` holdout ROC-AUC: `0.6024`

Evidence:

- [model_comparison.csv](../artifacts/ml_workflow/latest/model_comparison.csv)
- [workflow_summary.json](../artifacts/ml_workflow/latest/workflow_summary.json)

Interpretation:

- the workflow itself is functioning correctly
- the current dataset likely allows class separation that is easier than a real deployment scenario

### 9. The current ML evidence already highlights the main scientific risks

Warnings recorded by the workflow:

- at least one source is quality-failed
- at least one class has fewer than two distinct captures
- the dataset is imbalanced

Impact:

- row-level stratified splits are useful for engineering progress
- they are not enough for a strong “production-generalizes” claim

## Detection Findings

### 10. The multi-tier design improves precision dramatically after the weak first pass

Observed multi-tier metrics:

- Tier 1 recall: `0.9909`
- Tier 1 specificity: `0.2164`
- Tier 2 precision: `1.0`
- Tier 2 recall: `0.9909`
- Tier 2 F1: `0.9954`

Evidence:

- [workflow_summary.json](../artifacts/multi_tier/latest/workflow_summary.json)

Interpretation:

- the lightweight front door is broad and noisy
- the deep-model consensus layer removes false positives effectively on the current dataset

### 11. Requiring both deep models was the right default refinement

Finding:

- allowing a single deep model to pass a flow left one benign false positive in the initial multi-tier run
- requiring both deep models removed that false positive without hurting recall on current data

Evidence:

- initial run: `artifacts/multi_tier/baseline`
- refined run: [latest](../artifacts/multi_tier/latest)
- configuration: `configs/multi_tier_workflow.yaml`

Impact:

- the default workflow is now cleaner and more defensible

### 12. Graph enrichment is already surfacing analyst-meaningful suspicious structure

Observed cluster summary:

- one dominant suspicious cluster
- `1,846` nodes
- `1,845` edges
- centered on internal host `10.0.2.109`
- spans `2` windows

Evidence:

- [graph_nodes.csv](../artifacts/multi_tier/latest/graph_nodes.csv)
- [graph_edges.csv](../artifacts/multi_tier/latest/graph_edges.csv)
- [suspicious_clusters.csv](../artifacts/multi_tier/latest/suspicious_clusters.csv)

Impact:

- the project has already moved into analyst-ready analytical territory

## Current Risks To Carry Forward

### 13. The malicious dataset is still the biggest evidence-quality weakness

Risk:

- without complete malicious captures that Zeek can parse cleanly, we remain NFStream-grounded for malicious feature truth

What it affects:

- confidence in end-to-end Zeek-backed malicious labeling
- strength of future academic and production claims

### 14. Tier 1 still misses some malicious flows

Risk:

- Tier 1 currently drops `274` malicious flows before deeper inference can inspect them

What it affects:

- recall ceiling for the overall detector
- design of future alerting and escalation policy

### 15. Current modeling likely overestimates real-world performance

Risk:

- perfect or near-perfect tree-model scores are probably influenced by limited capture diversity and source-specific separability

What it affects:

- how confidently we can market the detector today
- what kind of validation we need before calling the system production-ready

## Platform Findings

### 16. The project now has a real service-platform layer, not only offline workflows

Finding:

- the repository now includes a backend package with API, metadata persistence, object storage, and queued worker execution

Evidence:

- `src/tls_dataset/backend/app.py`
- `src/tls_dataset/backend/models.py`
- `src/tls_dataset/backend/storage.py`
- `src/tls_dataset/backend/worker.py`
- `docker-compose.yaml`

Impact:

- the project can now evolve toward analyst-facing dashboards and automated scoring services instead of remaining notebook-adjacent

### 17. The backend uses durable job and artifact metadata rather than transient local state

Finding:

- every submitted PCAP now maps to persisted batch/job records and artifact references
- object storage is treated as the source of truth for uploaded inputs and produced outputs

Impact:

- this is a necessary foundation for auditability, operator workflows, and multi-user platform behavior

### 18. Local live HTTP verification is blocked by the current execution sandbox, not by the platform code itself

Finding:

- the FastAPI/backend code compiles and the backend tests pass
- local port binding failed in this sandbox when trying to expose a live server session

Impact:

- backend correctness is currently supported by automated tests and direct invocation
- a full live service smoke test should be repeated on a host/container runtime that allows normal port binding

## Finalization Findings

### 19. The backend is cleaner after removing the web-served dashboard surface

Finding:

- the final platform keeps FastAPI focused on health, model-bundle discovery, job intake, batch tracking, and scoring orchestration
- dashboard-specific routes and static UI assets were removed from the backend service boundary

Impact:

- the runtime surface is simpler to secure and maintain
- the published repository now reflects the production scoring platform more directly

### 20. Snapshot aggregation is still available without coupling it to the backend web layer

Finding:

- artifact-summary and graph-snapshot logic was preserved in a neutral reporting module instead of being tied to a served dashboard

Impact:

- presentation exports can still be generated locally when needed
- the backend no longer has to carry UI responsibilities to support those exports
