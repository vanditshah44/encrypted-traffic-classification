# EncFlow Project Work Plan

This plan is written for turning the current thesis-derived repository into a strong, defensible research artifact and paper submission. It assumes the active project is the top-level repository only; `encclassi/` is ignored.

The target is not just "make the numbers look good." The target is to make the system scientifically credible: reproducible data, honest evaluation, clear claims, working code, clean artifacts, and a paper whose tables and figures are generated from the same evidence the repository produces.

## Current Project Understanding

The project implements EncFlow: a privacy-preserving encrypted traffic analytics system for detecting malicious activity in TLS/QUIC traffic without decrypting payloads.

The active system has these major layers:

- Data pipeline: PCAP preparation, sanitization, TLS/QUIC filtering, Zeek execution/conversion, NFStream extraction, feature merging, quality gates, pruning, and canonical dataset construction.
- Dataset layer: canonical labeled flow CSVs with metadata such as `label`, `label_id`, `capture_id`, `protocol_family`, `window_id`, `source_dataset`, `quality_status`, and provenance paths.
- ML layer: GaussianNB, RandomForest, GradientBoosting, and XGBoost training with capture holdout, capture-aware CV, threshold sweeps, feature manifests, prediction exports, ROC/PR curves, and saved models.
- Multi-tier detection layer: Tier 1 GNB triage, Tier 2 RF/GB/XGB consensus, and Tier 3 endpoint graph enrichment.
- Backend platform: FastAPI job intake, queue-backed PCAP scoring, SQLite/Postgres-compatible metadata, object storage abstraction, model-bundle discovery, artifact registration, and batch/job APIs.
- Reporting/dashboard layer: artifact snapshot aggregation, static dashboard export, graph views, model summaries, quality status, and flow exploration helpers.
- Paper layer: ACSAC 2026 draft, figures, experiment plan, and submission checklist.

The code is not a throwaway prototype. It already has meaningful structure and tests. The test suite currently passes: 38 tests. The main weakness is not "there is no system"; the weakness is that the research evidence is not yet strong enough for top-tier claims.

## Honest Current Status

The project is promising but not yet ACSAC-ready as a technical paper.

The strongest current evidence is:

- `artifacts/canonical_v2/canonical_labeled_flows.csv`: 68,917 labeled TLS/QUIC flows.
- 9 capture IDs: 4 malicious, 5 benign.
- Held-out capture evaluation using `ctu_botnet_369_1` and `ctu_normal_21`.
- RandomForest held-out F1 around 0.880 and ROC-AUC around 0.961.
- Multi-tier Tier 2 precision around 0.996 and F1 around 0.830.
- Pure-flow RF F1 around 0.869, only 0.011 below all-features RF.

The main risks are:

- Quality status is mostly `fail` or `unknown`; there are no clean `pass` rows in the v2 canonical summary.
- Zeek TLS metadata is incomplete for malicious captures, creating feature-provenance asymmetry.
- Malicious data is still dominated by `ctu_botnet_primary`.
- QUIC coverage is only about 2%.
- Ablation artifacts currently look wrong: reported baseline RF F1 is around 0.046, contradicting the main workflow.
- Paper figures are stale or synthetic in `ACSAC2026_submission/generate_figures.py`.
- The LaTeX paper currently does not compile cleanly because `\xmark` is undefined.
- There is no leave-one-capture-out evaluation yet.
- There is no cross-dataset generalization experiment yet.
- There is no controlled adversarial perturbation experiment yet.

## Publication Strategy

### Primary Near-Term Target: WTMC 2026

WTMC is the best fit for the current work if strengthened properly. The project is about traffic measurement, encrypted traffic classification, anomaly detection, flow-level cybersecurity, and reproducible artifacts. That matches WTMC better than forcing an ACSAC technical submission before the evidence is mature.

The paper angle should be:

> EncFlow is a reproducible metadata-only encrypted traffic measurement and detection pipeline. It shows how capture-aware evaluation changes conclusions compared with row-level evaluation, and it provides a practical multi-tier system for TLS/QUIC flow triage under no-decryption constraints.

Do not overclaim that the system "solves" TLS 1.3/QUIC malware detection. The stronger claim is that it provides a rigorous, reproducible, privacy-preserving framework and exposes where encrypted traffic detection works and where it remains limited.

### Secondary Target: ACSAC Case Study or Later Technical Paper

ACSAC technical paper is high risk unless the evidence is expanded substantially. ACSAC case study may be more realistic if the backend platform, deployment story, artifact reproducibility, and limitations are framed well.

### Paper Claim Boundary

Allowed claims after the current fixes:

- Metadata-only flow statistics can detect some TLS/QUIC botnet behavior across held-out captures.
- Capture-aware splits significantly reduce over-optimistic row-level evaluation.
- NFStream flow features carry most of the signal in the current dataset.
- Multi-tier consensus can dramatically reduce false positives compared with a recall-oriented front-door classifier.
- The system is reproducible and deployable as a research artifact.

Claims to avoid:

- General malware detection in all TLS 1.3/QUIC traffic.
- Strong QUIC conclusions.
- Production-grade adversarial robustness.
- Full GDPR compliance unless anonymization and retention behavior are actually implemented and tested end to end.
- Zeek+NFStream parity across classes until quality-pass rows exist.

## Phase 0: Repository Hygiene and Evidence Freeze

Goal: Make the project unambiguous and prevent future confusion.

Tasks:

1. Add a short root-level note that `encclassi/` is out-of-scope or remove it from the research artifact bundle.
2. Decide which artifact directories are authoritative:
   - Canonical dataset: `artifacts/canonical_v2/`
   - ML full run: `artifacts/ml_workflow/v2_full/`
   - ML pure-flow run: `artifacts/ml_workflow/v2_pure_flow/`
   - Multi-tier run: `artifacts/multi_tier/v2_latest/`
3. Stop using stale directories such as `artifacts/canonical/`, `artifacts/ml_workflow/latest/`, and `artifacts/multi_tier/latest/` for paper claims unless they are deliberately regenerated.
4. Create a single `artifacts/MANIFEST_v2.md` or JSON manifest that records:
   - dataset path
   - source configs
   - command used
   - date generated
   - git commit if available
   - row counts
   - capture counts
   - quality status counts
   - model outputs
5. Add a `make` target or script alias for the canonical v2 workflow.

Acceptance criteria:

- A reader can identify the authoritative v2 dataset and model bundle in under one minute.
- No paper table or figure depends on stale `latest` output unless `latest` is deliberately synced to v2.
- The artifact manifest matches current generated files.

## Phase 1: Make the Paper and Figures Evidence-Generated

Goal: Remove all stale, synthetic, and hand-copied paper evidence.

Problems found:

- `ACSAC2026_submission/generate_figures.py` still hardcodes `49,158` flows.
- The ROC figure is described as reconstructed from thesis values.
- The paper text uses v2 values, but the figure script still reflects older artifacts.
- LaTeX uses `\xmark` without defining it.

Tasks:

1. Fix LaTeX compile:
   - Add `\usepackage{pifont}` and define:
     - `\newcommand{\cmark}{\ding{51}}`
     - `\newcommand{\xmark}{\ding{55}}`
   - Or replace `\xmark`/`\checkmark` with text-safe alternatives.
2. Update `generate_figures.py` to read real artifacts:
   - `artifacts/canonical_v2/canonical_labeled_flows_summary.json`
   - `artifacts/ml_workflow/v2_full/random_forest/roc_curve.csv`
   - `artifacts/ml_workflow/v2_full/model_comparison.csv`
   - `artifacts/multi_tier/v2_latest/workflow_summary.json`
3. Regenerate:
   - `pipeline.pdf` using 68,917 flows and 53 training features.
   - `tiers.pdf` using v2 held-out counts: 12,871 rows, 11,727 Tier-1 candidates, 6,956 Tier-2 suspicious rows, 2 clusters.
   - `roc_rf.pdf` from actual ROC CSV, not synthetic points.
4. Add new figures if space allows:
   - Capture distribution bar chart.
   - Per-capture held-out/LOCO results.
   - Threshold trade-off curve for GNB.
   - Quality status / provenance caveat diagram.
5. Replace all stale paper checklist references to 49,158 flows.
6. Add an automated paper table generator:
   - `scripts/generate_paper_tables.py`
   - Output `ACSAC2026_submission/generated/tables.tex` or Markdown/CSV tables.
   - Tables should be generated from artifact CSV/JSON files.

Acceptance criteria:

- `pdflatex -interaction=nonstopmode main.tex` exits cleanly after two runs.
- No `49,158` or synthetic ROC references remain in active paper-generation code.
- Every number in the paper can be traced to an artifact file.
- Paper figure captions match actual artifact values.

## Phase 2: Fix Ablation and Feature-Group Evidence

Goal: Make the feature analysis defensible.

Problem:

The current ablation artifact reports baseline RF F1 around 0.046. This contradicts the main workflow and should not be used.

Likely causes to investigate:

- Ablation uses grouped cross-validation with folds that lack class balance because capture groups are highly imbalanced.
- `StratifiedGroupKFold` may produce folds where the model has insufficient class diversity.
- The ablation code reports CV predictions over training captures, while the main table reports held-out capture test metrics.
- The label orientation or probability column may be wrong in the ablation path.
- Feature column count differs from the main workflow: ablation reports 67 features while v2 full reports 53 training features.

Tasks:

1. Reproduce the ablation issue with a small debug run.
2. Compare feature columns:
   - `artifacts/ml_workflow/v2_full/feature_manifest.json`
   - ablation-selected feature list
3. Make ablation use the exact same train/test split as the main workflow:
   - Train on all non-held-out captures.
   - Evaluate each ablation on the same held-out captures.
   - Report held-out F1 and ROC-AUC, not only CV.
4. Add a second ablation mode:
   - LOCO ablation after LOCO is implemented.
5. Make feature groups explicit and saved:
   - timing
   - packet size
   - volume/directionality
   - TCP flags
   - port/protocol
   - DPI/application confidence
   - burst/SPLT if present
6. Add tests for ablation:
   - Feature group matching works.
   - Baseline ablation equals main workflow behavior on a synthetic dataset.
   - Removing a feature group actually removes only intended columns.
7. Do not include ablation in the paper until fixed.

Acceptance criteria:

- Ablation baseline RF held-out F1 is close to the main RF held-out F1 when using the same split.
- Feature count matches the main workflow or differences are explained.
- The generated ablation table has plausible deltas.
- The paper discusses ablation as evidence, not speculation.

## Phase 3: Implement Leave-One-Capture-Out Evaluation

Goal: Produce the most important missing generalization evidence.

Current setup:

- Training/test split holds out `ctu_botnet_369_1` and `ctu_normal_21`.
- Cross-validation uses `StratifiedGroupKFold` over remaining captures.

Why LOCO matters:

Reviewers will ask whether performance depends on a lucky held-out pair. LOCO gives per-capture failure modes and makes the paper more honest.

Tasks:

1. Add LOCO support to `src/tls_dataset/ml/workflow.py` or create `src/tls_dataset/ml/loco.py`.
2. For each capture:
   - Hold out one capture as test.
   - Train on all other captures.
   - If the held-out capture contains only one class, report binary metrics carefully:
     - recall for malicious captures
     - false positive rate for benign captures
     - omit ROC-AUC when only one class is present
3. Also run paired holdouts:
   - One malicious capture + one benign capture per fold.
   - This gives full binary metrics per pair.
4. Save:
   - `artifacts/ml_workflow/loco/per_capture_metrics.csv`
   - `artifacts/ml_workflow/loco/per_pair_metrics.csv`
   - `artifacts/ml_workflow/loco/loco_summary.json`
5. Include model set:
   - RF
   - GB
   - XGBoost
   - GNB
   - Multi-tier if feasible
6. Add paper table:
   - capture_id
   - label
   - rows
   - model
   - precision/recall/F1 when valid
   - false positives or false negatives
7. Add paper discussion:
   - Which captures fail?
   - Are failures caused by low row count?
   - Are old CTU captures different from newer botnet captures?
   - Does `ctu_botnet_primary` dominance matter?

Acceptance criteria:

- LOCO results exist and can be regenerated.
- The paper reports variability, not only aggregate performance.
- If performance drops, the paper uses that honestly as a contribution: capture-aware evaluation exposes limits hidden by row-level metrics.

## Phase 4: Improve Dataset Diversity

Goal: Reduce source-correlation and capture-dominance objections.

Current dataset:

- 68,917 total flows.
- 41,205 malicious, 27,712 benign.
- 4 malicious captures, 5 benign captures.
- `ctu_botnet_primary` contributes 30,172 malicious flows.
- QUIC contributes only 1,403 flows.

Tasks:

1. Add more malicious TLS/HTTPS botnet captures:
   - Prioritize captures with real TLS/HTTPS flows.
   - Avoid adding PCAPs that produce only a handful of TLS flows unless used as negative evidence.
2. Add more benign captures:
   - Different OS.
   - Different browser.
   - Different time period.
   - Different network environment.
   - Cloud/API/update-heavy traffic, because these cause false positives.
3. Add a `capture_weighting` or `max_rows_per_capture` option:
   - Prevent `ctu_botnet_primary` from dominating training.
   - Run experiments with capped per-capture rows, such as 5,000 or 10,000 per capture.
4. Add source-balance experiment:
   - Full dataset.
   - Downsampled balanced-by-capture dataset.
   - Balanced-by-class dataset.
5. Add capture summary table:
   - capture_id
   - label
   - year
   - family/environment
   - raw PCAP size
   - TLS rows
   - QUIC rows
   - quality status
   - Zeek outputs present
6. Rebuild canonical v3 after adding sources.

Acceptance criteria:

- At least 8-10 malicious captures with meaningful TLS/QUIC flow counts.
- No single malicious capture contributes more than 40-50% of malicious rows in the primary evaluation dataset, or the imbalance is controlled by sampling.
- Per-capture results are reported.
- Dataset construction config is clean and fully documented.

## Phase 5: Fix Zeek Quality and Provenance Asymmetry

Goal: Make the Zeek + NFStream claim accurate and reduce reviewer objections.

Current issue:

Many CTU-Malware rows are marked `quality_status=fail`, often because Zeek did not produce `ssl.csv`, `tls.csv`, or `quic.csv`.

Tasks:

1. Inspect each quality report under `artifacts/runs/*/*_quality_report.json`.
2. Build a quality matrix:
   - capture_id
   - conn.csv present
   - ssl.csv present
   - tls.csv present
   - quic.csv present
   - x509.csv present
   - NFStream CSV rows
   - merged rows
   - encrypted rows retained
   - failure reason
3. Try Zeek reruns with:
   - explicit protocol analyzers
   - current Zeek version
   - older Zeek/Bro version if CTU PCAPs are old
   - unfiltered PCAP vs TLS/QUIC filtered PCAP
4. If Zeek still fails for old captures, separate the claim:
   - "NFStream-only benchmark path"
   - "Zeek+NFStream platform path"
5. Add code-level distinction:
   - `feature_view=nfstream_only`
   - `feature_view=zeek_nfstream`
6. Add a strict mode:
   - Train only on quality-pass rows.
   - This may reduce data heavily, but it provides an honest upper/lower comparison.
7. Add a "quality-aware experiment":
   - all rows
   - quality-pass-only rows
   - NFStream-only feature set
8. Update paper:
   - Do not imply all rows are Zeek-validated.
   - Make the feature-provenance asymmetry a central limitation.

Acceptance criteria:

- Every quality failure has a documented reason.
- Paper claims match actual feature provenance.
- At least one experiment demonstrates whether quality-failed rows materially affect results.

## Phase 6: Cross-Dataset Generalization

Goal: Show the model is not only learning CTU/lab artifacts.

Tasks:

1. Select one external dataset with PCAPs and attack labels:
   - CIC-IDS2018 if PCAP access is practical.
   - UNSW-NB15 if raw PCAPs and labels can be aligned.
   - USTC-TFC or another encrypted traffic dataset if labels are suitable.
2. Build a mapper from external labels to:
   - benign
   - malicious
   - unknown/excluded
3. Extract the same NFStream features.
4. Build an external canonical dataset:
   - `artifacts/canonical_external/...`
5. Run zero-shot evaluation:
   - Train on EncFlow v2/v3.
   - Test on external dataset.
   - No retraining.
6. Run fine-tuning comparison:
   - Train on external train split.
   - Test on external test split.
   - Compare with zero-shot.
7. Report:
   - zero-shot F1
   - zero-shot precision/recall
   - false-positive rate
   - performance by attack family if labels allow
8. If results are poor, use them honestly:
   - "Cross-dataset generalization remains limited."
   - This is still publishable if the evaluation is rigorous.

Acceptance criteria:

- At least one external zero-shot result exists.
- The paper does not claim broad generalization without this evidence.
- Failures are analyzed rather than hidden.

## Phase 7: Adversarial Robustness and Traffic Shaping

Goal: Address an obvious encrypted-traffic reviewer objection.

Threats to test:

- Packet padding.
- Timing jitter.
- Flow throttling.
- Burst smoothing.

Practical approach:

Start with feature-space perturbation before PCAP-level perturbation. PCAP-level perturbation is more realistic but slower and harder.

Tasks:

1. Implement `src/tls_dataset/ml/perturbation.py`.
2. Feature-space perturbations:
   - Add jitter to IAT features.
   - Scale packet-size features.
   - Smooth burst features.
   - Modify byte ratios toward benign medians.
3. Evaluate perturbation strengths:
   - 5%, 10%, 20%, 40%, 80%.
4. Report degradation curves:
   - RF F1 vs perturbation strength.
   - Tier-2 precision/recall vs perturbation strength.
   - Which feature groups are most fragile.
5. If time permits, add PCAP-level perturbation:
   - Use Scapy/editcap/tcprewrite where possible.
   - Re-extract NFStream features.
6. Add "adaptive adversary" discussion:
   - What can an adversary realistically change?
   - What changes harm C2 reliability?
   - What remains undetectable?

Acceptance criteria:

- Perturbation experiment produces CSV and plots.
- Paper includes at least one robustness figure or table.
- Claims are conservative: this is a stress test, not proof of robustness.

## Phase 8: Strengthen the Multi-Tier Detection Story

Goal: Make the three-tier architecture look necessary rather than decorative.

Current issue:

Tier 1 GNB has high recall but ROC-AUC below 0.5. The paper argues this is acceptable because GNB is used at one operating point, but reviewers may challenge it.

Tasks:

1. Add Tier-1 alternatives:
   - LogisticRegression
   - LinearSVM or SGDClassifier
   - shallow RandomForest
   - calibrated HistGradientBoosting if suitable
2. Compare Tier-1 options under constraints:
   - inference speed
   - recall at fixed candidate budget
   - false negative rate
   - calibration
3. Add candidate-budget curves:
   - x-axis: candidate rate
   - y-axis: malicious recall
   - compare GNB, LR, shallow RF
4. Decide whether GNB remains justified.
5. Make Tier-2 consensus configurable:
   - all models agree
   - majority agree
   - weighted score threshold
   - precision-target threshold
6. Add graph evaluation:
   - cluster purity when labels exist
   - number of internal hosts
   - repeated windows
   - endpoint degree distribution
7. Add analyst utility metrics:
   - flow alerts reduced to clusters
   - suspicious flows per cluster
   - false-positive clusters
   - investigation workload reduction

Acceptance criteria:

- The paper explains why each tier exists using data, not only design intuition.
- Tier 1 is either replaced by a stronger model or defended with candidate-budget results.
- Tier 3 has an analyst-workload argument.

## Phase 9: Backend and Deployment Hardening

Goal: Make the backend a credible artifact, not just extra code.

Current backend capabilities:

- FastAPI health and model-bundle endpoints.
- PCAP upload and path-based scoring job creation.
- Batch/job persistence.
- Queue abstraction.
- Object storage abstraction.
- PCAP scoring pipeline into multi-tier inference.

Tasks:

1. Add an end-to-end backend integration test:
   - create app
   - submit small PCAP or fixture
   - run worker in sync mode
   - verify artifacts are created and registered
2. Add a "local demo" script:
   - start API
   - submit sample PCAP
   - poll job
   - print suspicious clusters
3. Improve health checks:
   - Zeek available
   - tshark/editcap available
   - NFStream import available
   - model bundle valid
4. Add model-bundle validation:
   - required model directories exist
   - `feature_manifest.json` exists
   - thresholds exist
   - model files load
5. Add job failure diagnostics:
   - failed stage
   - stderr tail
   - missing dependency
   - quality gate failure
6. Add backend artifact documentation:
   - which artifacts are produced
   - how to retrieve them
   - how to reproduce a scoring run
7. Decide whether backend belongs in the paper:
   - For WTMC, backend can be artifact/deployment evidence.
   - Do not let backend distract from measurement/evaluation contribution.

Acceptance criteria:

- A reviewer can run a local scoring demo.
- Backend endpoints are tested at least at API contract level.
- Model-bundle errors fail early with clear messages.

## Phase 10: Privacy, Ethics, and GDPR Claims

Goal: Make privacy claims technically accurate.

Current paper claims:

- Metadata-only analysis.
- IP anonymization via salted hashing.
- No payload decryption.
- GDPR-compliant by construction.

Risk:

If salted hashing or retention policies are not implemented in the active pipeline, those claims are too strong.

Tasks:

1. Audit code for actual anonymization:
   - Are IPs hashed before ML training?
   - Are domains/SNI retained?
   - Are raw IPs present in canonical CSV?
2. If anonymization is missing, implement it:
   - configurable salt
   - hash IPs
   - optionally hash domains/server names
   - preserve private/public indicator
   - preserve graph consistency
3. Add anonymization tests:
   - no raw IPv4/IPv6 addresses in released canonical CSV when anonymization enabled
   - same endpoint hashes consistently within a run
   - different salt changes hashes
4. Add artifact release mode:
   - raw internal artifact
   - anonymized public artifact
5. Rewrite GDPR claim:
   - Say "privacy-preserving design" and "metadata-only" unless full compliance is legally verified.
   - Avoid claiming GDPR compliance as a legal conclusion unless supervised by legal review.

Acceptance criteria:

- Privacy claims match actual code behavior.
- Public artifact mode does not leak raw IPs.
- Ethics section is defensible.

## Phase 11: Reproducibility Package

Goal: Make the work independently rerunnable.

Tasks:

1. Create `REPRODUCIBILITY.md`.
2. Include exact commands:
   - environment setup
   - data download
   - malicious pipeline
   - benign pipeline
   - canonical dataset build
   - ML workflow
   - pure-flow workflow
   - ablation
   - LOCO
   - multi-tier detection
   - figure/table generation
3. Pin external tool versions:
   - Python
   - Zeek
   - tshark/editcap
   - NFStream
   - scikit-learn
   - XGBoost
4. Add a `scripts/check_environment.py`:
   - verifies Python deps
   - verifies external binaries
   - checks artifact directories
5. Add `scripts/reproduce_v2.sh`:
   - no hidden manual steps
   - logs to `artifacts/reproduce_logs/`
6. Add checksums for downloaded PCAPs if redistribution is not possible.
7. Add a small fixture workflow:
   - tiny PCAP or synthetic CSV
   - runs quickly in CI
   - validates pipeline wiring without large data.

Acceptance criteria:

- A fresh clone can reproduce core tables with documented data access.
- Missing external tools produce clear errors.
- Reviewer artifact instructions are short and reliable.

## Phase 12: Test Suite Expansion

Goal: Move from utility tests to research-guarantee tests.

Current tests are useful but light on full workflow guarantees.

Add tests for:

1. Canonical dataset:
   - metadata columns exist
   - no metadata leakage into feature list
   - capture IDs preserved
   - encrypted filtering works
2. ML workflow:
   - capture holdout excludes test captures from training
   - `StratifiedGroupKFold` receives groups
   - feature manifest excludes absolute time and labels
   - test predictions row count matches held-out split
3. Ablation:
   - baseline equals normal workflow on synthetic data
   - feature group removals are correct
4. LOCO:
   - each fold holds out the intended capture
   - one-class test folds are handled safely
5. Multi-tier:
   - Tier 2 only scores Tier-1 candidates
   - thresholds load correctly
   - graph clusters are stable
6. Backend:
   - model bundle validation
   - job creation
   - artifact classification
   - sync scoring path with fixtures
7. Paper generation:
   - generated tables parse
   - required artifact files exist
   - no stale old flow counts in generated figures.

Acceptance criteria:

- Tests still run quickly by default.
- Slow/integration tests are marked separately.
- Core scientific assumptions are covered by tests.

## Phase 13: Paper Rewrite Plan

Goal: Produce a paper that reviewers can trust.

Recommended title direction:

- "EncFlow: Capture-Aware Measurement and Detection of Malicious TLS/QUIC Flows Without Decryption"
- Or for WTMC: "EncFlow: A Reproducible Measurement Pipeline for Metadata-Only Detection of Malicious Encrypted Traffic"

Recommended structure:

1. Introduction:
   - encrypted traffic creates visibility limits
   - naive row-level ML overstates performance
   - contribution is a reproducible, capture-aware, metadata-only pipeline
2. Background:
   - TLS 1.3/QUIC visibility
   - metadata-only threat model
3. System:
   - PCAP processing
   - NFStream/Zeek feature extraction
   - quality gates
   - canonical dataset
   - ML workflow
   - multi-tier detector
4. Dataset:
   - exact captures
   - counts
   - quality status
   - QUIC share
   - limitations
5. Evaluation:
   - held-out capture
   - LOCO
   - pure-flow
   - ablation
   - perturbation
   - optional cross-dataset
6. Results:
   - main model table
   - multi-tier table
   - LOCO variability
   - feature group findings
   - robustness/cross-dataset
7. Discussion:
   - what works
   - what fails
   - deployment implications
   - limits
8. Ethics and artifact availability.

Tone:

- Be honest and precise.
- Treat limitations as part of the contribution.
- Do not hide weak results.
- Avoid inflated "production-grade" language in the paper.
- Keep "backend platform" as artifact/deployment support unless evaluated.

Acceptance criteria:

- The abstract contains only numbers generated by the artifact pipeline.
- The limitations section is not apologetic; it explains measurement reality.
- The conclusion does not overstate generalization.

## Phase 14: Final Pre-Submission Checklist

Before any submission:

1. Run all tests.
2. Rebuild canonical dataset from config.
3. Rerun ML workflow.
4. Rerun pure-flow workflow.
5. Rerun ablation.
6. Rerun LOCO.
7. Rerun perturbation.
8. Rerun multi-tier workflow.
9. Regenerate tables.
10. Regenerate figures.
11. Compile paper twice.
12. Check PDF metadata.
13. Search for identity leaks if double-blind.
14. Search for stale numbers:
    - `49,158`
    - `49158`
    - `1.0`
    - `0.999`
    - `thesis`
    - local usernames
15. Verify all citations exist.
16. Verify every figure and table is referenced.
17. Verify artifact instructions work on a clean environment.

Acceptance criteria:

- Clean tests.
- Clean LaTeX compile.
- No stale numbers.
- No synthetic figures.
- Artifact manifest matches paper.

## Suggested Execution Order

### Week 1: Evidence Cleanup

- Fix LaTeX compile.
- Fix figure generation.
- Generate paper tables from artifacts.
- Fix ablation or remove it from the paper.
- Add artifact manifest.

### Week 2: Core Evaluation

- Implement LOCO.
- Add capture-balanced/downsampled experiment.
- Add per-capture analysis.
- Update paper dataset and results sections.

### Week 3: Robustness and Generalization

- Add feature-space perturbation.
- Attempt cross-dataset zero-shot evaluation.
- Add Tier-1 candidate-budget comparison.
- Strengthen multi-tier analysis.

### Week 4: Reproducibility and Paper Polish

- Add reproducibility guide.
- Add environment checker.
- Add generated tables/figures workflow.
- Clean paper claims.
- Prepare submission package.

## Highest-Impact Immediate Tasks

If time is short, do these first:

1. Fix stale/synthetic figures.
2. Fix LaTeX compile.
3. Fix ablation or remove it.
4. Implement LOCO.
5. Add per-capture result table.
6. Add artifact manifest.
7. Rewrite paper claims around capture-aware measurement, not universal detection.

These seven items will improve publishability more than adding another model.

## Definition of a Strong Final Project

The project is strong when:

- The data pipeline can be rerun from documented sources.
- The paper's numbers are generated, not hand-copied.
- Evaluation is capture-aware and includes per-capture variability.
- Quality/provenance limitations are explicit and measured.
- Feature claims are backed by fixed ablation or permutation evidence.
- Robustness is tested at least with controlled feature perturbations.
- The backend has a working demo but does not distract from the research contribution.
- Privacy claims are implemented, tested, and worded carefully.
- The reviewer can reproduce the main tables and figures.

At that point, EncFlow becomes a credible research artifact: not perfect, but honest, useful, and much harder to reject on methodological grounds.
