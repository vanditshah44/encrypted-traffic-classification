# Tutorial 38 — Project Documentation

## Files Covered

| File | Purpose |
|---|---|
| `docs/README.md` | Reading-order guide for the docs folder |
| `docs/adr/0001-feature-extraction-stack.md` | Formal architectural decision: Zeek + NFStream over CICFlowMeter |
| `docs/findings-register.md` | Numbered technical findings, risks, and evidence-backed conclusions |
| `docs/project-journey.md` | Phase-by-phase implementation history (11 phases) |
| `docs/artifact-index.md` | Pointer map to every generated evidence artifact |
| `docs/backend-platform.md` | Architecture reference for the FastAPI/RQ/Postgres/MinIO platform |

## Prerequisites

All prior tutorials — the docs folder narrates and cross-references everything already studied.

---

## 1. Why Docs Live Next to Code

A thesis prototype can get away with a README and a notebook. A software project that other people (or your future self) will audit, extend, or defend in a committee cannot.

This `docs/` folder solves three specific problems:

1. **The code is executable; the reasoning is not.** Reading `pipeline/nfstream.py` tells you _what_ features are extracted. It does not tell you _why CICFlowMeter was removed from the plan_ or _what the malicious data actually produced_ when the pipeline ran. The docs capture the reasoning layer.

2. **Decisions made under time pressure get relitigated.** Without `adr/0001`, someone reviewing the repository two months later might ask "why isn't CICFlowMeter used if the thesis mentions it?" The ADR closes that question with a one-time formal answer instead of forcing it to be answered in every meeting.

3. **Findings rot if they stay in chat or notebooks.** The findings register captures what the data and models actually showed so the repository remains self-explanatory even without the original conversation history.

---

## 2. ADR 0001 — Feature Extraction Stack

### What an ADR Is

An **Architectural Decision Record** is a short document with a fixed structure: the context that forced a decision, the decision itself, the rationale, and the consequences (positive and negative). The format is intentionally minimal so it gets written under real project conditions.

### The Problem This ADR Solved

The thesis text referenced CICFlowMeter in the methodology chapter. The repository code was already built around Zeek + NFStream. That mismatch created three failure modes:

1. The written methodology would not match the executable pipeline — a thesis committee problem.
2. Future implementation work might split across two incompatible extractors — a maintainability problem.
3. Production hardening (Docker, CI, reproducible builds) becomes twice as hard when two parallel tool stacks exist.

None of these problems is catastrophic on day one. All of them become expensive if left unaddressed as the project grows.

### The Decision

```
The official production extraction stack is:
- Zeek  — authoritative source for TLS 1.3 and QUIC protocol-aware metadata
- NFStream — authoritative source for bidirectional statistical flow features

CICFlowMeter is not part of the forward production path.
```

This is a _narrowing decision_, not an expansion. The ADR does not add capability; it removes ambiguity about which tool owns which role.

### Why Not CICFlowMeter?

The ADR states four reasons:

| Reason | What it actually means |
|---|---|
| Zeek matches protocol-focused direction | TLS 1.3 and QUIC metadata require Zeek's deep-parse capabilities; CICFlowMeter's feature set is flow-statistics-first |
| NFStream already matches current scripts | `combineCSV.py`, `freeze_benign.py`, and the downstream CSVs are all NFStream-derived; switching extractors would invalidate every artifact |
| Single stack keeps pipeline reproducible | One set of tools → one Docker image → one `requirements.lock` → reproducible builds |
| Removes Java dependency | CICFlowMeter is Java-based; adding it means Java runtime management, a different CI path, and an additional merge surface at the NFStream-output join step |

### The Consequences the ADR Records Honestly

> "The thesis text will remain slightly out of sync until we add an explicit implementation note."

This is the correct thing to write. The ADR does not pretend the mismatch will magically resolve itself. It documents the trade-off so it can be handled as a deliberate task, not ignored as an embarrassment.

### Where This Decision Surfaces in Code

The ADR is not just a document — it is reinforced in code through `technical_direction.py` (Tutorial 33):

```python
TECHNICAL_DIRECTION = """
Production extraction stack: Zeek + NFStream.
CICFlowMeter: retained as academic reference only.
"""
```

A developer who never reads the docs folder encounters the same decision embedded in the source tree.

---

## 3. Findings Register

The findings register is a numbered log of what the data and models _actually produced_ when the pipeline ran. It is organized by category rather than chronologically, which makes it useful for defense preparation.

### The Structure

```
1–3   Confirmed infrastructure improvements
4–6   Data quality findings
7–9   ML findings
10–12 Detection findings
13–15 Current risks
16–20 Platform findings
```

Every finding has three components: the raw observation, the evidence pointers (artifact paths), and the impact statement. The impact statement is the part that matters in a defense — it translates the technical result into a scientific or engineering consequence.

### The Most Important Findings for a Defense

**Finding 4 — Non-TLS/QUIC leakage in benign merged data**

> "The quality-gate run on the benign pipeline exposed substantial non-TLS/QUIC leakage in merged outputs before canonical filtering was enforced."

This is the concrete justification for the quality gates introduced in Tutorial 09. Without the gates, the training data would silently contain non-encrypted traffic. The defense question "why did you add quality gates?" now has a data-backed answer: because running without them produced contaminated output.

**Finding 5 — Zeek produced only `conn.csv` for the malicious source**

> "The malicious pipeline rebuild successfully sanitized the local capture and extracted NFStream features. Zeek still produced only `conn.csv`, not `ssl.csv`, `tls.csv`, or `quic.csv`."

The finding distinguishes clearly between an implementation gap and a source-data limitation. The pipeline code works correctly; the available malicious PCAP simply does not contain TLS/QUIC traffic that Zeek can parse. This distinction matters because a reviewer might otherwise interpret the absence of Zeek TLS logs as a bug.

**Findings 8 and 9 — Tree models are perfect, and that is a warning**

> "RandomForest holdout metrics: perfect. GradientBoosting holdout metrics: effectively perfect."

Finding 9 immediately follows with:

> "At least one source is quality-failed. At least one class has fewer than two distinct captures. The dataset is imbalanced."

The workflow records these warnings automatically (Tutorial 19). The findings register surfaces them as explicit risks so the defense narrative can address them proactively: the workflow is correct; the dataset is the constraint on how strongly the results generalize.

**Findings 10 and 11 — Multi-tier precision/recall and the `min_deep_model_passes` refinement**

Finding 11 records a specific implementation iteration that improved the system:

> "Allowing a single deep model to pass a flow left one benign false positive. Requiring both deep models removed that false positive without hurting recall on current data."

This is the kind of evidence a thesis committee wants: a documented design refinement with a before/after comparison. The config change is in `configs/multi_tier_workflow.yaml` (`min_deep_model_passes: 2`).

**Finding 12 — Graph clustering produced analyst-meaningful structure**

> "One dominant suspicious cluster. 1,846 nodes. 1,845 edges. Centered on internal host 10.0.2.109. Spans 2 windows."

This finding is what justifies the graph layer in Tutorial 20. The output is not just a feature — it surfaces the internal host as a hub, which is exactly the kind of anomaly a network analyst would act on.

### The Risk Section Is Equally Important

Findings 13–15 record three explicit risks that remain open:

| Risk | What it limits |
|---|---|
| Malicious dataset is NFStream-only, no Zeek TLS logs | Confidence in Zeek-backed malicious labeling |
| Tier 1 drops 274 malicious flows | Recall ceiling for the overall detector |
| Tree-model scores are probably inflated | "Production-generalizes" claims |

Recording known risks is not a weakness in a thesis — it is evidence of scientific honesty and methodological rigor. A committee that asks "what are the limitations?" gets a precise, numbered answer from this document.

---

## 4. Project Journey

The project journey narrates 11 implementation phases. Each phase has the same pattern: what was implemented, why it mattered. The _why it mattered_ entries are the part worth memorizing for a defense.

### Phase Map

| Phase | Name | Key outcome |
|---|---|---|
| 1 | Repository Foundation | `src/`, `tests/`, `configs/`, `artifacts/` — reproducible layout |
| 2 | Technical Direction | ADR 0001 — resolved thesis/code mismatch |
| 3 | Pipeline Refactor | Benign and malicious share one parameterized pipeline |
| 4 | Quality Gates | Seven explicit checks — prevented silent bad-data propagation |
| 5 | Real Pipeline Execution | First real data run — exposed benign leakage and malicious PCAP truncation |
| 6 | Malicious Pipeline Rebuild | Formal malicious path with provenance; confirmed source-data constraint |
| 7 | Canonical Dataset | Single truth: 49,158 rows, 115 columns, stable schema |
| 8 | Full ML Workflow | Three models + reproducible evidence bundles; honest performance warnings |
| 9 | Multi-Tier Detection | Tier1 fast screen → Tier2 deep consensus → Tier3 graph enrichment; refined `min_deep_model_passes` |
| 10 | Backend Scoring Platform | FastAPI + RQ + Postgres + MinIO; PCAPs become tracked scored jobs |
| 11 | Finalization | Removed dashboard from FastAPI surface; reporting isolated in `snapshot.py` |

### Phase 5 Is the Honest Center of the Project

Phase 5 records what the first real data execution actually found:

- The benign pipeline completed but exposed non-TLS/QUIC leakage before filtering was applied.
- The malicious PCAP was confirmed truncated in its original state.

This is the point where the implementation met real data and produced findings that drove the next three phases. A project journey that only records successes is a marketing document. This one records what went wrong and what that forced the team to build.

### Why Phase 11 Removed the Dashboard

The dashboard was a served UI layer within FastAPI. Removing it was a scope discipline decision:

> "The backend now has a cleaner production boundary: API, queueing, metadata, storage, and scoring."

Mixing a served React/HTML dashboard with a scoring API couples two very different maintenance responsibilities into one container image. The snapshot and export functionality (Tutorials 31 and 32) was preserved in a neutral reporting module — it can still generate presentation materials, just not as a live-served route.

---

## 5. Artifact Index

The artifact index is a pointer map, not a data store. Its value is that every generated output has a canonical human-readable description of what it contains, indexed in one place.

### The `latest/` Convention

```
artifacts/ml_workflow/latest/
artifacts/multi_tier/latest/
```

`latest/` is a directory (or symlink to the most recent timestamped run directory). This convention lets scripts and documentation reference a stable path even when the underlying run directory is versioned with a timestamp. The artifact index points to `latest/`, not to a specific dated run, so the pointers remain valid after re-runs.

### What the Index Does Not Contain

The artifact index does not contain the data itself, performance numbers, or interpretation. Those belong in the findings register. The artifact index answers "where is the file?" — the findings register answers "what does the file show?"

This separation means you can update the findings register without updating the artifact index (the paths stay the same) and you can update artifact paths without rewriting the interpretation.

### Backend Artifact Conventions

```
artifacts/backend.sqlite3        — dev (SQLite, local mode)
artifacts/object_store/          — dev (local object storage)
artifacts/backend_jobs/          — job workspace directories during processing
```

In the Docker Compose stack the metadata source of truth is Postgres and the artifact source of truth is MinIO. The local paths above are used only when the backend runs in the default dev configuration with `LOCAL_OBJECT_STORAGE=true`.

---

## 6. Backend Platform Doc

`docs/backend-platform.md` is an architecture reference written for a reader who knows the project but wants a high-level picture of the backend without reading all eight backend modules (Tutorials 21–30).

### The Four Responsibilities

```
FastAPI     — API surface: health, model bundles, job submission, status
Postgres    — metadata: batches, jobs, artifacts
Object store — file persistence: input PCAPs, output bundles
Redis + RQ  — async worker queue
```

Each responsibility maps to a different layer of durability. FastAPI is stateless — any request that hits it can be handled without session memory. Postgres handles transactional metadata that must survive restarts. Object storage handles large binary artifacts that must survive container teardown. Redis is the only non-durable piece: if the queue is lost the jobs are replayed on resubmit (fine for a dev queue; a production deployment would configure Redis persistence).

### The Six-Step Scoring Flow

The doc describes the worker's scoring loop in six steps:

```
1. Download PCAP from object storage
2. Run sanitized Zeek + NFStream pipeline
3. Build inference-ready scoring dataset from merged output
4. Run multi-tier scoring with active model bundle
5. Save suspicious-flow, graph, and summary outputs
6. Upload output artifacts → update job metadata in Postgres
```

This is the same logical flow as the data pipeline tutorials (03–18) plus the ML and detection tutorials (19–20), compressed into an API-driven async job. Steps 2–4 call the same package functions covered in those tutorials — the backend did not reimplement the logic, it wrapped it behind a job queue.

### What "Not Live-Tested in This Sandbox" Means

The findings register and the backend platform doc both note:

> "Local port binding failed in this sandbox when trying to expose a live server session."

This is an honest constraint declaration. The backend code compiles, the tests pass (38 tests), and the architecture is verified at the unit level. A live `curl` against a running container was not performed inside the development environment used to build the project. The correct next step for full verification is running `docker compose up` on a normal host and performing smoke tests against the exposed port.

This kind of explicit limitation note is what separates a project journal from PR spin. It tells a reviewer exactly where the verification boundary is.

---

## 7. Interview Questions and Answers

**Q: What is an ADR and why does this project have one?**

A: An Architectural Decision Record is a short structured document recording the context, decision, rationale, and trade-offs for a significant architectural choice. This project has ADR 0001 because the thesis text referenced CICFlowMeter while the implementation was already built around Zeek and NFStream. Without a formal record, that mismatch would be silently present for every future reader. The ADR closes the question once with a documented answer, prevents future work from splitting across two extraction stacks, and reinforces the decision in code through `technical_direction.py`. The format is intentionally short so it gets written — a decision that never gets written down does not really exist.

---

**Q: The tree models achieved perfect holdout scores. Why is that a problem rather than a success?**

A: Perfect scores on a holdout set are a signal that the dataset separability is unusually high — usually because of limited capture diversity, source-specific artifacts, or class-specific network conditions that do not generalize to real-world traffic. The findings register records three concrete reasons to treat these results with caution: at least one malicious source has `quality_status=fail`; the malicious class currently has data from fewer than two distinct captures; and the dataset is imbalanced. The ML workflow emits these warnings automatically (Tutorial 19). The honest interpretation in the findings register is: "the workflow is functioning correctly; the current dataset likely allows class separation that is easier than a real deployment scenario." This is the answer to give in a defense — acknowledge the result, explain the constraint, and identify what kind of additional data would provide a stronger generalization claim.

---

**Q: The findings register records that Tier 1 drops 274 malicious flows. Is that a bug?**

A: No — it is a documented design trade-off. Tier 1 (GaussianNB) is intentionally a high-recall lightweight screen, not a high-precision classifier. Its job is to eliminate clearly-benign flows cheaply before the expensive deep models run. GaussianNB's weaker discriminative power on this dataset means it discards roughly 0.9% of malicious flows at the first stage. Those 274 flows never reach Tier 2 and cannot be recovered downstream. The findings register records this as a known risk that "affects the recall ceiling for the overall detector." The mitigation options are: lower the Tier 1 confidence threshold (reduces false negatives but also increases the Tier 2 workload), replace GaussianNB with a slightly stronger but still lightweight model, or accept the ceiling as a calibrated design point given the current data. The key point for a defense is that the number is measured and documented, not hidden.

---

*Next: [Tutorial 39 — Interview Cheatsheet](39_interview_cheatsheet.md)*
