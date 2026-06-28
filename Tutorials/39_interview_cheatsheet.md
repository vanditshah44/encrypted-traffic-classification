# Tutorial 39 — Interview Cheatsheet

## How to Use This Document

Every question here was drawn from a real design decision in the codebase. Every answer references the specific file and tutorial where the decision lives. Use the tutorial reference to go back and re-read the full context before your defense.

The questions are organized by the level at which an interviewer is likely to ask them: architecture first, then each layer in data-flow order, then cross-cutting concerns.

---

## Part A — System Architecture

**Q: Describe the end-to-end data flow of this project in one paragraph.**

A: Raw PCAPs are sanitized by `editcap` and filtered to TLS/QUIC traffic by `tshark` (`pipeline/filtering.py`, T04). The filtered PCAP goes to Zeek, which emits `ssl.log`/`tls.log`/`quic.log`/`conn.log` parsed into CSVs (`pipeline/zeek.py`, T06). The same PCAP is also passed to NFStream, which extracts bidirectional flow statistics and SPLT features (`pipeline/nfstream.py`, T07). The two outputs are joined on a 4-tuple + timestamp tolerance (`pipeline/merge_features.py`, T08). Merged output passes seven quality gates (`pipeline/quality.py`, T09), then is encoded and filtered to numeric features (`pipeline/build_dataset.py`, T10), pruned for near-constant and correlated columns (`pipeline/pruning.py`, T11), and finalized by removing temporal-leakage columns (`pipeline/finalize.py`, T12). The ML workflow trains three models and saves reproducible evidence bundles (`ml/workflow.py`, T19). The multi-tier detector applies GaussianNB → RF+GB consensus → BFS graph clustering to produce alert levels (`detection/multitier.py`, T20). The backend accepts PCAPs via FastAPI, stores them in object storage, queues jobs via RQ, and the worker runs the same pipeline end-to-end on each job (`backend/`, T21–30).

---

**Q: Why does the project use both Zeek and NFStream? Why not one tool?**

A: They solve different problems at different layers. Zeek is a network protocol analyzer — it parses TLS 1.3 and QUIC at the application layer and emits per-connection protocol metadata (SNI, JA3/JA4 fingerprints, certificate fields, cipher suites). It cannot compute bidirectional flow statistics. NFStream is a flow meter — it computes byte/packet counts, inter-arrival times, SPLT (sequence of first-N packet lengths and times) in both directions, but does not parse protocol-layer fields. The merge step (`pipeline/merge_features.py`, T08) joins the two outputs on 4-tuple + timestamp tolerance to produce a single row with both protocol evidence and flow statistics. Using both tools is the only way to have the full feature space the thesis requires. This decision is formalized in ADR 0001 (`docs/adr/`, T38).

---

**Q: Why was CICFlowMeter removed from the stack?**

A: CICFlowMeter was referenced in the thesis methodology but never used in the implementation. Keeping both stories alive without a formal decision would have: (1) left the written methodology mismatched with the executable pipeline, (2) created future implementation duplication across two incompatible extractors, (3) added a Java dependency and a second merge surface. ADR 0001 (`docs/adr/0001-feature-extraction-stack.md`, T38) formally names Zeek + NFStream as the production stack and retains CICFlowMeter only as historical academic context. The same decision is embedded in `technical_direction.py` (T33) so it is visible to anyone reading the source tree.

---

**Q: What is `DatasetArtifacts` and why does every path live inside it?**

A: `DatasetArtifacts` is a dataclass in `pipeline/common.py` (T03) that holds every intermediate file path as a named attribute — `filtered_pcap`, `zeek_log_dir`, `nfstream_csv`, `merged_csv`, etc. Every pipeline function receives a `DatasetArtifacts` instance and reads or writes paths through it. This centralizes path management: if the directory layout changes, only `DatasetArtifacts.__init__` needs updating. It also makes function signatures self-documenting — a function that takes `artifacts: DatasetArtifacts` announces that it participates in the shared pipeline state. The alternative — passing individual path strings — would scatter path construction logic across every module and make cross-function path consistency impossible to enforce.

---

## Part B — Data Pipeline

**Q: What does the tshark filter do and why is it applied before Zeek?**

A: The filter in `pipeline/filtering.py` (T04) keeps only packets where the transport layer port or the application layer decodes as TLS or QUIC. Applied before Zeek for two reasons. First, Zeek must parse the entire PCAP; a smaller file means faster Zeek execution. Second, without the filter the merge step would produce rows for non-TLS/QUIC flows, and quality gate six (`quality.py`, T09) would fail with non-encrypted traffic leakage — which is exactly what happened in the benign pipeline before the filter was enforced (Findings Register finding 4, T38).

---

**Q: How does the Zeek log parser handle the TSV vs JSON format difference?**

A: `pipeline/zeek.py` (T06) detects format at parse time by reading the first line of the file. Zeek TSV logs begin with `#separator` — a header comment that declares the field delimiter. JSON logs begin with `{`. The parser branches on this detection rather than taking a configuration flag, because the format is a property of the file itself, not of the caller. TSV logs are parsed with explicit `#fields` and `#types` header extraction; JSON logs are parsed row by row with `json.loads`. Both paths normalize to the same column names before returning a DataFrame.

---

**Q: What is the join tolerance in the merge step and why is a strict key join insufficient?**

A: `pipeline/merge_features.py` (T08) joins on 5-tuple (src IP, dst IP, src port, dst port, protocol) plus a timestamp tolerance window. The tolerance exists because Zeek and NFStream observe the same packet stream from different vantage points. Zeek records the timestamp of the first packet it parses from the stream; NFStream records the timestamp of the first packet in its internal flow state. On a loaded system or when processing a PCAP replay, these can differ by tens of milliseconds. A strict equality join on timestamp would produce large numbers of unmatched rows even for flows that are logically the same. The tolerance window (configurable in `configs/base.yaml`) allows matches within a defined skew budget. The match rate is checked by quality gate four, and a low match rate triggers a pipeline abort.

---

**Q: Name three quality gates and explain what each prevents.**

A: (1) **PCAP health check** (`quality.py`, T09): reads the PCAP magic bytes and verifies the file is not truncated. Prevents the entire pipeline from running on a corrupted input — a problem that actually occurred with the malicious PCAP in Phase 5 of the project journey. (2) **Non-TLS/QUIC leakage check**: counts flows where `protocol_family` is neither TLS nor QUIC in the merged output. Prevents training on non-encrypted traffic that would give the classifier an easy signal not present in real encrypted-traffic scenarios. (3) **UID uniqueness check**: verifies that Zeek connection UIDs are unique within a run. Duplicate UIDs occur when multiple PCAP files are processed together without being merged first; the duplicate UIDs would produce duplicate training rows that inflate class weights and corrupt cross-validation.

---

**Q: What does the pruning step remove and why are those columns removed statistically rather than manually?**

A: `pipeline/pruning.py` (T11) removes two classes of columns. Near-constant columns have a variance below a threshold — they carry almost no information because nearly every row has the same value. High-correlation columns have a Pearson correlation above a threshold with another retained column — they are redundant given that column. Both thresholds are in `configs/base.yaml`. Manual selection would require a human to inspect every column after every new data run. Statistical thresholds apply consistently regardless of dataset version and can be rerun automatically when new data arrives. The output column count is recorded in the pipeline artifact so the pruning effect is measurable across runs.

---

**Q: Why does `pipeline/finalize.py` exist as a separate step after pruning?**

A: Pruning (`pipeline/pruning.py`, T11) removes statistically redundant columns. Finalization (`pipeline/finalize.py`, T12) removes columns that carry temporal leakage — fields like `timestamp`, `capture_id`, or `window_id` that encode information about when a flow occurred rather than what it looks like. A model trained with these columns learns to associate a timestamp with a label rather than learning protocol behavior. The separation exists because temporal leakage is a logical problem, not a statistical one: a timestamp column might pass variance and correlation checks while still being invalid as a training feature. Having two distinct steps makes the distinction explicit.

---

**Q: What is `record_id` in the canonical dataset and how is it computed?**

A: `record_id` is a stable row identifier computed in `pipeline/canonical.py` (T17) as a SHA-256 hash of a tuple containing `(capture_id, window_id, src_ip, dst_ip, src_port, dst_port, protocol)`. It is stable across re-runs on the same data: the same flow in the same window always maps to the same `record_id`. This enables deduplication (if the canonical builder is run twice, duplicate rows are detected by `record_id`), artifact lineage tracking (a downstream report can reference a specific row by `record_id` without embedding all 115 column values), and provenance auditing (`pipeline/provenance.py`, T15).

---

## Part C — Machine Learning

**Q: Why are three models trained instead of just the best-performing one?**

A: The three models serve different roles in the multi-tier detection architecture (T20), not just in the ML evaluation. `GaussianNB` is used at Tier 1 as a lightweight fast screen — it is cheap to run, gives a probability estimate, and can eliminate clearly benign flows before the more expensive models execute. `RandomForestClassifier` and `GradientBoostingClassifier` are used at Tier 2 as the deep inference step. Training all three in the ML workflow (`ml/workflow.py`, T19) means the saved model files are immediately usable in the detector without a separate training run.

---

**Q: What is threshold optimization and why is it needed?**

A: A classifier's default decision boundary is 0.5 on the probability output. That default maximizes neither F1, precision, nor recall — it just splits the probability space in half. Threshold optimization (T19) sweeps the decision threshold across values from 0.01 to 0.99, computes F1 at each value on the validation fold, and selects the threshold that maximizes F1. The optimized threshold is saved alongside the model file. For GaussianNB, which has a ROC-AUC around 0.60 on this dataset, threshold optimization is particularly important: the naive 0.5 boundary would produce worse F1 than a tuned threshold.

---

**Q: Perfect holdout scores on Random Forest and Gradient Boosting — is that a good result?**

A: It is a warning, not a success. The findings register (finding 8, T38) and the ML workflow both emit explicit warnings: at least one source has `quality_status=fail`, at least one class comes from fewer than two distinct captures, and the dataset is imbalanced. Perfect scores under these conditions indicate that the current dataset allows class separation that is easier than real-world traffic — likely because malicious and benign flows come from different network environments with different IP ranges, packet sizes, or connection patterns, not just different application-layer behavior. The workflow is implemented correctly; the _dataset_ is the constraint. The finding explicitly states the results are "suitable for workflow development and evidence generation" but "not yet a strong final dataset for high-confidence deployment claims."

---

**Q: What is permutation importance and why is it computed alongside native feature importance?**

A: Native feature importance in tree models (Random Forest, Gradient Boosting) is computed during training by summing the impurity reduction contributed by each feature across all splits. This measure is biased toward high-cardinality features — a feature with many distinct values creates more split opportunities and accumulates more impurity reduction even if its predictive signal is weak. Permutation importance (`ml/workflow.py`, T19) is computed post-training: each feature column is randomly shuffled, the model is re-evaluated, and the drop in score is recorded as that feature's importance. Shuffling breaks the feature's real signal without changing anything else. Permutation importance is unbiased toward cardinality and measures actual predictive contribution. Both are saved so the comparison reveals whether the native ranking is inflated by cardinality.

---

## Part D — Multi-Tier Detection

**Q: Walk through what happens to one flow as it passes through all three tiers.**

A: (1) **Tier 1**: The flow is scored by GaussianNB. If the predicted probability of malicious exceeds the Tier 1 threshold (`configs/multi_tier_workflow.yaml`, T20), the flow becomes a Tier 1 candidate. If it falls below the threshold, it is classified as benign and exits the pipeline. (2) **Tier 2**: Each Tier 1 candidate is scored by both RandomForest and GradientBoosting. Each model emits a probability; the scores are averaged with configurable weights. If the weighted consensus score exceeds the Tier 2 threshold AND the flow was marked suspicious by at least `min_deep_model_passes` individual models (default: 2), the flow is labeled suspicious. (3) **Tier 3**: Suspicious flows are used to build an endpoint graph (`detection/multitier.py`, T20). Nodes are IP endpoints; edges connect source and destination IPs for each suspicious flow. BFS graph traversal identifies connected components (clusters). Each cluster receives an alert level based on cluster size, flow density, and whether it spans multiple time windows. The graph output is what the reporting layer (`reporting/snapshot.py`, T31) and static site export (`static_site/export_static_snapshot.py`, T32) visualize.

---

**Q: Why use GaussianNB as Tier 1 instead of something stronger?**

A: The Tier 1 purpose is _not_ to be accurate — it is to be cheap. In a production scenario where thousands of flows arrive per second, running Random Forest on every flow is too expensive. GaussianNB has O(1) per-sample inference time and O(features) memory. The Tier 1 decision threshold is set to favor recall over precision: it is better to pass a benign flow to Tier 2 (a false positive at Tier 1) than to drop a malicious flow here (a false negative that can never be recovered). Tier 2 removes the false positives. The known cost is that Tier 1 currently drops 274 malicious flows — findings register finding 14 (T38) records this as an open risk affecting the overall recall ceiling.

---

**Q: What is `min_deep_model_passes: 2` and what happened when it was set to 1?**

A: With `min_deep_model_passes: 1`, a flow is labeled suspicious if either RandomForest or GradientBoosting marks it suspicious (logical OR). With the default value of 2, both models must agree (logical AND on a two-model setup). When the system ran with `min_deep_model_passes: 1`, one benign flow received a suspicious label — a false positive. Requiring both models to agree removed that false positive without reducing recall on the current dataset. Findings register finding 11 (T38) records this iteration explicitly as evidence that the default setting is the correct calibration.

---

**Q: Why is BFS used for graph clustering instead of a community detection algorithm?**

A: The goal at Tier 3 is not to find densely interconnected communities — it is to find connected components. A suspicious cluster is any set of endpoints reachable from each other through suspicious flows, regardless of how tightly connected. BFS (breadth-first search) finds exactly connected components with O(V + E) complexity. Community detection algorithms (Louvain, spectral clustering) are designed for partitioning dense graphs into modules, which requires the graph to have community structure. An endpoint graph where one internal host fans out to 1,844 external peers has a star topology, not community structure. BFS on that graph correctly identifies the whole star as one component; community detection would either struggle with the topology or return meaningless partitions.

---

## Part E — Backend Platform

**Q: Why is the scoring pipeline async (queued via RQ) rather than synchronous within the API request?**

A: Processing a PCAP involves: sanitization with editcap, tshark filtering, Zeek log generation (which invokes a subprocess), NFStream extraction, feature merging, ML inference. This takes seconds to minutes depending on PCAP size. An HTTP request that blocks for minutes will time out at any proxy layer and provides no progress visibility. RQ (`backend/queue.py`, T25) decouples submission from execution: the API immediately returns a job ID, and the worker runs the pipeline asynchronously. The client polls `GET /api/v1/jobs/{job_id}` for status. This also means the API server can handle concurrent submissions without exhausting its thread pool on CPU-bound work.

---

**Q: What is the difference between `InlineQueueBackend` and `RQQueueBackend`?**

A: Both implement the same `QueueBackend` interface with `enqueue()` and `dequeue()` methods (`backend/queue.py`, T25). `InlineQueueBackend` executes the job function immediately in the same process — there is no Redis, no worker, no network hop. It exists for testing: a test that submits a PCAP job and checks the output artifact does not need a running Redis instance. `RQQueueBackend` pushes the job to a Redis queue, where the worker process picks it up. The test suite always uses `InlineQueueBackend` (set via environment variable, cleared by `clear_backend_settings_cache()` in test setUp/tearDown). Production Compose uses `RQQueueBackend` with the Redis service.

---

**Q: What does `clear_backend_settings_cache()` do and why is it called in both `setUp` and `tearDown`?**

A: `pydantic-settings` caches the settings object after first load. Without clearing the cache, a test that sets `DATABASE_URL=sqlite://` would see the previous test's settings if they were loaded first. `clear_backend_settings_cache()` invalidates the module-level singleton so the next call to `get_backend_settings()` re-reads environment variables from scratch (`tests/`, T36). It is called in `setUp` so the test starts clean regardless of what previous tests did. It is called in `tearDown` so the test cleans up after itself rather than leaving stale state for the next test. Both calls are necessary: `setUp` guards against stale state _entering_ the test; `tearDown` guards against stale state _leaking out_ of the test.

---

**Q: Why does object storage use an abstraction interface (`ObjectStorage`) rather than calling S3/local filesystem directly?**

A: `backend/storage.py` (T24) defines an `ObjectStorage` interface with `put()`, `get()`, and `delete()` methods. `LocalObjectStorage` and `S3ObjectStorage` implement it. The backend modules (`scoring.py`, `worker.py`, `services.py`) call the interface. This means: (1) tests can inject `LocalObjectStorage` without an S3 endpoint, (2) switching from MinIO (dev) to AWS S3 (production) requires changing one environment variable (`S3_ENDPOINT_URL`), not modifying business logic, (3) a future Google Cloud Storage adapter would implement the same interface with no changes to callers. The pattern is dependency inversion: high-level policy code depends on an abstraction, not a concrete implementation.

---

## Part F — Deployment

**Q: Why is the base image `python:3.12-slim` rather than `python:3.12-alpine`?**

A: Alpine Linux uses musl libc instead of glibc. Several scientific Python packages (NumPy, pandas, scikit-learn) ship pre-compiled wheel packages built against glibc. On Alpine, pip falls back to compiling from source, which requires a C toolchain in the image and significantly increases build time and image size. `python:3.12-slim` is Debian-based and uses glibc, so all pre-compiled wheels install directly. This is the standard tradeoff in scientific Python containers: `slim` for glibc compatibility, `alpine` only when binary size is the dominant constraint and all dependencies are pure-Python (`Dockerfile`, T37).

---

**Q: Tshark is installed in the Docker image but Zeek is not. Why?**

A: Tshark is a single apt package (`tshark`) that integrates cleanly into a Debian-based image. Zeek requires compiling from source or installing from a third-party package repository, which adds significant image build complexity and size. More importantly, the user likely already has Zeek installed on the host system for development. The Compose configuration bind-mounts the host Zeek binary into the container as read-only rather than shipping Zeek in the image (`docker-compose.yaml`, T37). This means the container's Zeek version tracks the host version automatically, and the image does not carry a large compiled binary. The trade-off is that a container without a bind-mounted Zeek will fail at the Zeek step — which is acceptable for a development-oriented Compose stack but would need to change for a fully self-contained production image.

---

**Q: Why is Redis persistence disabled in the Compose configuration?**

A: The Compose `redis` service starts with `--save "" --appendonly no` (`docker-compose.yaml`, T37). Redis persistence (AOF log or RDB snapshots) writes job queue state to disk so jobs survive Redis restarts. In the development Compose stack, job recovery on Redis restart is not a priority: if the queue is lost, jobs are resubmitted. Persistence adds disk I/O, a volume mount, and startup time for a feature that provides no benefit in development. A production deployment would configure `appendonly yes` and mount a durable volume. The explicit `--save "" --appendonly no` flags make the dev-only intent visible in the configuration rather than relying on Redis defaults.

---

## Part G — Cross-Cutting Concerns

**Q: What is provenance tracking and why is it important in an ML pipeline?**

A: `pipeline/provenance.py` (T15) records a SHA-256 fingerprint of every input artifact (PCAP files, intermediate CSVs) and writes a provenance JSON alongside each output. The provenance JSON maps output artifact → input artifact hash. If a model is later questioned ("was this trained on the same data as the report?"), the provenance chain can verify that the canonical CSV used for training and the canonical CSV used for reporting are the same file. Without provenance, reproducibility is a claim — with it, reproducibility is a verifiable property.

---

**Q: How does the CLI avoid slow startup when a subcommand is not requested?**

A: `cli.py` (T33) uses lazy imports inside each subcommand handler function. The `import` statements for heavy packages (pandas, sklearn, NFStream) are inside the function body, not at module level. This means `import tls_dataset.cli` does not load the entire scientific stack — it only loads argument parsing infrastructure. Only the requested subcommand's handler runs, and only that handler triggers the relevant imports. The practical effect: `tls-dataset --help` completes in milliseconds instead of the several seconds it would take to import pandas and scikit-learn.

---

**Q: What is the difference between `sys.path.insert(0, SRC)` and `sys.path.append(SRC)` in the shim scripts?**

A: `sys.path` is searched left to right. `insert(0, SRC)` places the local `src/` directory at the front of the search path — before site-packages. This means the local development copy of `tls_dataset` is imported unconditionally, even if the package is also installed globally or in another virtualenv. `append(SRC)` would place `src/` after site-packages; a previously `pip install`-ed version would shadow the source tree, making local changes invisible without reinstalling. The guard `if str(SRC) not in sys.path` prevents duplicate entries if multiple shims are loaded in the same session (`zeektocsv.py`, T35).

---

**Q: How does the static site export handle CORS when opened from a local filesystem?**

A: Browsers block `fetch()` requests to local files when the page is opened with `file://` protocol due to CORS restrictions. `export_static_snapshot.py` (T32) writes the data in two formats: `data.json` (a plain JSON file for server-hosted pages) and `data.js` (a JavaScript file that assigns the data to a global variable: `window.SNAPSHOT_DATA = {...}`). The HTML page loads `data.js` as a `<script>` tag. Script tags are not subject to the same CORS restrictions as `fetch()`, so the embedded data is available globally when the page is opened from `file://`. The two-file strategy means the export works both locally (via `data.js`) and when hosted on a server or GitHub Pages (via `data.json` loaded with `fetch()`).

---

**Q: What is `.nojekyll` and why does the static export create it?**

A: GitHub Pages uses Jekyll to process hosted sites by default. Jekyll skips directories and files whose names start with underscore (e.g. `_data/`, `_includes/`). Some static export conventions name data directories with underscores. A `.nojekyll` file at the repository root tells GitHub Pages to serve files as-is without Jekyll processing, preserving underscore-prefixed paths. `export_static_snapshot.py` (T32) creates `.nojekyll` automatically so the export is GitHub Pages-ready without manual configuration.

---

**Q: The canonical dataset has `quality_status=fail` for all malicious rows. Can the dataset still be used?**

A: Yes, with appropriate scope. The findings register (finding 6, T38) states: "suitable for workflow development and evidence generation; not yet a strong final dataset for high-confidence deployment claims." `quality_status=fail` for malicious rows means Zeek did not produce TLS/SSL/QUIC protocol logs for the malicious source — the malicious features are NFStream-only. The pipeline and ML workflow still run correctly on this data. The limitation is scientific: you cannot make strong claims about TLS-layer feature separability between benign and malicious traffic when the malicious class lacks TLS-layer features. The ML workflow emits a warning about quality-failed sources (`ml/workflow.py`, T19), and the findings register records it as a known dataset quality constraint, not a code defect.

---

## Quick Reference: File → Tutorial

| File | Tutorial |
|---|---|
| `configs/base.yaml` (and all configs) | 02 |
| `pipeline/common.py` | 03 |
| `pipeline/filtering.py` | 04 |
| `pipeline/zeek_runner.py` | 05 |
| `pipeline/zeek.py` | 06 |
| `pipeline/nfstream.py` | 07 |
| `pipeline/merge_features.py` | 08 |
| `pipeline/quality.py` | 09 |
| `pipeline/build_dataset.py` | 10 |
| `pipeline/pruning.py` | 11 |
| `pipeline/finalize.py` | 12 |
| `pipeline/orchestration.py` | 13 |
| `pipeline/pcap.py` | 14 |
| `pipeline/provenance.py` | 15 |
| `pipeline/malicious.py` | 16 |
| `pipeline/canonical.py` | 17 |
| `pipeline/inspect.py` | 18 |
| `ml/workflow.py` | 19 |
| `detection/multitier.py` | 20 |
| `backend/config.py` | 21 |
| `backend/models.py`, `backend/db.py` | 22 |
| `backend/schemas.py` | 23 |
| `backend/storage.py` | 24 |
| `backend/queue.py` | 25 |
| `backend/registry.py` | 26 |
| `backend/services.py` | 27 |
| `backend/scoring.py` | 28 |
| `backend/worker.py` | 29 |
| `backend/app.py` | 30 |
| `reporting/snapshot.py` | 31 |
| `static_site/export_static_snapshot.py` | 32 |
| `cli.py`, `__main__.py`, `technical_direction.py` | 33 |
| `pipeline/download.py` | 34 |
| Root shim scripts (9 files) | 35 |
| `tests/` (12 files) | 36 |
| `Dockerfile`, `docker-compose.yaml` | 37 |
| `docs/` (5 files) | 38 |

---

*Series complete. Start with [00_project_overview.md](00_project_overview.md) and return here when you are ready to defend.*
