# Tutorial 00 — Project Overview & Architecture

**File:** *(no single source file — this tutorial maps the whole project)*
**Prerequisite:** None. Start here.

---

## 1. What Problem Does This Project Solve?

The internet today is almost entirely encrypted. When you visit a website, your browser
and the server negotiate **TLS 1.3** (Transport Layer Security) or **QUIC** (Google's
UDP-based encrypted transport) and then exchange data that no one in the middle can read.

That is great for privacy. But it creates a serious problem for security:

> **How do you detect malware, botnets, and attacks when all traffic is encrypted?**

The traditional answer was: decrypt it (using a "man-in-the-middle" inspection box
inside corporate networks). That breaks privacy, is illegal in many contexts, and
becomes impossible when the remote server uses certificate pinning.

This project's answer is:

> **You don't need to read the content. You need to read the behaviour.**

Every network connection leaves behind **metadata** — connection timing, packet sizes,
flow duration, how many packets were sent vs received, which TLS ciphers were negotiated,
which certificates were presented, how quickly data bursts arrive. Malware behaves
differently from normal software even when the payload is encrypted.

This project builds a full, production-grade platform to:

1. Extract those metadata features from raw network captures (PCAPs)
2. Combine them into a labeled dataset
3. Train machine learning models on that dataset
4. Run a multi-stage detector on new PCAPs
5. Expose the whole system as a backend API with a job queue and persistent storage

---

## 2. The One-Line Summary

```
Raw encrypted PCAP  →  features  →  ML models  →  "this flow is malicious"
```

Without ever decrypting a single byte.

---

## 3. Key Terminology You Must Know

Before reading any code you need these terms locked in.

### PCAP / PCAPNG
A **packet capture file**. Every packet that crossed a network interface, saved to disk
with timestamps. `PCAP` = older format. `PCAPNG` = newer format (Wireshark's default).
Think of it as a video recording of all network traffic. Every tool in this project
— Zeek, NFStream, tshark, editcap, scapy — reads PCAPs as input.

### TLS 1.3
**Transport Layer Security**, version 1.3. The encryption protocol used by HTTPS, SMTP,
and most modern internet traffic. TLS 1.3 (2018) is significantly more private than 1.2
— it hides more of the handshake, makes it harder to inspect, and removed weak cipher
suites. Our target.

### QUIC
**Quick UDP Internet Connections**. Google's protocol, now IETF-standardised (RFC 9000).
Used by HTTP/3 (YouTube, Google, etc). Runs over UDP, is fully encrypted from the first
packet, and is harder to inspect than TLS over TCP. Also a target.

### Flow / Network Flow
A **bidirectional conversation** between two hosts on the same 5-tuple:
`(source_ip, dest_ip, source_port, dest_port, protocol)`. NFStream tracks all packets
belonging to the same conversation and computes statistics over them (total bytes, packet
count, inter-arrival times, etc). The word "flow" and "connection" are used interchangeably
in this project.

### Feature Extraction
The process of turning raw packets into a table of numbers that a machine learning model
can consume. A single flow becomes one row with ~100 numeric columns.

### Zeek
An open-source **network security monitor**. When you point it at a PCAP, it reads every
packet and produces structured log files:
- `ssl.log` / `tls.log` → TLS handshake metadata (certificate, cipher, version, SNI)
- `conn.log` → connection summary (duration, bytes, state)
- `x509.log` → certificate details
- `quic.log` → QUIC connection metadata

Zeek is **protocol-aware** — it understands what TLS looks like and extracts semantic --Logical
fields from the handshake that a flow-level tool can't see.

### NFStream
A Python library for **bidirectional flow statistics**. Given a PCAP it produces one
row per flow containing timing, byte counts, packet-size histograms, inter-arrival
time statistics, and more. It is fast, runs in Python, and is easier to integrate than
CICFlowMeter (which is Java-based and was abandoned for this project — see ADR 0001).

### CICFlowMeter (legacy, NOT used)
An older Java-based flow statistics tool referenced in the original thesis text. The
project formally dropped it in **ADR 0001** (`docs/adr/0001-feature-extraction-stack.md`).
It is mentioned only for historical context. The production stack is Zeek + NFStream.

### Canonical Dataset
A single, labeled CSV where every row is one network flow, every column is either a
feature or a metadata field (`label`, `attack_family`, `capture_id`, etc.). Both benign
and malicious traffic end up here. This is the file the ML workflow reads.

### Benign Traffic
Normal, non-malicious network activity — web browsing, software updates, background
system communication. Ground-truth label: `benign` (label_id = 0).

### Malicious Traffic
Botnet, malware, or attack traffic. Ground-truth label: `malicious` (label_id = 1).
The malicious dataset used in this project comes from the **CTU-13 dataset** (Czech
Technical University botnet captures).

### Multi-tier Detection
A staged scoring system:
- **Tier 1** — fast, lightweight model (GaussianNB) catches obvious malicious flows
- **Tier 2** — deeper ensemble (RandomForest + GradientBoosting) confirms suspicious ones
- **Graph enrichment** — clusters suspicious source/destination endpoints to find
  coordinated activity (botnets talk to many hosts)

### Artifact
Any file the pipeline produces — a CSV, a trained model `.joblib`, a metrics `.json`,
a confusion matrix `.png`. All artifacts live under `artifacts/`.

### Provenance
A record of **where a file came from and how it was produced** — its parent files,
the tool versions used, the SHA256 hash of the output. Enables reproducibility.

### Backend Platform
A FastAPI HTTP service that accepts PCAP uploads, queues scoring jobs via Redis,
runs the full pipeline in a background worker, and stores results in PostgreSQL and
object storage (MinIO / S3).

---

## 4. Technology Stack — Every Tool and Why It Was Chosen

```
Layer                Tool / Library        Why
─────────────────────────────────────────────────────────────────────────
Protocol extraction  Zeek                  TLS/QUIC-aware, structured logs
Flow statistics      NFStream              Python-native, fast, bidirectional
PCAP manipulation    scapy                 Merge multiple PCAPs in Python
PCAP sanitisation    editcap               Fix malformed/truncated captures
PCAP filtering       tshark                Display-filter: keep only TLS/QUIC
PCAP inspection      capinfos              Health check (packet count, timing)
─────────────────────────────────────────────────────────────────────────
Data manipulation    pandas 2.2            DataFrames, CSV I/O, joins
ML models            scikit-learn 1.5      GaussianNB, RandomForest,
                                           GradientBoosting, metrics
Serialisation        joblib                Save/load trained sklearn pipelines
Visualisation        matplotlib 3.9        ROC curves, PR curves, confusion
                                           matrices
Config parsing       PyYAML 6.0            YAML config files
─────────────────────────────────────────────────────────────────────────
API server           FastAPI 0.115         HTTP REST service
ASGI server          uvicorn 0.32          Serves FastAPI
API validation       Pydantic (via FastAPI) Request/response schemas
HTTP testing         httpx 0.28            Async test client for FastAPI
─────────────────────────────────────────────────────────────────────────
Database ORM         SQLAlchemy 2.0        Job/artifact metadata tables
DB driver            psycopg 3.2           PostgreSQL adapter (Python)
Job queue            rq 1.16               Redis-backed task queue
Queue broker         redis 5.2             Message broker for RQ
Object storage       boto3 1.35            S3/MinIO artifact storage
─────────────────────────────────────────────────────────────────────────
Testing              pytest 8.3            Unit + integration tests
Type checking        mypy 1.13             Static type checking
Linting              ruff 0.8              Fast Python linter
─────────────────────────────────────────────────────────────────────────
Containerisation     Docker / Compose      Full stack: API, worker, Postgres,
                                           Redis, MinIO
─────────────────────────────────────────────────────────────────────────
Python version       3.12+                 Required (uses modern type syntax)
```

---

## 5. Repository Layout — Every Directory Explained

```
tls_dataset/                        ← project root
│
├── src/
│   └── tls_dataset/                ← the Python package
│       ├── __init__.py             ← declares __version__ = "0.1.0"
│       ├── __main__.py             ← allows `python -m tls_dataset`
│       ├── cli.py                  ← all CLI commands (argparse)
│       ├── technical_direction.py  ← single source of truth: Zeek+NFStream
│       │
│       ├── pipeline/               ← data processing layer (Tutorials 03-18)
│       │   ├── common.py           ← DatasetArtifacts: all file paths
│       │   ├── orchestration.py    ← run_dataset_pipeline() master orchestrator
│       │   ├── filtering.py        ← editcap sanitise + tshark TLS/QUIC filter
│       │   ├── zeek_runner.py      ← run Zeek as subprocess
│       │   ├── zeek.py             ← parse Zeek log files to DataFrames
│       │   ├── nfstream.py         ← run NFStream, extract flow features
│       │   ├── merge_features.py   ← join Zeek + NFStream on 4-tuple + time
│       │   ├── quality.py          ← all data-quality gates
│       │   ├── build_dataset.py    ← raw merged → ML-ready numeric format
│       │   ├── pruning.py          ← remove constant/correlated features
│       │   ├── finalize.py         ← drop temporal leakage columns
│       │   ├── canonical.py        ← build single labeled dataset from sources
│       │   ├── malicious.py        ← malicious-specific pipeline
│       │   ├── provenance.py       ← SHA256 + lineage tracking
│       │   ├── pcap.py             ← scapy PCAP merging
│       │   ├── inspect.py          ← NFStream CSV statistics printer
│       │   └── download.py         ← (placeholder for future downloaders)
│       │
│       ├── ml/                     ← machine learning layer (Tutorial 19)
│       │   └── workflow.py         ← full train/eval/export ML workflow
│       │
│       ├── detection/              ← scoring layer (Tutorial 20)
│       │   └── multitier.py        ← Tier1, Tier2, graph enrichment
│       │
│       ├── backend/                ← API platform (Tutorials 21-30)
│       │   ├── app.py              ← FastAPI routes
│       │   ├── worker.py           ← RQ worker process
│       │   ├── scoring.py          ← PCAP → scored results
│       │   ├── services.py         ← job/batch business logic
│       │   ├── models.py           ← SQLAlchemy ORM tables
│       │   ├── db.py               ← engine + session factory
│       │   ├── schemas.py          ← Pydantic API schemas
│       │   ├── storage.py          ← local + S3 storage adapters
│       │   ├── queue.py            ← inline + RQ queue adapters
│       │   ├── registry.py         ← model bundle discovery
│       │   └── config.py           ← env-based configuration
│       │
│       ├── reporting/              ← analytics layer (Tutorial 31)
│       │   └── snapshot.py         ← dashboard summary builder
│       │
│       └── static_site/            ← export layer (Tutorial 32)
│           └── export_static_snapshot.py
│
├── tests/                          ← automated test suite (Tutorials 43-52)
│   ├── test_smoke.py
│   ├── test_pipeline_utils.py
│   ├── test_quality_gates.py
│   ├── test_canonical_dataset.py
│   ├── test_ml_workflow.py
│   ├── test_multitier_detection.py
│   ├── test_backend_platform.py
│   ├── test_provenance_and_malicious_utils.py
│   ├── test_zeek_compatibility.py
│   ├── test_zeek_runner.py
│   ├── test_reporting_snapshot.py
│   └── test_static_site_export.py
│
├── configs/                        ← all configuration (Tutorial 02)
│   ├── base.yaml
│   ├── dev.yaml
│   ├── prod.yaml
│   ├── canonical_sources.yaml
│   ├── ml_workflow.yaml
│   ├── multi_tier_workflow.yaml
│   └── backend.env.example
│
├── artifacts/                      ← ALL generated outputs (gitignored)
│   ├── runs/
│   │   ├── benign/                 ← benign pipeline outputs
│   │   └── malicious_full_v2/      ← malicious pipeline outputs
│   ├── canonical/
│   │   └── canonical_labeled_flows.csv   ← THE training dataset
│   ├── ml_workflow/
│   │   └── latest/
│   │       ├── gaussian_nb/
│   │       │   ├── model.joblib
│   │       │   ├── feature_manifest.json
│   │       │   ├── holdout_metrics.json
│   │       │   └── roc_curve.png
│   │       ├── random_forest/
│   │       └── gradient_boosting/
│   ├── multi_tier/
│   │   └── latest/
│   │       ├── graph_bundle.json
│   │       └── stage_metrics.json
│   └── backend_jobs/               ← per-job artifact storage (local mode)
│
├── docs/                           ← project documentation
│   ├── README.md
│   ├── project-journey.md          ← 11-phase implementation history
│   ├── findings-register.md
│   ├── artifact-index.md
│   ├── backend-platform.md
│   └── adr/
│       └── 0001-feature-extraction-stack.md   ← why Zeek+NFStream, not CICFlowMeter
│
├── Thesis/                         ← academic thesis PDF (reference only)
├── Dockerfile                      ← container build for API + worker
├── docker-compose.yaml             ← full stack: api, worker, postgres, redis, minio
├── pyproject.toml                  ← package metadata, dependencies, tool config
├── requirements.lock               ← pinned production dependencies
│
└── (root scripts — Tutorials 34-42)
    ├── extract-nfstream.py
    ├── zeektocsv.py
    ├── flows.py
    ├── combineCSV.py
    ├── clean.py
    ├── merge-pcaps.py
    ├── mscp_down.py
    ├── freeze_benign.py
    └── sanityChecks-basic.py
```

---

## 6. The End-to-End Data Flow

This is the most important diagram in the project. Everything you will study in later
tutorials is a step in this flow.

```
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: RAW DATA COLLECTION                                        │
│                                                                     │
│  Benign PCAP (lab traffic)        Malicious PCAP (CTU-13 botnet)   │
└────────────────┬───────────────────────────────┬────────────────────┘
                 │                               │
                 ▼                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 2: SANITISE & FILTER                                          │
│                                                                     │
│  editcap  →  fix malformed packets, remove truncation errors        │
│  tshark   →  keep ONLY packets matching "tls or quic" display filter│
│                                                                     │
│  Output: a clean PCAP containing only encrypted traffic             │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
           ┌─────────────────────┴───────────────────────┐
           │                                             │
           ▼                                             ▼
┌──────────────────────┐                    ┌────────────────────────┐
│  STEP 3a: ZEEK       │                    │  STEP 3b: NFSTREAM     │
│                      │                    │                        │
│  Reads PCAP          │                    │  Reads PCAP            │
│  Outputs log files:  │                    │  Computes per-flow     │
│  - conn.log          │                    │  statistics:           │
│  - ssl.log           │                    │  - byte counts         │
│  - tls.log           │                    │  - packet counts       │
│  - x509.log          │                    │  - duration            │
│  - quic.log          │                    │  - inter-arrival times │
│                      │                    │  - payload histograms  │
│  Then: convert to    │                    │                        │
│  CSV via zeek.py     │                    │  Output: nfstream.csv  │
└──────────┬───────────┘                    └──────────┬─────────────┘
           │                                           │
           └─────────────────────┬─────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 4: MERGE FEATURES                                             │
│                                                                     │
│  Join Zeek CSVs + NFStream CSV on:                                  │
│  (src_ip, dst_ip, src_port, dst_port)  within 2-second time window  │
│                                                                     │
│  Result: one row per flow with ALL features from both tools         │
│  Output: merged.csv (~100 columns per flow)                         │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 5: QUALITY GATES                                              │
│                                                                     │
│  Gate 1: PCAP not truncated (capinfos)                              │
│  Gate 2: Required Zeek logs exist                                   │
│  Gate 3: Merge match rate ≥ 90%  (enough flows matched)             │
│  Gate 4: Unmatched Zeek UIDs ≤ 10%                                  │
│  Gate 5: Non-TLS/QUIC leakage ≤ 5%  (only encrypted flows remain)  │
│  Gate 6: Duplicate flow keys = 0                                    │
│  Gate 7: Duplicate UIDs after merge = 0                             │
│                                                                     │
│  FAIL any gate → pipeline stops (or continues with --allow-failures)│
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 6: FEATURE ENGINEERING                                        │
│                                                                     │
│  build_dataset.py:                                                  │
│    - text columns → length-of-string numeric encoding               │
│    - drop identifier columns (IPs, ports, UIDs)                     │
│    - keep only numeric columns                                      │
│                                                                     │
│  pruning.py:                                                        │
│    - drop constant features (zero variance)                         │
│    - drop near-constant features (>99.5% same value)                │
│    - drop highly correlated features (Pearson r > 0.95)             │
│                                                                     │
│  finalize.py:                                                       │
│    - drop temporal columns that would cause data leakage            │
│    (e.g. ts_zeek_ssl, bidirectional_first_seen_ms)                  │
│                                                                     │
│  Output: ml_ready.csv (~50-70 clean numeric columns)               │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                          (repeat for both
                           benign + malicious)
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 7: CANONICAL DATASET                                          │
│                                                                     │
│  canonical.py reads configs/canonical_sources.yaml                  │
│  Loads benign ml_ready.csv  → adds label=benign, label_id=0        │
│  Loads malicious ml_ready.csv → adds label=malicious, label_id=1   │
│  Adds metadata: attack_family, capture_id, protocol_family,         │
│                 window_id, record_id, source_dataset ...            │
│  Concatenates everything into ONE file:                             │
│                                                                     │
│  Output: artifacts/canonical/canonical_labeled_flows.csv            │
│          49,158 rows × 115 columns                                  │
│          (18,986 benign + 30,172 malicious)                         │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 8: ML WORKFLOW (ml/workflow.py)                               │
│                                                                     │
│  Load canonical_labeled_flows.csv                                   │
│  Exclude metadata/temporal columns                                  │
│  Impute missing values (mean strategy)                              │
│  Train/test split: 80% train, 20% test, stratified, seed=42        │
│                                                                     │
│  For each of 3 models:                                              │
│    [GaussianNB, RandomForest(300 trees), GradientBoosting(200)]     │
│                                                                     │
│    1. Stratified 5-fold cross-validation on train set               │
│    2. Find optimal decision threshold (max F1 on CV folds)          │
│    3. Evaluate on holdout test set:                                 │
│       accuracy, precision, recall, F1, balanced_accuracy,           │
│       ROC-AUC, average_precision                                    │
│    4. Permutation feature importance (top 20 features)              │
│    5. Save: model.joblib, cv_summary.json, holdout_metrics.json,   │
│             feature_manifest.json, roc_curve.png, pr_curve.png      │
│                                                                     │
│  Results: RandomForest & GradientBoosting achieve near-perfect      │
│           GaussianNB F1 ≈ 0.80 (intentionally weaker, used Tier 1) │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 9: MULTI-TIER DETECTION (detection/multitier.py)              │
│                                                                     │
│  Input: canonical dataset + trained model bundles                   │
│                                                                     │
│  TIER 1 — Fast Screening (GaussianNB)                               │
│    Apply broad threshold → flag suspicious candidates               │
│    44,776 / 49,158 rows pass through (high recall, lower precision) │
│                                                                     │
│  TIER 2 — Deep Consensus (RandomForest + GradientBoosting)          │
│    Score tier1 candidates with both deep models                     │
│    Weighted average of probability outputs                          │
│    Both models must agree (min_deep_model_passes: 2)                │
│    29,898 flows flagged as suspicious (precision=1.0, recall=0.991) │
│                                                                     │
│  GRAPH ENRICHMENT (BFS clustering)                                  │
│    Build graph: suspicious flows → edges between src/dst endpoints  │
│    Find connected components (clusters)                             │
│    Assign alert levels by cluster size + flow count                 │
│    Result: 1 cluster, 1,846 nodes, 1,845 edges                      │
│    Dominant host: 10.0.2.109 → 1,844 public peers (botnet pattern) │
│                                                                     │
│  Output: graph_bundle.json, stage_metrics.json, alert_summary.json  │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 10: BACKEND PLATFORM (backend/)                               │
│                                                                     │
│  User uploads new PCAP via HTTP POST /api/v1/jobs                   │
│      ↓                                                              │
│  FastAPI stages file to object storage (MinIO/local)                │
│  Creates ProcessingJob record in PostgreSQL (status=QUEUED)         │
│      ↓                                                              │
│  Job enqueued on Redis via RQ                                       │
│      ↓                                                              │
│  Worker process picks job up (status=RUNNING)                       │
│  Runs scoring.py → malicious pipeline → multi-tier detection        │
│      ↓                                                              │
│  Artifacts uploaded to object storage                               │
│  Job updated (status=SUCCEEDED + artifact links)                    │
│      ↓                                                              │
│  User polls GET /api/v1/jobs/{job_id} → retrieves results           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 7. The Five Package Layers at a Glance

```
tls_dataset/
│
├── pipeline/     DATA LAYER
│                 Raw PCAP → clean, labeled, ML-ready features
│                 The most complex layer. 16 modules.
│
├── ml/           LEARNING LAYER
│                 Labeled CSV → trained models + evaluation evidence
│                 One module: workflow.py
│
├── detection/    SCORING LAYER
│                 New data + trained models → malicious/benign + clusters
│                 One module: multitier.py
│
├── backend/      SERVICE LAYER
│                 Everything above wrapped in a REST API with persistent state
│                 10 modules. Docker-deployed.
│
└── reporting/    EXPORT LAYER
    static_site/  Results → human-readable dashboards and static bundles
                  2 modules.
```

---

## 8. The 11-Phase Project Journey (Summarised)

This project was built in 11 phases, documented in `docs/project-journey.md`.
Understanding the order helps you explain *why* things were built the way they were.

| Phase | What was built | Key insight |
|-------|---------------|-------------|
| 1 | Repository foundation — `src/`, `tests/`, `configs/`, `artifacts/`, `Dockerfile` | No structure = no reproducibility |
| 2 | ADR 0001 — formally dropped CICFlowMeter, committed to Zeek+NFStream | Alignment between thesis text and code |
| 3 | Parameterised pipeline refactor — `orchestration.py`, all `pipeline/` modules | One path for benign and malicious instead of ad-hoc scripts |
| 4 | Data-quality gates — 7 checks before allowing features to proceed | Silent bad data was a real problem |
| 5 | Real pipeline execution — discovered benign works, malicious PCAP was truncated | Data curation is a real problem, not just code |
| 6 | Malicious pipeline rebuild — `malicious.py`, provenance, Zeek auto-detection | The malicious source only has conn.log — a data limitation, not a code bug |
| 7 | Canonical labeled dataset — `canonical.py`, 49,158 rows, 115 columns | Single truth for all downstream work |
| 8 | ML workflow — 3 models, CV, thresholds, evidence artifacts | RF/GB near-perfect but likely overfit to limited dataset diversity |
| 9 | Multi-tier detection + graph enrichment | Moved beyond classification into analyst-grade enrichment |
| 10 | Backend scoring platform — FastAPI, RQ, Postgres, MinIO | From research tool to operational service |
| 11 | Hardening — removed dashboard from backend, clean separation of concerns | Backend = scoring service, not UI |

---

## 9. The Entry Points — How You Run This Project

There are **three ways** to run this project:

### A. CLI (command-line, for data pipelines and ML)

The CLI is the main entry point for all data processing and ML work.

```bash
# The package registers this script via pyproject.toml:
# [project.scripts]
# tls-dataset = "tls_dataset.cli:main"

tls-dataset info                          # sanity check
tls-dataset run-dataset-pipeline ...      # benign or malicious raw PCAP → ML features
tls-dataset run-malicious-pipeline ...    # specialised malicious preparation
tls-dataset build-canonical-dataset ...  # combine into labeled CSV
tls-dataset run-ml-workflow ...           # train + evaluate models
tls-dataset run-multi-tier ...            # score + cluster
tls-dataset export-static-dashboard ...  # export static analytics bundle
```

You can also run it as a module (equivalent, no install needed):
```bash
PYTHONPATH=src python -m tls_dataset info
```

This works because `src/tls_dataset/__main__.py` contains:
```python
from tls_dataset.cli import main
if __name__ == "__main__":
    raise SystemExit(main())
```

### B. Docker Compose (for the backend platform)

```bash
docker compose up --build
# Starts: api (port 8000), worker, postgres, redis, minio (port 9000/9001)
```

Then use HTTP requests:
```bash
curl -X POST http://localhost:8000/api/v1/jobs \
     -F "file=@traffic.pcap" \
     -F "model_name=random_forest"
```

### C. Python import (for scripting / testing)

```python
from tls_dataset.pipeline.orchestration import run_dataset_pipeline
from tls_dataset.ml.workflow import run_ml_workflow
from tls_dataset.detection.multitier import run_multitier_detection
```

---

## 10. The `technical_direction.py` File — Why It Exists

`src/tls_dataset/technical_direction.py` is a deliberate design decision:

```python
@dataclass(frozen=True)
class TechnicalDirection:
    production_extractors: tuple[str, ...]
    thesis_legacy_extractors: tuple[str, ...]
    decision_summary: str

TECHNICAL_DIRECTION = TechnicalDirection(
    production_extractors=("zeek", "nfstream"),
    thesis_legacy_extractors=("cicflowmeter",),
    decision_summary=(
        "Zeek + NFStream is the official production extraction stack. "
        "CICFlowMeter remains thesis-era legacy and is not part of the forward build path."
    ),
)
```

**Why have a Python file for this?** Because architecture decisions should be
**code-level facts**, not just comments in a doc. When `cli.py` runs `info`, it imports
this object and prints it. Any developer reading the codebase immediately knows the
decision without reading a separate doc. The `frozen=True` on the dataclass means it
cannot be mutated — this is intentional, it models an immutable decision.

---

## 11. What Datasets Were Actually Used

| Dataset | Type | Size | Source |
|---------|------|------|--------|
| Lab traffic PCAP | Benign | 18,986 flows after processing | Captured locally |
| CTU-13 botnet capture | Malicious | 30,172 flows after processing | Czech Technical University |

**Combined canonical dataset:**
- Total rows: **49,158**
- Total columns: **115**
- TLS flows: **47,759** (97.2%)
- QUIC flows: **1,399** (2.8%)

**Important caveat from the project journey:**
> The malicious PCAP's Zeek output only contains `conn.log` — not `ssl.log`, `tls.log`,
> or `quic.log`. This means the malicious flows have fewer Zeek-derived protocol features.
> This is a **source data limitation**, not a bug. The near-perfect RandomForest / 
> GradientBoosting scores are likely inflated by the limited dataset diversity.

---

## 12. Key Files to Bookmark Right Now

| File | Why you need to know it |
|------|------------------------|
| `src/tls_dataset/cli.py` | All CLI commands and their argument wiring |
| `src/tls_dataset/pipeline/common.py` | All file paths — if you're lost on where a file goes, look here |
| `src/tls_dataset/pipeline/orchestration.py` | The master pipeline — chains everything |
| `src/tls_dataset/pipeline/quality.py` | The 7 quality gates — the project's safety net |
| `src/tls_dataset/ml/workflow.py` | All ML training, CV, evaluation in one file |
| `src/tls_dataset/detection/multitier.py` | The full detection system |
| `src/tls_dataset/backend/app.py` | All API routes |
| `configs/canonical_sources.yaml` | Which CSVs become the training dataset |
| `configs/ml_workflow.yaml` | All ML hyperparameters |
| `docs/project-journey.md` | The 11-phase history — answers "why is it built this way?" |
| `docs/adr/0001-feature-extraction-stack.md` | Why CICFlowMeter was dropped |

---

## 13. Interview Questions & Answers for Tutorial 00

**Q: What is the core problem this project solves?**
> Detecting malicious network activity in encrypted TLS 1.3 and QUIC traffic without
> decrypting the payloads. It analyses metadata — connection patterns, timing, packet
> sizes, TLS handshake fields — rather than content.

**Q: Why not just decrypt the traffic and inspect it?**
> Three reasons: (1) modern TLS 1.3 makes interception extremely difficult — forward
> secrecy means captured traffic cannot be decrypted even with the server's private key;
> (2) decryption violates privacy regulations in many jurisdictions; (3) certificate
> pinning in mobile apps prevents MITM interception entirely.

**Q: What tools extract features from PCAPs?**
> Zeek for protocol-aware metadata (TLS handshake fields, certificate info, QUIC
> metadata) and NFStream for bidirectional flow statistics (byte counts, packet counts,
> timing, inter-arrival times). Their outputs are joined into one feature table.

**Q: Why was CICFlowMeter dropped?**
> Formally decided in ADR 0001. CICFlowMeter is Java-based (extra dependency track),
> was already not used in the actual code, and its flow-level features overlap with
> NFStream's output. Keeping it would have created two incompatible feature tracks with
> no benefit. NFStream is Python-native and already integrated.

**Q: How many ML models are trained and why those three?**
> Three: GaussianNB, RandomForest, GradientBoosting. GaussianNB is the lightweight
> fast model used in Tier 1 screening — it's interpretable and probabilistic. RandomForest
> and GradientBoosting are the deep ensemble models used in Tier 2 consensus. Having
> two independent ensemble models in Tier 2 means both must agree before a flow is flagged
> as malicious, reducing false positives.

**Q: What is the multi-tier approach and why use it instead of one model?**
> A single powerful model applied to every flow is computationally expensive and produces
> false positives. The two-tier approach uses a cheap model (GaussianNB) to rapidly
> discard obvious benign traffic, then a slower ensemble only on the remaining candidates.
> The graph enrichment layer then identifies coordinated activity (like botnets) that
> individual flow scores cannot detect.

**Q: What are quality gates and why are they in the pipeline?**
> Quality gates are validation checks that stop the pipeline if the data is bad.
> Without them, truncated PCAPs, bad joins, or contaminated non-encrypted traffic
> would silently produce corrupt training data. The project discovered this the hard
> way — the benign pipeline's first run exposed encrypted-traffic leakage that would
> have contaminated the training set.

**Q: What is the canonical dataset?**
> A single labeled CSV that combines processed benign and malicious flows with stable
> metadata columns (label, attack_family, capture_id, record_id, protocol_family, etc.).
> It is the single source of truth for training, evaluation, and reporting. Having one
> canonical file means every downstream workflow interprets the same schema.

**Q: What does the backend platform add that the CLI doesn't have?**
> Persistence and operationalisation. The CLI processes one PCAP at a time interactively.
> The backend accepts PCAP uploads via HTTP, queues them as jobs in Redis, processes
> them asynchronously in a worker, stores results in PostgreSQL and MinIO, and allows
> users to poll for results. It's the difference between a research script and a service.

---

*Next: [01_setup_and_installation.md](01_setup_and_installation.md)*
