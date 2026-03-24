# Backend Platform

This project now includes a backend scoring platform layer on top of the existing pipeline, ML, and multi-tier detection work.

## Architecture

The backend is built around four production-oriented responsibilities:

- `FastAPI` serves the API surface for health, model-bundle discovery, PCAP job submission, and job/batch status inspection.
- `Postgres` stores metadata for batches, queued jobs, and artifact references.
- `Object storage` preserves uploaded PCAPs and generated outputs such as workflow summaries, CSVs, graphs, and reports.
- `Redis + RQ` provide the worker queue so batch PCAP processing happens asynchronously instead of inside API requests.

The implementation lives under `src/tls_dataset/backend/`.

## Main Components

Core modules:

- `src/tls_dataset/backend/app.py`
- `src/tls_dataset/backend/db.py`
- `src/tls_dataset/backend/models.py`
- `src/tls_dataset/backend/storage.py`
- `src/tls_dataset/backend/queue.py`
- `src/tls_dataset/backend/services.py`
- `src/tls_dataset/backend/scoring.py`
- `src/tls_dataset/backend/worker.py`

What they do:

- `app.py` exposes the FastAPI routes and startup lifecycle.
- `db.py` manages the SQLAlchemy engine, session factory, and schema initialization.
- `models.py` defines metadata tables for batches, jobs, and artifacts.
- `storage.py` supports both local object storage and S3-compatible storage such as MinIO.
- `queue.py` supports a real RQ backend and an inline backend for tests.
- `services.py` handles job intake, artifact registration, serialization, and model-bundle discovery.
- `scoring.py` turns merged pipeline output into an inference-ready dataset and runs the multi-tier scoring path for queued PCAPs.
- `worker.py` executes queued scoring jobs and updates metadata state.

## API Surface

Current endpoints:

- `GET /api/v1/health`
- `GET /api/v1/model-bundles`
- `GET /api/v1/jobs`
- `GET /api/v1/jobs/{job_id}`
- `GET /api/v1/batches/{batch_id}`
- `POST /api/v1/jobs/pcap-score`
- `POST /api/v1/batches/pcap-score`
- `POST /api/v1/jobs/pcap-score/from-path`
- `GET /api/v1/platform/summary`

Submission flow:

1. The API accepts one or more PCAPs.
2. Each upload is stored in object storage immediately.
3. A batch record and one queued job per PCAP are written to Postgres.
4. The worker later downloads the input artifact, runs the extraction and scoring pipeline, uploads produced artifacts, and writes the final summary back to Postgres.

## Scoring Flow

For each queued job:

1. Download the PCAP input artifact from object storage.
2. Run the sanitized Zeek + NFStream processing path through the standardized pipeline.
3. Build an inference-ready scoring dataset from the merged output.
4. Run multi-tier scoring with the active model bundle.
5. Save suspicious-flow outputs, graph outputs, and workflow summaries.
6. Upload all generated files as output artifacts and update job metadata.

This means the backend is not just serving static files. It is orchestrating the same evidence-producing pipeline and multi-tier logic that the thesis implementation now relies on.

## Environment Configuration

An example platform environment file is provided at:

- `configs/backend.env.example`

Important settings:

- database connection
- Redis queue connection
- object-store backend and credentials
- model-bundle root and default bundle directory
- job workspace path
- Zeek binary path

## Docker Compose Stack

The repository now includes a platform-oriented `docker-compose.yaml` with:

- `api`
- `worker`
- `postgres`
- `redis`
- `minio`

The API and worker share the project volume and the generated artifacts area. The worker also expects access to a Zeek binary through `ZEEK_BIN`, which can be provided by the image or a bind-mounted host install.

## Verification

The backend platform is covered by:

- `tests/test_backend_platform.py`
- `tests/test_reporting_snapshot.py`

Verified locally in this workspace:

- metadata/job creation works
- input artifacts are registered
- worker state transitions succeed
- output-artifact registration works in the tested path
- the full repository test suite passes with `38` tests

One local limitation remains in this sandbox: binding a live HTTP port for an interactive curl check was blocked by the execution environment, so runtime verification here is based on code-level tests rather than an exposed local server session.
