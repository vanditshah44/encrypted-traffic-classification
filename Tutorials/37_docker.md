# Tutorial 37 — Docker and Deployment (`Dockerfile`, `docker-compose.yaml`, `.dockerignore`)

## Prerequisites

- Tutorial 21 (`backend/config.py`) — all `TLS_BACKEND_*` environment variables set in
  docker-compose map directly to `BackendSettings` fields.
- Tutorial 25 (`backend/queue.py`) — `RQQueueBackend` is what the worker uses in the
  compose stack; `InlineQueueBackend` is the test fallback.
- Tutorial 29 (`backend/worker.py`) — the worker container command runs this module.
- Tutorial 30 (`backend/app.py`) — the api container command runs this FastAPI app.

---

## 1. The Five-Service Architecture

```
Browser / API client
        │
        ▼
   ┌─────────┐   HTTP :8000
   │   api   │──────────────── FastAPI (tls_dataset.backend.app)
   └────┬────┘
        │ enqueues job via RQ
        ▼
   ┌─────────┐   :6379
   │  redis  │──────────────── Job queue
   └────┬────┘
        │ worker polls queue
        ▼
   ┌─────────┐
   │ worker  │──────────────── Scoring pipeline (tls_dataset.backend.worker)
   └────┬────┘
        │
   ┌────┴──────────────────┐
   ▼           ▼           ▼
postgres     minio       /opt/zeek
(metadata)  (artifacts)  (host mount)
```

`api` and `worker` are two separate processes running from the **same image**. They differ
only in their `command`. This is the standard RQ deployment pattern: the API enqueues jobs
into Redis; the worker dequeues and executes them. Separating them into distinct containers
means the worker can be scaled independently (`docker-compose scale worker=3`) without
spinning up additional API processes.

---

## 2. `Dockerfile` — Line by Line

### Base image choice

```dockerfile
FROM python:3.12-slim
```

Three Python image variants exist: `python:3.12` (full Debian), `python:3.12-slim` (Debian,
essential packages only), `python:3.12-alpine` (Alpine Linux, musl libc). `slim` is chosen
over `alpine` because NFStream, psycopg (the PostgreSQL driver), and Scapy all contain C
extensions compiled against **glibc** (GNU libc). Alpine uses **musl libc**, which is
binary-incompatible — pre-built wheels from PyPI will not run, forcing a full recompile from
source that often fails for complex packages. `slim` keeps the image smaller than the full
Debian image while retaining glibc compatibility.

### ENV block

```dockerfile
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive
```

Each variable solves a specific container problem:

**`PYTHONDONTWRITEBYTECODE=1`** — Python normally writes `.pyc` bytecode files alongside
`.py` source files. In a container, the filesystem is ephemeral — these files are never
reused across container restarts. They add size to the writable layer and cause spurious
file-change events on the bind-mounted source volume (Tutorial 37 §4).

**`PYTHONUNBUFFERED=1`** — Python buffers stdout by default when not connected to a
terminal. Inside a container, stdout is not a terminal, so `print()` output and log messages
sit in an internal buffer and may never appear in `docker logs` before the process crashes.
`PYTHONUNBUFFERED=1` disables buffering: every log line appears in `docker logs` immediately.
This is critical for debugging worker jobs.

**`PIP_NO_CACHE_DIR=1`** — pip normally caches downloaded wheel files in `~/.cache/pip`.
In a container that is built once and run, this cache is never reused across builds. It just
adds 50–200MB to the image size. Disabling it keeps the image lean.

**`DEBIAN_FRONTEND=noninteractive`** — Some Debian packages prompt for timezone or keyboard
layout during installation (via `debconf`). In a non-interactive Docker build, these prompts
hang the build indefinitely. `noninteractive` instructs debconf to accept defaults silently.

### System package installation

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpcap-dev \
    tshark \
    && rm -rf /var/lib/apt/lists/*
```

Four packages:

**`build-essential`** — the Debian meta-package for C compilation: `gcc`, `g++`, `make`,
`libc-dev`. Required to compile Python C extensions from source (NFStream's underlying
`nfstream_core` C module, psycopg's binary extension if the wheel is absent for this
platform).

**`gcc`** — explicitly listed alongside `build-essential` for clarity, already pulled in by
it. Harmless to repeat.

**`libpcap-dev`** — the libpcap C library and development headers. NFStream and Scapy both
call into libpcap for raw packet access. Without the headers (`-dev` package), the C
compilation step fails with `pcap.h: No such file or directory`.

**`tshark`** — the command-line version of Wireshark used in `pipeline/filtering.py`
(Tutorial 04) to apply display filters and extract TLS/QUIC packets. This IS installed in the
image because it is small, well-packaged, and required for the filtering stage that the worker
runs.

**Why tshark but not Zeek?** tshark is ~50MB and available as a standard Debian package.
Zeek is 200–300MB and requires custom compilation or the Zeek project's own package
repository — neither is a clean apt-get line. More importantly, Zeek version consistency with
the training captures matters: if training was done with Zeek 6.0, scoring should use the
same version. Mounting the host Zeek installation guarantees this. See §4.

**`--no-install-recommends`** — prevents apt from installing "recommended" packages (packages
the maintainer suggests but doesn't require). For `tshark`, recommends include a GUI toolkit
and QT libraries — useless in a container, ~100MB of wasted space.

**`rm -rf /var/lib/apt/lists/*`** — apt stores the downloaded package index files
(`/var/lib/apt/lists/`) after `apt-get update`. They are only needed during this `RUN` layer.
Removing them in the same `RUN` command (same layer) prevents them from being committed to the
image. If the `rm` were a separate `RUN`, Docker would have already committed the lists in the
previous layer — removing them would only add a deletion entry to the overlay, not reclaim
the space in the prior layer.

### Layer cache optimisation

```dockerfile
COPY requirements.lock pyproject.toml README.md ./
RUN python -m pip install --upgrade pip && python -m pip install -r requirements.lock

COPY . .
RUN python -m pip install -e .
```

This ordering is the most important Dockerfile performance decision. Docker builds images as a
stack of layers, each cached by its inputs. When you change a file, every layer that depends
on it (directly or transitively) is invalidated and rebuilt.

If the order were reversed — `COPY . .` first, then `pip install` — every single code change
would invalidate the `pip install` layer and trigger a full reinstall of all dependencies
(including pandas, scikit-learn, NFStream). On a typical machine this takes 3–5 minutes.

With the correct ordering: `requirements.lock` and `pyproject.toml` rarely change. As long as
they don't, Docker reuses the cached `pip install -r requirements.lock` layer regardless of
what changed in the Python source files. A code-only change rebuilds only the final
`pip install -e .` layer (~2 seconds), not the dependency install.

`README.md` is included in the first `COPY` because `pyproject.toml` references it
(`readme = "README.md"`) and setuptools reads it during package metadata inspection.
Without it, `pip install -e .` would fail.

### Default command

```dockerfile
CMD ["python", "-m", "tls_dataset", "info"]
```

The default command just prints the package version and architecture direction (Tutorial 33).
It is not the command used in production — `docker-compose.yaml` overrides it for both `api`
and `worker`. The default exists so that `docker run tls-dataset:dev` without a compose file
gives immediate, useful feedback ("the package is installed and working") rather than
crashing or doing nothing.

---

## 3. `docker-compose.yaml` — Service by Service

### `api` — The FastAPI Server

```yaml
command: ["python", "-m", "uvicorn", "tls_dataset.backend.app:app",
          "--host", "0.0.0.0", "--port", "8000"]
ports:
  - "8000:8000"
```

`--host 0.0.0.0` binds uvicorn to all network interfaces inside the container. The default
`127.0.0.1` would only accept connections from within the container itself — the published
port `8000:8000` would be unreachable from the host or other containers. `0.0.0.0` is always
required when running behind a port mapping.

### `worker` — The Background Job Processor

```yaml
command: ["python", "-m", "tls_dataset.backend.worker"]
```

`backend/worker.py` contains `if __name__ == "__main__": raise SystemExit(main())`. Running it
with `-m tls_dataset.backend.worker` invokes Python's module execution, which sets
`__name__ = "__main__"`, triggering `main()`. `main()` starts an `rq.Worker` process that
blocks, polling Redis for scoring jobs (Tutorial 29).

**Why the worker uses the same image as the api:**
Both containers need the full pipeline code (Zeek parsing, NFStream extraction, merging,
quality gates, ML inference) plus all the backend infrastructure (SQLAlchemy, S3 client, RQ).
Maintaining two images with near-identical dependency sets would double build time and create
version drift. One image, two commands.

### Shared volumes

```yaml
volumes:
  - .:/app
  - /opt/zeek:/opt/zeek:ro
```

**`.:/app`** — bind-mounts the entire project root into the container at `/app`. Every code
change on the host is immediately visible inside the container without rebuilding the image.
This is the development workflow: edit `backend/app.py`, the change is live in the container
on the next request (uvicorn reloads on file change with `--reload`; the worker picks up
changes on the next job).

**`/opt/zeek:/opt/zeek:ro`** — bind-mounts the host Zeek installation as read-only. The
`ZEEK_BIN=/opt/zeek/bin/zeek` environment variable (Tutorial 05) points `resolve_zeek_binary`
to this path. `:ro` (read-only) prevents the container from accidentally modifying the Zeek
installation. This is a security and correctness measure: the container should only invoke
Zeek, never write to it.

### `depends_on` and health checks

```yaml
depends_on:
  - postgres
  - redis
  - minio
```

`depends_on` tells Compose to start `postgres`, `redis`, and `minio` before starting `api` and
`worker`. However, `depends_on` only waits for the container to **start**, not for the service
inside it to be **ready**. PostgreSQL takes a few seconds after its container starts before it
accepts connections. This is why `postgres` has a `healthcheck`:

```yaml
healthcheck:
  test: ["CMD-SHELL", "pg_isready -U tls_dataset -d tls_dataset"]
  interval: 10s
  timeout: 5s
  retries: 5
```

`pg_isready` is the standard PostgreSQL readiness probe. It checks whether the server is
accepting connections on the socket. Until this passes, `depends_on` (when combined with
`condition: service_healthy` in newer Compose versions) holds the dependent service. The
current compose file uses plain `depends_on` without conditions — the api and worker have
their own SQLAlchemy connection retry logic that handles the brief startup gap.

### `postgres:16-alpine`

```yaml
image: postgres:16-alpine
```

PostgreSQL's official Alpine image is used here (unlike the api/worker base image) because
PostgreSQL is a Go/C application compiled natively for Alpine. No Python C extensions are
involved — the musl vs glibc concern does not apply to the database container.

```yaml
volumes:
  - postgres_data:/var/lib/postgresql/data
```

`postgres_data` is a **named volume** managed by Docker. It persists across `docker-compose
down` and `docker-compose up` — the database survives container recreation. To reset the
database completely, run `docker-compose down -v` (the `-v` flag removes all named volumes).

### `redis:7-alpine`

```yaml
command: ["redis-server", "--save", "", "--appendonly", "no"]
```

Two persistence mechanisms are explicitly disabled:

**`--save ""`** — disables RDB snapshots. By default, Redis saves a point-in-time snapshot
to disk every 60–900 seconds. For a job queue, snapshot recovery is not needed: jobs that
were in Redis when the container stopped are expected to be resubmitted, not recovered from
a stale snapshot.

**`--appendonly no`** — disables the Append-Only File (AOF), Redis's write-ahead log.
Enabled AOF writes every command to disk, adding latency to every enqueue/dequeue operation.
For a development queue where throughput is not the bottleneck, this overhead is unnecessary.

Redis has no named volume for the same reason: its data is ephemeral by design here. There is
no `redis_data` volume.

### `minio` — S3-Compatible Object Store

```yaml
image: minio/minio:latest
command: ["server", "/data", "--console-address", ":9001"]
ports:
  - "9000:9000"   # S3 API
  - "9001:9001"   # Web console
volumes:
  - minio_data:/data
```

MinIO implements the S3 API. The backend's `S3ObjectStorage` (Tutorial 24) connects to
`http://minio:9000` and uses standard boto3 S3 calls — the code is identical whether the
backend is real AWS S3 or MinIO. This is the key benefit of MinIO in development: no AWS
account, no IAM roles, no network egress, but identical code path.

Port 9001 is MinIO's web console — a browser UI for browsing buckets and objects.
`--console-address :9001` binds the console to a separate port from the S3 API (9000), so
both are reachable independently.

`minio_data:/data` is a named volume, persisting uploaded PCAP artifacts and scoring results
across container restarts.

---

## 4. `.dockerignore` — What Never Enters the Image

```
.venv
artifacts
BotnetCapture
benign_process_csv
freezeData
zeek-out-benign
Thesis
*.pcap
*.pcapng
*.cap
*.log
```

`.dockerignore` works exactly like `.gitignore` but for the Docker build context. Every `COPY`
instruction copies from the build context; `.dockerignore` filters what is in that context
before the copy happens.

**`.venv`** — the local virtual environment directory. If included, Docker would copy
hundreds of megabytes of pre-installed packages into `/app/.venv`, then `pip install` into
the image's system Python at `/usr/local/lib/python3.12/`. The `.venv` packages would never
be used (Python in the container has no activation pointing to them) and would inflate the
image by 500MB+.

**`artifacts`** — pipeline outputs: trained models, CSVs, quality reports. These are
runtime-generated files, not source files. Including them would bake a specific run's outputs
into the image — the container would start with stale artifacts that might conflict with a
fresh run.

**`*.pcap`, `*.pcapng`, `*.cap`** — PCAP files can be several gigabytes each. Including any
of them in the build context would make `docker build` extremely slow (transferring gigabytes
to the Docker daemon) and the resulting image enormous.

**`*.log`** — Zeek produces `.log` files during processing runs. These are ephemeral outputs,
never needed in the image.

**`BotnetCapture`, `benign_process_csv`, `freezeData`, `zeek-out-benign`** — thesis-era data
directories specific to the local development machine. These paths would not exist on another
developer's machine or a CI server; excluding them prevents accidental inclusion if these
directories are present locally.

**`Thesis`** — the thesis writing directory (LaTeX, drafts). Irrelevant to the container.

---

## 5. The Full Development Workflow

```bash
# 1. Build the image (only needed once, or after requirements.lock changes)
docker-compose build

# 2. Start all services
docker-compose up

# 3. The stack is now running:
#    API:     http://localhost:8000
#    MinIO:   http://localhost:9000 (S3 API)
#             http://localhost:9001 (web console)
#    Postgres: localhost:5432
#    Redis:    localhost:6379

# 4. Submit a PCAP for scoring via the API (Tutorial 30)
curl -X POST http://localhost:8000/api/v1/jobs \
  -F "file=@capture.pcap" \
  -F "dataset_name=test_run"

# 5. Watch worker logs
docker-compose logs -f worker

# 6. Tear down (preserves postgres_data and minio_data volumes)
docker-compose down

# 7. Full reset including all data
docker-compose down -v
```

---

## 6. Interview Questions and Answers

**Q: Why is Zeek mounted from the host rather than installed in the Dockerfile?**

A: Three reasons. First, Zeek is 200–300MB and requires either compiling from source or
adding the Zeek project's custom apt repository — neither is a clean, stable `apt-get` line.
Second, version consistency matters: the model was trained on captures processed by a specific
Zeek version. If the container used a different Zeek version, column names or protocol
detection behaviour could differ, causing subtle inference errors. Mounting the host Zeek
guarantees the same binary for training and inference. Third, the PCAP captures are generated
on the host machine anyway — it makes sense for the host to own the Zeek installation rather
than duplicating it inside every container.

---

**Q: Why does `COPY requirements.lock pyproject.toml README.md ./` come before `COPY . .`?**

A: Docker layer caching. Each `RUN` or `COPY` instruction creates a new layer, and layers are
cached by their inputs. If dependencies are installed after copying all source files, any code
change invalidates the `pip install` layer and triggers a full dependency reinstall — 3–5
minutes. By copying only the dependency files first, the `pip install -r requirements.lock`
layer is only invalidated when `requirements.lock` or `pyproject.toml` actually changes, which
is rare. Code-only changes skip straight to the final `pip install -e .`, which takes seconds.

---

**Q: Redis persistence is disabled for the queue. What happens to in-flight jobs if the Redis container restarts?**

A: In-flight jobs (dequeued by the worker but not yet complete) are lost from Redis's
perspective — the worker holds the job in memory during execution. Queued-but-not-yet-dequeued
jobs are also lost since persistence is disabled. In production, this would require either
enabling AOF persistence or using a dedicated managed Redis with replication. For this
development setup, jobs are resubmitted through the API if the queue is lost. The database
(`postgres_data` volume) preserves all job records and their status — a lost Redis entry
means the job may revert to `queued` status in the DB and need to be retried, but no data is
permanently lost.

---

**Q: The api and worker containers both have `volumes: .:/app`. If the worker modifies an artifact file, does the api container see it immediately?**

A: Yes. Both containers mount the same host directory at `/app`. Writes to
`/app/artifacts/backend_jobs/...` by the worker are immediately visible to the api container
reading the same path — they share the underlying host filesystem. This is why the
`export_static_dashboard_bundle` (Tutorial 32) can be triggered from the API and the resulting
`data.json` is immediately available to serve: both processes see the same file tree.

---

*Next: [Tutorial 38 — Project Documentation](38_docs.md)*
