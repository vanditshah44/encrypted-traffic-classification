# Tutorial 27 — Services Layer (`backend/services.py`)

## Prerequisites

- Tutorial 22 (`backend/models.py`, `backend/db.py`) — `ProcessingJob`, `JobBatch`,
  `JobArtifact`, `ArtifactKind`, `JobStatus`, `session_scope`. The services layer is the
  primary consumer of all four ORM models.
- Tutorial 23 (`backend/schemas.py`) — the serialization functions here produce the dicts that
  FastAPI constructs `JobResponse`, `ArtifactResponse`, and `BatchResponse` from.
- Tutorial 24 (`backend/storage.py`) — `get_storage` wraps `build_object_storage`; `StoredObject`
  is what `put_file` returns and what `build_artifact_record` maps to a DB row.
- Tutorial 25 (`backend/queue.py`) — `get_queue` wraps `build_queue_backend`; `QueueTicket`
  fields land in `ProcessingJob.external_job_id` etc.
- Tutorial 26 (`backend/registry.py`) — `resolve_model_bundle_dir` and `discover_model_bundles`
  are both called here.

---

## 1. Why This File Exists

The API routes (Tutorial 30) and the worker (Tutorial 29) each need to:
- Accept a PCAP, store it, create DB records, and enqueue a job
- Upload output files after scoring and record them in the DB
- Fetch job/batch records and serialise them to JSON-ready dicts

Putting that logic directly in route handlers would scatter it across the API file and make it
untestable in isolation. `services.py` is the **business logic layer**: it owns all orchestration
that touches more than one subsystem (storage + DB, queue + DB, registry + serialisation). Route
handlers and the worker call these functions and stay thin.

---

## 2. Module-Level Constant (line 22)

```python
DATASET_SAFE = re.compile(r"[^a-zA-Z0-9_-]+")
```

A compiled regex that matches any run of characters that are **not** alphanumeric, hyphen, or
underscore. Compiled once at import time rather than inside `normalize_dataset_name`. If
`normalize_dataset_name` were called thousands of times (batch submission), re-compiling the
regex on every call would waste CPU. `re.compile` at module level is the standard pattern for
frequently used regexes.

---

## 3. `IncomingPcap` (lines 25–31)

```python
@dataclass(frozen=True)
class IncomingPcap:
    local_path: Path
    filename: str
    dataset_name: str
    content_type: str | None = None
```

A plain value object representing a PCAP file that has arrived from the API client but has not
yet been stored or turned into a DB record. `local_path` is the temporary location (from an
uploaded multipart file or a server-side path from `PathJobRequest`). `filename` may differ
from `local_path.name` — the client's original filename is preserved separately so the stored
artifact retains the original name regardless of where the temp file landed.

`frozen=True` — these are facts about what arrived. They should not be mutated between the
point of receipt and the point of storage.

`content_type: str | None = None` — optional because HTTP multipart uploads carry a
`Content-Type` header but path-based submissions (`PathJobRequest`) do not. When `None`,
`guess_content_type` infers from the filename extension.

---

## 4. `normalize_dataset_name` (lines 33–36)

```python
def normalize_dataset_name(value: str) -> str:
    cleaned = DATASET_SAFE.sub("_", value.strip())
    cleaned = cleaned.strip("_")
    return cleaned[:120] or "pcap_job"
```

`value.strip()` — removes leading/trailing whitespace before substitution. Without this, a name
like `"  my pcap  "` would become `"__my_pcap__"` (spaces converted to underscores, then the
leading/trailing underscores stripped anyway, but only by the second strip).

`DATASET_SAFE.sub("_", ...)` — replaces every run of unsafe characters with a single `_`.
The regex matches runs (`+`), so `"my  pcap!!name"` becomes `"my_pcap_name"`, not
`"my__pcap___name"`.

`.strip("_")` — removes leading and trailing underscores left by the substitution. A filename
like `"__capture.pcap"` would otherwise produce `"__capture_pcap"`.

`[:120]` — truncates to 120 characters. `dataset_name` is stored in `ProcessingJob.dataset_name`
which is a `VARCHAR` column; truncating here prevents database-level errors on absurdly long
filenames.

`or "pcap_job"` — if `cleaned` is empty after all transformations (e.g., the original name was
all special characters like `"!!!"`), the fallback ensures the field is never an empty string.
An empty `dataset_name` would cause downstream path-construction issues.

---

## 5. `guess_content_type` (lines 39–41)

```python
def guess_content_type(filename: str, override: str | None) -> str:
    return override or mimetypes.guess_type(filename)[0] or "application/octet-stream"
```

Three-level priority chain: explicit override → MIME sniffing from extension → binary fallback.
`mimetypes.guess_type` returns `(type, encoding)` and the `[0]` takes only the type. A `.pcap`
file returns `(None, None)` — not in the standard MIME database — so `.pcap` uploads always
fall through to `"application/octet-stream"`. This is correct: S3 will store the `Content-Type`
metadata as `"application/octet-stream"`, which tells clients to treat it as raw binary data.

---

## 6. `get_storage` and `get_queue` (lines 43–51)

```python
def get_storage(settings: BackendSettings | None = None) -> ObjectStorage:
    resolved = settings or get_backend_settings()
    storage = build_object_storage(resolved)
    storage.ensure_bucket(resolved.object_store_bucket)
    return storage
```

The critical difference from calling `build_object_storage` directly: `get_storage` always
calls `ensure_bucket` before returning. Every consumer of this function gets a storage object
where the bucket is guaranteed to exist. This removes the burden of bucket management from
callers — no route handler or worker function needs to remember to call `ensure_bucket`.

`ensure_bucket` is idempotent (Tutorial 24): `mkdir -p` for local, `HeadBucket` + conditional
`CreateBucket` for S3. The overhead per call is one filesystem stat or one S3 API call — cheap
compared to the file transfer that follows.

`get_queue` is a thinner wrapper because queues have no equivalent of "ensure bucket". The RQ
`Queue` object creates the Redis key on first use; no explicit initialization is needed.

---

## 7. `create_batch_from_pcaps` (lines 54–126)

This is the most complex function in the file. It coordinates four subsystems — model registry,
storage, database, and queue — in a precise order dictated by consistency requirements.

### Phase 1: Validation and resource resolution (lines 62–68)

```python
    resolved_settings = settings or get_backend_settings()
    if not uploads:
        raise ValueError("At least one PCAP must be provided")
    storage = get_storage(resolved_settings)
    queue = get_queue(resolved_settings)
    resolved_model_bundle_dir = resolve_model_bundle_dir(model_bundle_dir, settings=resolved_settings)
```

`resolve_model_bundle_dir` runs the four-level resolution ladder (Tutorial 26). It can raise
`FileNotFoundError` if no bundle is found. That error propagates to the API route, which
returns HTTP 422 or 500. Resolving this before creating any DB records means a missing bundle
is caught before any state is committed.

### Phase 2: Create and flush the batch (lines 69–77)

```python
    batch = JobBatch(
        batch_name=batch_name or f"pcap_batch_{len(uploads)}",
        request_payload={"job_count": len(uploads), "model_bundle_dir": str(resolved_model_bundle_dir)},
    )
    session.add(batch)
    session.flush()
```

`session.flush()` — sends the `INSERT` to the database within the current transaction but does
**not** commit. After flush, `batch.id` is populated (the UUID is generated by the
`default=uuid4` on the model column). Subsequent code can reference `batch.id` to set
`ProcessingJob.batch_id`. Without flushing first, `batch.id` would still be the SQLAlchemy
placeholder and the foreign key assignment would write `None`.

### Phase 3: Create jobs, store PCAPs, create artifact records (lines 79–114)

```python
    for upload in uploads:
        dataset_name = normalize_dataset_name(upload.dataset_name)
        job = ProcessingJob(
            batch_id=batch.id,
            ...
            status=JobStatus.QUEUED.value,
            ...
        )
        session.add(job)
        session.flush()   # ← gets job.id before computing object_key

        object_key = f"jobs/{job.id}/inputs/{Path(upload.filename).name}"
        stored = storage.put_file(upload.local_path, bucket=..., object_key=object_key, ...)
        artifact = build_artifact_record(job_id=job.id, ..., stored=stored, ...)
        session.add(artifact)
        jobs.append(job)
```

`session.flush()` after each job — same reason as the batch flush: `job.id` must be resolved
before it can be embedded in the `object_key`. The object key `"jobs/{job.id}/inputs/filename"`
namespaces stored files by job UUID, ensuring no collisions even if the same filename is
uploaded multiple times across different jobs.

`storage.put_file` is called while the transaction is still open. This means the file is
physically written to disk or uploaded to S3 before the DB records are committed. If the DB
commit later fails, the file exists in storage but has no DB record pointing to it — an
orphaned artifact. This is acceptable: storage costs for orphaned files are negligible, and
the alternative (committing the DB record before storing the file) would create DB records
pointing to non-existent files, which is worse.

### Phase 4: First commit — persists all DB state before touching the queue (line 116)

```python
    session.commit()
```

**Why commit before enqueueing?** The queue message contains only the `job_id`. The worker will
immediately call `session.get(ProcessingJob, job_id)` when it picks up the message. If the
worker receives the message before this commit, `session.get` returns `None` and the worker
raises `RuntimeError("Job not found")`. Committing first guarantees the worker always finds the
record. The ordering is:

```
commit DB → enqueue → worker picks up → worker loads job from DB ✓
enqueue → worker picks up → commit DB (delayed) → worker loads job → None ✗
```

### Phase 5: Enqueue and store ticket data (lines 118–124)

```python
    for job in jobs:
        ticket = queue.enqueue_scoring_job(job.id)
        job.queue_backend = ticket.backend
        job.queue_name = ticket.queue_name
        job.external_job_id = ticket.external_job_id

    session.commit()
    session.refresh(batch)
    return batch
```

`external_job_id` is the RQ job UUID (or the application `job_id` for inline). Writing it back
to `ProcessingJob` after enqueuing allows operators to cross-reference the application job with
the queue system record.

`session.refresh(batch)` — after the second commit, the session's in-memory batch object may
not reflect the latest DB state, specifically the `batch.jobs` relationship list (which was
populated incrementally). `refresh` reloads the batch and its relationships from the DB so the
caller gets a fully-populated `JobBatch` with all child jobs attached.

---

## 8. `build_artifact_record` (lines 129–152)

```python
def build_artifact_record(
    *,
    job_id: str,
    kind: str,
    artifact_type: str,
    logical_path: str,
    stored: StoredObject,
    metadata_payload: dict[str, Any] | None = None,
) -> JobArtifact:
    return JobArtifact(
        job_id=job_id, kind=kind, artifact_type=artifact_type,
        logical_path=logical_path,
        storage_backend=stored.backend, bucket=stored.bucket,
        object_key=stored.object_key, object_uri=stored.object_uri,
        filename=stored.filename, content_type=stored.content_type,
        size_bytes=stored.size_bytes, sha256=stored.sha256,
        metadata_payload=metadata_payload,
    )
```

Pure function: takes a `StoredObject` and the application-level context and maps them to a
`JobArtifact` constructor call. No session operations, no side effects. This is the exact
translation layer between the storage abstraction and the ORM. Keeping it separate from
`create_batch_from_pcaps` and `upload_output_artifacts` means the mapping can be read and
tested in isolation.

All keyword-only arguments (`*` at the start) — prevents `build_artifact_record(job.id, "input", ...)` 
where argument order determines correctness. Forcing keyword usage makes each call self-documenting.

---

## 9. `upload_output_artifacts` (lines 155–190)

```python
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        logical_path = path.relative_to(root).as_posix()
        object_key = f"jobs/{job.id}/outputs/{logical_path}"
        stored = storage.put_file(path, bucket=..., object_key=object_key)
        artifact = build_artifact_record(
            job_id=job.id,
            kind=ArtifactKind.OUTPUT.value,
            artifact_type=classify_output_artifact(logical_path),
            logical_path=f"outputs/{logical_path}",
            stored=stored,
        )
        session.add(artifact)
        uploaded.append(artifact)
    session.flush()
    return uploaded
```

`sorted(root.rglob("*"))` — `rglob("*")` yields all filesystem entries recursively (files and
directories). `not path.is_file()` skips directories. `sorted()` makes the upload order
deterministic — same results on every run, regardless of filesystem ordering.

`path.relative_to(root).as_posix()` — converts the absolute path to a relative path string
with forward slashes regardless of OS. If `root` is `/artifacts/backend_jobs/abc123/run/` and
`path` is `/artifacts/backend_jobs/abc123/run/results/suspicious_flows.csv`, the result is
`"results/suspicious_flows.csv"`. `as_posix()` ensures forward slashes on Windows too.

`object_key = f"jobs/{job.id}/outputs/{logical_path}"` — the output key mirrors the input key
structure: `jobs/{uuid}/inputs/` for inputs, `jobs/{uuid}/outputs/` for outputs. All artifacts
for a job are co-located under `jobs/{uuid}/` in the bucket, making it easy to enumerate or
clean up all artifacts for a specific job.

`session.flush()` at the end rather than `session.commit()`. The caller (the worker, Tutorial
29) owns the transaction boundary and will commit after also updating `job.summary_payload`,
`job.status`, etc. Flushing here ensures the artifact records are in the DB within the same
transaction, so if the worker's commit fails, the partial artifact list is also rolled back.

---

## 10. `classify_output_artifact` (lines 193–215)

```python
def classify_output_artifact(logical_path: str) -> str:
    lower = logical_path.lower()
    if lower.endswith("_quality_report.json"):
        return "quality_report"
    if lower.endswith("workflow_summary.json"):
        return "workflow_summary"
    if lower.endswith("platform_summary.json"):
        return "platform_summary"
    if lower.endswith("graph_bundle.json"):
        return "graph_bundle"
    if lower.endswith("suspicious_flows.csv"):
        return "suspicious_flows_csv"
    if lower.endswith("tiered_flow_scores.csv"):
        return "tiered_scores_csv"
    if lower.endswith(".png"):
        return "plot"
    if lower.endswith(".csv"):
        return "csv"
    if lower.endswith(".json"):
        return "json"
    if lower.endswith(".pcap") or lower.endswith(".pcapng"):
        return "pcap"
    return "artifact"
```

Cascade of `endswith` checks from **most specific to least specific**. Order matters: if
`".json"` came before `"workflow_summary.json"`, every JSON file would be classified as `"json"`
and the specific types would never be reached. The specific suffixes (`"_quality_report.json"`,
`"suspicious_flows.csv"`) are checked before the generic extension checks (`".json"`, `".csv"`).

The `lower` conversion makes classification case-insensitive — `"Suspicious_Flows.CSV"` and
`"suspicious_flows.csv"` both classify correctly. Case normalisation at the classification
layer means file-writing code does not need to enforce case conventions.

`"artifact"` is the catch-all fallback — any file that matches no known suffix gets a generic
type. This is preferable to raising: an unexpected output file (perhaps a new type added by
the scoring pipeline) is still recorded in the DB with a usable type label.

---

## 11. Serialization Functions (lines 218–281)

### `serialize_artifact` (lines 218–242)

```python
def serialize_artifact(artifact: JobArtifact, *, settings: BackendSettings | None = None) -> dict[str, Any]:
    resolved_settings = settings or get_backend_settings()
    storage = get_storage(resolved_settings)
    return {
        ...
        "download_reference": storage.build_reference(
            bucket=artifact.bucket,
            object_key=artifact.object_key,
            filename=artifact.filename,
        ),
        ...
        "metadata": artifact.metadata_payload or {},
        "created_at": artifact.created_at.isoformat(),
    }
```

`get_storage` is called here — which means `ensure_bucket` is called on every artifact
serialisation. This is the cost of the convenience pattern: a health-check call for every
artifact in every API response. For a job with 10 output artifacts, the response serialisation
makes 10 `ensure_bucket` calls. Since `ensure_bucket` is a single `mkdir` or `HeadBucket`,
the overhead is small, but a production hardening would cache the storage object per request.

`storage.build_reference(...)` — for S3, generates a presigned URL valid for
`s3_presign_expiry_seconds`. This is the point where the ephemeral `download_reference` field
(Tutorial 23) is computed from the durable `bucket`/`object_key`. For local storage it returns
the absolute path.

`artifact.metadata_payload or {}` — `metadata_payload` is a nullable JSON column. If `None`,
the API sends `"metadata": {}` rather than `"metadata": null`. Downstream clients can always
iterate `response.metadata.items()` without null-checking.

`artifact.created_at.isoformat()` — converts `datetime` to an ISO 8601 string
(`"2026-04-15T14:23:01+00:00"`). SQLAlchemy returns `datetime` objects; Pydantic schemas
declared as `str` in `ArtifactResponse.created_at` accept dicts with string values, not
datetime objects.

### `serialize_job` (lines 245–266)

```python
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "request": job.request_payload or {},
        "summary": job.summary_payload or {},
        "artifacts": [serialize_artifact(artifact, settings=settings) for artifact in job.artifacts],
```

`started_at` and `completed_at` use conditional `isoformat()` — they are `None` for queued and
running jobs respectively. `or {}` on `request_payload` and `summary_payload` — same null-guard
as for artifact metadata.

`job.artifacts` accesses the SQLAlchemy relationship loaded when the `ProcessingJob` was
queried. The serialisation recurses into each artifact via `serialize_artifact`, passing
`settings=settings` so each artifact's `build_reference` call reuses the same settings object
rather than calling `get_backend_settings()` fresh for each artifact.

### `serialize_batch` (lines 269–281)

```python
    status_counts: dict[str, int] = {}
    for job in batch.jobs:
        status_counts[job.status] = status_counts.get(job.status, 0) + 1
```

`status_counts` is computed in Python by iterating `batch.jobs`. An alternative would be a SQL
`GROUP BY` query, but since `batch.jobs` is already loaded by the relationship (the ORM
executes a `SELECT` for child jobs when the relationship is first accessed), a second query
would be redundant. The Python iteration is cheaper than a second DB round-trip for small
batches (< ~1000 jobs).

---

## 12. Query Functions (lines 284–302)

```python
def list_jobs(session: Session, *, limit: int = 50) -> list[ProcessingJob]:
    statement = select(ProcessingJob).order_by(ProcessingJob.created_at.desc()).limit(limit)
    return list(session.scalars(statement))

def get_job(session: Session, job_id: str) -> ProcessingJob | None:
    return session.get(ProcessingJob, job_id)

def count_jobs(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(ProcessingJob)) or 0)
```

`session.get(ProcessingJob, job_id)` uses SQLAlchemy's identity map: if the object was already
loaded in this session, it returns the in-memory instance without a DB query. For a fresh
session (the normal case for an API request), it executes a primary-key lookup. This is
distinct from `session.scalars(select(...).where(...))`, which always executes a query.

`select(func.count()).select_from(ProcessingJob)` generates `SELECT count(*) FROM processing_jobs`.
`session.scalar` returns the single scalar result, which is an `int` or `None` if the table is
empty (in practice never `None` for `COUNT`, but the `or 0` makes the intent explicit and
satisfies the type checker).

---

## 13. Model Bundle Functions (lines 305–321)

```python
def serialize_model_bundle(bundle: ModelBundle, *, settings: BackendSettings | None = None) -> dict[str, Any]:
    resolved_settings = settings or get_backend_settings()
    return {
        ...
        "model_names": list(bundle.model_names),
        "is_default": resolved_settings.default_model_bundle_dir == bundle.path,
        ...
    }
```

`list(bundle.model_names)` — `model_names` is a `tuple` (required by `frozen=True` in
`ModelBundle`, Tutorial 26). JSON serialises both `list` and `tuple` as arrays, but Pydantic's
`ModelBundleResponse.model_names: list[str]` expects a `list`. Converting here rather than in
the API layer keeps the schema honest.

`is_default: resolved_settings.default_model_bundle_dir == bundle.path` — comparing two `Path`
objects. `Path.__eq__` compares the resolved, normalised path strings. This is why
`BackendSettings.default_model_bundle_dir` is stored as a `Path` with `.expanduser().resolve()`
applied at settings construction time (Tutorial 21), and `ModelBundle.path` is also resolved
via `resolve()` in `discover_model_bundles` (Tutorial 26). If both are resolved, the comparison
is correct. If either were unresolved (e.g., one had `~` and one didn't), they would compare
unequal even for the same filesystem location.

---

## 14. `stage_uploaded_file` (lines 324–335)

```python
def stage_uploaded_file(
    *,
    source_path: str | Path,
    working_dir: str | Path,
    filename: str | None = None,
) -> Path:
    source = Path(source_path).expanduser().resolve()
    target_dir = Path(working_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / (filename or source.name)
    shutil.copy2(source, target)
    return target
```

Used by the API when a file arrives as a multipart upload. FastAPI writes multipart files to
a system temp directory (typically `/tmp/`). Before the temp file is cleaned up, this function
copies it to a structured working directory so it can be referenced by `IncomingPcap.local_path`.

`filename or source.name` — if a specific filename is requested (the client's original name),
use it; otherwise preserve the temp file's name. Retaining the original client filename ensures
the stored artifact's `filename` field reflects what the user uploaded, not a temp-file UUID.

`shutil.copy2` preserves metadata — same reasoning as Tutorial 24.

---

## 15. Interview Questions and Answers

**Q: Why are there two `session.commit()` calls in `create_batch_from_pcaps`, and why must they
happen in that specific order?**

A: The first commit persists all `ProcessingJob` and `JobArtifact` records before any job is
enqueued. The RQ worker executes asynchronously: it picks up the queue message and immediately
calls `session.get(ProcessingJob, job_id)`. If the first commit had not yet happened, the
worker would find no record and raise `RuntimeError("Job not found")`. The second commit saves
the `external_job_id` returned by the queue after enqueuing — this is informational and does
not affect worker execution. The ordering `commit → enqueue → commit` ensures the worker
always finds a valid DB record, at the cost of having orphaned queue messages if the second
commit fails (jobs in the queue with no `external_job_id` recorded, but still executable).

---

**Q: Why does `upload_output_artifacts` use `session.flush()` but `create_batch_from_pcaps`
uses `session.commit()`?**

A: `create_batch_from_pcaps` is a top-level operation that must complete atomically and be
visible to the worker process before the function returns. It owns its transaction boundary.
`upload_output_artifacts` is called from within the worker's transaction (`worker.py`), which
also updates `job.status`, `job.summary_payload`, and the three count fields in the same
session. Flushing sends the artifact inserts to the DB within the open transaction without
committing; the worker's single commit then atomically persists both the artifacts and the job
status update. If `upload_output_artifacts` committed itself, there would be a window where
artifacts exist in the DB but the job still shows `RUNNING` — a client polling between those
two commits would see a misleading partial state.

---

**Q: Why does `get_storage` call `ensure_bucket` on every invocation instead of once at
startup?**

A: The backend can start with `object_store_local_root` pointing at a directory that does not
yet exist, or start before an S3 bucket is created. Calling `ensure_bucket` once at startup
would require the storage backend to be available at startup time; a temporary S3 outage at
startup would prevent the API from launching. `ensure_bucket` at each `get_storage` call means
the bucket is created lazily, on first need, and re-created if it is accidentally deleted. The
idempotency of `ensure_bucket` (Tutorial 24) makes this safe to call repeatedly.

---

**Q: Why does `classify_output_artifact` check specific suffixes before generic extensions?**

A: Python's `if`/`elif` chain is a short-circuit: the first matching branch wins. If `.json`
were checked before `workflow_summary.json`, every JSON file would be classified as `"json"`
and the specific type labels would never be reached. The specific-to-generic ordering ensures
that `workflow_summary.json` is classified as `"workflow_summary"` and only truly generic
`.json` files fall through to `"json"`. This is the standard approach for any dispatch table
where more specific patterns must take priority over general ones.

---

**Q: `serialize_model_bundle` computes `is_default` by comparing two `Path` objects. When
could this comparison give a wrong answer?**

A: If either path is not fully resolved (i.e., contains `~`, `..`, or unresolved symlinks),
`Path.__eq__` would compare the raw strings and two paths pointing to the same filesystem
location could compare unequal. The code avoids this by ensuring both paths are resolved at
their origin: `BackendSettings.default_model_bundle_dir` is resolved in `get_backend_settings`
via `Path(...).expanduser().resolve()`, and `ModelBundle.path` is resolved in
`discover_model_bundles` via `Path(root_dir).expanduser().resolve()` on the root, followed by
`candidate` being an absolute subdirectory of that resolved root. As long as these invariants
hold, the `==` comparison is a reliable filesystem identity check.

---

*Next: [Tutorial 28 — Scoring Function](28_backend_scoring.md)*
