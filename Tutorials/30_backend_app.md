# Tutorial 30 — FastAPI Application (`backend/app.py`)

## Prerequisites

- Tutorial 21 (`backend/config.py`) — `get_backend_settings()` is called once inside
  `create_app()` and captured in closures by every route handler.
- Tutorial 22 (`backend/db.py`) — `get_db_session`, `init_database`, `get_engine`; the
  difference between `session_scope` (auto-commit) and `get_db_session` (caller manages commits)
  determines which routes commit and which rely on the services layer.
- Tutorial 23 (`backend/schemas.py`) — every `response_model` argument maps to a schema here.
- Tutorial 25 (`backend/queue.py`) — `build_queue_backend` is called in the health check.
- Tutorial 26 (`backend/registry.py`) — `discover_model_bundles` is called in the health check
  and the platform summary route.
- Tutorial 27 (`backend/services.py`) — `create_batch_from_pcaps`, `serialize_job`,
  `serialize_batch`, `stage_uploaded_file`, and the query functions are the workhorses behind
  every route.

---

## 1. Why This File Exists

All the components built in Tutorials 21–29 are headless: they have no HTTP interface. `app.py`
is the single entry point that wires them together as an HTTP API. It defines every route,
declares request and response types, handles file uploads, and sets up the application
lifecycle. It is intentionally thin: route handlers call services functions rather than
containing business logic themselves.

---

## 2. The `create_app` Factory (lines 40–208)

```python
def create_app() -> FastAPI:
    settings = get_backend_settings()
    ...
    app = FastAPI(title=settings.api_title, version="0.1.0", lifespan=lifespan)
    ...
    return app

app = create_app()
```

The application is built by a factory function rather than as a module-level object. `settings`
is read once inside `create_app()` and captured by every route handler's closure. All route
functions have access to `settings` without calling `get_backend_settings()` themselves, which
is important because `get_backend_settings()` is `lru_cache`-wrapped — calling it in every
request would still be fast, but it signals the wrong ownership: settings belong to the
application, not to individual requests.

`app = create_app()` at line 208 runs at import time. Uvicorn imports this module and looks for
the `app` attribute. The factory pattern also allows tests to call `create_app()` with
different environment variables set, getting a fresh application instance per test without
module-level singleton state interfering.

---

## 3. `lifespan` — Application Startup and Shutdown (lines 43–47)

```python
@asynccontextmanager
async def lifespan(_: FastAPI):
    init_database()
    get_storage(settings)
    yield
```

`lifespan` replaces the deprecated `@app.on_event("startup")` / `@app.on_event("shutdown")`
pattern. It is an async context manager: code before `yield` runs once when the server starts;
code after `yield` (none here) runs when the server shuts down. FastAPI passes the app instance
as the argument, ignored here with `_`.

`init_database()` — creates all ORM tables if they do not exist. This must run before any
request that touches the DB. Placing it here ensures the schema exists regardless of whether
the API or the worker process ran first.

`get_storage(settings)` — calls `build_object_storage` and then `ensure_bucket` (Tutorial 27,
Section 6). At startup, the object store bucket is created if it does not exist. Any storage
configuration error (wrong credentials, unreachable S3 endpoint) surfaces here, before the
server starts accepting requests, rather than on the first upload.

---

## 4. Missing Import: `Path` (a bug in the code)

`Path` is used in lines 115, 117, 123, 144, 148, 155, 175, 178, and 181, but
`from pathlib import Path` is not in the import block. This is a missing import — the module
would raise `NameError: name 'Path' is not defined` the first time any upload route is called.
The fix is to add `from pathlib import Path` to the imports. This is a latent bug that would
only be caught at runtime by calling one of the upload endpoints, not by import or type
checking alone (since `from __future__ import annotations` defers annotation evaluation).

---

## 5. Dependency Injection: `Depends(get_db_session)` (used across routes)

```python
session: Session = Depends(get_db_session)
```

FastAPI's `Depends` system calls `get_db_session()` for each request, injects the yielded
session into the route handler, and closes it in the `finally` block of `get_db_session` after
the response is sent. This gives each request its own session with a clean identity map.

`get_db_session` (Tutorial 22) does **not** auto-commit. The session is yielded and closed
with no commit. Route handlers that read data (`GET` routes) do not need to commit anything.
Routes that write (`POST` routes) pass the session to `create_batch_from_pcaps`, which calls
`session.commit()` explicitly. If a route raises `HTTPException` before committing, the session
is closed without a commit — the rollback is implicit (uncommitted changes are discarded when
the session closes).

This is different from `session_scope` used in the worker (Tutorial 29), which auto-commits on
clean exit. The API uses the more explicit pattern because route handlers need finer control:
a `create_batch_from_pcaps` failure partway through should not commit partial state.

---

## 6. Route: `GET /` (lines 51–58)

```python
@app.get("/", include_in_schema=False)
def root() -> dict[str, object]:
    return {"service": ..., "status": "ok", "api_base": "/api/v1", "docs_url": "/docs"}
```

`include_in_schema=False` — hides this route from the auto-generated OpenAPI (`/docs`) and
`/openapi.json`. It is a convenience endpoint for humans navigating to the root URL, not a
documented API surface. The `/docs` path is FastAPI's built-in Swagger UI, generated
automatically from all `response_model` annotations.

---

## 7. Route: `GET /api/v1/health` (lines 60–80)

```python
@app.get("/api/v1/health", response_model=HealthResponse)
def health() -> HealthResponse:
    database_health = {"ok": False}
    with get_engine().connect() as connection:
        connection.execute(text("SELECT 1"))
    database_health["ok"] = True
    ...
```

`text("SELECT 1")` — SQLAlchemy 2.0 requires `text()` to wrap raw SQL strings passed to
`execute()`. This sends one round-trip to the database; if the DB is unreachable, it raises
and the health endpoint returns HTTP 500.

The `database_health = {"ok": False}` then `database_health["ok"] = True` pattern is fragile:
if `connection.execute` raises, the exception propagates out of `health()` and FastAPI returns
a 500 error rather than a structured `HealthResponse` with `"ok": false`. A robust
implementation would wrap the DB check in `try/except` and set `{"ok": False, "error":
str(exc)}` on failure so monitoring systems receive a 200 with a degraded status rather than a
500. This is a known gap.

`queue.healthcheck()` — for RQ, calls `connection.ping()` (Tutorial 25). For inline, returns
the queue name dict. If Redis is unreachable in RQ mode, `ping()` raises, and the health
endpoint again returns 500 rather than a structured degraded response.

`model_bundles={"count": len(bundles), "root": ...}` — the health check does not verify that
individual bundles are loadable, only that `discover_model_bundles` can enumerate them. A
bundle with a corrupt `model.joblib` would pass this check.

---

## 8. Route: `GET /api/v1/jobs` (lines 86–91)

```python
@app.get("/api/v1/jobs", response_model=JobListResponse)
def jobs(
    limit: int = 50,
    session: Session = Depends(get_db_session),
) -> JobListResponse:
    return JobListResponse(items=[serialize_job(job, settings=settings) for job in list_jobs(session, limit=limit)])
```

`limit: int = 50` — because `limit` is not a path parameter and not declared as `Body`, FastAPI
treats it as a query parameter. Clients call `GET /api/v1/jobs?limit=100`. The default `50`
prevents unintentionally returning thousands of rows.

`[serialize_job(job, settings=settings) for job in list_jobs(...)]` — `serialize_job` returns
a `dict`; `JobListResponse(items=[...])` constructs the Pydantic model from the list of dicts.
Pydantic coerces each dict into a `JobResponse` instance via the `items: list[JobResponse]`
field declaration.

---

## 9. Routes: `GET /api/v1/jobs/{job_id}` and `GET /api/v1/batches/{batch_id}` (lines 93–105)

```python
job = get_job(session, job_id)
if job is None:
    raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
return JobResponse.model_validate(serialize_job(job, settings=settings))
```

`HTTPException(status_code=404)` — FastAPI catches `HTTPException` and converts it to an HTTP
response with the given status code and a JSON body `{"detail": "Job not found: ..."}`. Raising
rather than returning allows the function to have a single return path for the success case.

`JobResponse.model_validate(serialize_job(...))` — explicit Pydantic validation before
returning. `serialize_job` returns a `dict`; `model_validate` constructs a `JobResponse` and
raises `ValidationError` if any field is missing or has the wrong type. Compared to just
returning the dict and letting FastAPI serialise it, this surfaces schema mismatches eagerly:
if `serialize_job` changes and drops a required field, the route handler raises a 422 during
development rather than silently sending a malformed response.

---

## 10. Route: `POST /api/v1/jobs/pcap-score` (lines 107–135)

```python
@app.post("/api/v1/jobs/pcap-score", response_model=BatchResponse, status_code=201)
async def create_single_job(
    file: UploadFile = File(...),
    dataset_name: str | None = Form(default=None),
    model_bundle_dir: str | None = Form(default=None),
    batch_name: str | None = Form(default=None),
    session: Session = Depends(get_db_session),
) -> BatchResponse:
```

`async def` — this route is async because it awaits ASGI I/O. FastAPI runs `async def` routes
in the event loop; `def` routes in a thread pool. The `file.file` object is an ASGI
`SpooledTemporaryFile` — it must be read in an async context to avoid blocking the event loop.

`File(...)` and `Form(...)` — both declare multipart form fields. `file: UploadFile = File(...)`
declares the uploaded binary field. `dataset_name: str | None = Form(default=None)` declares
optional text fields in the same multipart body. You cannot mix `File`/`Form` fields with a
JSON body (`Body`) in a single request — multipart encoding is the only way to send both a
file and metadata in one HTTP request.

`status_code=201` — HTTP 201 Created is the semantically correct status for a `POST` that
creates a new resource. The default `200` would be technically wrong; the response includes the
created batch record.

### The temp-dir-then-cleanup pattern

```python
    temp_dir = Path(tempfile.mkdtemp(prefix="tls_dataset_upload_"))
    try:
        target = temp_dir / file.filename
        with target.open("wb") as handle:
            shutil.copyfileobj(file.file, handle)
        ...
        return BatchResponse.model_validate(...)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
```

`tempfile.mkdtemp` — creates a new empty directory under the system temp dir (e.g.,
`/tmp/tls_dataset_upload_abc123/`). Unlike `NamedTemporaryFile`, `mkdtemp` creates a directory
rather than a file, allowing multiple files to coexist (important for the batch route).

`shutil.copyfileobj(file.file, handle)` — streams the upload from the ASGI file object to disk
in chunks. Without streaming, a 500 MB PCAP would be read entirely into memory before writing.
`copyfileobj` uses an internal 16 KB buffer by default.

The `finally` block runs whether the `try` body succeeded, raised, or was interrupted. `shutil
.rmtree(temp_dir, ignore_errors=True)` deletes the temp directory and all contents.
`ignore_errors=True` prevents a cleanup failure (e.g., file locked) from masking the original
exception. Even if `create_batch_from_pcaps` raises, the temp file is cleaned up.

Why clean up? `create_batch_from_pcaps` calls `storage.put_file(upload.local_path, ...)`
which copies the file into object storage. After that call, the temp file is redundant. Leaving
temp files accumulating would eventually fill the disk on a busy server.

`dataset_name or Path(file.filename).stem` — if the client did not provide a `dataset_name`,
the filename stem is used (e.g., `"capture.pcap"` → `"capture"`). `Path(...).stem` strips the
extension and any directory component.

---

## 11. Route: `POST /api/v1/batches/pcap-score` (lines 137–168)

The batch upload route is structurally identical to the single upload route with two
differences:

`files: list[UploadFile] = File(...)` — accepts multiple files in a single multipart request.
HTTP clients send these as repeated `files` parts in the multipart body.

All files are staged to the same `temp_dir` before any are passed to
`create_batch_from_pcaps`. This means if staging the third file fails, the cleanup deletes all
three partial copies. `create_batch_from_pcaps` processes all `uploads` in a single call,
creating one `JobBatch` with one `ProcessingJob` per file — the correct semantics for a batch.

---

## 12. Route: `POST /api/v1/jobs/pcap-score/from-path` (lines 170–193)

```python
@app.post("/api/v1/jobs/pcap-score/from-path", response_model=BatchResponse, status_code=201)
def create_job_from_path(
    request: PathJobRequest,
    session: Session = Depends(get_db_session),
) -> BatchResponse:
    temp_dir = Path(tempfile.mkdtemp(prefix="tls_dataset_path_stage_"))
    try:
        staged = stage_uploaded_file(source_path=request.source_path, working_dir=temp_dir)
        ...
```

`def` not `async def` — no file upload, no ASGI I/O. The request body is a JSON object
(`PathJobRequest`); FastAPI deserialises it with Pydantic directly. FastAPI runs this in the
thread pool.

`request: PathJobRequest` — declared as a positional argument with a Pydantic model type.
FastAPI interprets this as a JSON request body. The client sends
`{"source_path": "/data/capture.pcap"}`.

`stage_uploaded_file(source_path=request.source_path, working_dir=temp_dir)` — copies the
server-side file to the temp directory. Why stage at all when the file is already local? Because
`create_batch_from_pcaps` calls `storage.put_file(upload.local_path, ...)`, which reads from
`local_path` and stores a copy. If `local_path` were the original file path, the services layer
would store it in the object store and the original file would remain. Staging creates a
controlled working copy, and the `finally` cleanup removes it. The original file is never
modified.

`content_type=None` — path-based submissions carry no Content-Type header. `guess_content_type`
in the services layer will infer from the extension (Tutorial 27, Section 5).

---

## 13. Route: `GET /api/v1/platform/summary` (lines 195–203)

```python
@app.get("/api/v1/platform/summary")
def platform_summary(session: Session = Depends(get_db_session)) -> dict[str, object]:
    return {
        "job_count": count_jobs(session),
        "batch_count": count_batches(session),
        "model_bundle_count": len(discover_model_bundles(settings.model_bundle_root)),
        "job_run_root": str(settings.job_run_root),
        "object_store_bucket": settings.object_store_bucket,
    }
```

No `response_model` — the return type annotation `dict[str, object]` is the only schema hint.
FastAPI serialises it as JSON without Pydantic validation. This is acceptable for an informal
dashboard endpoint; adding a `response_model` would require defining a schema for a rarely-used
route.

`discover_model_bundles` is called on every request to this endpoint, re-reading the
filesystem each time. For a small bundle directory (typically 2–5 entries), this is negligible.

---

## 14. The Inline Mode Gap

When `TLS_BACKEND_QUEUE_BACKEND=inline`, `InlineQueueBackend.enqueue_scoring_job` returns a
`QueueTicket` but does not call `process_scoring_job` (Tutorial 25, Section 4). Examining
`app.py`, there is no code that checks the queue backend and calls `process_scoring_job`
synchronously. This means: **in inline mode, jobs submitted through the API are created in the
DB with `status="queued"` and never executed.**

To process them, the operator must run the worker manually:

```bash
python -m tls_dataset.backend.worker --job-id <job_id>
```

Inline mode is therefore useful for testing the job-intake path (does the API correctly create
DB records and store the PCAP?) without requiring a running Redis instance, but it does not
provide end-to-end synchronous scoring from an API call. A production inline implementation
would require `app.py` to detect `inline` mode and call `process_scoring_job(job.id)`
immediately after enqueuing. The current code omits this.

---

## 15. `async def` vs `def` in FastAPI

| Route | Declaration | Why |
|---|---|---|
| `create_single_job` | `async def` | Reads `file.file` (ASGI I/O) |
| `create_batch_jobs` | `async def` | Same |
| `create_job_from_path` | `def` | JSON body only, no async I/O |
| `health`, `jobs`, `job_detail`, `batch_detail`, `platform_summary` | `def` | DB queries only |

FastAPI executes `def` route functions in a thread pool via `asyncio.run_in_executor`. This
prevents synchronous DB calls from blocking the event loop. `async def` functions run directly
in the event loop; blocking calls inside them (like `shutil.copyfileobj`) would stall all
concurrent requests. Here, `shutil.copyfileobj` is acceptable inside `async def` because
FastAPI uses Starlette's `SpooledTemporaryFile`, which is synchronous. For high-throughput
deployments, the file write should be replaced with `await file.read()` or
`aiofiles.open(target, "wb")`.

---

## 16. Interview Questions and Answers

**Q: Why use `create_app()` as a factory rather than defining `app` directly at module level?**

A: Two reasons. First, `get_backend_settings()` reads environment variables; calling it inside
the factory allows tests to set environment variables before calling `create_app()` and get a
correctly configured app. A module-level `app = FastAPI(...)` would call `get_backend_settings()`
at import time, before any test setup. Second, the factory captures `settings` in the closure
shared by all route handlers — settings are read once, not on every request. The module-level
`app = create_app()` is the production entry point; tests call `create_app()` independently.

---

**Q: What is the difference between `Depends(get_db_session)` and `session_scope()` used in
the worker?**

A: `session_scope()` is a context manager that auto-commits on clean exit and auto-rolls back
on exception. It is designed for operations that own their complete transaction lifecycle, like
the worker's three-session design. `get_db_session()` is a FastAPI generator dependency that
yields a session and closes it after the response, without committing. The route handler (or
the services layer it calls) is responsible for commits. This gives route handlers explicit
control: `create_batch_from_pcaps` commits its two-phase transaction explicitly; read-only
routes need no commit at all.

---

**Q: Why does the upload route write the file to a temp dir first rather than passing the ASGI
`UploadFile` directly to the storage layer?**

A: `storage.put_file` (Tutorial 24) is synchronous: it calls `shutil.copy2` or
`boto3.upload_file`, both of which operate on filesystem paths. The ASGI `UploadFile.file`
object is a `SpooledTemporaryFile` — it is a file-like object in memory or a temp file, not
necessarily at a stable filesystem path. Writing it to a named temp file produces a stable
`Path` that `storage.put_file` can operate on. It also decouples the storage layer from ASGI
specifics: `put_file` accepts any `str | Path`, making it testable without an HTTP context.

---

**Q: Why does `job_detail` use `JobResponse.model_validate(serialize_job(...))` instead of
just returning `serialize_job(...)` directly?**

A: Returning a dict and letting FastAPI serialise it against `response_model=JobResponse` also
performs Pydantic validation, so the end result is the same in normal operation. The difference
is timing: `model_validate` raises `ValidationError` inside the route handler before the
response is sent; FastAPI's implicit coercion catches errors during response rendering. Using
`model_validate` explicitly makes the validation failure visible in the handler's stack trace
rather than in FastAPI's internal serialisation code, which is easier to debug. It also makes
the code self-documenting: it is explicit that the dict must conform to `JobResponse`.

---

**Q: Why does the health check return HTTP 500 when the database is unreachable, rather than a
200 with a degraded status?**

A: The current implementation does not catch exceptions from `connection.execute(text("SELECT
1"))`. If the DB is down, the exception propagates to FastAPI's error handler and becomes a 500.
The correct design for a monitoring-friendly health check is to wrap each subsystem check in
`try/except`, record the error in the subsystem's status dict, and always return 200 with the
overall `status` field set to `"degraded"`. This allows monitoring systems (Kubernetes
readiness probes, uptime checks) to receive a structured response they can parse rather than an
opaque 500 error. The current implementation is a known gap — it works for manual inspection
but not for automated health-check consumers.

---

*Next: [Tutorial 31 — Reporting Snapshot](31_reporting_snapshot.md)*
