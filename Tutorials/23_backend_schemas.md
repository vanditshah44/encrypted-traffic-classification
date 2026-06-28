# Tutorial 23 — Pydantic Schemas (`backend/schemas.py`)

## Prerequisites

- Tutorial 22 (`backend/models.py`, `backend/db.py`) — the ORM layer this mirrors; every
  schema here corresponds directly to one or more ORM models.
- Tutorial 21 (`backend/config.py`) — `BackendSettings` fields that appear in `HealthResponse`.
- Tutorial 26 (`backend/registry.py`) — what a model bundle contains; `ModelBundleResponse`
  reflects that structure.

---

## 1. Why This File Exists

The ORM models in `models.py` (Tutorial 22) are tied to SQLAlchemy internals — they carry lazy
relationships, session state, and column metadata. You cannot directly serialise a
`ProcessingJob` ORM object to JSON and send it to an API client. Pydantic schemas solve this:
they are plain Python dataclasses with validation built in, and FastAPI automatically serialises
them to JSON for HTTP responses.

The schemas also serve as a **contract** between the backend and its clients (the frontend, other
services, the CLI). When you change the API response shape, you change a schema — the ORM can
stay untouched. When you add a new field the API should expose, you add it to the schema without
necessarily adding it to the database.

The split between what the ORM stores and what the schema exposes is intentional. For example,
`ProcessingJob` has `request_payload: JSON` and `summary_payload: JSON`, but `JobResponse`
exposes them as `request: dict` and `summary: dict` — the names are simplified and the
`_payload` suffix is dropped because API clients don't need to know that internally the field is
stored as a JSON column.

---

## 2. `BaseModel` and `Field`

Every schema inherits from `pydantic.BaseModel`. Key properties this gives:

- **Validation on construction**: `JobResponse(id=123, ...)` raises `ValidationError` because
  `id` is declared as `str`.
- **Automatic JSON serialisation**: FastAPI calls `.model_dump()` on the return value of a route
  handler, then serialises to JSON.
- **Schema generation**: FastAPI generates OpenAPI docs by inspecting the Pydantic model's field
  types — every schema in this file appears in the auto-generated `/docs` Swagger UI.

`Field(default_factory=dict)` and `Field(default_factory=list)` — these use a callable factory
instead of a literal default. Using `default={}` would share the same dict object across all
instances (Python's mutable default argument trap). `default_factory=dict` calls `dict()` for
each new instance.

---

## 3. `HealthResponse` (lines 10–16)

```python
class HealthResponse(BaseModel):
    status: str
    environment: str
    database: dict[str, Any]
    queue: dict[str, Any]
    object_storage: dict[str, Any]
    model_bundles: dict[str, Any]
```

The `/health` endpoint returns this. Four subsystems are checked independently and their status
is reported as free-form dicts rather than typed schemas. The dict shape is intentionally loose
— health check details vary (a database check might return `{"url": "...", "reachable": true}`;
an S3 check might return `{"bucket": "...", "accessible": true, "latency_ms": 12}`). Using
`dict[str, Any]` lets each subsystem return whatever diagnostic information is relevant without
requiring a separate schema for each.

`status: str` holds a top-level value like `"ok"` or `"degraded"`. A client monitoring the
system can check this single field and ignore the nested dicts unless it needs to diagnose which
subsystem failed.

---

## 4. `ArtifactResponse` (lines 19–35)

```python
class ArtifactResponse(BaseModel):
    id: str
    job_id: str
    kind: str                  # "input" | "output"
    artifact_type: str         # e.g. "suspicious_flows", "graph_bundle"
    logical_path: str          # human-readable name
    storage_backend: str       # "local" | "s3"
    bucket: str
    object_key: str
    object_uri: str            # full URI for direct access
    download_reference: str    # presigned URL or local path for download
    filename: str
    content_type: str          # MIME type
    size_bytes: int
    sha256: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str            # ISO8601 string
```

`download_reference` is not a column in `JobArtifact` (Tutorial 22). It is computed at response
time by the services layer (Tutorial 27) — for S3 storage it is a presigned URL valid for
`s3_presign_expiry_seconds`; for local storage it is a path or a `/download/{id}` URL. The
schema exposes it as a plain string so the client has a single field to follow regardless of
the storage backend.

`created_at: str` — timestamps are stored as `datetime` objects in the ORM but serialised as
ISO 8601 strings here (`"2024-03-15T14:23:01+00:00"`). Sending raw `datetime` objects would
require clients to handle Python's datetime representation. ISO 8601 strings are universally
parseable in every language.

`metadata: dict[str, Any]` maps from `JobArtifact.metadata_payload` — the field is renamed in
the schema (dropping `_payload`) to give the API a cleaner surface.

---

## 5. `JobResponse` (lines 38–57)

```python
class JobResponse(BaseModel):
    id: str
    batch_id: str | None = None
    job_type: str
    status: str
    dataset_name: str
    queue_name: str
    queue_backend: str
    external_job_id: str | None = None
    model_bundle_dir: str
    created_at: str
    started_at: str | None = None       # None = still queued
    completed_at: str | None = None     # None = still running
    error_message: str | None = None
    request: dict[str, Any] = Field(default_factory=dict)   # ← renamed from request_payload
    summary: dict[str, Any] = Field(default_factory=dict)   # ← renamed from summary_payload
    suspicious_flow_count: int | None = None
    candidate_flow_count: int | None = None
    cluster_count: int | None = None
    artifacts: list[ArtifactResponse] = Field(default_factory=list)
```

The three `| None = None` timestamp fields directly mirror the lifecycle from Tutorial 22 — a
client can determine job state from them alone:

| `started_at` | `completed_at` | `status` | Meaning |
|---|---|---|---|
| `None` | `None` | `"queued"` | Waiting in queue |
| set | `None` | `"running"` | Worker is executing |
| set | set | `"succeeded"` | Finished cleanly |
| set | set | `"failed"` | Worker errored; see `error_message` |

`artifacts: list[ArtifactResponse]` — nested response models. FastAPI serialises these
recursively. The default is `Field(default_factory=list)` because a job may have no artifacts
yet (e.g., still queued), and the client should receive `"artifacts": []` rather than
`"artifacts": null` — the difference matters for client-side iteration.

`request` and `summary` use `default_factory=dict` for the same reason: a queued job has no
`summary_payload` yet, and `"summary": {}` is cleaner than `"summary": null`.

---

## 6. `BatchResponse` (lines 60–67)

```python
class BatchResponse(BaseModel):
    id: str
    batch_name: str
    created_at: str
    request: dict[str, Any] = Field(default_factory=dict)
    job_count: int
    status_counts: dict[str, int] = Field(default_factory=dict)
    jobs: list[JobResponse] = Field(default_factory=list)
```

`status_counts: dict[str, int]` — a computed summary like
`{"queued": 3, "running": 1, "succeeded": 6, "failed": 0}`. This is not stored in the database
(there is no `status_counts` column on `JobBatch`). It is computed by the services layer from
the child `ProcessingJob` rows. The schema includes it so the client can display a batch progress
indicator without iterating all jobs.

`job_count: int` is likewise computed — `len(batch.jobs)`. Storing it in the schema avoids
forcing clients to count `jobs` themselves, and allows the API to return `job_count` without
embedding all `jobs` in every batch listing response (when the full job list is not needed, the
services layer can populate `job_count` and leave `jobs` as an empty list).

---

## 7. `JobListResponse` (lines 70–71)

```python
class JobListResponse(BaseModel):
    items: list[JobResponse]
```

A one-field wrapper. The pattern of wrapping lists in a `{"items": [...]}` object rather than
returning a bare JSON array is a REST API convention with two reasons:
1. A JSON array at the top level cannot be extended without breaking the client. Adding
   pagination metadata (`total`, `page`, `page_size`) to a bare array would require changing
   the response type from array to object — a breaking change. Wrapping in `{"items": [...]}`
   from the start leaves room to add `total` or `next_cursor` later without breaking clients.
2. Some HTTP intermediaries (proxies, CDNs) treat a JSON array response differently from an
   object — wrapping avoids edge cases.

---

## 8. `ModelBundleResponse` and `ModelBundleListResponse` (lines 74–85)

```python
class ModelBundleResponse(BaseModel):
    name: str                        # directory name, e.g. "run_20240315"
    path: str                        # absolute filesystem path
    model_names: list[str]           # ["gaussian_nb", "random_forest", "gradient_boosting"]
    rows: int | None = None          # training row count from feature_manifest.json
    columns: int | None = None       # training column count
    is_default: bool                 # True if this is the configured default bundle
    workflow_summary_path: str | None = None  # path to workflow_summary.json
```

`rows` and `columns` are `None` when the bundle's `feature_manifest.json` does not include
training metadata (possible with older or manually constructed bundles). The API still exposes
the bundle in this case — clients should treat `None` as "metadata unavailable" rather than
"bundle is invalid."

`is_default: bool` — computed by comparing `bundle.path` to
`settings.default_model_bundle_dir`. It is not stored anywhere; it is derived at response time
by the registry (Tutorial 26). This is correct: the "default" designation is a runtime
configuration, not a property of the bundle itself.

---

## 9. `PathJobRequest` (lines 88–92)

```python
class PathJobRequest(BaseModel):
    source_path: str
    dataset_name: str | None = None
    model_bundle_dir: str | None = None
    batch_name: str | None = None
```

This is the only **request** schema in the file — the input body for submitting a scoring job
via a filesystem path. It is minimal by design:

- `source_path` — the only required field: a path to a PCAP or CSV on the server's filesystem.
- `dataset_name` — if `None`, the backend derives it from the filename.
- `model_bundle_dir` — if `None`, the backend uses the configured default bundle.
- `batch_name` — if `None`, the backend generates one from the current timestamp.

Three of four fields are optional with `None` defaults — the simplest possible submission is
`{"source_path": "/data/capture.pcap"}`. This design minimises the burden on the client for
straightforward scoring requests.

The type is `str` not `Path` because Pydantic's `BaseModel` serialises `Path` objects as strings
in JSON anyway, and the schema is primarily a JSON deserialisation target. Using `str` makes
round-tripping through JSON transparent.

---

## 10. What Is Not in This File

The schemas deliberately omit:
- **Input validation beyond types** — no `@validator` or `@field_validator` for path existence,
  allowed characters, or max length. Path validation happens in the service layer where the
  filesystem is accessible. Schema-level validation of filesystem concerns would require the
  schema to know about the environment, breaking the clean separation.
- **ORM-to-schema conversion logic** — no `model_validate(orm_obj)` or `from_orm` calls here.
  That translation lives in `services.py` (Tutorial 27).
- **Pagination parameters** — `JobListResponse` has no `page`/`limit` fields in the request.
  The current API returns all items. Adding pagination later is a schema extension, not a
  rewrite.

---

## 11. Interview Questions and Answers

**Q: Why does `JobResponse` have `request` and `summary` as `dict[str, Any]` instead of typed
schemas?**

A: `request_payload` and `summary_payload` are JSON blobs whose shape varies by job type and
evolves over time. Typing them strictly (e.g., `summary: ScoringJobSummary`) would require every
schema change in the scoring pipeline to also update the API schema — a tight coupling. Using
`dict[str, Any]` makes the API schema stable while the payload content can evolve. The trade-off
is that clients lose type safety for the payload contents, but for a research/thesis project
where the summary structure is still changing, this is the right trade-off.

---

**Q: Why is `download_reference` on `ArtifactResponse` but not on `JobArtifact` in the ORM?**

A: A presigned S3 URL is ephemeral — it expires after `s3_presign_expiry_seconds` (default 1
hour). Storing it in the database would mean every row contains a URL that is stale after an
hour. The correct model is to generate the presigned URL on demand at response serialisation
time. The ORM stores the durable identifiers (`bucket`, `object_key`); the schema exposes the
transient derived value (`download_reference`). This is the correct separation of persistent
state vs ephemeral computed values.

---

**Q: Why wrap list responses in `{"items": [...]}` rather than returning a bare JSON array?**

A: A bare JSON array response cannot be extended without a breaking API change. If you later
need to add `total_count`, `next_page_token`, or `filtered_count` to the response, you must
change the top-level type from array to object — which breaks every client that assumed an array.
Starting with `{"items": [...]}` costs nothing at first use and preserves the ability to add
envelope fields later with no breaking changes. It is the standard REST API pattern for
collection endpoints.

---

*Next: [Tutorial 24 — Object Storage](24_backend_storage.md)*
