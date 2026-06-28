# Tutorial 22 — ORM Models and Database Session (`backend/models.py`, `backend/db.py`)

## Prerequisites

- Tutorial 21 (`backend/config.py`) — `get_backend_settings()` and `database_url`; this file
  reads that setting to construct the engine.
- Tutorial 15 (`provenance.py`) — SHA256 fingerprinting; `JobArtifact.sha256` stores the same
  kind of hash for uploaded and produced files.
- Tutorial 20 (`detection/multitier.py`) — the detection results that populate
  `suspicious_flow_count`, `candidate_flow_count`, and `cluster_count` on `ProcessingJob`.

---

## 1. Why These Two Files Exist

The backend needs to track every job it runs: what was submitted, where it is in the queue, what
it produced, and whether it succeeded. Two questions drive the design:

**Where does state live?** In a database. Jobs survive server restarts; a client can poll for
status minutes after submission. An in-memory dict would be lost on every restart.

**How does Python talk to that database?** Through SQLAlchemy's ORM (Object-Relational Mapper).
The ORM maps Python classes to database tables, Python attributes to columns, and Python objects
to rows — you write `job.status = "running"` and the ORM generates `UPDATE processing_jobs SET
status='running' WHERE id=...`. You never write raw SQL.

The two files have a clean separation of responsibility:
- `db.py` — infrastructure: engine, session factory, schema creation, session lifecycle
- `models.py` — schema: what tables exist and what each column means

---

## 2. `db.py` — Infrastructure

### `Base` (line 16)

```python
class Base(DeclarativeBase):
    """Base ORM model."""
```

`DeclarativeBase` is SQLAlchemy 2.0's metaclass for the ORM. Every table class in `models.py`
inherits from `Base`. SQLAlchemy uses this inheritance to discover all ORM-mapped classes and
build the full schema when `Base.metadata.create_all()` is called. The class itself has no body
beyond the docstring — it is a shared ancestor, not a table.

`Base` lives in `db.py`, not `models.py`, because `models.py` imports it from `db.py`. This
avoids a circular import: `db.py` knows nothing about the specific tables; `models.py` knows
the tables and imports `Base` from the infrastructure layer.

### `get_engine` (lines 20–26)

```python
@lru_cache(maxsize=1)
def get_engine() -> Engine:
    settings = get_backend_settings()
    connect_args: dict[str, object] = {}
    if settings.database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(settings.database_url, future=True, connect_args=connect_args)
```

`create_engine` is expensive — it parses the URL, resolves the dialect, sets up the connection
pool. `@lru_cache(maxsize=1)` ensures this happens once per process.

**`check_same_thread=False`** — SQLite's default behaviour is to refuse connections from any
thread other than the one that created the engine. FastAPI runs request handlers in a thread
pool; without this flag, every request from a non-main thread would raise `ProgrammingError:
SQLite objects created in a thread can only be used in that same thread`. Setting it to `False`
delegates thread safety to the application (the session scope pattern in `session_scope` handles
this). This flag is SQLite-specific — PostgreSQL has its own connection pool that handles threads
natively.

**`future=True`** — enables SQLAlchemy 2.0 behaviour on a 1.x engine installation. In 2.0 mode:
`Session.execute()` always returns a `CursorResult` (no legacy `ResultProxy`), and autocommit
is disabled by default. This future-proofs the code.

### `get_session_factory` (lines 29–31)

```python
@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, autocommit=False, expire_on_commit=False)
```

A `sessionmaker` is a factory — calling it (`get_session_factory()()`) creates a new `Session`
object. Three parameters matter:

- **`autoflush=False`** — SQLAlchemy normally flushes pending changes to the database before
  every query (to ensure reads see writes within the same session). Disabling this gives the
  application explicit control: changes are only written when `session.flush()` or
  `session.commit()` is called. For job processing where you want to batch multiple writes
  before committing, this avoids partial flushes.

- **`autocommit=False`** — each session starts an implicit transaction. Nothing is permanently
  written until `session.commit()`. This is the correct default — it enables rollback on error.

- **`expire_on_commit=False`** — by default, SQLAlchemy marks all ORM objects as "expired"
  after a commit, meaning any attribute access triggers a fresh SELECT from the database. With
  `expire_on_commit=False`, objects remain usable after commit without a round-trip. This is
  important in a FastAPI handler where you commit, then immediately serialize the object to
  JSON for the response — you don't want a second database query just to read back what you
  just wrote.

### `init_database` (lines 34–37)

```python
def init_database() -> None:
    import tls_dataset.backend.models  # noqa: F401
    Base.metadata.create_all(bind=get_engine())
```

`Base.metadata.create_all()` issues `CREATE TABLE IF NOT EXISTS` for every table subclassing
`Base`. It is idempotent — safe to call at every startup.

The `import tls_dataset.backend.models` line is not redundant. `Base.metadata` only knows about
tables whose classes have been imported and executed. If `models.py` has never been imported,
`Base.metadata` is empty and `create_all` creates nothing. The explicit import guarantees the
model classes are registered before the schema is created, regardless of whether any other
module has imported `models` yet.

`# noqa: F401` silences the "imported but unused" lint warning — the import is a side effect,
not a name binding.

### `session_scope` (lines 40–50)

```python
@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
```

This is the standard SQLAlchemy session lifecycle pattern, implemented as a context manager:

```python
with session_scope() as session:
    job = session.get(ProcessingJob, job_id)
    job.status = "running"
# commit happens automatically here; rollback on exception
```

Three invariants:
1. If the `with` block exits normally, `commit()` is called — changes are persisted.
2. If an exception is raised inside the block, `rollback()` is called — the transaction is
   undone, and the exception propagates up unchanged (`raise` with no argument re-raises).
3. Regardless of success or failure, `session.close()` runs in `finally` — the connection is
   returned to the pool.

The `commit()` being inside `try` (not `finally`) is deliberate: if `commit()` itself raises
(e.g., a constraint violation), the `except` block catches it, calls `rollback()`, and re-raises.
Without this, a failed commit would leave the session in a dirty state.

### `get_db_session` (lines 53–58)

```python
def get_db_session() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
```

This is the FastAPI dependency version of session management. FastAPI's dependency injection
calls generator functions with `yield` as dependencies — it runs everything before `yield` on
request entry and everything after on request exit. It does **not** commit — the FastAPI route
handler is responsible for calling `session.commit()` explicitly. This gives routes fine-grained
control over when data is persisted. Contrast with `session_scope`, which auto-commits at context
exit and is used in background workers where you want commit-on-success semantics.

### `clear_db_caches` (lines 61–63)

```python
def clear_db_caches() -> None:
    get_session_factory.cache_clear()
    get_engine.cache_clear()
```

Mirrors `clear_backend_settings_cache` from Tutorial 21. Tests that need a different database URL
(e.g., an in-memory SQLite for isolation) call this after patching the environment and before
creating their first session.

---

## 3. `models.py` — Schema

### `utc_now` (line 16–17)

```python
def utc_now() -> datetime:
    return datetime.now(timezone.utc)
```

`datetime.utcnow()` returns a naive datetime (no timezone info) that happens to contain UTC
values. `datetime.now(timezone.utc)` returns an aware datetime with explicit UTC timezone.
The difference matters in SQLAlchemy's `DateTime(timezone=True)` column — it stores and retrieves
timezone-aware datetimes correctly. Using `utcnow()` here would produce aware timestamps in the
column but naive objects in Python, causing comparison bugs when you subtract two datetimes or
compare with `datetime.now(timezone.utc)`. This function is passed as `default=utc_now` to
`mapped_column` — SQLAlchemy calls it at insert time, not at class definition time (which is why
it's a callable, not `default=datetime.now(timezone.utc)` which would be called once at class
load).

### `JobStatus` and `ArtifactKind` (lines 20–29)

```python
class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
```

`str, Enum` (a mixin) makes each member both a string and an enum value:
`JobStatus.QUEUED == "queued"` is `True`. This allows:
- Type-safe code: `job.status = JobStatus.RUNNING` (the enum member)
- Database storage: the `String(32)` column stores `"running"` as a plain string
- JSON serialisation: `str(JobStatus.RUNNING)` gives `"running"` without a custom encoder

The `status` column stores `JobStatus.QUEUED.value` as a string directly:
```python
status: Mapped[str] = mapped_column(String(32), default=JobStatus.QUEUED.value, ...)
```
This keeps the database column type as `VARCHAR` rather than a database-level ENUM type (which
would require a migration to add new statuses).

---

## 4. The Three Tables

### `JobBatch` (lines 32–44)

```
job_batches
├── id          VARCHAR(36), PK, UUID4
├── batch_name  VARCHAR(255)
├── created_at  TIMESTAMP WITH TIMEZONE
└── request_payload  JSON (nullable)
```

A `JobBatch` is a logical grouping of one or more `ProcessingJob` rows. A user might submit 10
PCAPs at once — they form one batch. The batch ID is returned to the client so they can query
all jobs in the batch with a single request. `request_payload` stores the original API request
body as JSON for audit purposes.

**UUID4 primary key** — `default=lambda: str(uuid4())` generates a random UUID at insert time.
UUID4 is preferred over auto-increment integers for distributed systems because IDs can be
generated client-side without a database round-trip, and there are no ID conflicts if you ever
shard the database. The `String(36)` length matches the canonical UUID string format
(`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` = 36 characters including dashes).

### `ProcessingJob` (lines 47–74)

```
processing_jobs
├── id                  VARCHAR(36), PK, UUID4
├── batch_id            FK → job_batches.id (nullable, index)
├── job_type            VARCHAR(64), default "pcap_score", index
├── status              VARCHAR(32), default "queued", index
├── dataset_name        VARCHAR(255), index
├── queue_name          VARCHAR(128)
├── queue_backend       VARCHAR(64)
├── external_job_id     VARCHAR(255) (nullable)  ← RQ job ID
├── model_bundle_dir    VARCHAR(2048)
├── created_at          TIMESTAMP, index
├── started_at          TIMESTAMP (nullable)
├── completed_at        TIMESTAMP (nullable)
├── error_message       TEXT (nullable)
├── request_payload     JSON (nullable)
├── summary_payload     JSON (nullable)       ← full scoring summary dict
├── suspicious_flow_count  INTEGER (nullable)
├── candidate_flow_count   INTEGER (nullable)
└── cluster_count          INTEGER (nullable)
```

**Three nullable timestamp columns** tell the full lifecycle story:
- `created_at` set on creation — always present
- `started_at` set when the worker picks up the job — `None` = still queued
- `completed_at` set on success or failure — `None` = still running

A query for stuck jobs is simply:
```python
session.query(ProcessingJob).filter(
    ProcessingJob.started_at.isnot(None),
    ProcessingJob.completed_at.is_(None),
    ProcessingJob.created_at < cutoff
)
```

**`external_job_id`** stores the RQ job ID returned by `rq.Queue.enqueue`. RQ is the queue
backend (Tutorial 25) — it assigns its own ID to each queued function call. This column lets
the backend look up job status directly via the RQ API (`rq.job.Job.fetch(external_job_id)`)
without querying the database.

**`model_bundle_dir VARCHAR(2048)`** — 2048 characters because this is a full filesystem path
that may include long directory hierarchies. Standard `VARCHAR(255)` would truncate deep paths.

**Denormalized summary columns** (`suspicious_flow_count`, `candidate_flow_count`,
`cluster_count`) duplicate data that also appears in `summary_payload`. They exist for query
performance: listing all jobs in a batch sorted by `suspicious_flow_count desc` should not
require deserializing a JSON blob for every row. These three integers are cheap to index.

**`cascade="all, delete-orphan"`** on the `artifacts` relationship means that deleting a
`ProcessingJob` automatically deletes all its `JobArtifact` rows. The application never needs to
manually delete child rows.

**`order_by="ProcessingJob.created_at"`** — using a string expression instead of the column
object avoids the forward-reference problem: `JobBatch` is defined before `ProcessingJob`, so
`ProcessingJob.created_at` is not yet defined when `JobBatch` is being parsed. The string is
resolved lazily by SQLAlchemy at first access.

### `JobArtifact` (lines 77–96)

```
job_artifacts
├── id               VARCHAR(36), PK, UUID4
├── job_id           FK → processing_jobs.id, index
├── kind             VARCHAR(16), default "output"  (INPUT | OUTPUT)
├── artifact_type    VARCHAR(128), index   e.g. "suspicious_flows", "graph_bundle"
├── logical_path     VARCHAR(1024)   human-readable name within the job
├── storage_backend  VARCHAR(64)     "local" | "s3"
├── bucket           VARCHAR(255)
├── object_key       VARCHAR(2048)   path within the bucket
├── object_uri       VARCHAR(4096)   full URI (s3://... or file:///...)
├── filename         VARCHAR(255)    original filename
├── content_type     VARCHAR(255)    MIME type
├── size_bytes       INTEGER
├── sha256           VARCHAR(64)     hex SHA256 of file contents
├── metadata_payload JSON (nullable)
└── created_at       TIMESTAMP
```

Every file the scoring pipeline produces (Tutorial 20 output artifacts) is recorded as a
`JobArtifact` row. This gives the API a complete manifest of what was produced and where it is
stored, which the API exposes as download links.

**`kind: INPUT | OUTPUT`** — the input PCAP itself is stored as an `INPUT` artifact. This
means the backend can later reproduce what was submitted, audit the input, or rerun scoring on
the same PCAP.

**`logical_path`** vs **`object_key`** — `object_key` is the storage-level identifier
(`"jobs/abc123/suspicious_flows.csv"` in S3). `logical_path` is human-readable within the
job context (`"suspicious_flows"`). The API exposes `logical_path`; the storage backend uses
`object_key`.

**`sha256 VARCHAR(64)`** — a hex SHA256 hash is always 64 characters (256 bits / 4 bits per
hex character). Using a fixed-length `VARCHAR(64)` is slightly more efficient than `TEXT` and
allows the database to create a hash index if needed. This ties back to Tutorial 15's SHA256
fingerprinting philosophy.

---

## 5. Relationship Map

```
JobBatch (1) ─────────────── (many) ProcessingJob
                                        │
                                        └── (many) JobArtifact
```

The ORM relationships are bidirectional:
- `batch.jobs` → list of `ProcessingJob` for that batch
- `job.batch` → the parent `JobBatch` (or `None` if standalone)
- `job.artifacts` → list of `JobArtifact` for that job
- `artifact.job` → the parent `ProcessingJob`

SQLAlchemy resolves these lazily by default — accessing `job.artifacts` issues a SELECT only
when the attribute is first read. With `expire_on_commit=False` (§2), accessing relationships
after a commit works without an extra round-trip, provided the related objects were loaded before
the commit.

---

## 6. Interview Questions and Answers

**Q: Why `check_same_thread=False` for SQLite and what thread-safety risk does it introduce?**

A: SQLite's default thread safety model assumes a single thread per connection. FastAPI's
thread pool means the same connection might be accessed from different threads if you reused a
connection across requests. `check_same_thread=False` disables SQLite's built-in check and
trusts the application to ensure thread safety. The application enforces this through the session
scope pattern: each request creates its own `Session` (and thus its own connection checkout from
the pool), uses it, and closes it. Sessions are never shared between threads. The risk is real if
someone bypasses the session factory and holds a connection across a thread boundary — but that
would be a code review issue, not a systemic flaw.

---

**Q: Why `expire_on_commit=False`? What's the risk?**

A: After `session.commit()`, SQLAlchemy normally marks all loaded objects as expired, meaning
any attribute access triggers a new SELECT. `expire_on_commit=False` skips this, keeping
objects usable post-commit. The risk: if another process or thread modifies the same row between
your commit and your attribute read, you see stale data. This is acceptable in a job tracking
context because: (1) `ProcessingJob` rows are primarily written by the worker that owns them;
(2) the FastAPI handler reads the just-written state back for the response, where staleness is
impossible (it wrote it). The alternative — a fresh SELECT after every commit — is unnecessary
overhead for the common case.

---

**Q: Why are `suspicious_flow_count`, `candidate_flow_count`, and `cluster_count` stored as
dedicated columns when `summary_payload` already contains them?**

A: SQL cannot index or filter on values inside a JSON column efficiently (without JSON path
indexes, which are database-specific). Storing these three integers as first-class columns allows
queries like `ORDER BY suspicious_flow_count DESC`, `WHERE cluster_count > 5`, or a dashboard
aggregate `SELECT AVG(suspicious_flow_count) FROM processing_jobs WHERE status='succeeded'`
to use B-tree indexes at normal SQL speed. The `summary_payload` JSON blob is for full result
retrieval; the integer columns are for filtering and ranking.

---

**Q: Why are primary keys UUID4 strings rather than auto-increment integers?**

A: Auto-increment integers are assigned by the database, so the application cannot know the ID
until after the INSERT completes. UUID4s are generated client-side (in Python, `str(uuid4())`),
so the application can assign an ID, include it in the queued job payload, and record it in
RQ — all before the database INSERT. This lets the worker report back to the database using an
ID that was established before the job started. It also avoids ID conflicts if the database is
ever scaled horizontally, though this project currently uses a single database.

---

*Next: [Tutorial 23 — Pydantic Schemas](23_backend_schemas.md)*
