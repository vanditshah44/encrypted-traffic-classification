# Tutorial 25 — Queue Backends (`backend/queue.py`)

## Prerequisites

- Tutorial 21 (`backend/config.py`) — `BackendSettings.queue_backend` (`"rq"` or `"inline"`),
  `queue_name` (`"pcap_scoring"`), and `redis_url` are the three settings this file consumes.
- Tutorial 22 (`backend/models.py`) — `ProcessingJob.external_job_id` stores
  `QueueTicket.external_job_id` after enqueuing. Understanding why the two ID fields differ
  requires knowing the ORM column.
- Tutorial 24 (`backend/storage.py`) — same Protocol + factory pattern repeated here. Read that
  first; this tutorial builds on the same design decisions without repeating them.

---

## 1. Why This File Exists

When the API accepts a PCAP scoring request it must not block the HTTP response thread while
Zeek, NFStream, and the ML models run — that pipeline takes minutes. The standard solution is a
**task queue**: the API records the job in the database, drops a message into a queue, and
returns immediately with a job ID. A separate worker process picks the message off the queue
and does the work.

`queue.py` abstracts that handoff. It provides two implementations:

- **`InlineQueueBackend`** — used in development. `enqueue_scoring_job` records the ticket but
  schedules nothing. The API layer calls `process_scoring_job` directly in the same process,
  making the HTTP request block until the job finishes. No Redis required, no worker process
  required, one command to run the whole system.
- **`RQQueueBackend`** — used in production. `enqueue_scoring_job` pushes a message into a
  Redis list. A separate `worker.py` process polls that list and executes the job. The API
  returns in milliseconds; the work happens asynchronously.

The Protocol ensures the API layer never needs to know which implementation it holds.

---

## 2. `QueueTicket` (lines 14–19)

```python
@dataclass(frozen=True)
class QueueTicket:
    backend: str
    queue_name: str
    external_job_id: str
```

`frozen=True` — same reasoning as `StoredObject` in Tutorial 24. A ticket is a receipt: it
records what was submitted to which queue under which ID. None of those facts should change
after the enqueue call.

`external_job_id` is the ID **in the queue system**, not in the application database. For RQ,
this is RQ's own UUID (`rq.job.Job.id`), which is distinct from the `ProcessingJob.id` UUID
in the SQLite/PostgreSQL database. For inline, there is no external system, so the application's
own `job_id` doubles as the `external_job_id`. The field is named "external" to signal that it
is an opaque token belonging to the queue system, not a first-class application identifier.

The services layer stores this in `ProcessingJob.external_job_id`. If a job gets stuck, an
operator can use this ID to inspect the job directly in RQ's Redis store (`rq info`, `rq job
show <id>`), independent of the application database.

`backend: str` mirrors the same field on `StoredObject`. It lets an operator reading a job row
know whether to look in Redis or to expect inline execution with no external record.

---

## 3. `QueueBackend` Protocol (lines 21–23)

```python
class QueueBackend(Protocol):
    def enqueue_scoring_job(self, job_id: str) -> QueueTicket: ...
    def healthcheck(self) -> dict[str, object]: ...
```

Only two methods — the thinnest possible interface. `enqueue_scoring_job` takes only the
application `job_id` string: the worker function already knows how to look up the full job from
the database using that ID, so nothing else needs to be passed through the queue. Passing a
minimal identifier (rather than a serialised job payload) through the queue means the worker
always reads from the database, which is the authoritative source. If the job record is updated
between enqueue and execution, the worker sees the latest version.

---

## 4. `InlineQueueBackend` (lines 26–41)

```python
class InlineQueueBackend:
    def __init__(self, queue_name: str) -> None:
        self.queue_name = queue_name

    def enqueue_scoring_job(self, job_id: str) -> QueueTicket:
        return QueueTicket(
            backend="inline",
            queue_name=self.queue_name,
            external_job_id=job_id,
        )
```

`enqueue_scoring_job` does nothing except return a ticket. It does not call
`process_scoring_job`, does not write to Redis, does not schedule any work. The calling code in
`app.py` (Tutorial 30) detects the `"inline"` backend and calls `process_scoring_job(job_id)`
directly after the ticket is returned. The inline backend only exists to return a
Protocol-compatible receipt so the API can use the same code path regardless of backend.

`external_job_id=job_id` — the application's own UUID becomes the external ID because there is
no external system. This is coherent: if an operator queries `ProcessingJob.external_job_id`
they get the same UUID as `ProcessingJob.id`, and in inline mode that is correct — the two ID
spaces are the same.

The `healthcheck` returns only the queue name — there is no connection to verify, no remote
system to ping. The health endpoint (Tutorial 30) aggregates all subsystem health checks; for
inline, the queue subsystem is always trivially healthy.

---

## 5. `RQQueueBackend` (lines 44–69)

### `__init__` (lines 45–49)

```python
def __init__(self, redis_url: str, queue_name: str) -> None:
    self.redis_url = redis_url
    self.queue_name = queue_name
    self.connection = Redis.from_url(redis_url)
    self.queue = Queue(name=queue_name, connection=self.connection)
```

`Redis.from_url` parses the URL (`redis://127.0.0.1:6379/0`) and creates a connection pool.
The `0` at the end is the Redis database index — Redis supports 16 logical databases (0–15) on
the same server, allowing multiple applications to share a Redis instance without key collisions.

`Queue(name=queue_name, connection=self.connection)` — RQ's `Queue` is a wrapper around a
Redis list. Internally, a `Queue` named `"pcap_scoring"` maps to a Redis key
`rq:queue:pcap_scoring`. When `enqueue` is called, RQ serialises the job and pushes the job ID
onto that list using Redis's `LPUSH`. Worker processes block on `BRPOP` (blocking right-pop)
on the same key, so they wake up immediately when a job arrives rather than polling.

Both `self.connection` and `self.queue` are created at `__init__` time, not per-call. Creating
a Redis connection pool is expensive relative to enqueuing a job; reusing the connection for the
lifetime of the backend instance avoids that overhead on every HTTP request.

### `enqueue_scoring_job` (lines 51–62)

```python
job = self.queue.enqueue(
    "tls_dataset.backend.worker.process_scoring_job",
    job_id,
    job_timeout="4h",
    result_ttl=86400,
)
return QueueTicket(
    backend="rq",
    queue_name=self.queue_name,
    external_job_id=job.id,
)
```

**The function is passed as a string path, not a callable.** When RQ serialises a job to push
into Redis, it must encode the function reference so the worker process can reconstruct it.
Using a string (`"tls_dataset.backend.worker.process_scoring_job"`) means RQ stores the
dotted import path and resolves it in the worker process via `importlib`. Passing the callable
directly (`worker.process_scoring_job`) would cause RQ to pickle the function object, which
works for simple functions but breaks for functions that close over non-picklable state. The
string path is the robust, recommended approach for cross-process function references.

`job_id` is the single positional argument passed to `process_scoring_job` when the worker
executes it. The worker then opens a database session and reads the full `ProcessingJob` row.
This is the "minimal token through the queue" design from Section 3.

`job_timeout="4h"` — RQ accepts duration strings. PCAP scoring runs Zeek, NFStream, ML
inference, and file uploads. A large PCAP (100+ MB, hours of traffic) can take tens of minutes.
Setting a 4-hour timeout prevents hung jobs from occupying a worker slot indefinitely. If the
worker process dies mid-job or the scoring function exceeds this timeout, RQ marks the job as
failed and the next `ProcessingJob` status update in the worker's `except` block records the
error.

`result_ttl=86400` — RQ stores the return value of `process_scoring_job` in Redis after
completion. Since `process_scoring_job` returns `None`, the result is trivial, but RQ still
writes a completion record. `86400` seconds (24 hours) is how long RQ keeps that record before
expiring it from Redis. The application does not use this RQ result — job status is tracked in
the database, not in Redis — so the TTL only matters for `rq info` operator tooling.

`job.id` is RQ's own UUID for the enqueued job, generated by RQ at enqueue time. This is
distinct from the application's `job_id` (the `ProcessingJob.id` UUID). `QueueTicket.external_job_id`
stores `job.id` so the services layer can write it to `ProcessingJob.external_job_id`. The
mapping is: one application job → one RQ job → one Redis list entry. The two UUIDs coexist
because they belong to different systems.

### `healthcheck` (lines 64–69)

```python
def healthcheck(self) -> dict[str, object]:
    return {
        "backend": "rq",
        "queue_name": self.queue_name,
        "redis_ping": bool(self.connection.ping()),
    }
```

`self.connection.ping()` sends Redis's `PING` command and receives `PONG`. This is a genuine
connectivity check — if Redis is unreachable, `ping()` raises an exception, which propagates
to the `/health` endpoint handler and marks the health response as degraded. The `bool()`
cast is defensive: `ping()` returns `True` on success, but the bool cast normalises any
future return value change to a JSON-serialisable boolean.

This is more useful than the local storage health check in Tutorial 24, because Redis is an
external process — the application can start successfully while Redis is down, and the health
check is the only mechanism that surfaces this.

---

## 6. `build_queue_backend` (lines 72–76)

```python
def build_queue_backend(settings: BackendSettings | None = None) -> QueueBackend:
    resolved = settings or get_backend_settings()
    if resolved.queue_backend == "inline":
        return InlineQueueBackend(queue_name=resolved.queue_name)
    return RQQueueBackend(redis_url=resolved.redis_url, queue_name=resolved.queue_name)
```

Identical pattern to `build_object_storage` (Tutorial 24): `None` default for testability,
explicit `"inline"` check with RQ as the soft default for any other value. In a test, passing
a `BackendSettings` with `queue_backend="inline"` ensures no Redis connection is attempted.

`InlineQueueBackend` receives only `queue_name` — no Redis URL, because it has no connection
to make. `RQQueueBackend` receives both `redis_url` and `queue_name` — the queue is defined by
both the connection target and the logical name.

---

## 7. How the Queue Fits Into the Full Flow

```
API handler
  → creates ProcessingJob in DB (status=queued)
  → uploads input PCAP to object store
  → calls queue.enqueue_scoring_job(job_id)
      → RQ: pushes job_id into Redis list rq:queue:pcap_scoring
      → inline: returns ticket, API calls process_scoring_job(job_id) directly
  → writes QueueTicket.external_job_id to ProcessingJob.external_job_id
  → returns JobResponse to HTTP client

Worker process (RQ mode only)
  → blocks on BRPOP rq:queue:pcap_scoring
  → wakes when job arrives
  → imports tls_dataset.backend.worker.process_scoring_job
  → calls process_scoring_job(job_id)
  → updates ProcessingJob.status to RUNNING, then SUCCEEDED or FAILED
```

The API never calls `process_scoring_job` in RQ mode. The worker process is a completely
separate OS process started with `python -m tls_dataset.backend.worker`. In Docker Compose,
this is a separate container that shares the same Redis and database.

---

## 8. Interview Questions and Answers

**Q: Why is the worker function passed to `queue.enqueue` as a string rather than a direct
callable reference?**

A: RQ must serialise the function reference so a separate worker process can resolve it. Using
the dotted import path string (`"tls_dataset.backend.worker.process_scoring_job"`) tells RQ
to re-import the module in the worker process and call the function by attribute lookup — no
pickling of the function object itself. Pickling callables is fragile: closures, lambdas, and
functions defined inside other functions cannot be pickled. The string import path is the
canonical, process-boundary-safe way to reference a task function in RQ.

---

**Q: Why does `enqueue_scoring_job` pass only `job_id` rather than the full job payload?**

A: The database is the authoritative source of job state. Passing only the ID through the queue
means the worker reads the freshest version of the job record when it starts executing. If the
API updates the job record between enqueue and worker pickup (e.g., adding metadata), the
worker sees those updates. If the full payload were serialised into the queue message, the
worker would operate on a stale snapshot. Keeping the queue message minimal also reduces the
size of each Redis entry — job payloads can be large (full PCAP paths, model bundle paths,
dataset names).

---

**Q: What is the difference between `ProcessingJob.id` and `QueueTicket.external_job_id`?**

A: `ProcessingJob.id` is a UUID generated by the application at job creation time and stored in
the database. `QueueTicket.external_job_id` is RQ's own UUID generated by `rq.Queue.enqueue`
and stored in Redis. They are from different ID namespaces: the application's is used to look
up the job in the database; RQ's is used to query job status in Redis via `rq info` or to
cancel the queued job via `rq cancel`. In inline mode, both IDs are the same value because
there is no external system.

---

**Q: Why does `InlineQueueBackend.enqueue_scoring_job` not call `process_scoring_job` itself?**

A: Because that would make the queue's `enqueue_scoring_job` do two things: produce a ticket
AND execute the job. The separation of concerns is: the queue layer signals intent (returns a
ticket); the API layer decides whether to execute inline or truly defer. The API layer can then
handle inline execution (set status to running, catch exceptions, set status to failed) with the
same error-handling logic it would use in any other context. Embedding execution inside the
queue adapter would also mean the queue layer needs access to the full scoring machinery, which
is a dependency inversion.

---

**Q: Why is `job_timeout="4h"` necessary? What happens if it is not set?**

A: Without a timeout, a hung worker — caused by a corrupt PCAP that causes Zeek to spin, an
NFStream deadlock, or a network stall during artifact upload — would occupy a worker slot
indefinitely. No other queued jobs on that worker could run. With `job_timeout="4h"`, RQ's
timeout watchdog sends `SIGALRM` to the worker after 4 hours, RQ catches it, marks the RQ job
as failed, and the worker is freed for the next job. The application's `except` block in
`worker.py` then marks the `ProcessingJob` as `FAILED` with the timeout error message.

---

*Next: [Tutorial 26 — Model Bundle Registry](26_backend_registry.md)*
