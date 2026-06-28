# Tutorial 29 — Worker Process (`backend/worker.py`)

## Prerequisites

- Tutorial 22 (`backend/db.py`, `backend/models.py`) — `session_scope`, `init_database`,
  `ProcessingJob`, `JobArtifact`, `JobStatus`. The worker is the heaviest consumer of the
  session pattern; understanding `session_scope`'s auto-commit and rollback is essential.
- Tutorial 24 (`backend/storage.py`) — `get_storage` and `download_file` are called here.
- Tutorial 27 (`backend/services.py`) — `upload_output_artifacts` is called inside the main
  transaction. The `flush()` vs `commit()` decision from Tutorial 27 Section 9 pays off here.
- Tutorial 28 (`backend/scoring.py`) — `run_pcap_scoring_job` is the long-running call this
  worker is built around. Its `ScoringRunResult.summary` becomes `job.summary_payload`.
- Tutorial 25 (`backend/queue.py`) — `RQQueueBackend.enqueue_scoring_job` queued the function
  `"tls_dataset.backend.worker.process_scoring_job"` by string. This file is what RQ imports
  and executes.

---

## 1. Why This File Exists

The queue (Tutorial 25) records a message in Redis: "run `process_scoring_job` with
`job_id=abc123`." Something must actually run that function. That something is `worker.py`.

It has two jobs:
1. Define `process_scoring_job` — the function RQ deserialises from the queue message, executes,
   and wraps in its own failure-handling machinery.
2. Define `run_worker` and `main` — the entry point that starts an RQ worker process which
   polls Redis indefinitely and dispatches queued functions.

---

## 2. Imports Worth Noting

```python
import shutil
import tempfile
```

Both are imported but not used in the current code. They are dead imports — leftovers from an
earlier version where the worker itself managed temporary directories before that
responsibility moved to `stage_uploaded_file` in `services.py`. They cause no harm but would
be removed in a cleanup pass.

---

## 3. `utc_now` (line 21)

```python
def utc_now() -> datetime:
    return datetime.now(timezone.utc)
```

`datetime.now(timezone.utc)` returns a **timezone-aware** datetime. The older
`datetime.utcnow()` returns a naive datetime with no timezone annotation. The difference
matters when values are stored in PostgreSQL's `TIMESTAMP WITH TIME ZONE` column: a naive
datetime is ambiguous and PostgreSQL may interpret it as local server time rather than UTC,
producing silent timestamp errors. Using `timezone.utc` explicitly makes every timestamp
unambiguous. SQLite stores timestamps as strings and ignores timezone info, but the aware
datetime is still correct to use.

---

## 4. `_input_artifact` (lines 25–29)

```python
def _input_artifact(job: ProcessingJob) -> JobArtifact:
    for artifact in job.artifacts:
        if artifact.kind == "input" and artifact.artifact_type == "input_pcap":
            return artifact
    raise RuntimeError(f"Job {job.id} is missing an input_pcap artifact")
```

Linear scan over `job.artifacts`. A job typically has exactly one input artifact — the
uploaded PCAP — so a linear scan over one element costs nothing. The two conditions `kind ==
"input"` and `artifact_type == "input_pcap"` mirror how `create_batch_from_pcaps` (Tutorial
27) creates the record. If the record was somehow not created (a bug in job intake), this
raises `RuntimeError` immediately rather than allowing `download_file` to be called with a
`None` path.

---

## 5. `process_scoring_job` — The Three-Session Design (lines 32–86)

This is the most important function to understand. It uses **three separate database sessions**
in a specific order that balances two competing needs: giving the API early visibility into job
state, and committing all final results atomically.

### Session 1 — Mark RUNNING (lines 37–43)

```python
    with session_scope() as session:
        job = session.get(ProcessingJob, job_id)
        if job is None:
            raise RuntimeError(f"Job not found: {job_id}")
        job.status = JobStatus.RUNNING.value
        job.started_at = utc_now()
        job.error_message = None
```

A short, immediately-committed transaction. By the time this `with` block exits, the DB row
has `status="running"` and a `started_at` timestamp. Any API client polling the job status
will see `RUNNING` before the scoring pipeline even starts.

`job.error_message = None` — clears any prior error. If this job was previously attempted and
failed (possible in certain retry scenarios), the old error message would otherwise persist in
the DB while the job shows `RUNNING`.

If `session.get` returns `None`, the `RuntimeError` propagates out of `session_scope`. The
`session_scope` context manager catches the exception, rolls back (nothing was committed), and
re-raises. The worker process records this as a failed job in RQ. There is no Session 2 in this
case.

### Workspace setup — outside any session (lines 45–49)

```python
    workspace_root = (settings.job_run_root / job_id).expanduser().resolve()
    input_dir = workspace_root / "input"
    run_dir = workspace_root / "run"
    input_dir.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
```

Directory creation happens outside any DB session. There is no reason to hold a DB connection
while creating directories. The workspace layout is:

```
settings.job_run_root / {job_id} /
├── input/     ← PCAP downloaded from object store
└── run/       ← workspace_dir for run_pcap_scoring_job
    ├── pipeline/   (Zeek logs, merged CSV, quality report)
    └── scoring/    (tiered CSVs, graph bundle, workflow_summary)
```

`run_dir` is the `output_root` passed to `upload_output_artifacts`. Everything under `run/`
gets uploaded to object storage and recorded as `JobArtifact` rows.

### Session 2 — The main transaction (lines 51–78)

```python
    try:
        with session_scope() as session:
            job = session.get(ProcessingJob, job_id)
            if job is None:
                raise RuntimeError(f"Job not found during processing: {job_id}")
            input_artifact = _input_artifact(job)
            local_input = storage.download_file(...)
            scoring_result = run_pcap_scoring_job(...)
            upload_output_artifacts(session, job=job, output_root=run_dir, settings=settings)
            inference_summary = scoring_result.summary.get("inference_summary", {})
            job.summary_payload = scoring_result.summary
            job.suspicious_flow_count = int(inference_summary.get("tier2_suspicious_rows", 0))
            job.candidate_flow_count = int(inference_summary.get("tier1_candidate_rows", 0))
            job.cluster_count = int(inference_summary.get("cluster_count", 0))
            job.status = JobStatus.SUCCEEDED.value
            job.completed_at = utc_now()
            job.error_message = None
```

**Everything in one session scope**: download the PCAP, run the full pipeline (minutes of CPU
and disk I/O), upload output artifacts, update the job record — all inside a single
transaction that commits when the `with` block exits normally.

The consequence: **the DB session is held open for the entire scoring duration**. For SQLite
this is fine — SQLite only locks briefly on writes, not for the duration of a transaction. For
PostgreSQL, holding an open transaction for minutes is problematic: idle transactions block
VACUUM, hold shared locks, and can time out connection pool leases. A production hardening
would split this into a short "claim" transaction (download + score) outside any DB session,
then a short "commit results" transaction at the end. For this research deployment the
single-session approach is acceptable and simpler to reason about.

`job = session.get(ProcessingJob, job_id)` re-fetches the job inside Session 2. The `job`
object from Session 1 is tied to that closed session and cannot be reused. Each `session_scope`
yields a fresh session; objects fetched in one session cannot be used in another without
re-attachment.

`upload_output_artifacts(session, ...)` is called with Session 2's session object. Inside, it
calls `session.flush()` (Tutorial 27, Section 9) — the artifact records are inserted into the
DB within the current transaction but not yet committed. The commit happens when Session 2's
`with` block exits normally, atomically persisting both the artifact records and the
`job.status = SUCCEEDED` update.

`inference_summary = scoring_result.summary.get("inference_summary", {})` — `scoring_result.summary`
is the `platform_summary` dict from `run_pcap_scoring_job` (Tutorial 28). The `"inference_summary"`
key contains the dict returned by `run_multitier_inference`. The three count fields are pulled
from there with `.get(..., 0)` defaults — if inference produced no suspicious flows, the counts
are 0 rather than `None`.

`int(inference_summary.get("tier2_suspicious_rows", 0))` — the `int()` cast converts the
value regardless of whether it came from the summary dict as a Python `int` or a NumPy integer.
This mirrors the `int()` casts in `run_multitier_inference` (Tutorial 28) but adds a defensive
layer in case the summary was read from JSON (where all numbers are Python `int` or `float`).

### Session 3 — The failure path (lines 79–86)

```python
    except Exception as exc:
        with session_scope() as session:
            job = session.get(ProcessingJob, job_id)
            if job is not None:
                job.status = JobStatus.FAILED.value
                job.completed_at = utc_now()
                job.error_message = str(exc)
        raise
```

If anything in the `try` block raises, `session_scope` catches it, **rolls back** Session 2
(none of the artifact records or status updates are committed), and re-raises. The `except`
block then opens Session 3 to record the failure.

**Why Session 3 cannot reuse Session 2**: `session_scope` closes the session in its `finally`
block unconditionally. After the exception, Session 2 is closed and rolled back. Opening a
new session is the only way to write to the DB.

`str(exc)` — converts the exception to a string for `job.error_message`. This captures the
exception type and message in a human-readable form (`"RuntimeError: Job not found..."`,
`"FileNotFoundError: No such file: /path/to/pcap"`).

`raise` — re-raises the original exception after recording the failure. **This is essential
for RQ**: RQ considers a job function successful if it returns normally and failed if it raises.
If `raise` were omitted, `process_scoring_job` would return `None` and RQ would mark the job
as "succeeded" in Redis, even though the DB says `FAILED`. The re-raise ensures RQ's own job
record matches the application's.

The `if job is not None` guard — if `session.get` in Session 3 returns `None` (extremely
unlikely: the job was found in Session 1), the `RuntimeError` would propagate and RQ would
still mark it as failed. The guard prevents a second exception from obscuring the original
failure message.

---

## 6. Session Lifecycle Summary

```
process_scoring_job("abc123")
│
├── Session 1  [short, committed]
│   status = RUNNING, started_at = now
│   → auto-commit via session_scope
│
├── mkdir input/, run/
│
└── try:
    │
    ├── Session 2  [long, either committed or rolled back]
    │   download PCAP → score → upload artifacts → update job
    │   → auto-commit on success
    │   or
    │   → auto-rollback on any exception
    │
    except:
    ├── Session 3  [short, committed]
    │   status = FAILED, completed_at = now, error_message = str(exc)
    │   → auto-commit
    └── raise  ← RQ records job as failed in Redis
```

---

## 7. `run_worker` (lines 89–97)

```python
def run_worker(*, burst: bool = False) -> None:
    settings = get_backend_settings()
    if settings.queue_backend != "rq":
        raise RuntimeError("RQ worker mode requires TLS_BACKEND_QUEUE_BACKEND=rq")
    init_database()
    connection = Redis.from_url(settings.redis_url)
    with Connection(connection):
        worker = Worker([settings.queue_name])
        worker.work(burst=burst)
```

`if settings.queue_backend != "rq"` — early guard. Starting an RQ worker when the backend is
`"inline"` would be a misconfiguration: the API would never push to Redis, the worker would
poll Redis forever and process nothing. The guard surfaces this clearly at startup.

`init_database()` — creates ORM tables if they don't exist. The worker process is a separate
OS process from the API; it cannot assume the API has already run `init_database`. This call is
idempotent: `Base.metadata.create_all()` is a no-op if the tables already exist.

`Redis.from_url(settings.redis_url)` — creates a connection pool. RQ needs a direct Redis
connection (not the same one used by `RQQueueBackend` in the API process).

`with Connection(connection)` — RQ's legacy global-state context manager. It registers the
connection as the default Redis connection for all RQ objects created inside the block. This
pattern predates RQ's newer per-object connection API but is still used here for compatibility.

`Worker([settings.queue_name])` — instantiates a worker that listens on a list of queues.
Passing a list allows a worker to drain multiple queues in priority order, but here there is
only one: `"pcap_scoring"`.

`worker.work(burst=burst)`:
- `burst=False` (default): the worker runs indefinitely, blocking on `BRPOP` for new jobs. This
  is the normal production mode. The OS process stays alive until killed.
- `burst=True`: the worker processes all jobs currently in the queue and exits when the queue
  is empty. Useful in CI pipelines ("process all pending test jobs and exit") or for manual
  one-off batch processing.

---

## 8. `main` (lines 100–114)

```python
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the backend scoring worker")
    parser.add_argument("--burst", action="store_true", ...)
    parser.add_argument("--job-id", default=None, ...)
    args = parser.parse_args(argv)

    if args.job_id:
        process_scoring_job(args.job_id)
        return 0
    run_worker(burst=args.burst)
    return 0
```

Two operating modes:

**`--job-id {uuid}`**: Bypasses the queue entirely and runs a specific job directly in the
current process. Used for:
- Debugging a failed job: `python -m tls_dataset.backend.worker --job-id abc123`
- Re-processing a job without re-submitting through the API
- Running in inline mode from a script

This mode is only safe when `TLS_BACKEND_QUEUE_BACKEND=inline` is in use, or when a job
exists in the DB with a known ID. Nothing checks that the job is in `QUEUED` state before
running — it will re-process even a `SUCCEEDED` job, overwriting its results.

**`--burst`**: Starts the full RQ worker but exits after draining the current queue contents.

`argv: list[str] | None = None` — passing `None` causes `argparse` to read from `sys.argv`.
The parameter allows tests to call `main(["--burst"])` without modifying the process's
argument vector.

`raise SystemExit(main())` at line 113 — the standard Python script entry point pattern.
`main()` returns `0` on success; `SystemExit(0)` exits cleanly. If `main()` raises an
uncaught exception, it propagates as a non-zero exit for the process.

---

## 9. How the Worker Fits Into the Full System

```
API process                    Redis                       Worker process
─────────────────────          ─────────────────           ────────────────────────────────
POST /jobs/upload
  create DB record             LPUSH rq:queue:pcap_scoring
  enqueue → ──────────────────────────────────────────>    BRPOP wakes up
                                                           process_scoring_job("abc123")
                                                             Session 1: status=RUNNING
                                                             download PCAP
                                                             run pipeline + inference
                                                             upload artifacts
                                                             Session 2: status=SUCCEEDED
GET /jobs/abc123
  reads DB (status=RUNNING)
  ...polls...
GET /jobs/abc123
  reads DB (status=SUCCEEDED)
  serialize_job → ArtifactResponse with presigned URLs
```

The API and the worker share only two things: the database and the object store. They have no
direct process communication. The API writes a job record; the worker reads it, executes, and
writes results back. The API then reads those results.

---

## 10. Interview Questions and Answers

**Q: Why does `process_scoring_job` use three separate DB sessions instead of one?**

A: Three separate concerns require three separate transaction scopes:
1. **Session 1** must commit the `RUNNING` status immediately, independently of whether the
   scoring succeeds or fails, so the API can show a running job during the long computation.
2. **Session 2** must atomically commit all scoring results — artifact records, summary payload,
   counts, and `SUCCEEDED` status — or roll them all back on failure. These must be in one
   transaction: a partial commit where artifacts exist but status is still `RUNNING` would leave
   the DB in an inconsistent state.
3. **Session 3** is needed because Session 2 is closed and rolled back on failure. You cannot
   re-use a rolled-back session; a new session is required to write the `FAILED` status.

---

**Q: Why does the `except` block end with `raise` rather than returning normally?**

A: RQ determines job success or failure by whether the function raised or returned. If the
except block swallowed the exception and `process_scoring_job` returned `None`, RQ would mark
the job as "succeeded" in Redis — even though the application DB says `FAILED`. An operator
using `rq info` or RQ's dashboard would see a "succeeded" job, contradicting the application
status. The `raise` at the end ensures RQ's record matches the application's record.

---

**Q: Session 2 holds a DB transaction open while running the pipeline, which can take minutes.
What is the risk of this design?**

A: For SQLite (the default development database), there is no meaningful risk — SQLite locks
briefly on writes and the long transaction doesn't cause problems. For PostgreSQL in production,
holding an open transaction for minutes causes two issues: idle transactions block PostgreSQL's
VACUUM autovacuum process (which prevents dead tuple cleanup and table bloat), and they hold
shared locks that can time out in connection pools. The correct production pattern would be:
close the session after marking `RUNNING`, perform the computation outside any transaction,
then open a new short transaction to commit results. This was not implemented because the
deployment target is a single-machine SQLite setup.

---

**Q: What happens if the worker process is killed between Session 1 and Session 2?**

A: The job remains in the DB with `status="running"` and `started_at` set, but `completed_at`
and `summary_payload` are never written. The queue message was consumed by RQ before
`process_scoring_job` started (RQ uses a "processing" registry in Redis), so RQ will consider
the job as "started" but not "completed". This is a stuck job — neither `SUCCEEDED` nor
`FAILED` in the DB. Recovery requires either a manual update of the job status, or a watchdog
process that detects jobs stuck in `RUNNING` for longer than `job_timeout` (4 hours) and
marks them as `FAILED`. This is a known gap in the current implementation.

---

*Next: [Tutorial 30 — FastAPI Application](30_backend_app.md)*
