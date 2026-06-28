# Tutorial 21 — Backend Configuration (`backend/config.py`)

## Prerequisites

- Tutorial 02 (`configuration_system.md`) — the YAML-based configs for the pipeline layer; this
  file is the equivalent for the backend, but uses environment variables instead of YAML.
- Tutorial 13 (`orchestration.py`) — knows what `pcap_display_filter` controls in the pipeline.
- Tutorial 19 (`ml/workflow.py`) — knows what a model bundle directory contains.

---

## 1. Why This File Exists

The pipeline layer (Tutorials 03–18) uses YAML configs. That works for a data scientist running
a one-shot pipeline from the command line. The backend is different: it is a long-running server
process that must be configured **at deploy time** without editing any source file. The standard
tool for that is environment variables — set them in a `.env` file, a Docker `--env-file`, or a
Kubernetes `ConfigMap`, and the process picks them up at startup.

This file answers one question: *what are all the environment variables the backend reads, and
what are their defaults?* Every variable has a `TLS_BACKEND_` prefix to namespace it away from
system variables or other application variables that might also live in the environment. The
`BackendSettings` frozen dataclass is the single source of truth — no other file calls
`os.environ.get` directly.

The backend is intentionally designed to run with **zero environment variables set** in
development: all defaults point to paths inside the project root and use SQLite + local object
storage. In production, you override only the variables that differ (database URL, S3 credentials,
Redis URL).

---

## 2. `_env_bool` and `_env_int` — Lines 11–22

```python
def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
```

Environment variables are always strings. `os.environ.get("TLS_BACKEND_SCORING_ALLOW_QUALITY_FAILURES")`
returns `"true"` or `"True"` or `"1"` — all of which should mean `True`. Python's built-in
`bool("false")` returns `True` (any non-empty string is truthy), so you cannot use it directly.

The accepted truthy strings — `{"1", "true", "yes", "on"}` — cover every common convention:
`"1"` (shell scripts), `"true"` (dotenv), `"yes"` (sysadmin convention), `"on"` (nginx-style
configs). Anything not in this set is falsy, which means `"false"`, `"no"`, `"0"`, `"off"`, and
even a typo like `"treu"` all evaluate to `False`. This is deliberate: the safe default for an
unknown value is off, not on.

```python
def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return int(raw)
```

`int(raw)` raises `ValueError` if the variable is set to a non-integer string (e.g.,
`TLS_BACKEND_API_PORT=eighty`). This fails loudly at startup rather than silently using the
default — a deliberate choice for misconfiguration that would otherwise cause a confusing bind
error later.

---

## 3. `BackendSettings` — Lines 25–48

```python
@dataclass(frozen=True)
class BackendSettings:
    environment: str              # "dev" | "prod" | "staging"
    project_root: Path            # derived, not user-supplied
    database_url: str             # SQLAlchemy URL
    queue_backend: str            # "rq" | "inline"
    queue_name: str               # Redis queue name
    redis_url: str                # Redis connection string
    object_store_backend: str     # "local" | "s3"
    object_store_bucket: str      # bucket name (S3) or namespace (local)
    object_store_local_root: Path # root for local storage
    s3_endpoint_url: str | None   # None = AWS; set for MinIO
    s3_region: str
    s3_access_key_id: str | None
    s3_secret_access_key: str | None
    s3_presign_expiry_seconds: int
    model_bundle_root: Path       # scanned for available model bundles
    default_model_bundle_dir: Path | None  # pre-selected bundle; None = require explicit
    job_run_root: Path            # per-job working directories
    api_title: str
    api_host: str
    api_port: int
    scoring_allow_quality_failures: bool
    pcap_display_filter: str
```

`frozen=True` — once constructed, no field can be reassigned. Combined with `@lru_cache` (§4),
this means the settings object is effectively a process-level singleton. Any code path that calls
`get_backend_settings()` gets the same immutable object. This prevents a class of bugs where
one module modifies a shared settings object and silently affects another.

### Key design decisions per field group

**Database:** `database_url` defaults to a SQLite file at
`artifacts/backend.sqlite3`. SQLite requires no server, no credentials, and no setup — it works
on a fresh clone with no configuration. In production, this is overridden with
`postgresql+psycopg2://user:pass@host/db`.

**Queue:** `queue_backend` defaults to `"rq"` (Redis Queue). Tutorial 25 shows that the backend
also supports `"inline"` which runs jobs synchronously in the same process — useful for testing
without a Redis server. The queue name `"pcap_scoring"` is the Redis key under which jobs are
pushed.

**Object storage:** Two backends coexist under a shared interface (Tutorial 24). `"local"` stores
files on the filesystem under `object_store_local_root`. `"s3"` uses boto3 with the provided
credentials. `s3_endpoint_url: str | None` is the MinIO hook: if `None`, boto3 uses the real AWS
S3 endpoints; if set to `"http://minio:9000"`, boto3 routes to a local MinIO instance. This is
how the same code serves both the Docker development stack (MinIO) and production (AWS S3) without
any code changes.

**Model bundles:** `model_bundle_root` is a directory that will be scanned for subdirectories
each containing a `model.joblib` and `feature_manifest.json` (Tutorial 26). `default_model_bundle_dir`
is `None` by default, meaning the API requires callers to specify which bundle to use. If set to
a specific path, the backend uses it when no bundle is specified in the request.

**`scoring_allow_quality_failures: bool`** defaults to `True` in development. The quality gates
(Tutorial 09) can produce `warn` or `fail` outcomes on uploaded PCAPs — if a PCAP has an
unexpected protocol mix or low match rate, the quality gate fails. In development, you want the
scoring to proceed anyway so you can inspect the output. In production, set this to `False` to
reject low-quality inputs.

**`pcap_display_filter`** defaults to `"tls or quic"`. This is passed directly to `tshark` by
the filtering stage (Tutorial 04). The backend exposes it as a config so an operator can restrict
to `"tls"` only or expand to `"tcp"` without code changes.

---

## 4. `get_backend_settings` — Lines 51–91

```python
@lru_cache(maxsize=1)
def get_backend_settings() -> BackendSettings:
    project_root = Path(__file__).resolve().parents[3]
    ...
    return BackendSettings(...)
```

### `@lru_cache(maxsize=1)`

`lru_cache` memoizes the function's return value. `maxsize=1` means only the most recent call's
result is cached — since there are no parameters, this effectively caches the single return value
forever. The result: `os.environ.get(...)` is called only once per process lifetime, not once
per request. In a FastAPI application handling 100 requests/second, this avoids 2,300+
`os.environ` lookups per second.

The cache is per-process. If you change an environment variable after the process starts, the
cache will not reflect the change. This is intentional — settings should be stable for the
process lifetime.

### `project_root` derivation

```python
project_root = Path(__file__).resolve().parents[3]
```

`__file__` = `.../src/tls_dataset/backend/config.py`
`.parents[0]` = `.../src/tls_dataset/backend/`
`.parents[1]` = `.../src/tls_dataset/`
`.parents[2]` = `.../src/`
`.parents[3]` = `.../` (the project root)

This is the standard idiom for finding the project root relative to a known source file. It
never requires the caller to pass a path and it works identically whether the package is installed
in editable mode (`pip install -e .`) or as a built wheel. The only assumption is that the
file's depth in the tree never changes — a valid assumption for a fixed package structure.

### `default_model_bundle_dir` two-step loading

```python
default_model_bundle_dir_raw = os.environ.get("TLS_BACKEND_DEFAULT_MODEL_BUNDLE_DIR")
default_model_bundle_dir = (
    Path(default_model_bundle_dir_raw).expanduser().resolve()
    if default_model_bundle_dir_raw
    else None
)
```

This cannot be written as a one-liner `os.environ.get("...", None)` because `Path(None)` raises
`TypeError`. The variable-first pattern explicitly handles the absent case before touching `Path`.
`expanduser()` handles paths like `~/artifacts/...` in `.env` files. `.resolve()` converts
relative paths to absolute — without it, a relative path would be relative to wherever the
process was launched, not the project root.

---

## 5. `clear_backend_settings_cache` — Line 94–95

```python
def clear_backend_settings_cache() -> None:
    get_backend_settings.cache_clear()
```

`lru_cache` objects expose a `.cache_clear()` method that invalidates the cache. This function
exists for exactly one use case: tests. A test that needs to simulate a different environment
sets `os.environ["TLS_BACKEND_ENV"] = "prod"`, calls `clear_backend_settings_cache()`, then
calls `get_backend_settings()` to get a fresh object reflecting the new environment. Without
this function, test isolation is impossible because the first test run locks in the cached
settings for the entire test session.

This is the only mutation point in an otherwise fully read-only module. Exposing it as a named
function (rather than calling `get_backend_settings.cache_clear()` directly in tests) makes the
intent explicit and lets type checkers verify it exists.

---

## 6. How the Rest of the Backend Uses This

Every backend module imports `get_backend_settings` and calls it at the point of use — not at
import time:

```python
# Good: settings read at request time
def get_db():
    settings = get_backend_settings()
    engine = create_engine(settings.database_url)
    ...

# Bad: settings read at import time — test isolation breaks, circular imports possible
settings = get_backend_settings()  # module-level
```

Because of `@lru_cache`, calling `get_backend_settings()` at request time costs nothing after
the first call — the overhead is one dict lookup into the LRU cache. This pattern gives you
test isolation (reset the cache between tests) with zero per-request cost.

---

## 7. Complete Environment Variable Reference

| Variable | Default | Type | Notes |
|---|---|---|---|
| `TLS_BACKEND_ENV` | `"dev"` | str | Deployment tier label |
| `TLS_BACKEND_DATABASE_URL` | SQLite at `artifacts/` | str | SQLAlchemy URL |
| `TLS_BACKEND_QUEUE_BACKEND` | `"rq"` | str | `"rq"` or `"inline"` |
| `TLS_BACKEND_QUEUE_NAME` | `"pcap_scoring"` | str | Redis queue key |
| `TLS_BACKEND_REDIS_URL` | `"redis://127.0.0.1:6379/0"` | str | DB index `/0` |
| `TLS_BACKEND_OBJECT_STORE_BACKEND` | `"local"` | str | `"local"` or `"s3"` |
| `TLS_BACKEND_OBJECT_STORE_BUCKET` | `"tls-dataset"` | str | S3 bucket or local ns |
| `TLS_BACKEND_OBJECT_STORE_LOCAL_ROOT` | `artifacts/object_store` | Path | |
| `TLS_BACKEND_S3_ENDPOINT_URL` | `None` | str\|None | MinIO if set |
| `TLS_BACKEND_S3_REGION` | `"us-east-1"` | str | |
| `TLS_BACKEND_S3_ACCESS_KEY_ID` | `None` | str\|None | |
| `TLS_BACKEND_S3_SECRET_ACCESS_KEY` | `None` | str\|None | |
| `TLS_BACKEND_S3_PRESIGN_EXPIRY_SECONDS` | `3600` | int | 1 hour |
| `TLS_BACKEND_MODEL_BUNDLE_ROOT` | `artifacts/ml_workflow` | Path | Scanned for bundles |
| `TLS_BACKEND_DEFAULT_MODEL_BUNDLE_DIR` | `None` | Path\|None | Pre-selected bundle |
| `TLS_BACKEND_JOB_RUN_ROOT` | `artifacts/backend_jobs` | Path | Per-job scratch dirs |
| `TLS_BACKEND_API_TITLE` | `"TLS Dataset Scoring Platform"` | str | OpenAPI title |
| `TLS_BACKEND_API_HOST` | `"0.0.0.0"` | str | Bind address |
| `TLS_BACKEND_API_PORT` | `8000` | int | |
| `TLS_BACKEND_SCORING_ALLOW_QUALITY_FAILURES` | `True` | bool | See §3 |
| `TLS_BACKEND_PCAP_DISPLAY_FILTER` | `"tls or quic"` | str | Passed to tshark |

---

## 8. Interview Questions and Answers

**Q: Why environment variables instead of YAML for the backend config?**

A: The pipeline layer uses YAML because a data scientist runs it interactively and edits YAML
files between runs. The backend is a server process that must be configured without modifying
files — environment variables are the standard 12-factor app mechanism for this. They work
natively with Docker (`--env-file`), Kubernetes (`ConfigMap`/`Secret`), and systemd unit files.
YAML would require either a mounted config file (adds deployment complexity) or rebuilding the
image (defeats the purpose of external config).

---

**Q: Why `@lru_cache(maxsize=1)` instead of a module-level singleton?**

A: A module-level singleton — `SETTINGS = BackendSettings(...)` at the top of `config.py` —
reads `os.environ` at import time. This breaks test isolation: the first test that imports the
module locks in whatever environment was set at that moment, and subsequent tests that try to
set different environment variables see the stale cached values. `@lru_cache` defers the first
read until the first call, and `cache_clear()` allows test teardown to invalidate it. The cost
is identical after the first call — both approaches return a pre-built object from memory.

---

**Q: What does `s3_endpoint_url: str | None` enable architecturally?**

A: It is the MinIO hook. AWS S3 and MinIO are API-compatible — the same boto3 code works with
both, provided you override the endpoint URL. Setting `s3_endpoint_url="http://minio:9000"` in
the Docker development stack routes all S3 API calls to a local MinIO container instead of
real AWS. This means the production S3 code path is exercised in development without incurring
AWS costs or requiring AWS credentials. The `None` case simply omits the `endpoint_url` argument
from the boto3 client constructor, which then defaults to the real AWS endpoints.

---

**Q: Why does `project_root` use `Path(__file__).resolve().parents[3]` instead of `Path.cwd()`?**

A: `Path.cwd()` returns the working directory of the process at runtime. If you launch the
server from `/home/vandit/Desktop` instead of the project root, all default paths
(`artifacts/backend.sqlite3`, `artifacts/ml_workflow`) would resolve to
`/home/vandit/Desktop/artifacts/` and fail. `Path(__file__).resolve().parents[3]` is always
relative to the source file's location in the repository tree, regardless of where the process
was launched. It makes the defaults reproducible and removes a hidden dependency on the working
directory.

---

*Next: [Tutorial 22 — ORM Models and Database Session](22_backend_models_db.md)*
