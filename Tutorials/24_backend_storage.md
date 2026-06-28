# Tutorial 24 — Object Storage Adapters (`backend/storage.py`)

## Prerequisites

- Tutorial 21 (`backend/config.py`) — `BackendSettings` fields `object_store_backend`,
  `object_store_local_root`, `s3_*`, and `s3_presign_expiry_seconds` that are consumed by
  `build_object_storage`.
- Tutorial 22 (`backend/models.py`) — `JobArtifact` ORM columns (`storage_backend`, `bucket`,
  `object_key`, `object_uri`, `filename`, `content_type`, `size_bytes`, `sha256`) map 1:1 to
  `StoredObject` fields. The services layer (Tutorial 27) translates `StoredObject → JobArtifact`.
- Tutorial 23 (`backend/schemas.py`) — `ArtifactResponse.download_reference` is computed from
  `build_reference()` at response time; the `object_uri` stored in the ORM is the durable
  identifier, not the presigned URL.

---

## 1. Why This File Exists

Once a worker finishes scoring a PCAP it produces several artifacts: a suspicious-flows CSV, a
graph bundle, possibly a scored dataset. Those files need to go somewhere durable so the API can
serve them back to the client. The pipeline itself writes files to a local job-run directory
under `artifacts/backend_jobs/`. That path is ephemeral — it is tied to the worker process and
the machine it ran on.

`storage.py` is the boundary between "file on worker disk" and "file in object store". It
provides two implementations with the same interface:

- **`LocalObjectStorage`** — copies files into a structured directory under
  `TLS_BACKEND_OBJECT_STORE_LOCAL_ROOT`. Used in development and single-machine deployments.
- **`S3ObjectStorage`** — uploads files to an S3-compatible bucket via `boto3`. Used in
  containerised or cloud deployments, including MinIO running in Docker.

The factory function `build_object_storage()` reads `BackendSettings` and returns whichever
implementation matches `object_store_backend`. The rest of the codebase only ever sees
`ObjectStorage` — the concrete backend is invisible past the factory call.

---

## 2. `StoredObject` (lines 18–28)

```python
@dataclass(frozen=True)
class StoredObject:
    backend: str
    bucket: str
    object_key: str
    object_uri: str
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
```

`frozen=True` makes every field read-only after construction. A `StoredObject` represents a
fact: a specific file was stored at a specific location at a specific moment, and these values
describe that fact immutably. SHA256 and `size_bytes` are properties of the stored content —
they must not change. Mutability would imply the record could drift from the actual stored
object.

**Why not just return a dict?** Because `StoredObject` is used as input to the services layer,
which maps it to a `JobArtifact` ORM row. Having named fields (instead of string-keyed dict
access) means a typo in the services layer is caught by the type checker rather than silently
storing `None` in the database.

`backend: str` is `"local"` or `"s3"` — the literal string. It becomes `JobArtifact.storage_backend`
in the ORM, which is then re-exposed as `ArtifactResponse.storage_backend`. A client can use
this field to decide whether `object_uri` is a filesystem path or an `s3://` URI.

`object_uri` is the **durable identifier** — for local storage it is the absolute path
(`/path/to/object_store/bucket/key`), for S3 it is `s3://bucket/key`. Neither form is a usable
download URL by itself. The ephemeral download URL is produced separately by `build_reference()`
and never stored in the database (see Tutorial 23, Section 4 for why).

---

## 3. `ObjectStorage` Protocol (lines 30–35)

```python
class ObjectStorage(Protocol):
    def ensure_bucket(self, bucket: str) -> None: ...
    def put_file(self, source_path, *, bucket, object_key, content_type) -> StoredObject: ...
    def download_file(self, *, bucket, object_key, destination_path) -> Path: ...
    def build_reference(self, *, bucket, object_key, filename) -> str: ...
    def healthcheck(self) -> dict[str, object]: ...
```

`Protocol` is structural subtyping — Python's `typing.Protocol` means "any class that has
these methods is compatible, without needing to inherit from me." This is the opposite of
`ABC` (Abstract Base Class), which uses nominal subtyping (you must explicitly inherit and
register).

**Why `Protocol` over `ABC` here?** Two reasons:

1. `LocalObjectStorage` and `S3ObjectStorage` don't share any implementation — there is no
   shared state or shared logic to put in a base class. An ABC would add an inheritance chain
   that carries zero substance.
2. `Protocol` is purely a type-checker contract. At runtime, no `isinstance(obj, ObjectStorage)`
   check is needed. The factory function `build_object_storage()` returns the right type; mypy
   confirms it. This keeps the code lighter.

Adding a third backend (e.g., Azure Blob Storage) requires only writing a new class with these
five methods. The Protocol and every call site that uses `ObjectStorage` require zero changes.

All four data methods use keyword-only arguments (the `*` separator). This prevents callers from
accidentally passing `bucket` and `object_key` in the wrong order, which would be a silent
correctness bug.

---

## 4. `compute_file_digest` (lines 38–46)

```python
def compute_file_digest(path: str | Path) -> tuple[str, int]:
    target = Path(path).expanduser().resolve()
    digest = hashlib.sha256()
    size_bytes = 0
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size_bytes += len(chunk)
    return digest.hexdigest(), size_bytes
```

`expanduser().resolve()` — `expanduser` expands `~` to the home directory (relevant when paths
come from environment variables like `TLS_BACKEND_OBJECT_STORE_LOCAL_ROOT`). `resolve()`
canonicalises `..` components and resolves symlinks, producing an absolute path. This prevents
path-traversal surprises where `../../etc/passwd` resolves somewhere unexpected.

The `iter(lambda: handle.read(1024 * 1024), b"")` idiom is a streaming read loop:
`iter(callable, sentinel)` calls the callable repeatedly until it returns the sentinel value.
Here `handle.read(1024 * 1024)` reads 1 MiB at a time; `b""` is returned when the file is
exhausted. This matters because PCAP files can be hundreds of megabytes — reading the whole
file into memory with `handle.read()` would exhaust RAM on large captures.

The function returns both `(sha256_hex, size_bytes)` in a single pass. Computing both in one
read is more efficient than reading the file twice: once for the hash and once for the size. The
caller needs both to populate `StoredObject`.

This is a module-level function, not a method, because it has no dependency on any storage
backend — it operates on a local file path regardless of where that file will ultimately go.
`S3ObjectStorage.put_file` calls it before uploading; `LocalObjectStorage.put_file` calls it
after copying. Both use the same function.

---

## 5. `LocalObjectStorage` (lines 49–97)

### `__init__` (line 50–51)

```python
def __init__(self, root: str | Path) -> None:
    self.root = Path(root).expanduser().resolve()
```

`resolve()` at construction time, not per-operation. The root path is fixed for the lifetime of
the object. Resolving once is cheaper than resolving on every `put_file` or `download_file`
call, and it prevents the root from silently changing if the working directory changes.

### `ensure_bucket` (lines 53–54)

```python
def ensure_bucket(self, bucket: str) -> None:
    (self.root / bucket).mkdir(parents=True, exist_ok=True)
```

"Bucket" in local storage is a subdirectory of `self.root`. `parents=True` creates all
intermediate directories if they don't exist. `exist_ok=True` makes the call idempotent — safe
to call on every job submission, not just the first. The caller should always call
`ensure_bucket` before `put_file`; the alternative of auto-creating the bucket inside
`put_file` would hide setup failures and make each write operation subtly stateful.

### `put_file` (lines 56–79)

```python
source = Path(source_path).expanduser().resolve()
destination = (self.root / bucket / object_key).resolve()
destination.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(source, destination)
sha256, size_bytes = compute_file_digest(destination)
```

`(self.root / bucket / object_key).resolve()` — `object_key` can contain `/` to represent
logical subdirectories (`"jobs/abc123/suspicious_flows.csv"`). Path division handles this
naturally. `resolve()` ensures no `..` in the key can escape `self.root`.

`destination.parent.mkdir(parents=True, exist_ok=True)` — creates any subdirectory structure
implied by the `object_key`. Even though `ensure_bucket` created `self.root/bucket/`, the
`object_key` might add another level (`jobs/abc123/`). This line handles that without requiring
the caller to know the key's depth.

`shutil.copy2` vs `shutil.copy` — `copy2` preserves the source file's metadata (modification
time, access time). This matters for artifact tracing: if the worker wrote a file at 14:23:01,
the stored copy retains that timestamp rather than showing the copy time. `copy` would update
the mtime to now.

**SHA256 is computed on the destination, not the source.** This is intentional: it verifies the
copy succeeded faithfully. If `shutil.copy2` silently truncated the file (unlikely but
theoretically possible on a full disk), the digest would differ from what the source would
produce. The ORM stores the digest of what was actually stored, not what was intended to be
stored.

`object_uri` is `str(destination)` — the absolute local path. This is a stable reference: as
long as the machine doesn't move the `object_store_local_root`, the URI is valid indefinitely.

### `download_file` (lines 81–86)

```python
source = (self.root / bucket / object_key).expanduser().resolve()
destination = Path(destination_path).expanduser().resolve()
destination.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(source, destination)
return destination
```

Returns the `Path` of the written file so the caller knows exactly where the file landed — the
caller may have passed a directory path and needs to know the final file path, or may have used
a temp dir.

### `build_reference` (lines 88–89)

```python
def build_reference(self, *, bucket: str, object_key: str, filename: str | None = None) -> str:
    return str((self.root / bucket / object_key).resolve())
```

For local storage, the "reference" is just the absolute path. A client that has access to the
filesystem can open this path directly. The `filename` parameter is accepted but ignored —
the key already encodes the filename. The method signature matches the Protocol, which requires
`filename` as an optional keyword argument, so it must be accepted even if unused.

### `healthcheck` (lines 91–97)

```python
def healthcheck(self) -> dict[str, object]:
    self.root.mkdir(parents=True, exist_ok=True)
    return {
        "backend": "local",
        "root": str(self.root),
        "writable": self.root.exists(),
    }
```

`mkdir` inside `healthcheck` is both a check and a repair: if the root directory was deleted
between startup and the health probe, this recreates it. `"writable": self.root.exists()` is
technically weak — `exists()` only checks presence, not write permission. For a thesis/research
deployment this is acceptable; a production system would `os.access(root, os.W_OK)`.

---

## 6. `S3ObjectStorage` (lines 100–158)

### `__init__` (lines 101–103)

```python
def __init__(self, client: BaseClient, *, presign_expiry_seconds: int) -> None:
    self.client = client
    self.presign_expiry_seconds = presign_expiry_seconds
```

The constructor receives an already-constructed `BaseClient` (the boto3 S3 client), not raw
credentials. This is the dependency-injection pattern: the factory function `build_object_storage`
is responsible for constructing the client with the right credentials and endpoint. The class
itself has no knowledge of credentials, environment variables, or endpoints — it only knows
how to use a client it was given. This makes `S3ObjectStorage` independently testable: tests
can pass a mock client.

`presign_expiry_seconds` is stored on the instance so it is applied consistently to every
`build_reference` call without the caller having to specify it each time. The value comes from
`BackendSettings.s3_presign_expiry_seconds` (default 3600 = 1 hour).

### `ensure_bucket` (lines 105–109)

```python
def ensure_bucket(self, bucket: str) -> None:
    try:
        self.client.head_bucket(Bucket=bucket)
    except Exception:
        self.client.create_bucket(Bucket=bucket)
```

`head_bucket` sends a lightweight HEAD request to check if the bucket exists and if the
credentials have access. It does not list or download any contents. If it raises (bucket does
not exist, or no access), `create_bucket` is called.

The `except Exception` broad catch is deliberate: the error type differs between a "bucket does
not exist" response (HTTP 404) and a "no access" response (HTTP 403). In a local MinIO
environment (where the worker has admin credentials), both cases are safe to attempt creation.
In a production AWS environment with restricted IAM, `create_bucket` would also fail, and the
error would propagate to the caller — which is the correct behaviour: don't silently swallow a
permissions error.

### `put_file` (lines 111–137)

```python
source = Path(source_path).expanduser().resolve()
sha256, size_bytes = compute_file_digest(source)
resolved_content_type = content_type or mimetypes.guess_type(source.name)[0] or "application/octet-stream"
self.client.upload_file(
    str(source),
    bucket,
    object_key,
    ExtraArgs={"ContentType": resolved_content_type},
)
```

**SHA256 is computed on the source, before upload.** The inverse of the local implementation.
Recomputing SHA256 from S3 after upload would require downloading the entire file over the
network — wasteful for large PCAPs. Since `upload_file` is not expected to silently corrupt
data (boto3 computes a server-side integrity check internally using MD5/CRC), computing on the
source is acceptable. The SHA256 stored in the ORM is the digest of the file as it left the
worker, which is the relevant fact for provenance tracking.

`mimetypes.guess_type(source.name)[0]` — `guess_type` returns a `(type, encoding)` tuple.
`[0]` takes the MIME type and discards the encoding. A `.pcap` file returns `None` (not a
registered MIME type in the standard library's database), so the chain falls through to
`"application/octet-stream"` — the RFC 2046 default for unknown binary data. S3 stores this as
the `Content-Type` metadata, which HTTP clients use to decide how to handle a download.

`upload_file` vs `put_object` — `upload_file` handles multipart upload automatically for files
above a configurable threshold (default 8 MB). A 500 MB PCAP would be split into ~63 parts
and uploaded in parallel, then reassembled by S3. `put_object` would attempt to send the
entire file in a single HTTP request, which times out or fails for large files. `upload_file`
is always the right choice for arbitrary file sizes.

`object_uri` is `f"s3://{bucket}/{object_key}"` — the canonical S3 URI. This is a stable
identifier: it does not expire, it does not change, and it can be used by any S3-compatible
tool (`aws s3 cp`, `boto3`, `s5cmd`) to retrieve the object. It is stored in the ORM.

### `download_file` (lines 139–143)

```python
destination = Path(destination_path).expanduser().resolve()
destination.parent.mkdir(parents=True, exist_ok=True)
self.client.download_file(bucket, object_key, str(destination))
return destination
```

`download_file` is boto3's counterpart to `upload_file` — it handles multipart downloads and
retries automatically. The destination must be a file path string (not a Path object) because
boto3's `download_file` signature predates `os.PathLike`.

### `build_reference` (lines 145–152)

```python
def build_reference(self, *, bucket: str, object_key: str, filename: str | None = None) -> str:
    return str(
        self.client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": object_key},
            ExpiresIn=self.presign_expiry_seconds,
        )
    )
```

`generate_presigned_url` creates a time-limited HTTPS URL that grants temporary read access to
a private S3 object without requiring the client to have AWS credentials. The signature is
computed from the access key and embedded in the URL as query parameters. After
`presign_expiry_seconds` (default 3600 = 1 hour), the URL returns HTTP 403.

This is why `download_reference` is not stored in the ORM (Tutorial 23, Section 4). Calling
`build_reference` on every API response ensures the client always receives a fresh URL valid
for at least another hour.

`filename` is also ignored here (as in `LocalObjectStorage`) — the filename is embedded in the
`object_key`. The parameter exists in the Protocol for flexibility: a future implementation
might need to set `Content-Disposition: attachment; filename="..."` in the presigned URL, which
requires the filename separately from the key.

### `healthcheck` (lines 154–158)

```python
def healthcheck(self) -> dict[str, object]:
    return {
        "backend": "s3",
        "endpoint": getattr(self.client.meta, "endpoint_url", None),
    }
```

Returns only the endpoint URL — no test request to S3. A real connectivity check would call
`head_bucket(Bucket=settings.object_store_bucket)`, but this is intentionally absent.
Health checks that make network requests introduce latency into the `/health` endpoint and can
cause cascading failures (a slow S3 endpoint makes every health probe slow). The health check
confirms the backend is `"s3"` and which endpoint it is pointed at; actual storage-layer health
is inferred from job success/failure rates, not from a probe.

`getattr(self.client.meta, "endpoint_url", None)` — `endpoint_url` is `None` when using the
default AWS endpoints (not MinIO). In production on AWS, this field would be `None`; in the
Docker MinIO setup it would be `"http://minio:9000"`.

---

## 7. `build_object_storage` (lines 161–172)

```python
def build_object_storage(settings: BackendSettings | None = None) -> ObjectStorage:
    resolved = settings or get_backend_settings()
    if resolved.object_store_backend == "s3":
        client = boto3.client(
            "s3",
            endpoint_url=resolved.s3_endpoint_url,
            region_name=resolved.s3_region,
            aws_access_key_id=resolved.s3_access_key_id,
            aws_secret_access_key=resolved.s3_secret_access_key,
        )
        return S3ObjectStorage(client, presign_expiry_seconds=resolved.s3_presign_expiry_seconds)
    return LocalObjectStorage(resolved.object_store_local_root)
```

The `settings: BackendSettings | None = None` pattern — the default of `None` means callers
can omit settings and get the environment-derived settings via `get_backend_settings()`. Passing
settings explicitly is the test path: tests construct a `BackendSettings` pointing at a temp
directory and pass it directly, without touching environment variables.

`endpoint_url=resolved.s3_endpoint_url` — when this is `None` (the default), boto3 uses the
standard AWS endpoint (`s3.amazonaws.com`). When it is `"http://minio:9000"` (the Docker
compose value), boto3 routes to MinIO. This single parameter is the only difference between an
AWS deployment and a local MinIO deployment — the rest of the client interface is identical.

`aws_access_key_id=resolved.s3_access_key_id` — both `access_key_id` and `secret_access_key`
can be `None`. When `None`, boto3 falls back to its credential resolution chain: environment
variables (`AWS_ACCESS_KEY_ID`), then `~/.aws/credentials`, then EC2 instance role metadata.
This means the code works without changes whether credentials are in `BackendSettings`,
in the standard AWS config files, or in an EC2/ECS IAM role.

The function returns the `LocalObjectStorage` instance as the else-branch (no explicit `elif
"local"`). Any value of `object_store_backend` that is not `"s3"` falls through to local. This
is an intentional soft default: a misconfigured `object_store_backend` value gets local
storage rather than an error, which is safe for development but would be a silent misconfiguration
in production. (In production you would add an explicit check and raise `ValueError`.)

---

## 8. How `StoredObject` Becomes a Database Row

The services layer (Tutorial 27) calls `storage.put_file(...)` and receives a `StoredObject`.
It then creates a `JobArtifact` ORM instance mapping the fields:

| `StoredObject` field | `JobArtifact` column |
|---|---|
| `backend` | `storage_backend` |
| `bucket` | `bucket` |
| `object_key` | `object_key` |
| `object_uri` | `object_uri` |
| `filename` | `filename` |
| `content_type` | `content_type` |
| `size_bytes` | `size_bytes` |
| `sha256` | `sha256` |

When the API returns an `ArtifactResponse`, the services layer also calls
`storage.build_reference(bucket=artifact.bucket, object_key=artifact.object_key)` to produce
the ephemeral `download_reference` field. The `StoredObject` is not stored; it is a transient
carrier that bridges the storage operation to the ORM insertion.

---

## 9. Interview Questions and Answers

**Q: Why is SHA256 computed on the destination for local storage but on the source for S3
storage?**

A: For local storage, computing the digest on the destination file verifies the copy was
faithful — if `shutil.copy2` silently truncated a file due to a full disk, the stored SHA256
would differ from any expected value. For S3, computing on the source before upload is correct
because reading the uploaded file back from S3 for verification would be an expensive network
download of potentially hundreds of megabytes. boto3's `upload_file` has its own internal
integrity checking (MD5/ETag), so the risk of silent corruption is low. In both cases the SHA256
stored in the ORM represents the content as it left the worker.

---

**Q: Why is `download_reference` not stored in the ORM, and why is `object_uri` stored
instead?**

A: A presigned S3 URL is ephemeral — it expires after `s3_presign_expiry_seconds` (default 1
hour). Storing it in the database means every artifact row would contain a URL that is stale
after an hour, and the database could not be used as a source of truth for re-fetching files.
`object_uri` (`s3://bucket/key`) never expires — it is the permanent address of the object in
S3. On every API call that returns artifact data, `build_reference` generates a fresh presigned
URL from the durable `object_uri`. The ORM stores what is permanently true; the schema exposes
what is transiently useful to the client.

---

**Q: What is the difference between `Protocol` and `ABC` in Python, and why is `Protocol`
used here?**

A: `ABC` (Abstract Base Class) uses nominal subtyping: a class is a subtype only if it
explicitly inherits from the ABC and implements its abstract methods. `Protocol` uses structural
subtyping: a class is compatible if it has the right methods, regardless of inheritance. Here,
`LocalObjectStorage` and `S3ObjectStorage` share no code and have no reason to share an
inheritance tree. Using `Protocol` makes `ObjectStorage` a pure type-checker contract —
mypy validates that both classes implement all five methods without requiring them to inherit
from anything. Adding a future `AzureBlobStorage` backend only requires writing the five
methods; the Protocol and every call site are untouched.

---

**Q: How does this code work against both AWS S3 and a local MinIO container without any
conditional logic beyond the factory?**

A: boto3 treats any S3-compatible API identically — it sends standard S3 API calls (PutObject,
GetObject, HeadBucket, CreateBucket, GeneratePresignedUrl). MinIO implements the same API.
The `endpoint_url` parameter redirects boto3's requests to the MinIO container instead of
`s3.amazonaws.com`. Everything else — authentication, multipart upload, presigned URL
generation — works identically. In Docker Compose, `TLS_BACKEND_S3_ENDPOINT_URL=http://minio:9000`
is the only environment variable that distinguishes the MinIO deployment from an AWS one.

---

**Q: Why does `build_object_storage` default unrecognised `object_store_backend` values to
local storage instead of raising an error?**

A: It is a soft default for development safety: a developer who forgets to set
`TLS_BACKEND_OBJECT_STORE_BACKEND` in their environment gets a working local backend rather than
a startup crash. The downside is that a misconfigured production deployment silently falls back
to local storage instead of S3 — artifacts would be stored on the worker's ephemeral disk and
lost when the container restarts. In a hardened production system you would add an explicit
check: `raise ValueError(f"Unknown object_store_backend: {resolved.object_store_backend}")`.
The current code is appropriate for a thesis/research deployment where development ergonomics
take priority.

---

*Next: [Tutorial 25 — Queue Backends](25_backend_queue.md)*
