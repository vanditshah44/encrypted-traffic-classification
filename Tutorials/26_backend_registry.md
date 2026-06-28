# Tutorial 26 — Model Bundle Registry (`backend/registry.py`)

## Prerequisites

- Tutorial 19 (`ml/workflow.py`) — the ML training run that produces the bundle structure on
  disk. Every file and subdirectory that `registry.py` looks for was written by `workflow.py`.
- Tutorial 21 (`backend/config.py`) — `BackendSettings.model_bundle_root` (default
  `artifacts/ml_workflow/`), `default_model_bundle_dir`, and how `get_backend_settings()` is
  cached with `lru_cache`.
- Tutorial 23 (`backend/schemas.py`) — `ModelBundleResponse` is the API representation of a
  `ModelBundle`. The fields map directly; `is_default` is computed by comparing `bundle.path`
  to the resolved default.

---

## 1. Why This File Exists

After training completes (Tutorial 19), the output lands in a versioned directory under
`artifacts/ml_workflow/`. The backend needs to answer three questions at runtime:

1. Which bundles exist on this machine?
2. Which one should be used for a new scoring job if the API client didn't specify one?
3. Is a specific bundle directory valid (i.e., not missing required files)?

`registry.py` answers all three without any database involvement. The filesystem **is** the
registry — a bundle exists if and only if it has the right files in the right places. There is
no bundle catalogue to maintain, no registration step, no migration to run when a new training
run completes. Drop a new directory into `artifacts/ml_workflow/` with the right shape and it
is immediately discoverable.

---

## 2. Bundle Structure on Disk

Before reading the code, internalise what a valid bundle looks like. The `verified` bundle from
the actual artifact directory illustrates it:

```
artifacts/ml_workflow/verified/
├── feature_manifest.json          ← REQUIRED sentinel file
├── workflow_summary.json          ← optional metadata
├── dataset_split_manifest.csv     ← (not used by registry)
├── gaussian_nb/
│   └── model.joblib               ← presence of this file marks the subdirectory as a model
├── random_forest/
│   └── model.joblib
└── gradient_boosting/
    └── model.joblib
```

The registry looks for exactly two things to validate a bundle:
- `feature_manifest.json` at the bundle root — the list of feature columns the model was
  trained on. Without it the scoring pipeline cannot align incoming NFStream output to the
  model's expected input; the bundle is unusable.
- At least one subdirectory containing `model.joblib` — the trained model itself.

Everything else (CSV reports, PNG plots, threshold summaries) is produced by the training run
but not needed by the registry or the scorer.

---

## 3. `ModelBundle` (lines 12–21)

```python
@dataclass(frozen=True)
class ModelBundle:
    name: str
    path: Path
    workflow_summary_path: Path | None
    feature_manifest_path: Path
    model_names: tuple[str, ...]
    rows: int | None
    columns: int | None
```

`frozen=True` — same reason as `StoredObject` and `QueueTicket`: this is a description of what
exists on disk at a specific moment. After discovery, the bundle should not be mutated; if the
filesystem changes, re-run discovery.

`model_names: tuple[str, ...]` — a `tuple`, not a `list`. `frozen=True` makes the dataclass
hashable (Python generates `__hash__` from all fields). For a dataclass to be hashable, every
field must itself be hashable. `list` is mutable and therefore not hashable; `tuple` is
immutable and hashable. This is not a style preference — using `list` here would raise a
`TypeError` at construction time because `frozen=True` would attempt to generate a `__hash__`
method that includes a non-hashable field.

`workflow_summary_path: Path | None` — `None` when `workflow_summary.json` does not exist.
Older or manually assembled bundles may not have this file. The registry still exposes such
bundles; `ModelBundleResponse.workflow_summary_path` will be `None` in the API response.

`feature_manifest_path: Path` — not `Path | None`. This field is never `None` because
`discover_model_bundles` only creates a `ModelBundle` if the manifest exists. The type
annotation reflects the invariant: if you have a `ModelBundle`, you have a manifest.

`rows: int | None` and `columns: int | None` — training dataset dimensions read from
`workflow_summary.json`. The actual values for the `verified` bundle are `49158` rows and
`115` columns. A bundle missing `workflow_summary.json` (or with a summary that lacks these
keys) gets `None` for both. The API exposes them in `ModelBundleResponse` so the UI can show
"trained on 49,158 samples, 115 raw columns, 53 features".

---

## 4. `_read_summary` (lines 23–26)

```python
def _read_summary(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))
```

The leading `_` marks this as a module-private helper — it is not part of the public API of
this file. The `if not path.exists(): return {}` guard means every downstream `.get()` call on
the result returns `None` for a missing file, rather than raising `FileNotFoundError`. This
keeps the caller clean: `summary.get("rows")` is always safe.

`path.read_text(encoding="utf-8")` then `json.loads` — two steps rather than `json.load(open(path))`.
`read_text` closes the file handle automatically (it is equivalent to `with open(path) as f: return f.read()`).
`json.loads` takes a string rather than a file handle, which is equally fast for files of this
size (kilobytes) and avoids leaving a file descriptor open if `json.load` raises mid-parse.

---

## 5. `discover_model_bundles` (lines 29–63)

```python
def discover_model_bundles(root_dir: str | Path) -> list[ModelBundle]:
    root = Path(root_dir).expanduser().resolve()
    if not root.exists():
        return []
```

Returns `[]` for a non-existent root rather than raising. The caller
(`resolve_model_bundle_dir`) handles an empty list by raising `FileNotFoundError` with a
helpful message. Separating "nothing found" from "root doesn't exist" at this level lets
callers decide whether absence is an error or just an empty state.

```python
    for candidate in sorted(root.iterdir()):
        if not candidate.is_dir():
            continue
        feature_manifest = candidate / "feature_manifest.json"
        if not feature_manifest.exists():
            continue
```

`sorted(root.iterdir())` — `Path.iterdir()` yields directory entries in filesystem order, which
is arbitrary on most filesystems. `sorted()` applies lexicographic ordering by full path. This
matters for `resolve_model_bundle_dir`: the last element of the returned list (`bundles[-1]`)
is used as the auto-selected bundle. Sorting ensures the selection is deterministic and
consistent across runs. If bundles are named with dates (`run_2026_03_24`, `run_2026_04_01`),
lexicographic order equals chronological order, and `bundles[-1]` is always the newest.

Skipping non-directories filters out files like `model_comparison.csv` that might exist at the
root level. Skipping directories without `feature_manifest.json` filters out incomplete or
in-progress training runs — a training run that crashed before writing the manifest would
otherwise pollute the bundle list.

```python
        model_names = tuple(
            sorted(
                child.name
                for child in candidate.iterdir()
                if child.is_dir() and (child / "model.joblib").exists()
            )
        )
        if not model_names:
            continue
```

Iterates the bundle's subdirectories looking for those that contain `model.joblib`. Only
subdirectories count (`child.is_dir()`) — the root-level `feature_manifest.json` is not a
model directory. A bundle with a manifest but zero models (perhaps training was interrupted
after writing the manifest) is skipped: `if not model_names: continue`. The result is a
sorted tuple of names like `("gaussian_nb", "gradient_boosting", "random_forest")` — the
multi-tier detection layer (Tutorial 20) loads all three by name.

`tuple(sorted(...))` — `sorted()` returns a `list`; wrapping with `tuple()` satisfies the
`frozen=True` hashability requirement from Section 3.

```python
        summary_path = candidate / "workflow_summary.json"
        summary = _read_summary(summary_path)
        bundles.append(
            ModelBundle(
                name=candidate.name,
                path=candidate,
                workflow_summary_path=summary_path if summary_path.exists() else None,
                feature_manifest_path=feature_manifest,
                model_names=model_names,
                rows=int(summary["rows"]) if isinstance(summary.get("rows"), int) else None,
                columns=int(summary["columns"]) if isinstance(summary.get("columns"), int) else None,
            )
        )
```

`isinstance(summary.get("rows"), int)` — guards against three failure modes:
1. `summary` is `{}` (file missing) — `.get("rows")` returns `None`, `isinstance(None, int)` is `False`.
2. `"rows"` key missing from a partial summary — same result.
3. `"rows"` is a JSON string like `"49158"` (malformed) — `isinstance("49158", int)` is `False`.

Only an actual JSON integer passes, and `int(x)` converts it to a Python `int`. The `int(...)`
cast is defensive: JSON integers parse as Python `int`, but the cast makes the type explicit
and eliminates any doubt about whether `json.loads` might return a `float` for large integers
on some Python implementations (it doesn't, but the cast is cheap and self-documenting).

`name=candidate.name` — the bare directory name (`"verified"`, `"latest"`), not the full path.
This is the human-readable label used in API responses.

---

## 6. `resolve_model_bundle_dir` (lines 66–89)

This function implements a four-level resolution ladder. Each level is tried in order; the
first that succeeds wins.

```python
def resolve_model_bundle_dir(
    requested_dir: str | Path | None = None,
    *,
    settings: BackendSettings | None = None,
) -> Path:
    resolved_settings = settings or get_backend_settings()
```

`settings: BackendSettings | None = None` — keyword-only via `*`. The same
testability pattern from Tutorials 24 and 25: tests pass a constructed `BackendSettings`
pointing at a temp directory; production code passes nothing and gets the environment-derived
settings.

### Level 1 — Explicit request (lines 73–76)

```python
    if requested_dir:
        candidate = Path(requested_dir).expanduser().resolve()
        if not (candidate / "feature_manifest.json").exists():
            raise FileNotFoundError(f"Model bundle is missing feature_manifest.json: {candidate}")
        return candidate
```

An explicit path is validated immediately. If `feature_manifest.json` is missing, a
`FileNotFoundError` is raised — an explicit request should succeed or fail loudly. There is no
fallback to the next level; if the caller specified a bundle, using a different one silently
would be wrong. Note that `model.joblib` presence is **not** validated here: the validation only
checks the manifest. The scorer will fail later if models are missing, and that failure message
is more informative.

### Level 2 — Configured default (lines 77–78)

```python
    if resolved_settings.default_model_bundle_dir is not None:
        return resolved_settings.default_model_bundle_dir
```

`TLS_BACKEND_DEFAULT_MODEL_BUNDLE_DIR` — if an operator has pinned a specific bundle via
environment variable, use it. No validation is performed here: the settings layer already
resolved the path at startup. This is the "I know what I want" operator setting; treating it
as authoritative avoids the overhead of validating on every scoring request.

### Level 3 — `latest/` symlink convention (lines 80–82)

```python
    latest_bundle = resolved_settings.model_bundle_root / "latest"
    if (latest_bundle / "feature_manifest.json").exists():
        return latest_bundle.resolve()
```

`artifacts/ml_workflow/latest/` is a convention from `ml/workflow.py` — the training workflow
writes to a timestamped directory and also writes (or symlinks) the same output to `latest/`.
The `verified/` bundle in this project is the manually reviewed copy; `latest/` is the most
recent run. Checking `feature_manifest.json` presence first (without raising) lets this level
fail silently and fall through to level 4 if `latest/` is incomplete.

`latest_bundle.resolve()` — if `latest/` is a symlink, `resolve()` follows it and returns the
real path. Storing the real path rather than the symlink path in `ProcessingJob.model_bundle_dir`
ensures the record is stable even if the `latest/` symlink is later repointed to a different
run.

### Level 4 — Discovery fallback (lines 84–89)

```python
    bundles = discover_model_bundles(resolved_settings.model_bundle_root)
    if not bundles:
        raise FileNotFoundError(
            f"No model bundles discovered under {resolved_settings.model_bundle_root}"
        )
    return bundles[-1].path
```

Runs full discovery and selects `bundles[-1]` — the last in sorted lexicographic order, which
equals the newest if bundles are named with dates. This level is the last resort: reached only
when no explicit request, no configured default, and no valid `latest/` directory exist. The
`FileNotFoundError` at this level is a hard failure: if no bundles can be found anywhere, the
backend cannot score jobs and must not pretend otherwise.

---

## 7. What Is Deliberately Absent

**No caching of discovery results.** `discover_model_bundles` reads the filesystem on every
call. This is correct: bundles can be added or removed at runtime (a new training run
completes while the API is running). Caching would mean the API never sees new bundles without
a restart. The cost of a filesystem `iterdir()` over a small directory (typically 2–5 bundles)
is negligible compared to scoring job overhead.

**No model loading.** `ModelBundle` stores `feature_manifest_path` and the names of model
subdirectories, but never calls `joblib.load()`. Loading is deferred to the scorer and the
multi-tier detection layer, which load models once per scoring job. Loading all models at
discovery time would consume gigabytes of RAM for a large bundle set and would fail at startup
if any model file is corrupt.

**No write operations.** The registry is read-only. Creating, deleting, or renaming bundles is
done by the training workflow or manually by an operator — never by the registry itself.

---

## 8. Interview Questions and Answers

**Q: Why is `feature_manifest.json` the sentinel file for bundle validity, rather than
checking for `model.joblib` directly?**

A: The manifest is required first because it encodes the contract between the training run and
the scoring pipeline: the exact list of feature columns, in the exact order, that the model
expects. A directory with `model.joblib` but no manifest is useless — the scorer cannot know
which columns from the incoming NFStream output to select, and which to drop. The manifest is
the prerequisite; `model.joblib` is the payload. Validating the prerequisite first produces a
clearer error at the point of discovery rather than a cryptic column-mismatch error during
scoring.

---

**Q: Why is `model_names` a `tuple` instead of a `list`?**

A: `ModelBundle` is a `frozen=True` dataclass, which means Python generates a `__hash__`
method from all fields. For `__hash__` to work, every field must be hashable. `list` is
mutable and not hashable; `tuple` is immutable and hashable. Using `list` would raise
`TypeError` at construction time. This is not a style preference — it is a type-system
requirement imposed by `frozen=True`.

---

**Q: Why does Level 1 of `resolve_model_bundle_dir` raise `FileNotFoundError` for an invalid
explicit path, but Level 3 silently falls through to Level 4 when `latest/` is incomplete?**

A: An explicit request represents a conscious choice by the caller — they specified a directory
and expect it to work. Falling back silently to a different bundle would violate the caller's
intent and could score against the wrong model without any signal. Level 3 (`latest/`) is an
automatic convention, not an explicit choice: if `latest/` is incomplete (perhaps a training
run is still in progress), the correct behaviour is to keep looking, not to fail the entire
scoring request. The asymmetry in error handling reflects the asymmetry in intent.

---

**Q: The discovery function returns bundles sorted lexicographically and `resolve_model_bundle_dir`
picks `bundles[-1]`. What naming convention makes this correct?**

A: Bundle directories are named with a leading date component by `ml/workflow.py`:
`run_2026_03_24_verified`, `run_2026_04_01`, etc. ISO 8601 date strings (`YYYY_MM_DD`) are
designed so that lexicographic order equals chronological order — `"2026_04_01" > "2026_03_24"`
lexicographically. So `sorted()` on directory names produces the oldest-to-newest ordering,
and `[-1]` selects the newest. If bundles were named without dates (e.g., `experiment_a`,
`experiment_b`), this heuristic would still sort deterministically but `[-1]` would have no
chronological meaning. The convention is on the training workflow to use dated names, not on
the registry to enforce it.

---

*Next: [Tutorial 27 — Services Layer](27_backend_services.md)*
