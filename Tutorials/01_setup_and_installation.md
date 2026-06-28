# Tutorial 01 — Setup & Installation

**Primary files:**
- `pyproject.toml`
- `requirements.lock`
- `src/tls_dataset/__init__.py`
- `src/tls_dataset/__main__.py`
- `.gitignore`
- `.dockerignore`
- `Dockerfile` *(partial — full Docker coverage is Tutorial 53)*

**Prerequisite:** Tutorial 00 (Project Overview)

---

## 1. The Big Picture Before Reading Any File

Python projects need four things to work properly:

1. **A package declaration** — tells Python "this directory is a package with this name
   and these dependencies"
2. **A locked dependency list** — pins every library to an exact version so the project
   runs identically on every machine
3. **An isolated environment** — a virtual environment so your project's libraries don't
   clash with system Python libraries
4. **An entry point** — a command the shell can call without writing `python src/...`
   every time

`pyproject.toml` handles 1 and 4.
`requirements.lock` handles 2.
`.venv/` (created by you) handles 3.
`__init__.py` and `__main__.py` are the Python-internal glue for the package.

---

## 2. `pyproject.toml` — Line by Line

`pyproject.toml` is the modern standard for Python project metadata (PEP 517/518/621).
It replaced the older `setup.py` and `setup.cfg` approach. Every major Python tool —
pip, mypy, ruff, pytest — reads this file.

```toml
[build-system]
requires = ["setuptools>=69", "wheel"]
build-backend = "setuptools.build_meta"
```

**What this means:**

- `[build-system]` tells pip *how to build* the package when you run `pip install -e .`
- `requires` = the build tools pip must install first before it can build the project.
  `setuptools>=69` is the modern package builder. `wheel` creates the `.whl` distribution
  format.
- `build-backend = "setuptools.build_meta"` names the Python object pip calls to start
  the build. `setuptools.build_meta` is setuptools' standard build backend.

> **Why does this exist?** Before PEP 518, `setup.py` was just a Python script that ran
> at install time — you never knew what it would import or what it depended on. The
> `[build-system]` table lets pip install the right build tools *before* even running
> the build, in an isolated environment. Reproducible and safe.

---

```toml
[project]
name = "tls-dataset"
version = "0.1.0"
description = "Privacy-preserving encrypted traffic analytics platform for TLS 1.3 and QUIC."
readme = "README.md"
requires-python = ">=3.12"
license = { text = "Proprietary" }
authors = [
  { name = "Vandit Shah" }
]
```

**Field by field:**

| Field | Value | Why it matters |
|-------|-------|----------------|
| `name` | `tls-dataset` | The package name on pip. Note the hyphen — pip normalises `tls-dataset`, `tls_dataset`, `TLS_Dataset` to the same package. |
| `version` | `0.1.0` | Semantic version. 0.x.x means pre-release / not yet stable. Also set in `__init__.py` as `__version__` — they must stay in sync. |
| `description` | one-liner | Shows up in `pip show tls-dataset` |
| `readme` | `README.md` | PyPI (if published) uses this as the long description |
| `requires-python` | `>=3.12` | pip will refuse to install on Python < 3.12. The project uses modern Python 3.12 syntax — `type X = Y` type aliases, `match` statements work properly, `tomllib` built-in, etc. |
| `license` | `Proprietary` | Not open source. Cannot be redistributed. |
| `authors` | Vandit Shah | For attribution |

---

```toml
dependencies = [
  "boto3>=1.35,<2",
  "beautifulsoup4>=4.12,<5",
  "fastapi>=0.115,<1",
  "matplotlib>=3.9,<4",
  "nfstream>=6.5,<7",
  "numpy>=2.1,<3",
  "pandas>=2.2,<3",
  "psycopg[binary]>=3.2,<4",
  "python-multipart>=0.0.18,<1",
  "PyYAML>=6.0,<7",
  "redis>=5.2,<6",
  "requests>=2.32,<3",
  "rq>=1.16,<2",
  "scapy>=2.5,<3",
  "scikit-learn>=1.5,<2",
  "SQLAlchemy>=2.0,<3",
  "uvicorn>=0.32,<1",
]
```

These are **minimum/maximum version constraints** — not pinned exact versions.
The exact pinned versions live in `requirements.lock` (covered in Section 3).

**Why use `>=X,<Y` (compatible range) in `pyproject.toml` but pin exactly in
`requirements.lock`?**

`pyproject.toml` declares what versions the project *can* work with — a range.
`requirements.lock` declares what versions the project *will* use right now — exact.
The range in `pyproject.toml` ensures the project remains installable in the future
when newer patch versions come out. The lock file ensures every developer and every
CI run uses the exact same bytes.

**Every dependency explained:**

| Package | Version | What it does in this project |
|---------|---------|------------------------------|
| `boto3` | >=1.35 | AWS SDK for Python. Used in `backend/storage.py` to upload/download artifacts to S3 or MinIO (S3-compatible) |
| `beautifulsoup4` | >=4.12 | HTML parser. Used optionally for scraping/parsing dataset manifest pages |
| `fastapi` | >=0.115 | The HTTP API framework. Every `/api/v1/...` route in `backend/app.py` is a FastAPI route |
| `matplotlib` | >=3.9 | Plotting library. Generates ROC curves, PR curves, confusion matrices in `ml/workflow.py` |
| `nfstream` | >=6.5 | The flow statistics extractor. `pipeline/nfstream.py` wraps it |
| `numpy` | >=2.1 | Numerical arrays. Used by pandas and scikit-learn internally; also directly for array operations |
| `pandas` | >=2.2 | DataFrames. Almost every pipeline module uses pandas to read, transform, and write CSVs |
| `psycopg[binary]` | >=3.2 | PostgreSQL database adapter. `[binary]` means it uses a compiled C extension for speed. Used in `backend/db.py` |
| `python-multipart` | >=0.0.18 | Required by FastAPI to handle file uploads (multipart/form-data). Without this, `POST /api/v1/jobs` with a PCAP file would fail |
| `PyYAML` | >=6.0 | YAML parser. Reads all `.yaml` config files in `configs/` |
| `redis` | >=5.2 | Redis client. Used in `backend/queue.py` to connect to Redis for the RQ job queue |
| `requests` | >=2.32 | HTTP client. Used for downloading datasets or checking URLs |
| `rq` | >=1.16 | Redis Queue — the job queue library. `backend/worker.py` is an RQ worker |
| `scapy` | >=2.5 | Packet manipulation library. Used in `pipeline/pcap.py` to merge PCAPs with `RawPcapReader`/`PcapWriter` |
| `scikit-learn` | >=1.5 | Machine learning. GaussianNB, RandomForestClassifier, GradientBoostingClassifier, train_test_split, cross_val_score, metrics — all from sklearn |
| `SQLAlchemy` | >=2.0 | ORM. `backend/models.py` defines database tables as Python classes. `backend/db.py` creates the engine |
| `uvicorn` | >=0.32 | ASGI server. Runs the FastAPI app: `uvicorn tls_dataset.backend.app:app` |

---

```toml
[project.optional-dependencies]
dev = [
  "httpx>=0.28,<1",
  "mypy>=1.11,<2",
  "pytest>=8.3,<9",
  "ruff>=0.8,<1",
]
```

These are **development-only** dependencies. Not needed to run the pipeline or the
backend — only needed when writing or testing code.

| Package | What it does |
|---------|-------------|
| `httpx` | Async HTTP client. Used by FastAPI's test client in `tests/test_backend_platform.py`. FastAPI's `TestClient` needs httpx under the hood |
| `mypy` | Static type checker. Reads all type annotations in the source and flags type errors before runtime |
| `pytest` | Test runner. Discovers and runs all files in `tests/` |
| `ruff` | Fast linter and formatter. Checks code style, unused imports, variable naming, line length (set to 100 chars) |

**Install dev dependencies with:**
```bash
pip install -e ".[dev]"
```

The `[dev]` syntax tells pip to install the `dev` group from `optional-dependencies`
*in addition to* the base `dependencies`.

---

```toml
[project.scripts]
tls-dataset = "tls_dataset.cli:main"
```

**This is the most important line for the CLI.** It tells pip:

> "When I install this package, create a shell script called `tls-dataset` that calls
> the `main` function from the `tls_dataset.cli` module."

After `pip install -e .`, you can type:
```bash
tls-dataset info
```

And pip has already created a script at `.venv/bin/tls-dataset` that contains roughly:
```python
#!/path/to/.venv/bin/python
from tls_dataset.cli import main
main()
```

The format is `command-name = "package.module:callable"`. The colon separates the
module path from the function name. You could have multiple scripts here:
```toml
[project.scripts]
tls-dataset = "tls_dataset.cli:main"
tls-worker = "tls_dataset.backend.worker:main"
```

---

```toml
[tool.setuptools]
package-dir = {"" = "src"}

[tool.setuptools.packages.find]
where = ["src"]
```

**Why does this exist?** The Python package lives at `src/tls_dataset/`, not at
`tls_dataset/` in the project root. This is called the **`src` layout** — a deliberate
pattern that prevents accidentally importing the package from the project root without
installing it first.

- `package-dir = {"" = "src"}` — the empty string `""` means "the root namespace".
  Map it to the `src/` directory. So `import tls_dataset` looks inside `src/`.
- `packages.find where = ["src"]` — tells setuptools to scan the `src/` directory
  to discover packages (directories with `__init__.py`).

**Why the `src` layout?** When Python is looking for a module to import, it searches
`sys.path` in order. If your project root is in `sys.path` and you have a `tls_dataset/`
folder there, Python might import it *without the package being installed*, giving you
the raw source instead of the installed version. The `src/` layout puts the package
one level down, so this only works after proper installation. This is why the README
shows `PYTHONPATH=src` — it explicitly adds `src/` to Python's search path for
development runs.

---

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

- `testpaths = ["tests"]` — when you run `pytest`, it only looks in the `tests/`
  directory. Without this it would scan the entire project, including `src/`, which
  is slow and can cause import confusion.
- `pythonpath = ["src"]` — pytest automatically adds `src/` to `sys.path` before
  running any test. This means you can write `from tls_dataset.pipeline.common import ...`
  in a test file without setting `PYTHONPATH` manually.

---

```toml
[tool.ruff]
line-length = 100
target-version = "py312"
```

- `line-length = 100` — lines over 100 characters trigger a linting warning. The default
  PEP 8 is 79 characters, but 100 is a common modern choice for wider monitors.
- `target-version = "py312"` — ruff uses this to know which Python syntax is valid.
  It won't flag Python 3.12-only syntax as an error.

---

```toml
[tool.mypy]
python_version = "3.12"
packages = ["tls_dataset"]
warn_unused_configs = true
disallow_untyped_defs = true
```

- `python_version = "3.12"` — mypy assumes Python 3.12 semantics when checking types.
- `packages = ["tls_dataset"]` — mypy checks the whole `tls_dataset` package (not
  just individual files you pass on the command line).
- `warn_unused_configs = true` — mypy warns if you have per-file mypy settings that
  no file matches (catches typos in config).
- `disallow_untyped_defs = true` — **every function must have type annotations**. If
  you write `def foo(x):` instead of `def foo(x: str) -> None:`, mypy raises an error.
  This is what makes the codebase type-safe.

---

## 3. `requirements.lock` — Line by Line

```
# Runtime dependencies
boto3==1.35.66
beautifulsoup4==4.12.3
fastapi==0.115.5
matplotlib==3.9.2
nfstream==6.5.4
numpy==2.1.3
pandas==2.2.3
psycopg[binary]==3.2.3
python-multipart==0.0.19
PyYAML==6.0.2
redis==5.2.0
requests==2.32.3
rq==1.16.2
scapy==2.5.0
scikit-learn==1.5.2
SQLAlchemy==2.0.36
uvicorn==0.32.1

# Development dependencies
httpx==0.28.1
mypy==1.13.0
pytest==8.3.3
ruff==0.8.1
```

**Key difference from `pyproject.toml`:**

`pyproject.toml` says `pandas>=2.2,<3` — any 2.x version from 2.2 onwards.
`requirements.lock` says `pandas==2.2.3` — exactly this version, no flexibility.

**Why pin exact versions?**

- **Reproducibility:** If a new pandas 2.2.4 comes out with a subtle behaviour change,
  everyone using `requirements.lock` is still on 2.2.3. Without the lock file, running
  `pip install` today vs next month could give you different library versions.
- **Trust:** You know exactly what code is running. Security audits are easier.
- **CI stability:** The CI pipeline doesn't silently pick up a new version that breaks
  your tests.

**Why is `requirements.lock` NOT auto-generated here?**

Proper lock files are generated by tools like `pip-tools` (`pip-compile`), `poetry`, or
`pdm`. In this project the lock file is manually curated — you can see it's a simple
flat list without dependency hashes. In production you'd want `pip-compile` to generate
a lock with SHA256 hashes for every package.

**How to install from the lock file:**
```bash
pip install -r requirements.lock
```

**Notice what's NOT in the lock file:**

The lock file only lists *direct* dependencies — the packages you explicitly use.
It does NOT list transitive dependencies (what boto3 depends on, what pandas depends on,
etc.). A fully locked environment would include those too. This is a known limitation of
the current approach.

---

## 4. Virtual Environments — Why and How

A **virtual environment** is an isolated Python installation. When you activate it,
`python` and `pip` point to that isolated install, not your system Python.

**Why isolate?**

Your system might have `scikit-learn==1.3` installed globally (for another project).
This project needs `scikit-learn>=1.5`. Without a virtual environment, installing
`scikit-learn==1.5.2` for this project would break the other project. With a venv,
each project has its own private copies of every library.

**The exact steps from the README:**

```bash
# Step 1: Create the virtual environment
python3 -m venv .venv
```

This creates a `.venv/` directory in the project root. Inside it:
```
.venv/
├── bin/
│   ├── python3       ← a copy/symlink of python3
│   ├── pip           ← pip for this venv only
│   └── tls-dataset   ← will appear after pip install -e .
├── lib/
│   └── python3.12/
│       └── site-packages/   ← all installed packages land here
└── pyvenv.cfg        ← records which system Python this venv was built from
```

```bash
# Step 2: Activate the virtual environment
. .venv/bin/activate         # bash/zsh
# OR
source .venv/bin/activate    # same thing, longer form
```

After activation, your shell prompt shows `(.venv)` and:
- `python` points to `.venv/bin/python`
- `pip` points to `.venv/bin/pip`
- `tls-dataset` (after install) points to `.venv/bin/tls-dataset`

The `.gitignore` correctly excludes `.venv/`:
```gitignore
.venv/
venv/
```

```bash
# Step 3: Install pinned dependencies
.venv/bin/pip install -r requirements.lock
```

Note: the README uses `.venv/bin/pip` directly (not `pip` after activation). Both work —
using the full path is explicit and avoids any shell confusion.

```bash
# Step 4: Install the project itself in editable mode
.venv/bin/pip install -e .
```

This is the critical step explained in the next section.

---

## 5. Editable Install (`pip install -e .`) — What It Actually Does

The `-e` flag means **editable** (also called **development mode** or a **`dev install`**).

**Without `-e`** (normal install):
```bash
pip install .
```
pip copies `src/tls_dataset/` into `.venv/lib/python3.12/site-packages/tls_dataset/`.
When you edit `src/tls_dataset/pipeline/quality.py`, Python still runs the *copied*
version. You must reinstall every time you change the code.

**With `-e`** (editable install):
```bash
pip install -e .
```
pip does NOT copy the source. Instead, it creates a special pointer file:
```
.venv/lib/python3.12/site-packages/tls-dataset.egg-link
```
or (in modern setuptools):
```
.venv/lib/python3.12/site-packages/__editable__.tls_dataset-0.1.0.pth
```

This `.pth` file contains the path to `src/`. Python reads `.pth` files at startup and
adds them to `sys.path`. So `import tls_dataset` resolves directly to
`/path/to/project/src/tls_dataset/`. When you edit a source file, the change is
**instantly visible** without reinstalling.

It also creates the `tls-dataset` script at `.venv/bin/tls-dataset` (the CLI entry
point defined in `[project.scripts]`).

**Verify the install worked:**
```bash
PYTHONPATH=src .venv/bin/python -m tls_dataset info
```

Expected output:
```
tls-dataset v0.1.0
project_root=/home/vandit/Desktop/Projects/tls_dataset
status=repository scaffold initialized
production_extractors=zeek,nfstream
thesis_legacy_extractors=cicflowmeter
next_phase=dependency installation and data-quality validation
```

---

## 6. `PYTHONPATH=src` — Why It's Needed

You will see this prefix repeatedly in the README:

```bash
PYTHONPATH=src python -m tls_dataset info
PYTHONPATH=src python -m unittest discover -s tests
```

**What `PYTHONPATH` does:**

`PYTHONPATH` is an environment variable that adds directories to `sys.path` — the
list of places Python searches for modules to import. Setting `PYTHONPATH=src` means
Python looks in the `src/` directory when resolving `import tls_dataset`.

**When is it needed and when is it not?**

| Scenario | PYTHONPATH needed? | Why |
|----------|-------------------|-----|
| After `pip install -e .` in an active venv | No | The `.pth` file already adds `src/` to `sys.path` automatically |
| Running python directly without venv activated | Yes | Nothing has added `src/` to `sys.path` |
| Running tests with pytest (after `pip install -e .`) | No | pytest reads `pythonpath = ["src"]` from `pyproject.toml` |
| Docker container after `pip install -e .` | No | Same as venv — `.pth` file handles it |

The README uses `PYTHONPATH=src` as a belt-and-suspenders approach — it works
regardless of whether you have the venv activated or the package installed.

---

## 7. `src/tls_dataset/__init__.py` — The Package Declaration

```python
"""Core package for the TLS dataset platform."""

__all__ = ["__version__"]

__version__ = "0.1.0"
```

This is the **package initialisation file**. Its existence is what makes
`src/tls_dataset/` a Python package (importable as `import tls_dataset`).

**Line by line:**

- `"""Core package..."""` — module docstring. Shows up in `help(tls_dataset)` and
  `pydoc tls_dataset`. Tools like mypy and IDEs use it for documentation.
- `__all__ = ["__version__"]` — controls what `from tls_dataset import *` exports.
  Without `__all__`, a star import would pull in everything. With it, only `__version__`
  is exported. It is a contract: "these are the public symbols from this package."
- `__version__ = "0.1.0"` — the version string. Accessible anywhere via
  `from tls_dataset import __version__`. Used in `cli.py` in the `info` command:
  ```python
  from tls_dataset import __version__
  print(f"tls-dataset v{__version__}")
  ```

**Convention:** `__version__` in `__init__.py` must stay in sync with `version` in
`pyproject.toml`. In a real CI/CD pipeline you'd automate this — e.g., a `release.py`
script that reads from `pyproject.toml` and writes to `__init__.py`.

---

## 8. `src/tls_dataset/__main__.py` — The Module Entry Point

```python
from tls_dataset.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

This tiny file enables running the package as a module:
```bash
python -m tls_dataset info
```

**How `python -m` works:**

When Python sees `-m package_name`, it:
1. Finds the `package_name` package in `sys.path`
2. Looks for `package_name/__main__.py` inside it
3. Executes that file with `__name__ == "__main__"`

Without `__main__.py`, `python -m tls_dataset` would fail with:
```
/path/to/python: No module named tls_dataset.__main__; 'tls_dataset' is a package and cannot be directly executed
```

**Why `raise SystemExit(main())`?**

`main()` returns an integer exit code (0 for success, non-zero for failure). `SystemExit`
passes that code to the operating system. This is how shell scripts and CI pipelines
detect whether a command succeeded:
```bash
tls-dataset run-ml-workflow --config configs/ml_workflow.yaml
echo $?   # 0 = success, 1 or 2 = failure
```

If `main()` raised an exception instead of returning a code, the shell would just see a
traceback — it couldn't programmatically check success.

---

## 9. The Two Ways to Call the CLI — and How They Connect

```bash
# Way 1: via the installed script
tls-dataset info

# Way 2: via python -m
PYTHONPATH=src python -m tls_dataset info
```

Both ultimately call the same function: `tls_dataset.cli.main()`.

Trace:
```
tls-dataset info
    ↓
.venv/bin/tls-dataset   (generated by pip from [project.scripts])
    ↓ calls
tls_dataset.cli:main()
    ↓
build_parser() → parse "info" → handle_info()
    ↓
prints version, project_root, production_extractors, etc.

python -m tls_dataset info
    ↓
src/tls_dataset/__main__.py
    ↓ calls
tls_dataset.cli:main()  ← same function
    ↓
identical execution
```

---

## 10. `.gitignore` — What Is Excluded From Version Control

```gitignore
# Python
__pycache__/
*.py[cod]
*.so
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/
.venv/
venv/
```

- `__pycache__/` — Python's compiled bytecode cache. Generated automatically when you
  run Python. Not portable (machine-specific) and always regeneratable.
- `*.py[cod]` — `.pyc` (compiled), `.pyo` (optimised), `.pyd` (Windows DLL) files.
  Same reason as above.
- `*.so` — compiled C extension files. Machine-specific.
- `.pytest_cache/` — pytest's caching directory for test result history.
- `.mypy_cache/` — mypy's incremental type-check cache.
- `.ruff_cache/` — ruff's lint result cache.
- `.coverage` — pytest-cov's coverage data file.
- `.venv/` — the virtual environment. Each developer creates their own locally.

```gitignore
# Build outputs
build/
dist/
*.egg-info/
```

- `build/` and `dist/` — generated when you run `python -m build` to create a
  distributable package. Not version-controlled.
- `*.egg-info/` — setuptools metadata directory created during installation.

```gitignore
# Local artifacts and future data directories
data/
showcase/
artifacts/**
!artifacts/**/
!artifacts/**/.gitkeep
!artifacts/README.md
```

**This is the trickiest part of the gitignore:**

- `artifacts/**` — ignore everything inside `artifacts/`
- `!artifacts/**/` — except: keep all subdirectories (the `**` glob matches directories too)
- `!artifacts/**/.gitkeep` — except: keep `.gitkeep` files (empty marker files that
  make Git track otherwise-empty directories)
- `!artifacts/README.md` — except: keep the README

**Why?** The `artifacts/` directory contains generated outputs — CSVs, trained models,
metrics JSON, plots. These can be gigabytes in size and should not live in Git. But you
want the *directory structure* to exist in the repo so a fresh clone has the right
folder skeleton ready to receive outputs.

```gitignore
# Thesis-era generated assets
BotnetCapture/
benign_filtered.pcap
benign_process_csv/
freezeData/
zeek-out-benign/
*.pcap
*.pcapng
*.cap
```

All PCAP files and thesis-era directories are excluded. PCAPs are often gigabytes. They
also contain real network traffic that may be sensitive.

---

## 11. `.dockerignore` — What Is Excluded From the Docker Build Context

```
.git
.gitignore
.venv
__pycache__
.pytest_cache
.mypy_cache
.ruff_cache
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

When you run `docker build .`, Docker sends everything in the project directory to the
Docker daemon as a "build context." The `.dockerignore` file tells Docker which files
to skip.

**Key exclusions:**
- `.venv` — the container builds its own Python environment from scratch using
  `requirements.lock`; your local venv is irrelevant and could conflict
- `artifacts/` — generated outputs, often gigabytes; the container produces its own
- `*.pcap` — large data files; passed in at runtime if needed
- `.git` — the git history is not needed at runtime; including it would bloat the image

---

## 12. `Dockerfile` — The Container Build for the Backend

```dockerfile
FROM python:3.12-slim
```

- Uses the official Python 3.12 slim image (Debian-based, stripped of non-essentials)
- `slim` saves ~200MB compared to the full image by removing compilers, documentation,
  and package manager caches

```dockerfile
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive
```

| Variable | Effect |
|----------|--------|
| `PYTHONDONTWRITEBYTECODE=1` | Don't write `.pyc` bytecode files (saves disk space in a container) |
| `PYTHONUNBUFFERED=1` | Don't buffer stdout/stderr — logs appear immediately in `docker logs` |
| `PIP_NO_CACHE_DIR=1` | Don't cache pip downloads (saves disk space in the image layer) |
| `DEBIAN_FRONTEND=noninteractive` | Prevents apt-get from asking interactive questions during package installs |

```dockerfile
WORKDIR /app
```

Sets the working directory inside the container to `/app`. All subsequent `COPY`, `RUN`,
and `CMD` instructions are relative to this path.

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpcap-dev \
    tshark \
    && rm -rf /var/lib/apt/lists/*
```

Installs system packages needed by the Python libraries:

| Package | Why needed |
|---------|-----------|
| `build-essential` | C compiler and make tools (needed to compile C extensions in nfstream, scapy, psycopg) |
| `gcc` | The C compiler itself |
| `libpcap-dev` | C library for reading PCAPs — required by nfstream and scapy at compile time |
| `tshark` | Wireshark's command-line tool — used by `pipeline/filtering.py` to apply display filters |

`rm -rf /var/lib/apt/lists/*` deletes the apt package index cache after installation.
This shrinks the Docker image layer because those lists are not needed at runtime.

```dockerfile
COPY requirements.lock pyproject.toml README.md ./
RUN python -m pip install --upgrade pip && python -m pip install -r requirements.lock
```

**Why copy only these three files first, before copying the full source?**

Docker builds images in layers. If you copy everything first and then run pip install,
Docker must re-run pip install every time ANY source file changes — even a one-line
edit to a `.py` file. By copying only the dependency files first, Docker caches the
pip install layer. The slow step (downloading and installing all packages) is only
re-run when `requirements.lock` or `pyproject.toml` changes, not when source changes.

```dockerfile
COPY . .
RUN python -m pip install -e .
```

Now copy the entire source (minus `.dockerignore` exclusions) and install the package
in editable mode. The editable install creates the `tls-dataset` CLI script inside
the container.

```dockerfile
CMD ["python", "-m", "tls_dataset", "info"]
```

The default command when the container starts with no arguments. It just prints the
info output — a sanity check that the package is properly installed. In production,
Docker Compose overrides this with the actual service command (see `docker-compose.yaml`).

---

## 13. The Full Install Sequence Explained Step by Step

Here is the exact sequence from the README with every step explained:

```bash
# 1. Create virtual environment
python3 -m venv .venv
```
Creates `.venv/` directory. Uses Python 3.12 (or whatever `python3` points to on your
system — must be >=3.12).

```bash
# 2. Activate it (bash/zsh)
. .venv/bin/activate
# prompt changes to: (.venv) $
```

```bash
# 3. Install all pinned runtime + dev dependencies
.venv/bin/pip install -r requirements.lock
```
Downloads and installs 21 packages with exact versions.

```bash
# 4. Install the project package (editable mode)
.venv/bin/pip install -e .
```
Reads `pyproject.toml`, creates the `tls-dataset` CLI script, links `src/` into
`sys.path` via a `.pth` file.

```bash
# 5. Verify
PYTHONPATH=src .venv/bin/python -m tls_dataset info
```
Should print:
```
tls-dataset v0.1.0
project_root=/home/vandit/Desktop/Projects/tls_dataset
status=repository scaffold initialized
production_extractors=zeek,nfstream
thesis_legacy_extractors=cicflowmeter
next_phase=dependency installation and data-quality validation
```

```bash
# 6. Run tests
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests
# OR (pytest knows pythonpath from pyproject.toml)
.venv/bin/pytest
```

---

## 14. Summary Diagram — How All Setup Files Connect

```
pyproject.toml
│
├── [build-system]           → tells pip HOW to build the package
│   └── setuptools + wheel
│
├── [project]
│   ├── name, version        → package identity
│   ├── requires-python      → enforces Python 3.12+
│   ├── dependencies         → version RANGES (what CAN work)
│   └── optional-dependencies.dev → dev tools (pytest, mypy, ruff, httpx)
│
├── [project.scripts]
│   └── tls-dataset → tls_dataset.cli:main   → creates the CLI command
│
├── [tool.setuptools]
│   └── package-dir src/     → package lives in src/, not root
│
├── [tool.pytest.ini_options]
│   └── pythonpath = ["src"] → pytest auto-adds src/ to sys.path
│
├── [tool.ruff]
│   └── line-length = 100, target-version = py312
│
└── [tool.mypy]
    └── disallow_untyped_defs = true → all functions must be typed

requirements.lock
└── exact versions (==) for every runtime + dev package

src/tls_dataset/__init__.py
└── __version__ = "0.1.0"   → readable by code + CLI info command

src/tls_dataset/__main__.py
└── enables: python -m tls_dataset <command>

.venv/ (created by you, gitignored)
└── isolated Python + all packages + tls-dataset script
```

---

## 15. Interview Questions & Answers for Tutorial 01

**Q: What is the difference between `pyproject.toml` and `requirements.lock`?**
> `pyproject.toml` declares version *ranges* for dependencies — what the project is
> compatible with. `requirements.lock` pins every dependency to an *exact* version.
> The range in `pyproject.toml` keeps the project installable as libraries update.
> The lock file ensures every developer and CI run uses identical library versions,
> giving reproducible behaviour.

**Q: What does `pip install -e .` do and why use it?**
> `-e` is editable mode. Instead of copying source files into `site-packages`, pip
> creates a `.pth` pointer file that makes Python resolve `import tls_dataset` directly
> from `src/tls_dataset/` in the project directory. Any edit to a source file is
> instantly reflected without reinstalling. It also creates the `tls-dataset` CLI
> script.

**Q: Why is the package in a `src/` subdirectory instead of the project root?**
> The `src` layout prevents accidentally importing an uninstalled version of the package.
> If `tls_dataset/` were at the project root, Python would find it in `sys.path` without
> installation — you'd be running the raw source rather than the installed package, which
> can cause subtle import path bugs. The `src/` layout forces you to install first.

**Q: What is `PYTHONPATH=src` and when is it needed?**
> `PYTHONPATH` adds directories to Python's module search path at runtime.
> `PYTHONPATH=src` tells Python to look in the `src/` directory for packages.
> It's needed when running Python directly without an activated venv or without the
> package installed via `pip install -e .`. After a proper editable install, the `.pth`
> file handles this automatically.

**Q: What does `[project.scripts]` in `pyproject.toml` do?**
> It tells pip to create a shell script named `tls-dataset` in the venv's `bin/`
> directory. That script imports and calls `tls_dataset.cli.main`. This is how the
> `tls-dataset info` command works — it's a generated script, not a standalone executable.

**Q: Why does `__main__.py` exist alongside the CLI entry point?**
> `__main__.py` enables running the package with `python -m tls_dataset`. Python looks
> for `__main__.py` in the package when you use `-m`. It calls the same `main()`
> function as the CLI script, so both invocation methods are identical in behaviour.
> The `-m` form works without installing the CLI script — useful for development and
> Docker contexts.

**Q: What does `disallow_untyped_defs = true` in mypy config enforce?**
> Every function in the `tls_dataset` package must have full type annotations — both
> parameter types and return type. If any function is missing them, mypy raises an error.
> This catches type mismatches at check time rather than at runtime, making the codebase
> more reliable and self-documenting.

**Q: Why does the Dockerfile copy `requirements.lock` before copying source code?**
> Docker builds images in layers, and layers are cached by their inputs. If you copy
> source first and then run pip install, any single-line change to any source file
> invalidates the pip cache and forces a full reinstall. Copying only the requirements
> file first means the slow pip install layer is cached and only re-run when the
> requirements actually change — which is far less frequent than source edits.

**Q: What system packages does the Dockerfile install and why?**
> `build-essential` and `gcc` for compiling C extensions (nfstream, psycopg, scapy
> all have C components). `libpcap-dev` is the C library for reading PCAP files —
> required by nfstream and scapy at compile time. `tshark` is Wireshark's command-line
> packet analyser — used by the pipeline's filtering step to apply TLS/QUIC display
> filters.

---

*Previous: [00_project_overview.md](00_project_overview.md)*
*Next: [02_configuration_system.md](02_configuration_system.md)*
