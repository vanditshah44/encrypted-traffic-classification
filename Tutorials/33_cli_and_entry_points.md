# Tutorial 33 — CLI and Package Entry Points (`cli.py`, `__main__.py`, `technical_direction.py`, `__init__.py`)

## Prerequisites

Every tutorial from 04 through 32. `cli.py` is the public surface of the entire platform — each
subcommand is a one-line bridge into one of the workflows already studied. Understanding this
tutorial requires knowing what each handler delegates to.

---

## 1. Why These Files Exist Together

Four files define how the outside world invokes the package:

| File | Role |
|---|---|
| `technical_direction.py` | Architecture decision record — what extractors are canonical and why |
| `__init__.py` | Package version — single source of truth for `__version__` |
| `cli.py` | Unified command-line interface — seven subcommands, one binary |
| `__main__.py` | Module invocation — makes `python -m tls_dataset` work |

None of these files contain pipeline logic. They are the *shell* around all the logic covered
in tutorials 04–32: they parse user input, call the right function, and print the result. The
reason they are worth a full tutorial is that the decisions made here — lazy imports, subcommand
design, output format, entry point registration — directly affect the usability of the platform
for a thesis defense, a CI pipeline, or a production deployment.

---

## 2. `technical_direction.py` — Architecture Decision as Code (lines 1–22)

```python
@dataclass(frozen=True)
class TechnicalDirection:
    production_extractors: tuple[str, ...]
    thesis_legacy_extractors: tuple[str, ...]
    decision_summary: str

TECHNICAL_DIRECTION = TechnicalDirection(
    production_extractors=("zeek", "nfstream"),
    thesis_legacy_extractors=("cicflowmeter",),
    decision_summary="Zeek + NFStream is the official production extraction stack. ...",
)
```

This is a frozen dataclass used as an **architecture decision record (ADR)**. The content itself
is not new information — tutorials 05 and 07 explained why Zeek and NFStream were chosen over
CICFlowMeter. What is new here is the mechanism: the decision is stored as importable Python,
not as a comment or a README.

**Why a frozen dataclass?**

1. **Machine-readable**: `cli.py`'s `handle_info()` calls
   `",".join(TECHNICAL_DIRECTION.production_extractors)` and prints it. A README note cannot be
   queried programmatically; a frozen dataclass can be imported by tests, printed by CLI
   commands, and serialised to JSON.
2. **Immutable at runtime**: `frozen=True` prevents any code path from accidentally overwriting
   the decision. If `TECHNICAL_DIRECTION.production_extractors = ("cicflowmeter",)` appeared
   somewhere, Python would raise `FrozenInstanceError` immediately.
3. **Version-controlled diff signal**: If the architecture changes, the `git diff` on this file
   is unambiguous — one place, one change, reviewable without reading prose.

**Why `tuple[str, ...]` and not `list[str]`?**

Lists are mutable. A tuple is frozen by value even when the dataclass is not annotated
`frozen=True`. Here the frozen dataclass and the tuple type reinforce each other: neither the
container nor its contents can be modified after construction.

---

## 3. `__init__.py` — Package Version (5 lines)

```python
__all__ = ["__version__"]
__version__ = "0.1.0"
```

`__version__` is the single source of truth for the package version inside the Python runtime.
`pyproject.toml` also declares `version = "0.1.0"` — currently these are kept in sync manually.

A more mature approach uses `importlib.metadata.version("tls-dataset")` to read from the
installed package metadata, avoiding duplication:

```python
from importlib.metadata import version, PackageNotFoundError
try:
    __version__ = version("tls-dataset")
except PackageNotFoundError:
    __version__ = "0.0.0.dev"
```

The current approach works because this is a thesis project that is always run from a `pip
install -e .` environment where the version is fixed. The `PackageNotFoundError` fallback would
be needed if the package were importable without being installed (e.g., by adding `src/` to
`PYTHONPATH` directly) — in that case `importlib.metadata` would fail.

`__all__ = ["__version__"]` means `from tls_dataset import *` only exposes `__version__`.
This matters for IDEs and documentation generators that use `__all__` to determine the public API.

---

## 4. `static_site/__init__.py` — Re-export Pattern

```python
from .export_static_snapshot import (
    build_static_dashboard_snapshot,
    export_static_dashboard_bundle,
)
__all__ = ["build_static_dashboard_snapshot", "export_static_dashboard_bundle"]
```

This is the re-export pattern: the public API of the `static_site` subpackage is defined in
`__init__.py`, not in `export_static_snapshot.py`. Callers use:

```python
from tls_dataset.static_site import export_static_dashboard_bundle
```

rather than the internal path:

```python
from tls_dataset.static_site.export_static_snapshot import export_static_dashboard_bundle
```

`cli.py`'s `handle_export_static_dashboard` uses the short form. The benefit: if the internal
module is ever split or renamed, the public API in `__init__.py` remains stable and only one
file changes.

---

## 5. `cli.py` — Unified CLI Surface

### Entry Point Registration (`pyproject.toml`, line 44)

```toml
[project.scripts]
tls-dataset = "tls_dataset.cli:main"
```

`[project.scripts]` tells setuptools to generate a thin executable wrapper when the package is
installed (`pip install -e .`). The generated script calls `tls_dataset.cli:main` — the `main`
function in `cli.py`. This is what makes `tls-dataset run-dataset-pipeline ...` work as a
terminal command without `python -m`.

The `tls-dataset` binary name (hyphenated) differs from the Python package name `tls_dataset`
(underscored). Convention: Python package names use underscores; executables use hyphens. Both
refer to the same code.

### `build_parser` — Subcommand Structure (lines 16–126)

```python
subparsers = parser.add_subparsers(dest="command", required=True)
```

`required=True` was added because Python 3.7+ made subparsers *optional* by default — a
regression from Python 2 behaviour. Without `required=True`, running `tls-dataset` with no
subcommand produces no error and `args.command` is `None`, causing the dispatch in `main()` to
fall through to the `parser.error` line. With `required=True`, argparse itself raises the error
and prints the usage message before `main()` is ever called.

The seven subcommands map directly to the seven workflows studied in prior tutorials:

| Subcommand | Handler | Tutorial |
|---|---|---|
| `info` | `handle_info` | — |
| `run-dataset-pipeline` | `handle_run_dataset_pipeline` | 13 (orchestration) |
| `run-malicious-pipeline` | `handle_run_malicious_pipeline` | 16 (malicious) |
| `build-canonical-dataset` | `handle_build_canonical_dataset` | 17 (canonical) |
| `run-ml-workflow` | `handle_run_ml_workflow` | 19 (ml/workflow) |
| `run-multi-tier` | `handle_run_multi_tier` | 20 (detection/multitier) |
| `export-static-dashboard` | `handle_export_static_dashboard` | 32 (static_site) |

### Quality Gate Thresholds as CLI Arguments

`run-dataset-pipeline` exposes five quality gate thresholds:

```
--min-merge-match-rate       default=0.90
--max-unmatched-uid-rate     default=0.10
--max-non-tls-quic-rate      default=0.05
--max-duplicate-flow-rate    default=0.0
--max-duplicate-uid-rate     default=0.0
```

These are the same thresholds that live in `QualityGateConfig` (Tutorial 09). Exposing them as
CLI arguments allows one-off experiments to relax a gate without editing config files:
`--max-non-tls-quic-rate 0.15` for a capture known to have more non-TLS traffic than usual.
The defaults are the production values — the CLI contract is that running with no threshold
flags is equivalent to running with the production quality config.

### Negated Boolean Flags

```python
run_parser.add_argument("--no-decode-tunnels", action="store_true")
run_parser.add_argument("--no-statistical-analysis", action="store_true")
```

These are negated flags (opt-out) rather than affirmative flags (opt-in). The default behaviour
— tunnel decoding on, statistical analysis on — is the safe production default. Users who want
to disable these features must explicitly pass `--no-decode-tunnels`. The handler inverts the
flag before passing it:

```python
decode_tunnels=not args.no_decode_tunnels,
statistical_analysis=not args.no_statistical_analysis,
```

The alternative — `--decode-tunnels/--no-decode-tunnels` boolean pair with `BooleanOptionalAction`
— would require the user to always explicitly state both values, which is noisier for the common
case. The negated-only design matches the "safe defaults, explicit overrides" principle used
throughout the quality gate design.

---

## 6. Lazy Imports in Handler Functions

Every handler function imports its dependency at call time, not at module load time:

```python
def handle_run_dataset_pipeline(args: argparse.Namespace) -> int:
    from tls_dataset.pipeline.orchestration import run_dataset_pipeline  # ← inside function
    ...

def handle_run_ml_workflow(args: argparse.Namespace) -> int:
    from tls_dataset.ml.workflow import run_ml_workflow  # ← inside function
    ...
```

**Why?** Each import triggers the full import chain for that module:
`run_dataset_pipeline` pulls in pandas, scikit-learn, NFStream, Zeek runner utilities, and more.
If all these were at the top of `cli.py`, every invocation — including `tls-dataset --help` and
`tls-dataset info` — would spend 1–3 seconds importing the entire dependency tree before
printing anything. With lazy imports, `tls-dataset info` starts in milliseconds; only the
invoked subcommand pays the import cost.

This also matters for partial installations. If a researcher only installs the ML dependencies
but not NFStream (which requires a compiled C extension), `tls-dataset run-ml-workflow` works
even though `from tls_dataset.pipeline.orchestration import ...` would fail. The CLI
itself loads without error; only the specific subcommand that needs the missing dependency fails
when invoked.

---

## 7. Output Format Design

All handlers follow the same output pattern:

```python
# Single-level dict results
for key, value in result.items():
    print(f"{key}={value}")

# Nested section results (orchestration, malicious pipeline)
for section, payload in results.items():
    print(f"[{section}]")
    if isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}={value}")
    else:
        print(payload)
```

The output format is `key=value` pairs grouped under `[section]` headers — the same format used
by INI files and by many Unix tools (`git config --list`, systemd unit status output). This is
intentional: the output can be parsed by shell scripts without `jq`:

```bash
output_dir=$(tls-dataset run-dataset-pipeline ... | grep '^output_dir=' | cut -d= -f2)
```

JSON output would require `| python3 -c "import sys,json; print(json.load(sys.stdin)['output_dir'])"` —
verbose and fragile if the output contains unexpected lines. The `key=value` format is also
robust to truncation: if a pipeline run prints 200 lines and the shell only captures the last
50, each captured line is still a self-contained key-value pair.

The exception is `handle_run_dataset_pipeline`, which uses `isinstance(payload, dict)` to
handle the multi-section dict returned by `run_dataset_pipeline` (which wraps results from
filtering, Zeek, NFStream, merge, quality, and build stages). The `handle_run_malicious_pipeline`
handler skips the `isinstance` check because `run_malicious_pipeline` returns a flat dict of
strings, not nested dicts.

---

## 8. `handle_info` — The Architecture Probe

```python
def handle_info() -> int:
    root = project_root()
    print(f"tls-dataset v{__version__}")
    print(f"project_root={root}")
    print("status=repository scaffold initialized")
    print("production_extractors=" + ",".join(TECHNICAL_DIRECTION.production_extractors))
    print("thesis_legacy_extractors=" + ",".join(TECHNICAL_DIRECTION.thesis_legacy_extractors))
    print("next_phase=dependency installation and data-quality validation")
    return 0
```

`handle_info` is the only handler that does not make a lazy import — it only reads
`TECHNICAL_DIRECTION` (already imported at the top of the file) and `__version__` (from the
package `__init__.py`). It serves as a smoke test: if `tls-dataset info` runs and prints the
expected lines, the package is correctly installed and `TECHNICAL_DIRECTION` is intact. In a
CI script, `tls-dataset info | grep production_extractors=zeek,nfstream` would validate the
installation in one line.

---

## 9. `__main__.py` — Module Invocation (5 lines)

```python
from tls_dataset.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

`__main__.py` makes `python -m tls_dataset` work. Without it, running `python -m tls_dataset`
raises:
```
No module named tls_dataset.__main__; 'tls_dataset' is a package and cannot be directly executed
```

`raise SystemExit(main())` ensures that the integer return value of `main()` becomes the process
exit code. Without `raise SystemExit(...)`, a non-zero return value from `main()` would be
printed as a string to stdout (Python's default behaviour for a module that returns a value)
rather than used as the exit code. Shell scripts that check `if tls-dataset ...; then` depend on
the exit code being correct.

`python -m tls_dataset` and `tls-dataset` are equivalent in behaviour:

| Invocation | How it starts | Import path |
|---|---|---|
| `tls-dataset` | setuptools-generated script | Calls `tls_dataset.cli:main` directly |
| `python -m tls_dataset` | Python's `__main__.py` | Imports `cli.main`, calls it |

Both eventually call the same `main()` function.

---

## 10. The `main()` Dispatch (lines 273–293)

```python
def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "info":
        return handle_info()
    if args.command == "run-dataset-pipeline":
        return handle_run_dataset_pipeline(args)
    ...
    parser.error(f"Unknown command: {args.command}")
    return 2
```

`argv: list[str] | None = None` — passing `None` means argparse reads from `sys.argv[1:]`.
Passing an explicit list allows tests to call `main(["info"])` without subprocess overhead. All
handler tests in `tests/` use this pattern.

The final `parser.error(f"Unknown command: {args.command}")` is unreachable in normal operation
— argparse with `required=True` subparsers raises an error before `main()` runs if the command
is missing, and the `if` chain covers every registered subcommand. The line exists as a defence
against future subcommand additions where a developer adds a parser entry but forgets the
corresponding `if` branch — the error message names the unhandled command explicitly, which is
easier to diagnose than a silent `return 2`.

The `if/if/if` pattern (not `if/elif`) is deliberate: each branch returns, so the `elif` chain
is logically equivalent, but `if` makes each branch independently readable in a diff. When
a new subcommand is added, the diff shows one new `if` block rather than a change inside an
`elif` chain.

---

## 11. How Everything Wires Together

The seven subcommands, the three entry-point files, and `technical_direction.py` form one
coherent layer:

```
tls-dataset info
    → handle_info() → TECHNICAL_DIRECTION, __version__

tls-dataset run-dataset-pipeline ...
    → handle_run_dataset_pipeline() → pipeline.orchestration.run_dataset_pipeline (Tutorial 13)

tls-dataset run-malicious-pipeline ...
    → handle_run_malicious_pipeline() → pipeline.malicious.run_malicious_pipeline (Tutorial 16)

tls-dataset build-canonical-dataset ...
    → handle_build_canonical_dataset() → pipeline.canonical.build_canonical_dataset (Tutorial 17)

tls-dataset run-ml-workflow ...
    → handle_run_ml_workflow() → ml.workflow.run_ml_workflow (Tutorial 19)

tls-dataset run-multi-tier ...
    → handle_run_multi_tier() → detection.multitier.run_multitier_detection (Tutorial 20)

tls-dataset export-static-dashboard ...
    → handle_export_static_dashboard() → static_site.export_static_dashboard_bundle (Tutorial 32)
```

The entire pipeline — PCAP ingestion, Zeek, NFStream, merge, quality gates, build, pruning,
finalization, canonical dataset, ML training, multi-tier detection, graph enrichment, reporting,
and static export — is accessible through a single installed binary with seven subcommands.

---

## 12. Interview Questions and Answers

**Q: Why are all the pipeline imports inside the handler functions rather than at the top of `cli.py`?**

A: Top-level imports execute at module load time. Every `tls-dataset` invocation — including
`--help` and `info` — would pay the full cost of importing pandas, scikit-learn, NFStream, and
all their transitive dependencies before printing a single line. Lazy imports inside each
handler mean `tls-dataset info` starts instantly, and only the subcommand that is actually
invoked imports its dependency tree. This also allows the CLI to load successfully even if one
optional dependency group (e.g., NFStream's C extension) is not installed, as long as the user
doesn't invoke the subcommand that requires it.

---

**Q: What is the purpose of `__main__.py`, and how does it differ from the `[project.scripts]` entry point?**

A: `__main__.py` makes `python -m tls_dataset` work by providing the module that Python
executes when a package is run with the `-m` flag. `[project.scripts]` in `pyproject.toml`
makes `tls-dataset` work as a shell command by generating a thin wrapper script at install time
that calls `tls_dataset.cli:main`. Both paths call the same `main()` function. `python -m
tls_dataset` is useful in environments where the PATH is not set up for the installed scripts
(e.g., a virtual environment that hasn't been activated) or when the exact Python interpreter
matters (e.g., `python3.12 -m tls_dataset` explicitly targets Python 3.12).

---

**Q: `TECHNICAL_DIRECTION` is a frozen dataclass that contains only strings. Why not just use module-level constants?**

A: Three reasons. First, grouping the related constants under one named type makes the intent
explicit — these are not independent constants, they are a single architecture decision with
three facets. Second, `frozen=True` prevents accidental mutation anywhere in the codebase; a
module-level `list` could be appended to without error. Third, the dataclass is inspectable:
`handle_info()` iterates its fields, tests can `assert TECHNICAL_DIRECTION.production_extractors
== ("zeek", "nfstream")`, and future tooling can enumerate fields without parsing source code.
Module-level constants would require knowing the constant names in advance.

---

**Q: Why does `main()` use `if args.command == "..." return ...` rather than a dispatch dictionary like `handlers = {"info": handle_info, ...}`?**

A: The dictionary approach requires constructing the dict at function definition time, which
means every function name must be known at parse time — not a problem here, but it also means
the dispatch table is separated from the handler definitions. The if-chain co-locates each
command name with its handler in a way that makes the relationship obvious in `git diff` and
`git blame`. The final `parser.error(...)` acts as a compile-time-style guard against adding a
subcommand parser entry without the corresponding dispatch branch — if a developer adds a new
`subparsers.add_parser("new-command", ...)` but forgets the `if` branch, the first real
invocation of `new-command` hits `parser.error` and immediately names the missing command. With
a dict, the missing key would produce a less informative `KeyError`.

---

*Next: [Tutorial 34 — PCAP Downloader](34_pcap_downloader.md)*
