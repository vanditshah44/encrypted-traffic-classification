# Tutorial 35 — Root-Level Shim Scripts

## Files Covered

| Script | Delegates to | Tutorial |
|---|---|---|
| `zeektocsv.py` | `tls_dataset.pipeline.zeek:main` | 06 |
| `extract-nfstream.py` | `tls_dataset.pipeline.nfstream:main` | 07 |
| `merge-pcaps.py` | `tls_dataset.pipeline.pcap:main` | 14 |
| `combineCSV.py` | `tls_dataset.pipeline.merge_features:main` | 08 |
| `freeze_benign.py` | `tls_dataset.pipeline.build_dataset:main` | 10 |
| `sanityChecks-basic.py` | `tls_dataset.pipeline.pruning:main` | 11 |
| `clean.py` | `tls_dataset.pipeline.finalize:main` | 12 |
| `flows.py` | `tls_dataset.pipeline.inspect:main` | 18 |
| `mscp_down.py` | `tls_dataset.pipeline.download:main` | 34 |

## Prerequisites

Tutorials 06, 07, 08, 10, 11, 12, 14, 18, 34 — each shim is a wrapper around one of those
modules. Tutorial 33 (`cli.py`) — understanding the difference between these shims and the
unified `tls-dataset` CLI is the main insight here.

---

## 1. Why These Scripts Exist

Every script has the same 14 lines:

```python
#!/usr/bin/env python3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from tls_dataset.pipeline.<module> import main

if __name__ == "__main__":
    raise SystemExit(main())
```

These are **shim scripts** — thin wrappers that make a pipeline module's `main()` callable as a
standalone script without installing the package. They predate the `pip install -e .` workflow
and the unified `tls-dataset` CLI (Tutorial 33).

The project evolved in two phases:

**Phase 1 — Script-first**: The pipeline modules were written and tested individually.
A researcher running `python zeektocsv.py --help` is more intuitive than remembering
`tls-dataset run-dataset-pipeline --convert-zeek`. Each script had a name describing what it
*does* from the user's perspective ("convert Zeek to CSV"), not what it *is* architecturally.

**Phase 2 — Package-first**: `pyproject.toml` registered `tls-dataset = "tls_dataset.cli:main"`,
and `cli.py` became the single entry point. The shim scripts were kept for two reasons:
1. Compatibility — existing shell scripts or Makefile rules that call `python zeektocsv.py`
   continue to work without modification.
2. Development convenience — a developer can run `python zeektocsv.py` from the project root
   without activating a virtual environment, as long as dependencies are importable. The shim
   manually injects `src/` into `sys.path` so the package resolves from source.

---

## 2. The `sys.path` Injection

```python
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
```

`Path(__file__).resolve().parent` gives the project root regardless of what working directory
the script is called from. `resolve()` follows symlinks and eliminates `..` components, so if
`zeektocsv.py` is run as `python ../../tls_dataset/zeektocsv.py` from a subdirectory, `ROOT`
is still the project root.

`sys.path.insert(0, str(SRC))` puts `src/` at the *front* of the import search path, not the
end. This matters when multiple versions of `tls_dataset` exist on the machine — for example,
if the package was previously installed globally or in a different virtual environment. By
inserting at index 0, the local source tree takes unconditional priority over any installed
version.

The guard `if str(SRC) not in sys.path` prevents duplicating the entry if the script is
imported twice in the same session (unlikely in normal use, but possible in testing contexts
where multiple shims are exercised in sequence).

After this block, `from tls_dataset.pipeline.zeek import main` resolves to
`src/tls_dataset/pipeline/zeek.py` — the same file studied in Tutorial 06.

---

## 3. The Naming Mismatch as Architecture History

The script names are the most informative part of these files. They reveal what the operations
*meant* to the researcher before the codebase was structured:

| Script name | What the name implies | What the module does |
|---|---|---|
| `zeektocsv.py` | "Convert Zeek logs to CSV" | `zeek.py` — runs tshark conversion, then Zeek log→CSV |
| `extract-nfstream.py` | "Extract features with NFStream" | `nfstream.py` — runs NFStream over a PCAP |
| `merge-pcaps.py` | "Merge PCAP files" | `pcap.py` — PCAP merging and filter operations |
| `combineCSV.py` | "Combine the CSV files" | `merge_features.py` — feature-level join of Zeek and NFStream outputs |
| `freeze_benign.py` | "Freeze the benign dataset" | `build_dataset.py` — applies protocol filter, prunes, writes ML-ready CSV |
| `sanityChecks-basic.py` | "Run basic sanity checks" | `pruning.py` — near-constant and correlation pruning |
| `clean.py` | "Clean the dataset" | `finalize.py` — removes residual temporal-leakage columns |
| `flows.py` | "Inspect flows" | `inspect.py` — summary statistics and per-flow analysis |
| `mscp_down.py` | "MCFP/MSCP downloader" | `download.py` — Apache index crawler and resumable downloader |

`sanityChecks-basic.py` → `pruning.py` is the sharpest example. From a script perspective,
dropping near-constant and correlated features *feels like* a sanity check — "make sure the
features are reasonable." The module name `pruning` is more precise: this is a deliberate
dimensionality reduction step based on statistical thresholds, not a validation that something
is wrong.

`freeze_benign.py` → `build_dataset.py` reflects a dataset construction stage where benign
captures were "frozen" (fixed, finalized) before malicious captures were added. The module name
`build_dataset` generalises to both benign and malicious; the script name preserves the
original context of when it was first written.

---

## 4. `raise SystemExit(main())` — Exit Code Propagation

```python
if __name__ == "__main__":
    raise SystemExit(main())
```

This is the same pattern as `__main__.py` (Tutorial 33). `main()` returns an integer exit code
(0 for success, non-zero for failure). `raise SystemExit(code)` propagates that code to the
shell. Without it, the script would exit with code 0 regardless of whether `main()` returned
an error code, silently hiding failures from shell `if` conditions and `set -e` scripts.

---

## 5. When to Use These Scripts vs. `tls-dataset` CLI

| Situation | Recommended invocation |
|---|---|
| Normal project use, package installed | `tls-dataset <subcommand>` (Tutorial 33) |
| Quick single-step invocation, no install | `python zeektocsv.py` (this tutorial) |
| Docker container, source mounted without install | `python zeektocsv.py` |
| Existing shell script that predates the CLI | `python zeektocsv.py` (no change needed) |
| CI pipeline with `pip install -e .` | `tls-dataset <subcommand>` |

The shim scripts do not offer any arguments that the CLI does not — they call the exact same
`main()` function with the exact same argument parser. The only difference is the invocation
path and the `sys.path` injection.

---

## 6. What the `encclassi/` Directory Is

The project root contains an `encclassi/` directory that mirrors the entire project structure —
same scripts, same `src/tls_dataset/` package, same `tests/`, same `configs/`, same `docs/`.
All mirrored files are byte-for-byte identical to their counterparts in the project root. The
only addition is an empty `encclassi/src/tls_dataset/backend/ui/` directory.

`encclassi/` appears to be a preserved snapshot taken before the backend UI layer was planned —
a checkpoint of the repository state. It is not used by any import or CI step. The shim scripts
in `encclassi/` have the same `sys.path.insert(0, str(SRC))` pattern but point to
`encclassi/src/` rather than the main `src/`.

---

## 7. Interview Questions and Answers

**Q: Why does `sys.path.insert(0, ...)` use index 0 rather than `sys.path.append(...)`?**

A: `sys.path` is searched left to right when resolving an import. Inserting at index 0 puts
`src/` before all other entries, including site-packages. This ensures the local development
copy of `tls_dataset` is always imported rather than any previously installed version. `append`
would place `src/` after site-packages, so a `pip install tls-dataset` in the same environment
would shadow the source tree — the installed copy would be imported instead, making local
changes invisible without reinstalling.

---

**Q: The shim scripts predate the `tls-dataset` CLI. If you were adding a new pipeline module
today, would you add a shim script for it?**

A: No. The shim pattern served its purpose when the package was not yet installable. Now that
`pyproject.toml` registers `tls-dataset` as a console script and all pipeline modules have
`main()` functions reachable through `cli.py`, the correct extension path is adding a new
subcommand to `build_parser()` in `cli.py` (Tutorial 33). The existing shim scripts are
retained for backward compatibility with any workflows that reference them by name, not as the
forward design pattern.

---

*Next: [Tutorial 36 — Test Suite Overview](36_tests_overview.md)*
