# Tutorial 13 — Pipeline Orchestration (`pipeline/orchestration.py`)

## Prerequisites

All of Tutorials 04–12. This file calls every other pipeline module in sequence. You must
understand what each stage does before you can understand why they are wired together the way
they are here.

---

## 1. What This File Does and Why It Exists

Every pipeline stage covered so far is a standalone function with its own inputs and outputs.
A caller using them directly would have to:

1. Resolve all artifact paths manually.
2. Decide which stages to run and in which order.
3. Decide where to run quality gates relative to each stage.
4. Thread the output of one stage as the input to the next.
5. Handle the two quality-gate write points (pre-merge and post-merge).

`orchestration.py` encapsulates all of that into a single function: `run_dataset_pipeline()`.
It is the **conductor** — it holds no data-processing logic of its own, only the wiring and
sequencing that connects the stages.

This design is a deliberate architectural boundary. Every stage remains independently callable
(useful for testing, re-running a single step, or scripting). The orchestration layer adds
convenience without coupling.

---

## 2. The Full Signature — Every Parameter Explained

```python
def run_dataset_pipeline(
    *,
    dataset_name: str,
    output_dir: str | Path,
    pcap: str | Path | None = None,
    nfstream_csv: str | Path | None = None,
    zeek_log_dir: str | Path | None = None,
    zeek_csv_dir: str | Path | None = None,
    extract_nfstream: bool = False,
    convert_zeek: bool = False,
    all_zeek_logs: bool = False,
    merge_tolerance_sec: float = 2.0,
    protocol_filter: str = "encrypted_only",
    near_const_threshold: float = 0.995,
    corr_threshold: float = 0.95,
    final_drop_cols: list[str] | None = None,
    allow_quality_failures: bool = False,
    min_merge_match_rate: float = 0.90,
    max_unmatched_uid_rate: float = 0.10,
    max_non_tls_quic_rate: float = 0.05,
    max_duplicate_flow_rate: float = 0.0,
    max_duplicate_uid_rate: float = 0.0,
    decode_tunnels: bool = True,
    bpf_filter: str | None = None,
    statistical_analysis: bool = True,
    splt_analysis: int = 20,
    n_meters: int = 4,
) -> dict[str, object]:
```

The `*` makes every parameter keyword-only. With 24 parameters, positional calling would be
an error-prone nightmare — one wrong ordering and `dataset_name` silently receives a path string.
Keyword-only enforcement makes call sites self-documenting.

**Group 1 — Identity and location (always required):**

| Parameter | Meaning |
|-----------|---------|
| `dataset_name` | Identifier used to name all artifact files via `DatasetArtifacts` |
| `output_dir` | Root directory where all artifacts are written |

**Group 2 — Input source overrides (all optional):**

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `pcap` | `None` | Path to the filtered PCAP. Required only if `extract_nfstream=True` or for PCAP health check |
| `nfstream_csv` | `None` | Explicit path to an existing NFStream CSV. If `None`, defaults to `artifacts.nfstream_csv` |
| `zeek_log_dir` | `None` | Path to raw Zeek `.log` files. Required only if `convert_zeek=True` |
| `zeek_csv_dir` | `None` | Explicit path to an existing Zeek CSV directory. If `None`, defaults to `artifacts.zeek_csv_dir` |

These four parameters exist because the pipeline can be entered at different points. If NFStream
and Zeek have already been run externally (e.g., on a cluster, before calling this function),
you pass those pre-computed paths directly and skip re-extraction.

**Group 3 — Stage activation flags:**

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `extract_nfstream` | `False` | If `True`, run NFStream extraction from `pcap`. If `False`, expect the NFStream CSV to already exist |
| `convert_zeek` | `False` | If `True`, convert Zeek `.log` files to CSV. If `False`, expect CSV files to already exist |
| `all_zeek_logs` | `False` | Passed through to `convert_zeek_logs()` — converts all Zeek log types, not just TLS/QUIC-relevant ones |

These boolean flags implement a **re-entrant pipeline pattern**: you can run the expensive
NFStream and Zeek steps once, then iterate on the merge/build/prune stages without reprocessing
the raw PCAP. This is critical for research workflows where you want to test different merge
tolerances or pruning thresholds without waiting for NFStream (which can take minutes on large
PCAPs) to re-run.

**Group 4 — Stage parameters (passed through to individual stage functions):**

| Parameter | Default | Passed to |
|-----------|---------|-----------|
| `merge_tolerance_sec` | `2.0` | `merge_nfstream_with_zeek()` |
| `protocol_filter` | `"encrypted_only"` | `build_dataset_outputs()` |
| `near_const_threshold` | `0.995` | `prune_feature_dataset()` |
| `corr_threshold` | `0.95` | `prune_feature_dataset()` |
| `final_drop_cols` | `None` | `finalize_feature_dataset()` |

These are pass-through parameters. The orchestration function does not interpret them — it
forwards them. Centralising them here means a single call site can control the entire pipeline's
behaviour without touching individual stage functions.

**Group 5 — Quality gate thresholds:**

| Parameter | Default | Gate it controls |
|-----------|---------|-----------------|
| `allow_quality_failures` | `False` | Master switch — if `True`, gates are written but never raise |
| `min_merge_match_rate` | `0.90` | `check_merged_dataset()` |
| `max_unmatched_uid_rate` | `0.10` | `check_merged_dataset()` |
| `max_non_tls_quic_rate` | `0.05` | `check_merged_dataset()` |
| `max_duplicate_flow_rate` | `0.0` | `check_nfstream_csv()` |
| `max_duplicate_uid_rate` | `0.0` | `check_merged_dataset()` |

`allow_quality_failures=False` is the default — the pipeline is strict. Setting it to `True` is
a research escape hatch: you want to see the merged output even if quality gates would normally
block it (e.g., when deliberately processing a low-quality or truncated capture for diagnostic
purposes). It never suppresses the quality report being written to disk.

**Group 6 — NFStream extraction parameters:**

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `decode_tunnels` | `True` | NFStream decodes tunnelled traffic (GRE, VXLAN, etc.) |
| `bpf_filter` | `None` | Berkeley Packet Filter applied before NFStream processing |
| `statistical_analysis` | `True` | Enable NFStream's statistical feature computation |
| `splt_analysis` | `20` | Sequence of Packet Lengths and Times — first N packets to analyse |
| `n_meters` | `4` | Number of parallel NFStream meters (thread count) |

These are only meaningful when `extract_nfstream=True`. When NFStream is pre-run, they are
ignored. `splt_analysis=20` means NFStream records the length and inter-arrival time of the
first 20 packets per flow, generating 40 additional feature columns. This is the primary source
of sequential behavioral features that distinguish C2 beaconing from normal browsing.

---

## 3. Execution Flow — Stage by Stage

### Phase A — Path Resolution (Lines 53–58)

```python
artifacts: DatasetArtifacts = build_dataset_artifacts(dataset_name=dataset_name, output_dir=output_dir)
artifacts.output_dir.mkdir(parents=True, exist_ok=True)
quality_report = QualityReport(dataset_name=dataset_name)

resolved_nfstream_csv = Path(nfstream_csv).expanduser().resolve() if nfstream_csv else artifacts.nfstream_csv
resolved_zeek_csv_dir = Path(zeek_csv_dir).expanduser().resolve() if zeek_csv_dir else artifacts.zeek_csv_dir
```

`build_dataset_artifacts()` constructs the `DatasetArtifacts` frozen dataclass — all artifact
paths are pre-computed here once. Every subsequent stage reads from `artifacts.*`.

The two `resolved_*` variables implement the **override-or-default** pattern: if the caller
passed explicit paths, use those; otherwise fall back to the paths that `DatasetArtifacts`
derived from `dataset_name` and `output_dir`. This is what allows pre-computed NFStream/Zeek
results to be injected mid-pipeline.

`QualityReport` is initialised empty here. Gates are added to it incrementally throughout
execution. The report is an accumulator — it is written to disk *twice* (once before the merge,
once after), capturing the quality state at two points in time.

---

### Phase B — NFStream Stage (Lines 60–74)

```python
if extract_nfstream:
    if pcap is None:
        raise ValueError("pcap must be provided when extract_nfstream=True")
    extract_nfstream_csv(
        pcap_file=pcap,
        output_csv=resolved_nfstream_csv,
        decode_tunnels=decode_tunnels,
        bpf_filter=bpf_filter,
        statistical_analysis=statistical_analysis,
        splt_analysis=splt_analysis,
        n_meters=n_meters,
    )
elif not resolved_nfstream_csv.exists():
    raise FileNotFoundError(f"NFStream CSV not found: {resolved_nfstream_csv}")
quality_report.add(check_nfstream_csv(resolved_nfstream_csv, max_duplicate_flow_rate=max_duplicate_flow_rate))
```

The `if/elif` structure encodes three possible states:

1. `extract_nfstream=True` → run NFStream now, output to `resolved_nfstream_csv`.
2. `extract_nfstream=False` and CSV exists → proceed (use the pre-existing file).
3. `extract_nfstream=False` and CSV does not exist → crash with a clear message.

The `raise ValueError` for missing `pcap` when `extract_nfstream=True` is an **eager validation**
— fail before starting any work, not halfway through the pipeline after wasting time on the Zeek
stage. Precondition checks at the top of pipeline stages are a correctness pattern, not
defensive overcoding.

The quality gate runs **regardless of which path was taken**. Whether NFStream ran just now or
was pre-computed last week, the CSV is checked for required columns and duplicate flows. This
ensures the gate catches corruption or schema changes in pre-existing files too.

---

### Phase C — Zeek Stage (Lines 76–82)

```python
if convert_zeek:
    if zeek_log_dir is None:
        raise ValueError("zeek_log_dir must be provided when convert_zeek=True")
    convert_zeek_logs(zeek_dir=zeek_log_dir, out_dir=resolved_zeek_csv_dir, all_logs=all_zeek_logs)
elif not resolved_zeek_csv_dir.exists():
    raise FileNotFoundError(f"Zeek CSV directory not found: {resolved_zeek_csv_dir}")
quality_report.add(check_zeek_outputs(resolved_zeek_csv_dir))
```

Identical structure to Phase B — same three-state pattern, same eager validation, same
always-run quality gate. The symmetry between the NFStream and Zeek phases is intentional: both
are external tool wrappers that produce intermediate files the rest of the pipeline consumes.
Treating them symmetrically makes the code predictable.

`all_zeek_logs=False` by default means only TLS/QUIC-relevant Zeek logs are converted (conn,
ssl, tls, x509, quic). Setting it `True` converts all logs including http, dns, files, etc. —
useful for research that wants those additional protocol fields in the merged output.

---

### Phase D — PCAP Health Check (Lines 84–85)

```python
if pcap is not None:
    quality_report.add(check_pcap_health(pcap))
```

Two lines, but they encode a deliberate ordering decision: the PCAP health check runs **after**
NFStream and Zeek processing, not before.

**Why?** If NFStream and Zeek already ran successfully (i.e., `extract_nfstream=False` and
`convert_zeek=False`), checking the PCAP now is still useful (it tells you whether the source
was truncated) but is not blocking. Conversely, if both flags are `True`, the PCAP was just
processed — and the NFStream/Zeek quality gates already implicitly validated output quality.
The capinfos check adds an independent source of truth.

If `pcap is None` (caller is using pre-existing NFStream and Zeek outputs and never provided a
PCAP path), the check is skipped entirely — no PCAP to check.

---

### Phase E — First Quality Report Write + Gate Check (Lines 87–89)

```python
quality_report.write(artifacts.quality_report_json)
if not allow_quality_failures:
    raise_for_failed_gates(quality_report)
```

**This is the first of two quality report writes.** At this point the report contains three
outcomes: NFStream CSV check, Zeek outputs check, and optionally PCAP health check. The merge
has not run yet.

**Why write before the merge?**

If any pre-merge gate fails (e.g., Zeek CSV directory missing), you stop here and write the
quality report showing exactly which gate failed. Without this early write, a merge failure
would leave behind no quality report at all — the user would see a Python traceback and have to
re-read the code to understand why the pipeline stopped.

The `allow_quality_failures` check here is critical: if `True`, a failed gate does NOT raise —
the pipeline continues into the merge with a bad NFStream or Zeek input. This is the research
escape hatch in action.

---

### Phase F — Merge (Lines 91–96)

```python
merge_results = merge_nfstream_with_zeek(
    nfstream_csv=resolved_nfstream_csv,
    zeek_dir=resolved_zeek_csv_dir,
    out_csv=artifacts.merged_csv,
    tolerance_sec=merge_tolerance_sec,
)
```

The merge runs unconditionally at this point (pre-merge gates either passed or were allowed to
fail). The output path `artifacts.merged_csv` is always derived from `DatasetArtifacts` —
there is no override for the merged CSV because it is always a pipeline-internal intermediate,
never injected from outside.

`merge_results` is the dict returned by `merge_nfstream_with_zeek()` (Tutorial 08) containing
`nfstream_rows`, `matched_rows`, `matched_pct`, etc. It is included in the final return dict so
the caller can inspect merge quality without loading the merged CSV.

---

### Phase G — Post-Merge Quality Gate + Second Write (Lines 97–108)

```python
quality_report.add(
    check_merged_dataset(
        artifacts.merged_csv,
        min_match_rate=min_merge_match_rate,
        max_unmatched_uid_rate=max_unmatched_uid_rate,
        max_non_tls_quic_rate=max_non_tls_quic_rate,
        max_duplicate_uid_rate=max_duplicate_uid_rate,
    )
)
quality_report.write(artifacts.quality_report_json)
if not allow_quality_failures:
    raise_for_failed_gates(quality_report)
```

**This is the second quality report write** — it overwrites the file written in Phase E with an
updated report that now also contains the `check_merged_dataset` outcome.

**Why write again?**

`quality_report.write()` is not append-only — it serialises the full `QualityReport` to JSON
each time. The second write produces the complete picture: pre-merge gates + post-merge gate in
one file. If the post-merge gate fails, the on-disk report shows all four outcomes, making the
failure fully interpretable.

**Why a second `raise_for_failed_gates` call?**

The merged dataset gate (`check_merged_dataset`) is added after the first gate-check call. If
the orchestration only called `raise_for_failed_gates` once at the end, a bad NFStream CSV that
caused the pre-merge check to fail would proceed through the expensive merge step before being
stopped. Two gate-check points — one before the merge, one after — implement **fail-fast at
the earliest possible moment** while still generating the complete quality report.

---

### Phase H — Build, Prune, Finalize, Inspect (Lines 110–128)

```python
build_results   = build_dataset_outputs(merged_csv=artifacts.merged_csv, ...)
prune_results   = prune_feature_dataset(input_csv=artifacts.ml_ready_csv, ...)
finalize_results = finalize_feature_dataset(input_csv=artifacts.ml_pruned_csv,
                                            output_csv=artifacts.ml_final_csv,
                                            drop_cols=final_drop_cols or DEFAULT_DROP_COLS)
inspect_results = inspect_nfstream_csv(resolved_nfstream_csv)
```

These four stages run unconditionally if the post-merge gate passed. They are wired sequentially
via `DatasetArtifacts` path references:

```
merged_csv → build_dataset_outputs → ml_ready_csv
                                             ↓
                                    prune_feature_dataset → ml_pruned_csv
                                                                   ↓
                                                        finalize_feature_dataset → ml_final_csv
```

`final_drop_cols or DEFAULT_DROP_COLS` is a direct mirror of the logic inside
`finalize_feature_dataset` itself. The `or` ensures that passing `None` (the function default)
falls back to `DEFAULT_DROP_COLS` — the caller does not need to import `DEFAULT_DROP_COLS`
separately to get the default behaviour.

`inspect_nfstream_csv` (Tutorial 18) runs last as a read-only diagnostic — it prints statistics
about the NFStream CSV (flow count, protocol distribution) without modifying any files.

---

### Phase I — Return Dictionary (Lines 130–138)

```python
return {
    "artifacts": artifacts.as_dict(),
    "quality": quality_report.to_dict(),
    "merge": merge_results,
    "build": build_results,
    "prune": prune_results,
    "finalize": finalize_results,
    "inspect": inspect_results,
}
```

The return value is a **complete pipeline run record**. Every stage's output statistics plus all
artifact paths are accessible in a single nested dict. Callers (the CLI, the backend scoring
function, tests) can:

- Extract `results["artifacts"]["ml_final_csv"]` to know where the training data landed.
- Check `results["quality"]["failed"]` to confirm all gates passed.
- Read `results["merge"]["matched_pct"]` to log or alert on match quality.
- Compare `results["prune"]["columns"]` across runs to detect schema drift.

This structure also means the entire pipeline run is JSON-serialisable — a caller can write
`json.dumps(results)` for logging, provenance tracking, or debugging.

---

## 4. The Two-Phase Quality Report Pattern — Why It Matters

The quality report is written to disk twice, but `raise_for_failed_gates` is called twice too.
The full sequence:

```
[pre-merge gates added]
    quality_report.write()          ← write #1: 3 outcomes on disk
    raise_for_failed_gates()        ← stops pipeline if pre-merge failed

[merge runs]
[post-merge gate added]
    quality_report.write()          ← write #2: 4 outcomes on disk (overwrites #1)
    raise_for_failed_gates()        ← stops pipeline if post-merge failed

[build / prune / finalize / inspect run]
```

This ensures:
- **Always-on-disk audit trail**: if the pipeline stops at any point, the most recent quality
  report reflects the state at failure.
- **Earliest possible failure**: no expensive work runs against data that has already failed a
  quality check.
- **No silent success on bad data**: `allow_quality_failures=True` must be explicitly set;
  the default is strict.

---

## 5. What This Function Does NOT Do

Understanding the boundaries is as important as understanding what is inside them.

`run_dataset_pipeline()` does not:
- **Run `editcap` or `tshark` filtering** — that is `pipeline/filtering.py`. The input PCAP is
  assumed to already be the filtered PCAP from Tutorial 04. The pipeline assumes filtering was
  done upstream.
- **Run Zeek itself** — that is `pipeline/zeek_runner.py` (Tutorial 05). It only converts
  existing Zeek `.log` files to CSV (the `convert_zeek` flag calls `convert_zeek_logs`, not
  `run_zeek_on_pcap`).
- **Record provenance** — that is `pipeline/provenance.py` (Tutorial 15). The orchestration
  function returns all the data needed for provenance but does not write a provenance JSON.
  Callers like `pipeline/canonical.py` build on top of this function and add provenance.
- **Train an ML model** — that is `ml/workflow.py` (Tutorial 19). `ml_final.csv` is the
  handoff point.

---

## 6. Interview Questions and Answers

**Q: Why does `run_dataset_pipeline` not run `editcap`/`tshark` filtering or Zeek itself, only
the Zeek-log-to-CSV conversion?**

A: Pipeline stages that invoke system tools with long runtimes (editcap, tshark, Zeek) are kept
outside the orchestration boundary so they can be run on different machines or in different
environments. In practice, Zeek might run on a dedicated sensor or cluster node while the
Python pipeline runs on a workstation. The separation means the orchestration function is purely
a Python+pandas operation — no system tool dependency. The `convert_zeek` flag only calls
`convert_zeek_logs()` (a log-format conversion, pure Python) not `run_zeek_on_pcap()`.

---

**Q: Why are quality gates written to disk twice — not once at the very end?**

A: Writing at the end would mean a failed pre-merge gate produces no quality report on disk (the
pipeline raised before reaching the write). The first write ensures the on-disk report reflects
the pre-merge state at the moment of failure. The second write augments it with the post-merge
outcome. If a caller only ever checks the final written file, they always see the complete,
up-to-date picture regardless of where the pipeline stopped.

---

**Q: What is the purpose of `allow_quality_failures=True`?**

A: It is a research escape hatch, not a production setting. When diagnosing a new PCAP source
(e.g., a third-party botnet capture with incomplete TLS metadata), you may want to see the
merged and built CSV even if the match rate is only 60% — to understand what features are
present before deciding whether to tighten the filter or adjust the tolerance. With
`allow_quality_failures=True`, all gates run and are recorded in the quality report, but none
stop the pipeline. This lets you inspect the output of a bad pipeline run without changing any
gate thresholds.

---

**Q: How does the re-entrant pipeline design work in practice?**

A: The `extract_nfstream` and `convert_zeek` flags are both `False` by default. If you ran the
pipeline once and it failed at the merge quality gate, you can fix the merge tolerance and re-run
the function with `extract_nfstream=False`, `convert_zeek=False`, and
`nfstream_csv=path_to_existing` — the expensive NFStream and Zeek steps are skipped entirely and
only the merge onwards re-runs. This is the core research iteration loop: run the slow steps once,
iterate fast on the analysis steps.

---

**Q: The function returns a large nested dict. Why not return a dataclass or a typed object?**

A: The dict is intentionally untyped for two reasons. First, each nested value (`merge_results`,
`build_results`, etc.) comes from a different function with a different return type — wrapping
them in a shared typed object would require either a very loose `Any`-typed container or a
purpose-built dataclass that duplicates the structure of each individual result. Second, the dict
is directly JSON-serialisable without a custom serialiser — the backend scoring function
(`backend/scoring.py`, Tutorial 28) and the provenance tracker can log it with `json.dumps()`
without transformation.

---

*Next: [Tutorial 14 — PCAP Utilities](14_pipeline_pcap.md)*
