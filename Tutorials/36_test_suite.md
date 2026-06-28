# Tutorial 36 — Test Suite (`tests/`)

## Files Covered

| File | Tests | What it exercises |
|---|---|---|
| `test_smoke.py` | 8 | Package import, CLI wiring, `TECHNICAL_DIRECTION` |
| `test_pipeline_utils.py` | 3 | Artifact paths, Zeek format detection |
| `test_quality_gates.py` | 4 | Quality gate functions directly |
| `test_zeek_runner.py` | 1 | `resolve_zeek_binary` env override |
| `test_zeek_compatibility.py` | 2 | Zeek quality gate, TLS CSV path resolution |
| `test_provenance_and_malicious_utils.py` | 3 | SHA-256 hashing, manifest resolution |
| `test_ml_workflow.py` | 2 | Feature column selection, threshold optimisation |
| `test_multitier_detection.py` | 3 | Weighted scoring, connected components, alert levels |
| `test_canonical_dataset.py` | 2 | Protocol family derivation, full pipeline integration |
| `test_reporting_snapshot.py` | 5 | Dashboard summary, flow explorer, graph view |
| `test_static_site_export.py` | 2 | Static snapshot, bundle file output |
| `test_backend_platform.py` | 3 | Health endpoint, job submission, worker state |

## Prerequisites

The relevant source module tutorial for each test file. Tutorial 21 (`backend/config.py`) for
`clear_backend_settings_cache`. Tutorial 22 (`backend/db.py`) for `init_database` and
`session_scope`.

---

## 1. Why `unittest.TestCase` and Not Bare pytest

All 12 files use `unittest.TestCase` even though `pytest` is in the dev dependencies
(`pyproject.toml`). pytest runs `unittest.TestCase` classes natively — no adapter needed — so
the choice is not either/or.

`TestCase` is preferred here because every test that touches the database, filesystem, or
environment needs per-test `setUp` and `tearDown`. The explicit lifecycle is clearer in a
thesis codebase than implicit pytest fixtures, and `setUp`/`tearDown` names are unambiguous to
any Python reader regardless of pytest knowledge. Additionally, `assertAlmostEqual` is built
into `TestCase` for float comparisons — the ML and multi-tier tests use it without importing a
third-party assertion library.

---

## 2. Cross-Cutting Patterns

Three patterns appear in every test that touches external state. Understanding them once avoids
repeating the explanation per test file.

### `tempfile.TemporaryDirectory()`

```python
self.temp_dir = tempfile.TemporaryDirectory()
self.root = Path(self.temp_dir.name)
...
def tearDown(self):
    self.temp_dir.cleanup()
```

Every test that writes files creates a `TemporaryDirectory` in `setUp` and calls `.cleanup()`
in `tearDown`. This guarantees isolation: two test runs cannot share artifact directories, and
leftover files from one test cannot cause a false pass in the next. Using the context manager
form (`with tempfile.TemporaryDirectory() as tmp_dir`) would not work across `setUp`/`tearDown`
because the `with` block would close the directory before `tearDown` runs.

### `patch.dict(os.environ, ..., clear=False)`

```python
self.env_patch = patch.dict(
    os.environ,
    {"TLS_BACKEND_DATABASE_URL": f"sqlite:///{database_path}", ...},
    clear=False,
)
self.env_patch.start()
...
def tearDown(self):
    self.env_patch.stop()
```

`clear=False` overlays only the specified keys onto the existing environment, leaving all other
variables intact. `clear=True` would wipe the entire environment for the duration of the test,
causing unrelated library calls that read `PATH`, `HOME`, or `TMPDIR` to fail unexpectedly.

`.start()` and `.stop()` (rather than the `with` form) work across `setUp`/`tearDown`
boundaries.

### `clear_backend_settings_cache()` + `clear_db_caches()`

`BackendSettings` is returned from a `@lru_cache`-decorated function (Tutorial 21). The
SQLAlchemy engine is a module-level singleton (Tutorial 22). Both are cached at import time,
not per-call. Without clearing them in `setUp`, a test that runs after another test would
inherit the previous test's database URL and object store path — the patched environment
variables would be read too late.

Called in **both** `setUp` and `tearDown`:
- `setUp`: clears any state left by the previous test before this test configures its own
- `tearDown`: resets the cached state so the next test starts clean even if this test fails
  before `setUp` completes normally

---

## 3. `test_smoke.py` — Package Health Check

Eight tests, all completing in milliseconds. They do not touch the filesystem or any external
service.

```python
def test_version_is_defined(self) -> None:
    self.assertEqual(__version__, "0.1.0")
```

This asserts the exact version string, not just that it is a non-empty string. If the version
is bumped in `__init__.py` without updating this test, the test fails immediately — a
deliberate forcing function to keep the test and the version in sync.

```python
def test_run_pipeline_command_is_available(self) -> None:
    parser = build_parser()
    args = parser.parse_args(["run-dataset-pipeline", "--dataset-name", "sample", "--output-dir", "out"])
    self.assertEqual(args.command, "run-dataset-pipeline")
```

`build_parser()` is called directly — no process spawning, no subprocess. The parser is
exercised with a minimal valid argument list. This verifies three things without running any
pipeline code: the subcommand is registered, its required arguments (`--dataset-name`,
`--output-dir`) are accepted, and `args.command` is set correctly by `dest="command"`.

```python
def test_production_extraction_stack_is_standardized(self) -> None:
    self.assertEqual(TECHNICAL_DIRECTION.production_extractors, ("zeek", "nfstream"))
    self.assertEqual(TECHNICAL_DIRECTION.thesis_legacy_extractors, ("cicflowmeter",))
```

`TECHNICAL_DIRECTION` is a frozen dataclass (Tutorial 33). This test guards against accidental
mutation of the architecture decision record — if someone modifies the tuple, the test fails.

---

## 4. `test_pipeline_utils.py` — Artifact Paths and Format Detection

### Artifact path parameterisation

```python
artifacts = build_dataset_artifacts(dataset_name="malicious", output_dir="/tmp/outputs")
self.assertTrue(str(artifacts.nfstream_csv).endswith("/tmp/outputs/malicious_nfstream.csv"))
```

Uses `endswith` rather than `assertEqual` on the full path. `build_dataset_artifacts` returns
absolute paths (via `.resolve()`), so the full path includes the system's `/tmp` symlink
resolution (on Linux, `/tmp` may resolve to `/private/tmp` or similar). `endswith` checks that
the naming convention and directory are correct without being fragile to symlink resolution.

### Zeek format detection

```python
log_path.write_text("#separator \\x09\n#fields ts uid\n1.0\tABC\n", encoding="utf-8")
self.assertEqual(sniff_format(log_path), "zeek_tsv")
separator, fields = parse_zeek_tsv_header(log_path)
self.assertEqual(separator, "\t")
self.assertEqual(fields, ["ts", "uid"])
```

The Zeek TSV file is written with the literal string `\\x09` (two characters: backslash, `x`,
`0`, `9`) in the `#separator` line — this matches what Zeek actually writes. `sniff_format` and
`parse_zeek_tsv_header` must correctly parse `\x09` as the tab character. The test verifies
both detection and parsing in one sequence, confirming that the separator is correctly
interpreted as `"\t"` (a single tab) and not the literal four-character string.

---

## 5. `test_quality_gates.py` — Gate Functions in Isolation

### Duplicate flow gate

```python
writer.writerow({"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": "1111",
                 "dst_port": "443", "protocol": "6", "bidirectional_first_seen_ms": "1000"})
writer.writerow(same row again)
outcome = check_nfstream_csv(path)
self.assertEqual(outcome.status, "fail")
```

The test writes a CSV with two identical rows and asserts the gate fails. The five-tuple
`(src_ip, dst_ip, src_port, dst_port, protocol)` plus `bidirectional_first_seen_ms` is the
uniqueness key — two flows with identical tuples and the same start timestamp are duplicates.
Why write to a real CSV rather than passing a DataFrame? `check_nfstream_csv` reads from a
file path, not a DataFrame — testing it this way exercises the actual file-read path, not a
shortcut.

### Merged dataset leakage gate

```python
writer.writerow({"uid": "", ...})  # a row with no Zeek match (uid blank)
outcome = check_merged_dataset(path, min_match_rate=0.90, ...)
self.assertEqual(outcome.status, "fail")
```

The merged CSV has 2 rows: one with a non-blank `uid` (Zeek-matched), one with a blank `uid`
(NFStream-only). Match rate = 1/2 = 0.50, which is below `min_merge_match_rate=0.90`. The gate
fails. This test directly validates the threshold logic — if `check_merged_dataset` miscalculates
the match rate or uses the wrong column, this test catches it.

---

## 6. `test_zeek_runner.py` — Environment Variable Priority

```python
with patch.dict("os.environ", {"ZEEK_BIN": str(zeek_path)}, clear=False):
    with patch("shutil.which", return_value=None):
        self.assertEqual(resolve_zeek_binary(), str(zeek_path.resolve()))
```

Two patches in a nested `with`: the env var `ZEEK_BIN` is set to a real (but empty) file, and
`shutil.which` is stubbed to return `None` (simulating Zeek not being on PATH). The test
verifies that `resolve_zeek_binary` returns the `ZEEK_BIN` path even when `which` fails — the
env var takes priority over PATH lookup.

The temp file `zeek_path.write_text("#!/bin/sh\n")` gives the file content (though it's never
executed here) and makes it a valid file path that `Path.exists()` returns `True` for.

---

## 7. `test_zeek_compatibility.py` — SSL vs TLS CSV Resolution

```python
ssl_path = tmp_path / "ssl.csv"
tls_path = tmp_path / "tls.csv"
ssl_path.write_text("uid\nSSL\n", encoding="utf-8")
tls_path.write_text("uid\nTLS\n", encoding="utf-8")
self.assertEqual(resolve_tls_csv_path(tmp_path), ssl_path.resolve())
```

When both `ssl.csv` and `tls.csv` exist, `resolve_tls_csv_path` must prefer `ssl.csv`. This
is the Zeek naming convention: older captures use `ssl.log`; newer captures use `tls.log`.
Both must be handled. The test creates both files and verifies the preference. Without this
test, a refactor that accidentally reversed the preference would be invisible until a real
older capture was processed.

---

## 8. `test_provenance_and_malicious_utils.py` — Hashing and Manifest Lookup

### SHA-256 length check

```python
path.write_bytes(b"abc123")
entry = build_provenance_entry(stage="raw", path=path)
self.assertEqual(entry.size_bytes, 6)
self.assertEqual(len(entry.sha256), 64)
```

`b"abc123"` is 6 bytes. The SHA-256 hex digest is always 64 characters. The test does not
assert the exact hash value (`ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f7f6399f...`) —
it only checks the length. This avoids hardcoding a value that could change if the content
changes during test maintenance, while still verifying that `build_provenance_entry` actually
hashes the file rather than returning an empty string.

### Manifest lookup by filename

```python
writer.writerow({"url": "https://example.test/capture1.pcap",
                 "rel_path": "botnet/capture1.pcap",
                 "local_path": "/some/other/place/capture1.pcap"})
url, rel_path = resolve_manifest_source(capture, manifest)
self.assertEqual(url, "https://example.test/capture1.pcap")
```

The manifest's `local_path` is `/some/other/place/capture1.pcap` — a different directory from
the actual `capture` file (`tmp_dir/capture1.pcap`). `resolve_manifest_source` must match by
filename (`capture1.pcap`), not by full path. This tests the fallback matching logic described
in Tutorial 16: when the stored `local_path` doesn't exist, match by filename instead.

---

## 9. `test_ml_workflow.py` — Feature Selection and Threshold Maths

### Feature column selection

```python
df = pd.DataFrame({
    "record_id": [...], "label_id": [...], "flow_start_ms": [...],
    "bidirectional_first_seen_ms": [...], "duration": [...],
    "packets": [...], "src_ip": [...],
})
feature_columns, excluded = select_feature_columns(df, target_column="label_id")
self.assertEqual(feature_columns, ["duration", "packets"])
self.assertEqual(excluded["record_id"], "metadata")
self.assertEqual(excluded["bidirectional_first_seen_ms"], "absolute_time")
self.assertEqual(excluded["src_ip"], "non_numeric")
```

Four exclusion categories tested in one assertion block: `record_id` is metadata,
`flow_start_ms` is metadata (timestamp column with a known metadata name pattern),
`bidirectional_first_seen_ms` is `absolute_time` (a specific NFStream absolute timestamp
column), `src_ip` is non-numeric (a string column). `label_id` is excluded as the target
column, not listed in `excluded`. Only `duration` and `packets` remain as feature columns.

The test constructs the exact boundary case where each exclusion rule applies to exactly one
column — making the assertions unambiguous.

### Threshold optimisation

```python
y_true = pd.Series([0, 0, 1, 1])
y_score = np.array([0.1, 0.4, 0.6, 0.9])
frame = evaluate_thresholds(y_true, y_score, thresholds=np.array([0.3, 0.5, 0.7]))
best = select_best_threshold(frame, "f1")
self.assertAlmostEqual(best["threshold"], 0.5)
self.assertAlmostEqual(best["f1"], 1.0)
```

At threshold 0.5: scores `[0.1, 0.4]` are below (predict 0), `[0.6, 0.9]` are above (predict
1). True labels are `[0, 0, 1, 1]`. Perfect classification — F1 = 1.0. At threshold 0.3:
`[0.1]` below, `[0.4, 0.6, 0.9]` above. `0.4` is a false positive — F1 < 1.0. At threshold
0.7: `[0.1, 0.4, 0.6]` below, `[0.9]` above. `0.6` is a false negative — F1 < 1.0. The test
hand-picks values that make threshold 0.5 provably optimal, so `select_best_threshold` must
return 0.5 and F1 = 1.0 — no tolerance ambiguity.

---

## 10. `test_multitier_detection.py` — Weighted Scores, Graphs, Alert Levels

### Weighted mean

```python
scores = weighted_mean_scores(frame, {"rf": 1.0, "gb": 3.0})
self.assertAlmostEqual(scores.iloc[0], 0.5)
```

Row 0: `rf=0.2`, `gb=0.6`. Weighted mean = `(0.2×1 + 0.6×3) / (1+3) = (0.2 + 1.8) / 4 = 0.5`.
Row 1: `rf=0.8`, `gb=0.4`. Weighted mean = `(0.8×1 + 0.4×3) / 4 = (0.8 + 1.2) / 4 = 0.5`.
Both rows produce 0.5 by design — different raw scores, same weighted outcome — confirming
that the weights applied correctly and not that the rows happened to have identical scores.

### Connected components (union-find)

```python
assignments = build_connected_components([
    ("10.0.0.1", "10.0.0.2"),
    ("10.0.0.2", "8.8.8.8"),
    ("1.1.1.1", "9.9.9.9"),
])
self.assertEqual(assignments["10.0.0.1"], assignments["8.8.8.8"])
self.assertNotEqual(assignments["10.0.0.1"], assignments["1.1.1.1"])
```

Three edge pairs: the first two share `10.0.0.2`, so `10.0.0.1`, `10.0.0.2`, and `8.8.8.8`
are in one component. `1.1.1.1` and `9.9.9.9` form a separate component. The test does not
assert the specific cluster IDs (which are implementation-defined), only that the grouping is
correct: transitively connected nodes share the same ID, disconnected nodes do not.

### Alert level assignment

```python
alert_level = assign_alert_level(
    tier1_pass=pd.Series([True, True, False]),
    tier2_pass=pd.Series([True, False, False]),
    deep_pass_count=pd.Series([2, 0, 0]),
    deep_model_total=2,
    deep_consensus_score=pd.Series([0.95, 0.0, 0.0]),
)
self.assertEqual(alert_level.tolist(), ["high", "candidate", "none"])
```

Three rows encode three alert paths:
- Row 0: both tiers pass, both deep models agree, score 0.95 → `"high"`
- Row 1: tier1 passes but tier2 fails, 0 deep models pass → `"candidate"` (passed screening,
  failed consensus)
- Row 2: tier1 fails → `"none"` (not even a candidate)

The `deep_model_total=2` parameter tells the function how many deep models ran, so
`deep_pass_count=2` means unanimous agreement. If `deep_pass_count < deep_model_total`, the
alert cannot be `"high"`. Row 0 is the only one that satisfies all conditions for `"high"`.

---

## 11. `test_canonical_dataset.py` — Full Pipeline Integration

### Protocol family derivation

```python
df = pd.DataFrame({
    "application_name": ["TLS.Google", "QUIC.Google", "HTTP", "", None],
    "version": ["", "", "", "TLSv13", ""],
    "client_scid": ["", "", "", "", "abcd"],
})
protocol_family = derive_protocol_family(df).tolist()
self.assertEqual(protocol_family, ["tls", "quic", "other", "tls", "quic"])
```

Five cases in one assertion, each testing a different detection path:
- Row 0: `application_name` starts with `"TLS."` → `"tls"`
- Row 1: `application_name` starts with `"QUIC."` → `"quic"`
- Row 2: `application_name = "HTTP"`, no version, no SCID → `"other"`
- Row 3: empty `application_name`, but `version = "TLSv13"` → `"tls"` (Zeek fallback)
- Row 4: empty everything, but `client_scid = "abcd"` (non-empty QUIC connection ID) → `"quic"`

This is a complete decision table for the three-column derivation logic.

### Integration test window assignment

```python
result["window_id"].tolist() == ["capture_alpha:w000000", "capture_alpha:w000001"]
result["window_start_ms"].tolist() == [1000, 61000]
```

The source CSV has flows at `bidirectional_first_seen_ms = [1000, 2000, 61500]`.
`window_size_ms = 60_000`. With `encrypted_only=True`, the HTTP row (ms=2000) is filtered out.
Remaining: TLS at 1000ms and QUIC at 61500ms.

Window assignment: the minimum timestamp is 1000ms. Window 0 covers `[1000, 60999]`; window 1
covers `[61000, 120999]`. The TLS flow (1000ms) lands in window 0 (`window_start_ms=1000`,
`window_id="capture_alpha:w000000"`). The QUIC flow (61500ms) lands in window 1
(`window_start_ms=61000`, `window_id="capture_alpha:w000001"`). This verifies that the window
boundary at 60000ms works correctly and that window_start_ms is the window start, not the
first flow timestamp.

---

## 12. `test_reporting_snapshot.py` — Fixture Design

The `_write_dashboard_fixture` method writes 10 files across 5 directories — the minimal
realistic artifact tree that `build_dashboard_summary`, `query_flow_explorer`, and
`build_graph_view` all need without error:

```
artifacts/
  canonical/
    canonical_labeled_flows.csv       ← 3 rows: 1 benign TLS, 1 malicious TLS, 1 malicious QUIC
    canonical_labeled_flows_summary.json
  ml_workflow/latest/
    feature_manifest.json
    workflow_summary.json
    model_comparison.csv              ← 2 models: RF (F1=0.99), GB (F1=0.97)
    gaussian_nb/feature_importance_native.csv
    random_forest/feature_importance_native.csv
    gradient_boosting/feature_importance_native.csv
  multi_tier/latest/
    tiered_flow_scores.csv            ← all 3 flows with scoring columns
    suspicious_flows.csv              ← 2 tier2_pass=True flows
    tier1_candidates.csv
    suspicious_clusters.csv           ← 1 cluster with 3 endpoints
    cluster_window_summary.csv
    graph_nodes.csv                   ← 3 nodes: 1 private, 2 public
    graph_edges.csv                   ← 2 edges from the private hub
  runs/sample_run/
    sample_quality_report.json
```

The 3-row canonical dataset is not arbitrary: it covers TLS (2 flows) and QUIC (1 flow), benign
(1) and malicious (2), two different windows, and both quality states (`unknown` and `fail`).
This minimal fixture lets the tests assert `total_flows=3`, `tls_flows=2`, `quic_flows=1`,
`suspicious_flows=2` without requiring a larger dataset.

### `dataclasses.replace` for settings isolation

```python
base_settings = get_backend_settings()
self.settings = replace(
    base_settings,
    project_root=self.root,
    model_bundle_root=self.root / "artifacts" / "ml_workflow",
    default_model_bundle_dir=self.root / "artifacts" / "ml_workflow" / "latest",
    ...
)
```

`get_backend_settings()` returns the cached singleton built from patched env vars.
`replace(...)` creates a new `BackendSettings` instance with specific path fields pointing to
the temp directory. Functions under test receive this explicit `settings` argument rather than
calling `get_backend_settings()` internally — functions that accept `settings=None` fall back
to the global singleton, but these tests always pass the explicit instance to control paths
precisely.

### `test_reporting_snapshot_helpers_share_the_same_fixture`

```python
summary = build_dashboard_summary(settings=self.settings)
flows = query_flow_explorer(settings=self.settings, only_suspicious=True)
graph = build_graph_view(settings=self.settings, cluster_id="cluster-1", max_nodes=2)

self.assertEqual(summary["overview"]["suspicious_flows"], 2)
self.assertEqual(flows["total"], 2)
self.assertEqual(graph["cluster_id"], "cluster-1")
```

This test calls all three public functions of `snapshot.py` against the same fixture and
asserts they return consistent counts. It is an integration coherence check: the 2 suspicious
flows in the summary should match the 2 flows returned by the explorer, which are the flows
in the cluster returned by the graph view.

---

## 13. `test_static_site_export.py` — Privacy and File Output

```python
self.assertNotIn("10.0.0.9", (output_dir / "data.json").read_text(encoding="utf-8"))
```

This assertion checks the full text of `data.json` for the raw IP address `10.0.0.9`. In the
fixture, `10.0.0.9` is the private internal hub. `_build_endpoint_catalog` assigns it the
display name `"Internal Gateway Alpha"` (Tutorial 32). The assertion verifies that no raw IP
leaked into the output — not in node labels, not in paths, not in spotlight flows. If any
display function accidentally falls back to the raw IP (e.g., when the endpoint catalog lookup
fails), this test catches it.

```python
self.assertIn("window.TLS_DATASET_STATIC_DASHBOARD", (output_dir / "data.js").read_text(...))
```

Verifies that `data.js` contains the global variable assignment — the key requirement for
offline `file://` use (Tutorial 32).

---

## 14. `test_backend_platform.py` — Worker with Fake Runner

```python
def _fake_runner(**_: object):
    fake_output_dir.mkdir(parents=True, exist_ok=True)
    (fake_output_dir / "workflow_summary.json").write_text(
        '{"tier1_candidate_rows": 12, "tier2_suspicious_rows": 5, "cluster_count": 2}', ...
    )
    return type("FakeScoringRun", (), {"summary": {"inference_summary": {...}}})()

with patch("tls_dataset.backend.worker.run_pcap_scoring_job", side_effect=_fake_runner):
    process_scoring_job(job_id)
```

`run_pcap_scoring_job` is the function that would actually invoke Zeek, NFStream, and the ML
models — it requires real PCAP files, real binaries, and real trained models. Calling it in a
test would require the full environment. Instead, `_fake_runner` is substituted: it writes the
output files that the worker expects to find after a scoring run, and returns an object with
the `summary.inference_summary` structure the worker reads.

The test then verifies what the worker does with those outputs:
```python
self.assertEqual(job.status, JobStatus.SUCCEEDED.value)
self.assertEqual(job.suspicious_flow_count, 5)
self.assertEqual(job.candidate_flow_count, 12)
self.assertEqual(job.cluster_count, 2)
```

The numbers `5`, `12`, `2` come from the fake `workflow_summary.json`. The test is
specifically about the worker's orchestration logic: does it correctly update the database
record with the values from the scoring summary? The ML accuracy is not under test here.

### Direct route handler invocation

```python
self.route_map = {
    route.path: route.endpoint
    for route in self.app.routes
    if hasattr(route, "path") and hasattr(route, "endpoint")
}
...
payload = self.route_map["/api/v1/health"]().model_dump()
```

`self.route_map["/api/v1/health"]` is the handler function registered at that path. Calling
it with `()` bypasses the ASGI stack (HTTP parsing, middleware, request/response serialisation)
and invokes the handler directly. This works for synchronous handlers that take no path
parameters. The result is a Pydantic response model; `.model_dump()` converts it to a dict
for assertion.

The alternative — using `httpx.AsyncClient` or FastAPI's `TestClient` — would be more
realistic but requires more setup and adds a dependency on the ASGI transport layer. For a
test that only verifies the health endpoint's data, direct invocation is simpler and faster.

---

## 15. Interview Questions and Answers

**Q: Why do `setUp` and `tearDown` both call `clear_backend_settings_cache()` and `clear_db_caches()`? Shouldn't `tearDown` be enough?**

A: `tearDown` is not guaranteed to run if a previous test's `setUp` raises an exception. If
test 1's `setUp` raises before `tearDown` registers, test 2's `setUp` inherits test 1's stale
cache. Calling `clear_*` at the start of `setUp` ensures the test always begins with a clean
state regardless of what happened in the previous test. The `tearDown` call is belt-and-suspenders
for the normal case, cleaning up so the next test's `setUp` finds nothing to clear.

---

**Q: The `test_canonical_dataset` integration test writes a real YAML config and CSV and calls `build_canonical_dataset`. Why not just unit-test the sub-functions individually?**

A: Because the integration bugs in `build_canonical_dataset` arise at the boundary between
sub-functions: the window assignment reads the output of `derive_protocol_family`, which reads
the output of the CSV parser. A unit test of `derive_protocol_family` alone would not catch a
bug where the column produced by the parser has a different name than the column
`derive_protocol_family` expects. The integration test exercises the full call graph from YAML
config to output CSV — the only path that exercises all those boundaries at once. The test is
small (3 rows) precisely to keep it fast while still covering all the boundaries.

---

**Q: Why does `test_multitier_detection` not assert the specific cluster ID values from `build_connected_components`?**

A: Cluster IDs are implementation-defined — they are assigned by the union-find algorithm in
an order that depends on the input order. The specification says: "nodes in the same cluster
get the same ID; nodes in different clusters get different IDs." The test asserts exactly that
property (`assertEqual` for same cluster, `assertNotEqual` for different cluster) without
pinning an arbitrary implementation detail. If the cluster ID format changes from integer to
UUID, the test still passes. This is the correct way to test graph algorithms: assert the
structural property, not the opaque identifier.

---

*Next: [Tutorial 37 — Configuration Files](37_configs.md)*
