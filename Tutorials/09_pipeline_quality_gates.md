# Tutorial 09 — Quality Gates (`pipeline/quality.py`)

## Prerequisites

- Tutorial 03 (`common.py`) — understand `DatasetArtifacts` and the artifact paths this file
  validates.
- Tutorial 06 (`zeek.py`) — know what Zeek produces and which CSV files are expected.
- Tutorial 07 (`nfstream.py`) — understand what NFStream produces and which columns are required.
- Tutorial 08 (`merge_features.py`) — understand the merge step that produces `merged.csv` and
  what a "matched row" means.

---

## 1. Why Does This File Exist? The Defence-in-Depth Philosophy

Every stage of the pipeline (filtering → Zeek → NFStream → merge) can silently produce bad output:

| Stage | Silent failure mode |
|-------|-------------------|
| Filtering | PCAP is corrupted or truncated — Zeek runs but processes garbage data |
| Zeek runner | Zeek ran but produced no `ssl.log` because all traffic was plain HTTP |
| NFStream | NFStream ran but produced duplicate flow keys due to a loopback artefact |
| Merge | 40% of flows matched Zeek — data is technically written but scientifically useless |
| Merge | TLS metadata columns all `NaN` — the most important features are empty |

Without guards, bad data would silently propagate all the way into ML training. The model would
train on garbage, produce nonsense predictions, and you would only discover the problem when
results looked wrong — potentially after hours of training runs.

`quality.py` inserts **explicit checkpoints** between stages. Each checkpoint is called a
**quality gate**. A gate either passes, warns, or fails. A failure raises an exception and stops
the pipeline before wasting compute on bad data.

```
PCAP                     NFStream.csv          merged.csv
  │                           │                    │
  ▼                           ▼                    ▼
check_pcap_health()   check_nfstream_csv()  check_merged_dataset()
  │                           │                    │
Zeek CSVs                     │                    │
  │                           │                    │
  ▼                           │                    │
check_zeek_outputs()          │                    │
                              │                    │
                              └────────────────────┘
                                  raise_for_failed_gates()
                                  writes QualityReport JSON
```

The design principle is: **fail loudly and early, never silently accept bad data.**

---

## 2. Module-Level Constants — Lines 13–29

```python
TRUNCATION_MARKERS = (
    "appears to have been cut short",
    "cut short in the middle of a packet",
    "middle of a packet",
)

FLOW_KEY_COLUMNS = (
    "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "bidirectional_first_seen_ms",
)

TLS_SIGNAL_COLUMNS = ("version", "cipher", "server_name", "ja3", "ja3s")
QUIC_SIGNAL_TOKENS = ("quic", "cid", "scid", "dcid", "h3", "http3")
```

These four constants drive the entire gate logic. Understanding them upfront makes every function
easier to read.

### `TRUNCATION_MARKERS`

Exact substrings that `capinfos` (a Wireshark tool) writes to `stderr` when it detects a
truncated PCAP. A truncated PCAP means the file was cut off mid-write (disk full, network drop
during transfer, killed process). Zeek and NFStream will still process it but the tail of the
capture is missing — you lose flows and get incorrect statistics.

Rather than parsing a structured error code, the gate does a string search on stderr. This is
intentional: capinfos' human-readable messages are stable across versions and the tool is
explicitly designed for scripting.

### `FLOW_KEY_COLUMNS`

The six columns that together uniquely identify a flow in the NFStream CSV. This is the
**5-tuple + timestamp**:

```
(src_ip, dst_ip, src_port, dst_port, protocol, bidirectional_first_seen_ms)
```

If two rows share all six values, they are duplicates — they represent the same flow appearing
twice in the output (a defect).

### `TLS_SIGNAL_COLUMNS`

Column names from `ssl.csv` / `tls.csv` that only have values if TLS metadata was successfully
extracted. If *all* of these are `NaN` for a row in `merged.csv`, that row is considered to lack
TLS/QUIC evidence.

| Column | What it contains if TLS worked |
|--------|-------------------------------|
| `version` | `"TLSv13"`, `"TLSv12"` etc. |
| `cipher` | e.g., `"TLS_AES_256_GCM_SHA384"` |
| `server_name` | SNI hostname from the ClientHello |
| `ja3` | MD5 hash of TLS ClientHello fingerprint |
| `ja3s` | MD5 hash of TLS ServerHello fingerprint |

### `QUIC_SIGNAL_TOKENS`

QUIC-specific substrings that may appear as column *names* in `quic.csv` output. Unlike TLS
signal columns (which are exact names), QUIC columns vary by Zeek version so this uses token
matching on the column header strings rather than exact equality.

| Token | What it refers to |
|-------|------------------|
| `quic` | General QUIC metadata columns |
| `cid` | Connection ID |
| `scid` | Source Connection ID |
| `dcid` | Destination Connection ID |
| `h3` / `http3` | HTTP/3 over QUIC |

---

## 3. Data Classes — `GateOutcome` and `QualityReport`

### 3.1 `GateOutcome` (frozen dataclass) — Lines 32–38

```python
@dataclass(frozen=True)
class GateOutcome:
    name: str
    status: str
    message: str
    metrics: dict[str, object] = field(default_factory=dict)
```

A single gate's result. Every gate function returns exactly one `GateOutcome`.

| Field | Type | Meaning |
|-------|------|---------|
| `name` | str | Machine-readable gate identifier (e.g., `"pcap_health"`) |
| `status` | str | One of `"pass"`, `"warn"`, `"fail"` |
| `message` | str | Human-readable explanation |
| `metrics` | dict | Numeric evidence — row counts, rates, file paths |

**Why `frozen=True`?**

`frozen=True` makes the dataclass immutable — you cannot accidentally mutate a gate result after
it is created. Gate outcomes are facts about a pipeline run; they should never change. If you
need a different outcome, create a new `GateOutcome`. This is the same principle as immutable
value objects in domain-driven design.

**Why a `metrics` dict?**

Rather than defining typed fields for every possible measurement (which would differ per gate),
`metrics` is an open dict. This makes `GateOutcome` reusable across gates with very different
shapes of evidence. Downstream consumers (the JSON report, the orchestration layer) can inspect
whatever metrics are relevant.

---

### 3.2 `QualityReport` — Lines 41–63

```python
@dataclass
class QualityReport:
    dataset_name: str
    outcomes: list[GateOutcome] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(outcome.status == "fail" for outcome in self.outcomes)

    def add(self, outcome: GateOutcome) -> None:
        self.outcomes.append(outcome)

    def to_dict(self) -> dict[str, object]:
        return {
            "dataset_name": self.dataset_name,
            "failed": self.failed,
            "outcomes": [asdict(outcome) for outcome in self.outcomes],
        }

    def write(self, output_path: str | Path) -> None:
        target = Path(output_path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
```

A container that collects all `GateOutcome` objects for one pipeline run and can serialise them
to a JSON file.

**`failed` property:** Uses `any()` — even a single failing gate marks the entire report as
failed. There is no partial success: if the PCAP is truncated, it doesn't matter that NFStream
ran fine.

**`to_dict()` + `asdict()`:** `asdict()` is from Python's `dataclasses` module. It recursively
converts a dataclass to a plain dict, including nested dataclasses and the `metrics` dict. This
makes the output directly JSON-serialisable without manual field listing.

**`write()`:** Saves the report to disk as a formatted JSON file. This is a **provenance
artifact** — a record that quality was checked, what the results were, and the specific metrics
at the time. The orchestration layer saves this next to the pipeline outputs so you can audit any
run's data quality after the fact.

**Example output JSON:**
```json
{
  "dataset_name": "benign_2024_01_15",
  "failed": false,
  "outcomes": [
    {
      "name": "pcap_health",
      "status": "pass",
      "message": "PCAP passed truncation checks",
      "metrics": {
        "pcap": "/data/capture.pcap",
        "capinfos_returncode": 0,
        "Number of packets": "142857",
        "Capture duration (seconds)": "3600.123",
        "File size (bytes)": "89234567"
      }
    },
    ...
  ]
}
```

---

## 4. Helper Functions

### 4.1 `is_truncation_warning(stderr_text)` — Lines 65–67

```python
def is_truncation_warning(stderr_text: str) -> bool:
    lowered = stderr_text.lower()
    return any(marker in lowered for marker in TRUNCATION_MARKERS)
```

Normalises the `capinfos` stderr output to lowercase and checks if any of the three truncation
marker strings appear. The lowercase normalisation means the check survives any future `capinfos`
version that capitalises differently.

---

### 4.2 `_is_present(value)` — Lines 70–74

```python
def _is_present(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower()
    return normalized not in ("", "nan", "none", "null")
```

A CSV-aware "is this field populated?" check. When you read a CSV with Python's `csv.DictReader`,
every value is a string — including missing values, which appear as the literal strings `"nan"`,
`"None"`, `"null"`, or just empty `""`.

This function treats all of those as "not present". A field is only considered present if it
contains a real non-empty, non-null-like string.

**Why this matters:** After the merge step, rows with no Zeek UID match have `uid=""` or
`uid="nan"` in the CSV (pandas writes `NaN` as the string `"nan"` when saving to CSV). This
function lets the gate correctly count those rows as unmatched.

---

### 4.3 `row_has_encrypted_signal(row, fieldnames)` — Lines 77–85

```python
def row_has_encrypted_signal(row: Mapping[str, str], fieldnames: Iterable[str]) -> bool:
    if any(_is_present(row.get(column)) for column in TLS_SIGNAL_COLUMNS):
        return True

    for fieldname in fieldnames:
        lowered = fieldname.lower()
        if any(token in lowered for token in QUIC_SIGNAL_TOKENS) and _is_present(row.get(fieldname)):
            return True
    return False
```

Returns `True` if a merged CSV row shows evidence of TLS *or* QUIC traffic.

**TLS check:** Looks at the five exact `TLS_SIGNAL_COLUMNS`. If any one of them is present (not
null/empty), the row has TLS evidence. Even a single populated column (e.g., just `server_name`)
is enough — partial TLS metadata is better than none.

**QUIC check:** Iterates over *all* column names in the file and checks if any column name
contains a QUIC token AND has a non-null value in this specific row. This two-level check
(column-name filter + value-presence filter) is needed because:
1. QUIC column names vary across Zeek versions — exact name matching is fragile.
2. A row may have QUIC columns in the schema (because some rows have QUIC data) but this
   particular row may have them as `NaN` — you need the value check.

**Why `Mapping[str, str]` and `Iterable[str]`:** These are the exact types returned by
`csv.DictReader` (`row` is a dict-like mapping; `fieldnames` is a list of strings). Using the
abstract types instead of `dict` / `list` makes the function easier to test with any mapping.

---

## 5. Gate Functions — One by One

### 5.1 `check_pcap_health(pcap_path)` — Lines 88–119

**What it checks:** Whether the PCAP file exists and whether `capinfos` reports truncation.

```python
def check_pcap_health(pcap_path: str | Path) -> GateOutcome:
```

**Step 1 — Existence check:**
```python
if not path.exists():
    return GateOutcome("pcap_health", "fail", f"PCAP file does not exist: {path}")
```
Fails immediately if the file is missing. No point running capinfos on a non-existent file.

**Step 2 — capinfos availability check:**
```python
capinfos = shutil.which("capinfos")
if capinfos is None:
    return GateOutcome("pcap_health", "warn", "capinfos is not available; truncation check skipped", ...)
```

`shutil.which()` locates an executable on `PATH`, the same way a shell does. If `capinfos` is
not installed (it comes with Wireshark/tshark), the gate returns `"warn"` rather than `"fail"`.

**Why warn instead of fail?** Capinfos is an optional dependency. In a minimal Docker container
or CI environment that only has Zeek/NFStream, you still want the pipeline to run. The warning
tells you the truncation check was skipped without stopping everything.

**Step 3 — Run capinfos:**
```python
result = subprocess.run(
    [capinfos, "-Tm", str(path)],
    capture_output=True,
    text=True,
    check=False,
)
```

`-T` = machine-readable (tab-separated) output format.
`-m` = include more metadata fields.
`check=False` = don't raise `CalledProcessError` on non-zero exit — the gate handles exit codes
manually.

**Step 4 — Parse capinfos output:**
```python
lines = [line for line in result.stdout.splitlines() if line.strip()]
if len(lines) >= 2:
    reader = csv.DictReader(lines)
    first_row = next(reader, None)
    if first_row is not None:
        for key in ("Number of packets", "Capture duration (seconds)", "File size (bytes)"):
            if key in first_row:
                metrics[key] = first_row[key]
```

Capinfos with `-T` produces a CSV-like output (first line = headers, second line = values). By
wrapping the output lines in `csv.DictReader`, the code can extract named fields without
positional fragility. The three extracted metrics go into the `GateOutcome.metrics` dict for the
JSON report.

**Step 5 — Decide outcome:**
```python
if truncated:
    return GateOutcome("pcap_health", "fail", "PCAP appears truncated according to capinfos", metrics)
if result.returncode != 0:
    return GateOutcome("pcap_health", "warn", "capinfos returned a non-zero status without a truncation marker", metrics)
return GateOutcome("pcap_health", "pass", "PCAP passed truncation checks", metrics)
```

Three outcomes:
- **fail** — explicit truncation marker in stderr → bad PCAP, stop the pipeline.
- **warn** — capinfos exited with an error but no truncation marker → suspicious but not
  definitively broken; let the pipeline proceed but log it.
- **pass** — capinfos ran cleanly and no truncation marker found.

---

### 5.2 `check_zeek_outputs(zeek_csv_dir)` — Lines 122–143

**What it checks:** Whether the Zeek CSV directory has the mandatory files and at least one
encrypted-protocol log.

```python
required = {"conn.csv"}
encrypted_evidence = {"ssl.csv", "tls.csv", "quic.csv"}
```

**Why `conn.csv` is the only required file:**

`conn.csv` must exist for the merge to work (Tutorial 08). The TLS-specific files
(`ssl.csv`/`tls.csv`/`quic.csv`) are required as a group — at least one must exist — but not
individually, because a capture containing only QUIC would have `quic.csv` but not `ssl.csv`.

```python
present = {child.name for child in path.glob("*.csv")}
missing_required = sorted(required - present)
has_encrypted_evidence = bool(encrypted_evidence & present)
```

Uses set operations:
- `required - present` = set difference → which required files are absent.
- `encrypted_evidence & present` = set intersection → which encrypted-protocol files exist.

**Why check for encrypted evidence:**

This project is specifically about TLS/QUIC traffic classification. If Zeek ran successfully but
produced zero `ssl.csv`, `tls.csv`, or `quic.csv`, it means the filtered PCAP contained no TLS
or QUIC flows. This is a critical signal failure — the data cannot be used for TLS classification
and the pipeline should stop rather than produce an ML dataset with empty TLS feature columns.

**Outcomes:**
- **fail** — `conn.csv` missing → merge impossible.
- **fail** — No TLS/QUIC logs → data lacks protocol evidence.
- **pass** — `conn.csv` present + at least one TLS/QUIC log.

---

### 5.3 `check_nfstream_csv(nfstream_csv, *, max_duplicate_flow_rate)` — Lines 146–187

**What it checks:** Whether the NFStream CSV has required columns and an acceptable duplicate
flow rate.

```python
def check_nfstream_csv(
    nfstream_csv: str | Path,
    *,
    max_duplicate_flow_rate: float = 0.0,
) -> GateOutcome:
```

The default `max_duplicate_flow_rate=0.0` means **zero duplicates are acceptable**. Any duplicate
flow immediately fails the gate. This is a strict threshold — justified because NFStream should
produce exactly one row per bidirectional flow from a given PCAP. Duplicates indicate something
went wrong (e.g., NFStream processed overlapping PCAP slices).

**Column validation:**
```python
fieldnames = reader.fieldnames or []
missing_columns = [column for column in FLOW_KEY_COLUMNS if column not in fieldnames]
if missing_columns:
    return GateOutcome("nfstream_csv", "fail", ...)
```

Checks that all six `FLOW_KEY_COLUMNS` are present in the CSV header before reading any data.
Fails fast with the exact list of missing columns so the user knows exactly what went wrong.

**Duplicate detection:**
```python
seen_keys: set[tuple[str, ...]] = set()
for row in reader:
    total_rows += 1
    flow_key = tuple(row[column] for column in FLOW_KEY_COLUMNS)
    if flow_key in seen_keys:
        duplicate_rows += 1
    else:
        seen_keys.add(flow_key)
```

Reads the CSV row-by-row (memory efficient — does not load the full DataFrame) and tracks the
set of seen flow keys. A flow key is a 6-tuple of string values from the CSV. Using a `set` of
tuples gives O(1) average lookup per row.

**Why read row-by-row instead of using pandas?**

For large NFStream CSVs (millions of rows), loading the entire DataFrame to check for duplicates
would consume gigabytes of RAM. Row-by-row reading with a set keeps memory at O(unique keys)
which grows linearly with the number of unique flows but never loads the whole file.

**Outcome decision:**
```python
if duplicate_rate > max_duplicate_flow_rate:
    return GateOutcome("nfstream_csv", "fail", "NFStream CSV contains duplicate flow keys", metrics)
return GateOutcome("nfstream_csv", "pass", ...)
```

---

### 5.4 `check_merged_dataset(merged_csv, *, ...)` — Lines 190–257

This is the most complex gate. It runs **four independent sub-checks** on the merged CSV in a
single pass through the file.

**Signature with defaults:**
```python
def check_merged_dataset(
    merged_csv: str | Path,
    *,
    min_match_rate: float = 0.90,
    max_unmatched_uid_rate: float = 0.10,
    max_non_tls_quic_rate: float = 0.05,
    max_duplicate_uid_rate: float = 0.0,
) -> GateOutcome:
```

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `min_match_rate` | 0.90 | At least 90% of NFStream flows must have matched a Zeek UID |
| `max_unmatched_uid_rate` | 0.10 | At most 10% of rows may have `uid=NaN` |
| `max_non_tls_quic_rate` | 0.05 | At most 5% of rows may lack all TLS/QUIC signal columns |
| `max_duplicate_uid_rate` | 0.00 | Zero duplicate UIDs tolerated |

Note that `min_match_rate` and `max_unmatched_uid_rate` are **complementary** (`0.90` and `0.10`
sum to 1.0). Both thresholds exist as separate parameters so they can be tightened independently
if needed.

**The counting loop:**
```python
for row in reader:
    total_rows += 1
    uid_value = row.get("uid", "")
    if _is_present(uid_value):
        matched_rows += 1
        uid_counts[uid_value] = uid_counts.get(uid_value, 0) + 1
    else:
        unmatched_rows += 1

    if not row_has_encrypted_signal(row, fieldnames):
        non_encrypted_rows += 1
```

In a single pass it counts:

1. **`matched_rows`** — rows where `uid` is a real value (Zeek matched).
2. **`unmatched_rows`** — rows where `uid` is `NaN`/empty (no Zeek match).
3. **`uid_counts`** — a dict mapping each UID to how many times it appears. Used post-loop to
   count duplicate UIDs.
4. **`non_encrypted_rows`** — rows with no TLS or QUIC signal (via `row_has_encrypted_signal`).

**Duplicate UID calculation:**
```python
duplicate_uid_rows = sum(count - 1 for count in uid_counts.values() if count > 1)
```

For a UID that appears 3 times, `count - 1 = 2` duplicate rows (the first is the legitimate
occurrence, the other two are duplicates). Summing these gives the total count of excess rows due
to uid duplication.

**Why duplicate UIDs in merged.csv are wrong:**

From Tutorial 08 you know the merge is NFStream-left-side. Each NFStream row gets at most one
Zeek UID via `merge_asof`. So duplicate UIDs in the merged output mean two different NFStream
flows were assigned the same Zeek UID — a sign of the directionality expansion (`conn_a +
conn_b`) matching the same Zeek row to two NFStream rows. This is a data integrity problem.

**The four failure checks:**
```python
failures: list[str] = []
if match_rate < min_match_rate:
    failures.append(f"match_rate<{min_match_rate}")
if unmatched_rate > max_unmatched_uid_rate:
    failures.append(f"unmatched_uid_rate>{max_unmatched_uid_rate}")
if non_encrypted_rate > max_non_tls_quic_rate:
    failures.append(f"non_tls_quic_rate>{max_non_tls_quic_rate}")
if duplicate_uid_rate > max_duplicate_uid_rate:
    failures.append(f"duplicate_uid_rate>{max_duplicate_uid_rate}")

if failures:
    return GateOutcome("merged_dataset", "fail", "Merged dataset failed quality gates: " + ", ".join(failures), metrics)
```

All four checks run regardless — the failure message lists every violated threshold, not just the
first one. This is important: if both match rate and non-TLS rate are bad, you want to know about
both in one pipeline run rather than fixing match rate, re-running, and then discovering the TLS
problem.

---

### 5.5 `raise_for_failed_gates(report)` — Lines 260–264

```python
def raise_for_failed_gates(report: QualityReport) -> None:
    if not report.failed:
        return
    failing = [f"{outcome.name}: {outcome.message}" for outcome in report.outcomes if outcome.status == "fail"]
    raise RuntimeError("Quality gates failed: " + " | ".join(failing))
```

The bridge between the `QualityReport` data structure and actual pipeline execution control.

**Pattern:** The gate functions only *record* outcomes — they never raise exceptions themselves.
This separation of concerns lets you run all gates, collect all outcomes, write the JSON report,
and *then* decide whether to stop the pipeline. If `raise_for_failed_gates` was built into each
gate function, you could not write a partial report before raising.

**Typical usage in orchestration:**
```python
report = QualityReport(dataset_name="benign_2024")
report.add(check_pcap_health(pcap_path))
report.add(check_zeek_outputs(zeek_dir))
report.add(check_nfstream_csv(nfstream_csv))
report.add(check_merged_dataset(merged_csv))
report.write(artifacts.quality_report_json)   # always write, even on failure
raise_for_failed_gates(report)                # now stop if anything failed
```

---

## 6. The Three-Level Status System

| Status | Meaning | Pipeline behaviour |
|--------|---------|-------------------|
| `"pass"` | Gate condition fully satisfied | Continue |
| `"warn"` | Suspicious but not definitively broken | Continue with logged warning |
| `"fail"` | Gate condition violated | `raise_for_failed_gates` raises `RuntimeError` |

`"warn"` exists specifically for the capinfos availability case — a missing optional tool should
not block the pipeline, but it should be visible in the quality report so a human can decide
whether to install the tool on production systems.

---

## 7. Complete Data Flow Through the File

```
PCAP file
  └──► check_pcap_health()
         ├─ path.exists() check
         ├─ shutil.which("capinfos")
         ├─ subprocess.run(capinfos -Tm)
         └─ GateOutcome("pcap_health", "pass"/"warn"/"fail", metrics)

Zeek CSV directory
  └──► check_zeek_outputs()
         ├─ path.exists() check
         ├─ glob("*.csv") to get present files
         ├─ set difference for missing_required
         ├─ set intersection for encrypted_evidence
         └─ GateOutcome("zeek_outputs", ...)

NFStream CSV
  └──► check_nfstream_csv()
         ├─ path.exists() check
         ├─ csv.DictReader header validation (FLOW_KEY_COLUMNS)
         ├─ row-by-row duplicate key detection (set of tuples)
         └─ GateOutcome("nfstream_csv", ...)

Merged CSV
  └──► check_merged_dataset()
         ├─ path.exists() check
         ├─ "uid" in fieldnames check
         ├─ single-pass row counting:
         │    matched_rows / unmatched_rows (via _is_present on uid)
         │    uid_counts dict for duplicate detection
         │    non_encrypted_rows (via row_has_encrypted_signal)
         ├─ compute 4 rates
         ├─ check all 4 thresholds, collect all failures
         └─ GateOutcome("merged_dataset", ...)

All GateOutcomes
  └──► QualityReport.add(outcome)  [x4]
         └──► QualityReport.write(json_path)   ← always written
               └──► raise_for_failed_gates(report)  ← raises if any "fail"
```

---

## 8. Interview Questions and Answers

**Q: Why do quality gates run as separate functions instead of raising exceptions inline in the
pipeline stages?**

A: Separating gate logic from processing logic gives three advantages. First, you can run *all*
gates and collect *all* failures before stopping — the pipeline reports every violated threshold
in one go rather than failing on the first bad check. Second, you always write the JSON quality
report before raising, giving you an audit trail even for failed runs. Third, the gate functions
are pure (no side effects other than reading files), which makes them trivially unit-testable
without mocking a whole pipeline run.

---

**Q: What is the difference between `min_match_rate=0.90` and `max_unmatched_uid_rate=0.10`?
Aren't they the same thing?**

A: Mathematically on a single file they sum to 1.0, so they appear redundant. But they are
separate tunable parameters because you might want asymmetric thresholds for different failure
conditions. For example, in a strict production environment you might set `min_match_rate=0.95`
(95% of flows must match) while keeping `max_unmatched_uid_rate=0.10` (warn separately if more
than 10% are unmatched regardless of the match rate calculation). Having both also makes failure
messages clearer — each threshold has its own name in the failure list.

---

**Q: Why use `csv.DictReader` instead of `pd.read_csv` in the gate functions?**

A: Two reasons. First, memory: gate functions on large files (millions of rows) cannot afford to
load the entire DataFrame. `csv.DictReader` processes one row at a time with O(1) memory per row.
Second, speed: the gates only need to count rows and check specific column values — they do not
need pandas' numerical operations, type inference, or indexing. The overhead of loading pandas
and constructing a DataFrame for a counting task would be wasteful.

---

**Q: What does a `non_tls_quic_rate` failure mean practically?**

A: It means more than 5% of rows in the merged CSV show no TLS or QUIC evidence — none of
`version`, `cipher`, `server_name`, `ja3`, `ja3s` are populated and no QUIC column has a value.
This indicates the filtering step (Tutorial 04) leaked non-TLS/QUIC flows into the dataset.
Those rows would pollute an ML model trained to classify TLS traffic. The root fix is to tighten
the `tshark` display filter or check why the BPF/display filter in `filtering.py` passed
non-encrypted traffic.

---

**Q: Why is `max_duplicate_flow_rate=0.0` (zero tolerance) for NFStream but duplicate UIDs are
also zero-tolerance in the merged dataset? Is zero always the right threshold?**

A: For NFStream duplicates: yes, always zero. NFStream processes a single PCAP and produces
exactly one row per bidirectional flow by design. Any duplicate is a bug. For merged dataset
duplicate UIDs: also zero in most cases, but this parameter is tunable. Edge cases where you
might relax it include stress-testing with intentionally duplicated PCAPs or specific research
scenarios involving connection re-use within milliseconds. The default of zero is the correct
production setting.

---

**Q: Why does `check_pcap_health` return `"warn"` when capinfos is missing instead of `"fail"`?**

A: Capinfos is part of Wireshark — it is an optional dependency. In minimal Docker containers
(e.g., Zeek-only images) or CI pipelines that only need the ML training stage, installing the
full Wireshark suite just for a truncation check would be wasteful. The `"warn"` outcome records
that the check was skipped without blocking the pipeline. The decision to treat missing tooling as
a warning versus failure is a conscious trade-off between strict validation and operational
flexibility. On production systems where full Wireshark is installed, `capinfos` will be
present and the gate will run fully.

---

*Next: [Tutorial 10 — Building the ML-Ready Dataset](10_pipeline_build_dataset.md)*
