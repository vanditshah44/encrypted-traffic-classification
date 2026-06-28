# Tutorial 18 — NFStream Inspection Utility (`pipeline/inspect.py`)

## Prerequisites

- Tutorial 07 (`nfstream.py`) — know what columns NFStream produces, specifically `protocol`
  and `tls_version`.
- Tutorial 13 (`orchestration.py`) — this function is the last call in `run_dataset_pipeline`,
  at line 128, after all transformation stages have completed.

---

## 1. Why This File Exists

Every pipeline stage from Tutorial 04 onwards transforms data. After `run_dataset_pipeline`
completes, you have `ml_final.csv` — but you have not yet seen a human-readable summary of what
NFStream actually extracted from the PCAP. Questions that matter before you trust the pipeline
output:

- How many flows did NFStream find?
- Which transport protocols are present — is it really TLS-heavy?
- What TLS versions appear — is this 1.2 or 1.3 traffic?

`inspect.py` answers these without requiring you to manually load the NFStream CSV in a notebook.
It is a **read-only diagnostic** — it does not transform or filter anything — and it runs at the
end of every orchestrated pipeline run so the answers are always available in the return dict.

The file is intentionally minimal. Its job is observation, not computation. Keeping it small and
side-effect-free means it can always run safely as the final step regardless of what happened
upstream.

---

## 2. `inspect_nfstream_csv(input_csv, *, top_n)` — Lines 12–27

```python
def inspect_nfstream_csv(input_csv: str | Path, *, top_n: int = 5) -> dict[str, object]:
    input_path = Path(input_csv).expanduser().resolve()
    df = pd.read_csv(input_path, low_memory=False)

    summary: dict[str, object] = {
        "input_csv": str(input_path),
        "flows": int(len(df)),
        "columns": int(len(df.columns)),
    }

    if "protocol" in df.columns:
        summary["top_protocols"] = df["protocol"].value_counts().head(top_n).to_dict()
    if "tls_version" in df.columns:
        summary["tls_version_distribution"] = df["tls_version"].value_counts(dropna=False).head(top_n).to_dict()

    return summary
```

### `top_n=5` as keyword-only

`*` makes `top_n` keyword-only — it cannot be passed positionally. The default of 5 is
practical: it covers TCP, UDP, ICMP, and a couple of others in a typical capture without
flooding the log. For a capture dominated by a single protocol (pure TLS over TCP), `top_n=1`
would suffice; for research with diverse traffic, `top_n=10` gives more detail. Making it a
named parameter instead of hardcoded makes it tunable from the CLI or by the orchestration
caller without touching any source code.

### The three always-present keys

`"input_csv"`, `"flows"`, `"columns"` are populated unconditionally.

- `"flows"` = `len(df)` = number of rows = number of bidirectional flows NFStream found in the
  PCAP. A flow count of 0 immediately signals that either the PCAP was empty or NFStream failed
  silently. A flow count far lower than expected (e.g., 50 when you expected 50,000) signals that
  the PCAP was truncated or filtered too aggressively.

- `"columns"` = the feature dimension of this NFStream output. NFStream's column count varies
  with its configuration — `statistical_analysis=True` adds ~40 columns, `splt_analysis=20`
  adds 40 more (packet length and inter-arrival time for first 20 packets per direction). A
  column count of 20 when you expected 200 tells you the statistical analysis was not enabled.

### `protocol` — without `dropna=False`

```python
summary["top_protocols"] = df["protocol"].value_counts().head(top_n).to_dict()
```

The `protocol` column in NFStream is an IANA protocol number (6 for TCP, 17 for UDP, 1 for
ICMP). Every flow has a protocol — it is a mandatory field derived from the IP header. `NaN`
in `protocol` would mean a flow with an unrecognised or corrupt protocol field. Excluding NaN
from the count (the default `value_counts()` behaviour) is correct here: an unrecognised
protocol is not a meaningful category to report in the top-N list.

A typical output:
```python
{"top_protocols": {6: 42801, 17: 7243, 1: 312}}
# TCP (6) = 42801 flows, UDP (17) = 7243, ICMP (1) = 312
```

### `tls_version` — with `dropna=False`

```python
summary["tls_version_distribution"] = df["tls_version"].value_counts(dropna=False).head(top_n).to_dict()
```

`tls_version` is an NFStream field populated only for flows where NFStream's nDPI module
identified TLS and recorded the negotiated version (e.g., `"TLS 1.3"`, `"TLS 1.2"`). For
UDP flows, ICMP flows, or TCP flows that aren't TLS, this column is `NaN`.

`dropna=False` is **deliberately different** from the `protocol` column. The `NaN` count for
`tls_version` is itself diagnostic — it tells you how many flows had no TLS version (i.e.,
were not TLS). A typical output on a TLS-filtered PCAP:

```python
{"tls_version_distribution": {"TLS 1.3": 39801, "TLS 1.2": 8240, None: 5015}}
# 5015 flows are non-TLS (NaN shown as None in the dict)
```

If 5015 non-TLS flows remain despite the `tls or quic` display filter, this is the signal you
need: the filter passed some non-TLS traffic and the `max_non_tls_quic_rate` quality gate (Tutorial 09)
should have caught this if the rate exceeded 5%. Seeing it here, in a plain count, makes the
situation immediately legible.

The asymmetry between the two `value_counts` calls is intentional. For `protocol`, NaN is
meaningless noise. For `tls_version`, NaN is informative signal about the composition of the
traffic.

### Defensive column checks

```python
if "protocol" in df.columns:
    ...
if "tls_version" in df.columns:
    ...
```

Neither column is guaranteed to exist. `tls_version` in particular is not a standard NFStream
output column in all versions — it was added in a later release. If it is absent, the summary
simply omits that key. The caller checks for `summary.get("tls_version_distribution")` rather
than `summary["tls_version_distribution"]`. This makes the function forward and backward
compatible with different NFStream versions without any version-checking logic.

### Return value shape

```python
return {
    "input_csv": str(input_path),
    "flows": int(len(df)),
    "columns": int(len(df.columns)),
    # optionally:
    "top_protocols": {...},
    "tls_version_distribution": {...},
}
```

The return dict is **not fixed-schema** — it may have 3, 4, or 5 keys depending on which
columns were present. This is consistent with every other pipeline function's return dict and
makes `inspect_nfstream_csv` composable: it is included as `results["inspect"]` in the
orchestration return dict (Tutorial 13, line 137), and callers extract only the keys they care
about.

---

## 3. Where It Sits in the Pipeline

From Tutorial 13:

```python
# orchestration.py line 128
inspect_results = inspect_nfstream_csv(resolved_nfstream_csv)
```

It runs after `finalize_feature_dataset` — after all transformation is complete. It reads the
NFStream CSV, not the final ML CSV. This is intentional: the NFStream CSV is the raw extraction
output before any filtering, merging, pruning, or column dropping. Inspecting it gives you the
ground truth about what came out of the PCAP, not what survived the transformation chain.

If you want to understand the full funnel:

```
NFStream flows: 50,000           ← from inspect_results["flows"]
  TLS-only rows: 43,200          ← from build_results["tls_rows"]
  Matched to Zeek UID: 41,000    ← from merge_results["matched_rows"]
  ml_ready rows: 41,000          ← from build_results["ml_rows"]
  ml_final rows: 41,000          ← from finalize_results["rows"]
  ml_final columns: 80           ← from finalize_results["columns"]
```

`inspect_results["flows"]` is the entry point of that funnel — the total before any filtering.

---

## 4. The `main()` Function

```python
parser.add_argument("--top-n", type=int, default=5, help="Number of top values to report")
```

The `--top-n` CLI flag exposes the `top_n` parameter directly. This lets you run the inspection
standalone on any NFStream CSV without writing Python:

```bash
python -m tls_dataset.pipeline.inspect \
  --input artifacts/ctu13_s1_nfstream.csv \
  --top-n 10
```

Output:
```
input_csv=/path/to/ctu13_s1_nfstream.csv
flows=50213
columns=196
top_protocols={6: 44821, 17: 5312, 1: 80}
tls_version_distribution={'TLS 1.3': 39100, 'TLS 1.2': 5721, None: 5392}
```

This gives you the essential traffic composition in under a second without loading the data
into a notebook or writing any analysis code.

---

## 5. Interview Questions and Answers

**Q: Why does `tls_version` use `dropna=False` but `protocol` does not?**

A: For `protocol`, NaN means a corrupt or unrecognised IP protocol number — not a meaningful
category worth reporting. For `tls_version`, NaN means "this flow is not TLS" — which is
precisely the information you want to see. The NaN count for `tls_version` tells you how many
flows in the NFStream output are not TLS-encrypted. If that count is unexpectedly high in a
post-filter capture, it is a data quality signal that the display filter may have passed
non-TLS traffic. The asymmetry in `dropna` reflects the semantic difference between the two
NaN populations.

---

**Q: Why does this function run at the very end of `run_dataset_pipeline` rather than at the
beginning?**

A: It is a diagnostic that summarises the NFStream extraction result. Running it at the
beginning would mean running it before the pipeline has had a chance to validate, merge, and
process the data — the flow count would be available but no downstream context would exist to
interpret it against. Running it at the end means `inspect_results["flows"]` is available in
the same return dict as `merge_results["matched_rows"]` and `build_results["tls_rows"]` — you
can immediately compare the three numbers to understand the full filtering funnel in one look.

---

**Q: This file is only 44 lines. Why does it exist as a separate module rather than just being
two lines inside `orchestration.py`?**

A: Two reasons. First, it is independently useful as a CLI tool — you can run it against any
NFStream CSV from any source, not just ones produced by this pipeline. Making it a standalone
module with its own `main()` gives it that utility. Second, the separation follows the pipeline's
design principle: each module has one clear responsibility. Orchestration wires stages together;
inspection observes output. Embedding inspection logic in orchestration would blur that boundary
and make the orchestrator harder to test in isolation.

---

*Next: [Tutorial 19 — ML Workflow](19_ml_workflow.md)*
