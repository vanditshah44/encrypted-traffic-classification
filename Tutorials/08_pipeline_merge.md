# Tutorial 08 — Merging Zeek and NFStream Features (`pipeline/merge_features.py`)

## Prerequisites

- Tutorial 03 (`common.py`) — you know `DatasetArtifacts` and what `merged_csv` path is.
- Tutorial 06 (`zeek.py`) — you know Zeek produces `conn.csv`, `ssl.csv`/`tls.csv`, `x509.csv`,
  `quic.csv` in a directory.
- Tutorial 07 (`nfstream.py`) — you know NFStream produces one CSV where every row is a
  bidirectional flow with statistical features.

---

## 1. Why Does This File Exist? The Core Problem

After Tutorials 06 and 07 you have **two independent CSV files** sitting on disk:

| File | Produced by | Key join column | What it knows |
|------|------------|-----------------|---------------|
| `nfstream.csv` | NFStream | 5-tuple (src_ip, dst_ip, src_port, dst_port, proto) + timestamp | Byte counts, inter-arrival times, packet length stats |
| `conn.csv` / `ssl.csv` / `x509.csv` / `quic.csv` | Zeek | `uid` (Zeek's own unique connection ID) | Cipher suite, SNI, JA3 fingerprint, certificate fields |

**The problem:** NFStream does not know Zeek's `uid`. Zeek does not produce NFStream features.
They describe the *same flows* in the network traffic, but they label those flows with completely
different identifiers.

To build a single ML-ready feature row you need **one row per flow** that contains:
- NFStream's behavioral statistics (timing, bytes, lengths)
- Zeek's TLS metadata (cipher, SNI, JA3, certificates)

`merge_features.py` bridges that gap.

```
nfstream.csv                          conn.csv  ssl.csv  x509.csv  quic.csv
(flows with statistics)               (flows with uid + TLS metadata)
        │                                           │
        │    merge on 5-tuple + timestamp           │
        └──────────────────────────────────────────►│
                                                    │
                                             merged.csv
                               (one row = one flow, all features combined)
```

---

## 2. Key Concept — Why You Cannot Join on `uid` Directly

Zeek assigns a `uid` (a random string like `C3l2bD1abc`) internally when it first sees a
connection. NFStream is an entirely separate tool that processes the same PCAP independently — it
never sees Zeek's `uid`.

What both tools *do* agree on is the **5-tuple** that uniquely identifies a connection at the
network level:

```
(source IP, destination IP, source port, destination port, protocol)
```

Both tools also record *when* the connection started (a Unix timestamp in seconds). So the join
key is:

```
5-tuple  +  start_timestamp  (within a tolerance window)
```

This is called a **time-nearest join** or **asof merge** — for each NFStream row find the Zeek
`conn.csv` row that has the same 5-tuple *and* whose timestamp is nearest in time, within
`tolerance_sec` seconds.

---

## 3. Key Concept — The Directionality Problem

NFStream records flows as **bidirectional** — one row covers both directions:

```
NFStream row:
  src_ip=192.168.1.5  src_port=54321  dst_ip=1.2.3.4  dst_port=443  proto=6
```

Zeek records the **originating** side of the connection as `id.orig_h/id.orig_p` and the
**responding** side as `id.resp_h/id.resp_p`. In practice Zeek *always* records the client
(connection initiator) as orig and the server as resp:

```
Zeek conn row:
  uid=C3l2bD  id.orig_h=192.168.1.5  id.orig_p=54321  id.resp_h=1.2.3.4  id.resp_p=443
```

This usually lines up with NFStream — but not always. Some PCAP capture points are mid-network
and may see the server side first, or the traffic may be captured in the reverse direction. To
defend against this, `merge_features.py` creates **two orientations** of every Zeek conn row:

- **Orientation A**: orig→resp  (Zeek's natural order)
- **Orientation B**: resp→orig  (reversed)

The pandas `merge_asof` then tries both orientations and picks the nearest match. This guarantees
a match regardless of which direction the 5-tuple appears in the NFStream CSV.

---

## 4. File Walkthrough — Function by Function

### 4.1 `proto_to_num(p)` — Lines 7–13

```python
def proto_to_num(p):
    if isinstance(p, str):
        p = p.lower()
        if p == "tcp": return 6
        if p == "udp": return 17
        if p == "icmp": return 1
    return np.nan
```

**What it does:** Converts a protocol string to its IANA protocol number.

**Why it exists:** NFStream stores protocol as an integer (6 for TCP, 17 for UDP). Zeek stores it
as a string (`"tcp"`, `"udp"`). You cannot join on `"tcp" == 6`. This function normalises the
Zeek side to integers so both sides speak the same language during the join.

| Zeek string | IANA number |
|-------------|-------------|
| `"tcp"` | 6 |
| `"udp"` | 17 |
| `"icmp"` | 1 |
| anything else | `NaN` (excluded from join) |

Returning `NaN` for unknowns is important — `dropna(subset=["proto_num"])` later removes
ambiguous rows rather than risking wrong matches.

---

### 4.2 `safe_read_csv(path)` — Lines 15–16

```python
def safe_read_csv(path):
    return pd.read_csv(path, low_memory=False)
```

**What it does:** Reads a CSV and disables low-memory mode.

**Why `low_memory=False`:** By default pandas reads a CSV in chunks to save memory, but this
causes it to make mixed dtype guesses per chunk. For flow CSVs with thousands of columns (NFStream
can produce 200+), this causes columns to come back as `object` when they should be `float64`.
`low_memory=False` forces a full pass so dtypes are inferred correctly the first time.

---

### 4.3 `pick_first_per_uid(df)` — Lines 18–22

```python
def pick_first_per_uid(df):
    if df is None or df.empty or "uid" not in df.columns:
        return df
    return df.sort_values(df.columns[0]).drop_duplicates("uid", keep="first")
```

**What it does:** Deduplicates a Zeek log DataFrame so there is exactly one row per `uid`.

**Why needed:** Zeek's `ssl.log` / `tls.log` can produce multiple rows per connection UID. For
example, TLS 1.3 with early data (0-RTT) can produce two handshake events under the same `uid`.
If you merge on `uid` with multiple rows per `uid` you get a **one-to-many join** that explodes
your row count — instead of 1000 flows you suddenly have 1500 rows. Deduplication keeps the join
1-to-1.

`sort_values(df.columns[0])` sorts by the first column, which is typically the timestamp (`ts`),
so `keep="first"` retains the earliest event for that UID — the most informative one for TLS
(the initial handshake).

---

### 4.4 `aggregate_x509(x509)` — Lines 24–71

This is the most complex function in the file. It needs special treatment because x509 data is
fundamentally different from ssl/conn data.

**Background — Why x509 is different:**

A single TLS connection (`uid`) can present **multiple X.509 certificates** — the leaf
certificate plus every intermediate CA certificate in the chain:

```
uid=C3l2bD  →  x509 row 1: leaf cert (example.com)
uid=C3l2bD  →  x509 row 2: intermediate CA (Let's Encrypt R3)
uid=C3l2bD  →  x509 row 3: root CA (ISRG Root X1)
```

You cannot just `pick_first_per_uid` because throwing away the intermediate and root cert rows
loses information. Instead, `aggregate_x509` **summarises** all rows for a UID into a single row
using statistical aggregates.

**Step-by-step walkthrough:**

```python
df = x509.copy()

for c in df.columns:
    if c == "uid":
        continue
    df[c + "__num"] = pd.to_numeric(df[c], errors="coerce")
```

For every column (except `uid`), it attempts to convert values to numbers. Columns like
`certificate.not_valid_after` (a Unix timestamp stored as a float) become proper numerics.
Columns like `certificate.subject` (a string like `"CN=example.com"`) become `NaN` — those
are handled separately below.

```python
str_cols = [c for c in x509.columns if c != "uid" and x509[c].dtype == "object"]
for c in str_cols:
    df[c + "__len"] = x509[c].astype("string").str.len()
```

For string columns, it computes the **character length** of each value. `"CN=example.com"` has
length 14. The intuition: a very long subject name or a very long SAN (Subject Alternative Name)
list is a certificate-level signal. You cannot average strings, but you *can* average their
lengths.

```python
agg_dict = {}
for c in num_cols:
    agg_dict[c] = ["mean", "max", "min"]
for c in len_cols:
    agg_dict[c] = ["mean", "max"]

grouped = df.groupby("uid").agg(agg_dict)
grouped["x509_record_count"] = df.groupby("uid").size()
```

It groups by `uid` and aggregates:
- Numeric columns → mean, max, min
- String-length columns → mean, max
- Always adds `x509_record_count` = how many certificates were in the chain

```python
grouped.columns = ["x509_" + "_".join([str(a) for a in col if a]) for col in grouped.columns.to_flat_index()]
```

After `groupby().agg()` with a dict of lists, pandas produces a MultiIndex column like
`("certificate.not_valid_after__num", "mean")`. This line flattens it to a single string:
`"x509_certificate.not_valid_after__num_mean"`. The `x509_` prefix ensures these columns are
identifiable as coming from x509 data downstream.

**What you get out:**

For each unique `uid`, one row with columns like:
- `x509_certificate.not_valid_after__num_mean` — average expiry time of all certs in chain
- `x509_certificate.not_valid_after__num_max` — latest expiry in chain
- `x509_certificate.subject__len_mean` — average subject name length
- `x509_record_count` — how many certs were in the chain (1 = self-signed, 3 = full chain)

---

### 4.5 `resolve_tls_csv_path(zeek_dir)` — Lines 74–80

```python
def resolve_tls_csv_path(zeek_dir: str | Path) -> Path:
    base_dir = Path(zeek_dir).expanduser().resolve()
    ssl_path = base_dir / "ssl.csv"
    tls_path = base_dir / "tls.csv"
    if ssl_path.exists():
        return ssl_path
    return tls_path
```

**What it does:** Picks between `ssl.csv` and `tls.csv` based on which file exists.

**Why two possible names:** Tutorial 06 (`zeek.py`) explains this: Zeek names the log `ssl.log`
for TLS 1.2 connections and `tls.log` for TLS 1.3 connections. The parser writes out whichever
name Zeek used. This helper function abstracts that ambiguity — the merge logic does not need to
know which version of TLS was in the traffic.

Note: if *neither* exists, the function returns the `tls_path` (a non-existent path). The caller
handles the missing-file case with `if tls_or_ssl_path.exists()`.

---

### 4.6 `merge_nfstream_with_zeek(...)` — Lines 82–201

This is the main function. It is long but follows a clear sequence of steps.

**Signature:**
```python
def merge_nfstream_with_zeek(
    nfstream_csv: str | Path,
    zeek_dir: str | Path,
    out_csv: str | Path,
    *,
    tolerance_sec: float = 2.0,
) -> dict[str, str | int | float]:
```

| Parameter | Type | Default | Meaning |
|-----------|------|---------|---------|
| `nfstream_csv` | path | required | The NFStream output CSV |
| `zeek_dir` | path | required | Directory containing Zeek CSVs |
| `out_csv` | path | required | Where to write the merged CSV |
| `tolerance_sec` | float | `2.0` | Max timestamp difference (in seconds) to still count as a match |

Returns a dict of statistics (row counts, match percentage) so the caller (orchestration, quality
gates) can inspect the match quality without re-reading the output CSV.

---

**Step 1 — Load NFStream CSV (Lines 93–104)**

```python
nf = safe_read_csv(nfstream_csv)

required_nf = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bidirectional_first_seen_ms"]
missing = [c for c in required_nf if c not in nf.columns]
if missing:
    raise RuntimeError(f"NFStream CSV missing required columns: {missing}")

nf["ts"] = nf["bidirectional_first_seen_ms"] / 1000.0
nf["proto_num"] = pd.to_numeric(nf["protocol"], errors="coerce")
```

- Guards that the required join columns exist — fail loudly if NFStream changed its schema.
- Converts `bidirectional_first_seen_ms` (milliseconds since epoch) to `ts` in **seconds** so
  timestamps are comparable with Zeek's `ts` column which is always in seconds.
- Converts `protocol` (already a number in NFStream) to a numeric type with `errors="coerce"` to
  handle any unexpected string values.

---

**Step 2 — Load Zeek CSVs (Lines 107–119)**

```python
conn_path = zeek_dir / "conn.csv"
tls_or_ssl_path = resolve_tls_csv_path(zeek_dir)
x509_path = zeek_dir / "x509.csv"
quic_path = zeek_dir / "quic.csv"

if not conn_path.exists():
    raise FileNotFoundError(...)

conn = safe_read_csv(conn_path)
ssl  = safe_read_csv(tls_or_ssl_path) if tls_or_ssl_path.exists() else None
x509 = safe_read_csv(x509_path) if x509_path.exists() else None
quic = safe_read_csv(quic_path) if quic_path.exists() else None
```

`conn.csv` is **mandatory** — it is the bridge between NFStream flows and Zeek UIDs. Without it,
no matching is possible.

`ssl.csv`/`tls.csv`, `x509.csv`, and `quic.csv` are **optional** — not every PCAP contains TLS
or QUIC traffic (though in practice for this project they should). `None` values are handled
gracefully in later merge steps.

---

**Step 3 — Build the Two-Orientation conn Table (Lines 121–151)**

This is the directionality fix described in Section 3.

```python
conn["proto_num"] = conn["proto"].apply(proto_to_num)

conn_a = conn.rename(columns={
    "id.orig_h": "src_ip",  "id.resp_h": "dst_ip",
    "id.orig_p": "src_port","id.resp_p": "dst_port",
})[["uid","ts","src_ip","dst_ip","src_port","dst_port","proto_num"]]

conn_b = conn.rename(columns={
    "id.orig_h": "dst_ip",  "id.resp_h": "src_ip",
    "id.orig_p": "dst_port","id.resp_p": "src_port",
})[["uid","ts","src_ip","dst_ip","src_port","dst_port","proto_num"]]

conn_expanded = pd.concat([conn_a, conn_b], ignore_index=True).dropna(subset=["proto_num","ts"])
```

`conn_a` = Zeek's natural direction: orig is src, resp is dst.
`conn_b` = Reversed: orig is dst, resp is src.

The resulting `conn_expanded` has **twice as many rows** as `conn`. This is intentional — it
doubles the chance of a 5-tuple match. After the join, a single NFStream row will match at most
one of the two orientations (both orientations carry the same `uid`, so you still end up with
the right Zeek UID either way).

Port and protocol columns are cast to numeric with `errors="coerce"` to avoid type mismatch
errors in `merge_asof`.

---

**Step 4 — Time-Nearest Merge (`merge_asof`) (Lines 157–168)**

```python
nf_sorted    = nf.sort_values("ts")
conn_sorted  = conn_expanded.sort_values("ts")

merged = pd.merge_asof(
    nf_sorted,
    conn_sorted,
    on="ts",
    by=["src_ip","dst_ip","src_port","dst_port","proto_num"],
    direction="nearest",
    tolerance=tolerance_sec
)
```

**`pd.merge_asof` — what it does:**

`merge_asof` is pandas' time-series join. Unlike a regular join which requires exact key equality,
`merge_asof` requires the `on` column (here `ts`) to be sorted and matches each left row to the
nearest right row within a tolerance.

```
NFStream row:  ts=1609459203.5  src_ip=192.168.1.5  src_port=54321 ...
Zeek conn row: ts=1609459202.8  src_ip=192.168.1.5  src_port=54321 ...

Difference: 0.7 sec  < tolerance_sec=2.0  → MATCH
```

The `by=` parameter requires **exact equality** on the 5-tuple fields before the timestamp
proximity is considered. This prevents false matches between different connections that happen to
start at similar times.

`direction="nearest"` means it looks both backward and forward in time (picks the closest), as
opposed to `"backward"` (only look at earlier rows) or `"forward"` (only later rows).

**The tolerance_sec default of 2.0 seconds:**

NFStream and Zeek process the same PCAP but may not timestamp the flow start identically:
- NFStream uses the timestamp of the first packet in the flow.
- Zeek uses the timestamp of the first packet Zeek processes, which may differ slightly due to
  internal batching.

2 seconds is generous enough to absorb any tool-internal delay while still being tight enough to
avoid matching flows from different connections.

After the merge, `merged["uid"]` is `NaN` for any NFStream flow that had no matching Zeek conn
entry within the tolerance window.

---

**Step 5 — Match Rate Reporting (Lines 170–173)**

```python
matched = merged["uid"].notna().sum()
print(f"[OK] NFStream flows: {len(nf)}")
print(f"[OK] Zeek conn rows (expanded): {len(conn_expanded)}")
print(f"[OK] Matched flows with Zeek uid: {matched} ({matched/len(nf)*100:.2f}%)")
```

This is instrumentation only — it logs how many NFStream flows received a Zeek UID. The quality
gate in `pipeline/quality.py` (Tutorial 09) will read the match percentage from the returned
`dict` and fail the pipeline if it falls below an acceptable threshold.

A low match rate (e.g., < 80%) indicates a problem:
- The PCAP was captured in a direction Zeek could not parse.
- The tolerance window is too tight.
- The traffic contains non-TCP/UDP flows that Zeek ignores.

---

**Step 6 — Merge SSL, QUIC, X509 on uid (Lines 175–189)**

```python
if ssl is not None and "uid" in ssl.columns:
    ssl = pick_first_per_uid(ssl)
    merged = merged.merge(ssl, on="uid", how="left", suffixes=("", "_zeek_ssl"))

if quic is not None and "uid" in quic.columns:
    quic = pick_first_per_uid(quic)
    merged = merged.merge(quic, on="uid", how="left", suffixes=("", "_zeek_quic"))

if x509 is not None and "uid" in x509.columns:
    x509_agg = aggregate_x509(x509)
    merged = merged.merge(x509_agg, on="uid", how="left")
```

Now that every NFStream row has a Zeek `uid` (where a match was found), you can do straightforward
`uid`-keyed left joins.

**Why `how="left"`:** You do not want to lose NFStream rows that have no TLS metadata (e.g., plain
TCP flows that passed through the filter, or flows where Zeek did not produce an ssl entry). A
left join keeps all NFStream rows and fills TLS columns with `NaN` for those rows.

**Why `suffixes=("", "_zeek_ssl")`:** If NFStream and Zeek happen to produce a column with the
same name (e.g., both have a `ts` column), pandas would normally suffix both. The empty string
`""` keeps the NFStream column name intact, while `"_zeek_ssl"` is appended to the Zeek
duplicate. This avoids the default `_x`/`_y` suffixes which are harder to interpret downstream.

`x509` uses `aggregate_x509()` (Section 4.4) instead of `pick_first_per_uid()` because the
cert chain has multiple rows — you aggregate rather than discard.

---

**Step 7 — Write Output and Return Stats (Lines 191–201)**

```python
merged.to_csv(out_path, index=False)
print(f"[DONE] Saved merged CSV: {out_path}")
return {
    "nfstream_csv": str(...),
    "zeek_dir": str(zeek_dir),
    "out_csv": str(out_path),
    "nfstream_rows": int(len(nf)),
    "conn_rows_expanded": int(len(conn_expanded)),
    "matched_rows": int(matched),
    "matched_pct": float((matched / len(nf) * 100.0) if len(nf) else 0.0),
}
```

The returned dict is a **provenance record** — it captures what went in, what came out, and the
match quality. The orchestration layer stores this for lineage tracking.

`index=False` prevents pandas from writing an unnamed integer index column (which would show up
as `Unnamed: 0` in downstream reads — a classic pandas footgun).

---

### 4.7 `main(argv)` — Lines 203–221

```python
def main(argv: list[str] | None = None):
    ap = argparse.ArgumentParser(...)
    ap.add_argument("--nfstream", required=True, ...)
    ap.add_argument("--zeek-dir", required=True, ...)
    ap.add_argument("--out", required=True, ...)
    ap.add_argument("--tolerance-sec", type=float, default=2.0, ...)
    args = ap.parse_args(argv)
    results = merge_nfstream_with_zeek(...)
    print(f"matched_rows={results['matched_rows']}")
    return 0
```

Provides a CLI interface so this module can be run as a standalone script:

```bash
python -m tls_dataset.pipeline.merge_features \
  --nfstream artifacts/nfstream.csv \
  --zeek-dir artifacts/zeek/ \
  --out artifacts/merged.csv \
  --tolerance-sec 2.0
```

The `argv=None` pattern (passing `None` falls through to `sys.argv`) means the function is also
unit-testable by passing a list of strings: `main(["--nfstream", "a.csv", ...])`.

---

## 5. Complete Data Flow Through the File

```
nfstream.csv
  (N rows, each = 1 bidirectional flow)
        │
        │  Step 1: load, validate columns, convert ts to seconds
        ▼
  nf_sorted (sorted by ts)

conn.csv
  (M rows, each = 1 Zeek connection with uid)
        │
        │  Step 3: build conn_a (orig→resp) + conn_b (resp→orig)
        ▼
  conn_expanded (2M rows, sorted by ts)

        │
        │  Step 4: pd.merge_asof on ts, by 5-tuple, tolerance=2s
        ▼
  merged (N rows, now with uid where a Zeek conn matched)

ssl.csv / tls.csv
  (P rows, 1 per TLS handshake, deduplicated to 1 per uid)
        │
        │  Step 6a: left join on uid
        ▼
  merged (N rows, now with TLS columns: cipher, SNI, JA3...)

quic.csv
  (Q rows, deduplicated to 1 per uid)
        │
        │  Step 6b: left join on uid
        ▼
  merged (N rows, now with QUIC metadata where applicable)

x509.csv
  (R rows, MULTIPLE per uid — cert chain)
        │
        │  Step 6c: aggregate_x509 → 1 row per uid → left join
        ▼
  merged.csv
  (N rows, all features combined: NFStream stats + Zeek TLS + cert chain aggregates)
```

---

## 6. What the Output CSV Looks Like

The merged CSV has one row per NFStream flow. Its columns come from four sources:

| Column group | Source | Example columns |
|-------------|--------|-----------------|
| NFStream flow features | NFStream | `bidirectional_bytes`, `src2dst_packets`, `bidirectional_mean_ps`, `bidirectional_stddev_ps` |
| Derived from NFStream | This file | `ts` (converted from ms), `proto_num` |
| Zeek connection metadata | `conn.csv` | `uid`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state` |
| TLS handshake metadata | `ssl.csv`/`tls.csv` | `server_name` (SNI), `cipher`, `ja3`, `ja3s`, `version` |
| QUIC metadata (if present) | `quic.csv` | `version`, `server_name` (QUIC SNI) |
| Certificate chain aggregates | `x509.csv` | `x509_record_count`, `x509_certificate.not_valid_after__num_mean`, `x509_certificate.subject__len_mean` |

Rows where no Zeek UID was found have `uid=NaN` and all Zeek-sourced columns are `NaN`. These are
not immediately dropped here — the quality gate in Tutorial 09 decides whether the unmatched rate
is acceptable.

---

## 7. Interview Questions and Answers

**Q: Why use `merge_asof` instead of a regular pandas `merge`?**

A: A regular merge requires exact equality on all join keys. Timestamp equality is impossible here
because NFStream and Zeek independently process the same PCAP and may record the flow start time
at slightly different instants. `merge_asof` performs a time-nearest join — it requires exact
equality on the 5-tuple and then finds the nearest timestamp within a tolerance window. This is
the correct approach for joining two independent tools processing the same network stream.

---

**Q: Why does the code double the Zeek conn rows (`conn_a` + `conn_b`)?**

A: NFStream records flows with a consistent src/dst orientation derived from the packet capture
point. Zeek always assigns the connection initiator (client) as `orig` and the server as `resp`.
These may or may not agree depending on where the traffic was captured. By creating a forward and
a reversed version of every Zeek row, the join can match regardless of orientation.

---

**Q: Why is `conn.csv` mandatory but `ssl.csv` and `x509.csv` optional?**

A: `conn.csv` contains the `uid` that links Zeek and NFStream. Without it, there is no way to
attach any Zeek metadata to NFStream flows — the whole merge fails. `ssl.csv`, `x509.csv`, and
`quic.csv` are value-add: they enrich rows that already matched via `conn.csv`. Not every flow
will have a corresponding TLS handshake or QUIC session, so missing these files is handled
gracefully with a left join.

---

**Q: What does a low match rate (e.g., 60%) indicate?**

A: It means 40% of NFStream flows could not be matched to a Zeek UID. Possible causes:
1. **Directionality not covered** — both orientations failed, unusual for legitimate traffic.
2. **Tolerance too tight** — the 2-second window was too small for some flows.
3. **Non-TCP/UDP traffic** — e.g., ICMP or GRE flows that Zeek did not log in `conn.log`.
4. **Filtered flows** — flows that passed NFStream's threshold but Zeek considered too short.
5. **PCAP truncation** — some flows had their SYN/handshake cut off so Zeek never opened a `uid`.

The quality gate in Tutorial 09 will raise an error if the match rate falls below a configured
threshold.

---

**Q: Why aggregate x509 instead of just keeping the first certificate?**

A: The certificate chain carries important information. A self-signed certificate
(`x509_record_count=1`) looks very different from a properly chained CA-signed certificate
(`x509_record_count=3`). Malicious actors often use self-signed or short-chain certificates.
Discarding chain-length information by keeping only the first cert would lose that signal. The
aggregation strategy preserves the chain structure as numerical features the ML model can use.

---

**Q: What is the `tolerance_sec=2.0` default based on?**

A: It is an empirical threshold chosen to absorb the small timestamp discrepancy between two
tools processing the same PCAP independently. The actual difference is typically under 1ms (both
read from disk). The 2-second window is intentionally generous to handle edge cases like:
- Very large PCAPs where processing latency causes slight offset.
- Flows that start near a PCAP capture boundary.
Any larger tolerance risks matching flows from different connections that happen to share a
5-tuple within a short time window (e.g., rapid connection re-use on the same port).

---

*Next: [Tutorial 09 — Quality Gates](09_pipeline_quality_gates.md)*
