# Tutorial 06 — Zeek Log Format Detection and Conversion (`pipeline/zeek.py`)

## Prerequisites

- Tutorial 05 (Zeek Runner) — you understand that `run_zeek_on_pcap()` drops `.log` files into
  an output directory. This tutorial covers what happens to those `.log` files next.
- Basic familiarity with CSV, JSON, and tab-separated values.

---

## 1. What Problem Does This File Solve?

After Zeek finishes running, you have a directory of `.log` files. The trouble is that Zeek can
produce them in **two completely different text formats** depending on how Zeek was installed or
configured:

| Format | Description | Example first line |
|--------|-------------|-------------------|
| **Zeek TSV** (default) | A special tab-separated format with metadata comment headers | `#separator \x09` |
| **JSON Lines** | Each event is one JSON object on its own line | `{"ts":1609459200.1,"uid":"C…"}` |

The format is set by the Zeek site policy (`LogAscii::use_json` in `local.zeek`). You have no
control over which format a given Zeek installation produces — you get whatever the system
operator chose.

`zeek.py` solves this by:

1. **Detecting** the format without asking the user
2. **Parsing** whichever format it finds
3. **Writing out a clean CSV** that the rest of the pipeline (merging, ML) can read uniformly

```
┌──────────────┐     sniff_format()    ┌─────────────────┐
│  conn.log    │──────────────────────►│ "zeek_tsv"      │
│  ssl.log     │                       │ "json"          │
│  tls.log     │                       │ "unknown"       │
│  x509.log    │                       └────────┬────────┘
│  quic.log    │                                │
│  http.log    │                   ┌────────────▼──────────────┐
└──────────────┘                   │ convert_zeek_tsv_to_csv() │
                                   │ convert_json_lines_to_csv()│
                                   └────────────┬──────────────┘
                                                │
                                        ┌───────▼──────┐
                                        │ conn.csv     │
                                        │ ssl.csv      │
                                        │ tls.csv      │
                                        │ x509.csv     │
                                        │ quic.csv     │
                                        └──────────────┘
```

---

## 2. The Two Zeek Log Formats — Background

Before diving into code, you need to understand both formats deeply so the parsing code makes
complete sense.

### 2a. Zeek TSV Format (the default)

The "Zeek TSV" format is NOT a plain TSV file. It has a preamble of comment lines that begin with
`#`. These comment lines contain metadata about the log itself:

```
#separator \x09
#set_separator ,
#empty_field (empty)
#unset_field -
#path ssl
#open 2021-10-01-00-00-00
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p version cipher curve ...
#types  time  string addr  port  addr  port  string string  string ...
C9ZqwX1Sz34TZcAK1g  192.168.1.5  54321  1.2.3.4  443  TLSv12  ...
```

**Key comment lines:**

| Line | Meaning |
|------|---------|
| `#separator \x09` | Field separator is tab (hex `09`). `\x09` is Zeek's literal notation for tab. |
| `#set_separator ,` | When a field holds a set of values, they are comma-separated within the field |
| `#empty_field (empty)` | A field that is empty (not the same as unset) contains this literal string |
| `#unset_field -` | A field that has no value contains a literal hyphen `-` |
| `#path ssl` | The log type (conn, ssl, x509, etc.) |
| `#open` | Timestamp when Zeek opened this log file |
| `#fields` | **The column names** — the most important comment line |
| `#types` | The data type of each column (time, string, addr, port, etc.) |

After the `#close` comment at the end, the file is closed.

The **data rows** are just tab-separated values. No `#` prefix. Simple.

### 2b. JSON Lines Format

When `LogAscii::use_json = T` in the Zeek policy, every logged event becomes a JSON object on its
own line:

```
{"ts":1633046400.123456,"uid":"C9ZqwX1Sz34TZcAK1g","id.orig_h":"192.168.1.5","id.orig_p":54321,...}
{"ts":1633046401.654321,"uid":"D7AbPQ2Ty45UaDLM2h","id.orig_h":"192.168.1.7","id.orig_p":55555,...}
```

**Characteristics:**
- One JSON object per line. Empty lines are ignored.
- The opening `{` and closing `}` are always on the same line.
- Field names include dots (e.g., `id.orig_h`). These are valid JSON keys.
- Timestamps are Unix epoch floats.
- Missing fields simply do not appear in the object — no `-` sentinel.

**The complication with JSON Lines:**

Different events (rows) **may have different keys**. For example, an ssl.log entry for a TLS 1.2
connection might include `"curve"` while a TLS 1.3 entry adds `"next_protocol"`. This means you
cannot just read the first row's keys and use them as columns — you need to scan the entire file to
find the **union of all keys** across all rows.

---

## 3. `LOGS_OF_INTEREST` — Which Logs Matter

```python
# zeek.py  line 7
LOGS_OF_INTEREST = ["conn.log", "ssl.log", "tls.log", "x509.log", "quic.log", "http.log"]
```

Zeek produces many log files. On a busy network capture you might see:
`conn.log`, `ssl.log`, `tls.log`, `x509.log`, `quic.log`, `http.log`, `dns.log`, `weird.log`,
`notice.log`, `reporter.log`, `dpd.log`, `capture_loss.log`, `packet_filter.log`, ...

For this project, we care only about six:

| Log file | What it contains | Why we need it |
|----------|-----------------|----------------|
| `conn.log` | Every connection: src IP/port, dst IP/port, duration, bytes, protocol, service | Core join key, timing, byte counts |
| `ssl.log` | TLS handshake fields: version, cipher suite, SNI, JA3 fingerprint, validation status | The primary TLS-specific features |
| `tls.log` | Similar to ssl.log — in newer Zeek versions the TLS analyser writes here | Overlap with ssl.log; kept for compatibility |
| `x509.log` | Certificate details: subject, issuer, validity dates, public key info | Certificate-based features (self-signed, expired certs are malware signals) |
| `quic.log` | QUIC connection metadata: version, SNI, CID | QUIC-encrypted traffic features |
| `http.log` | HTTP requests/responses (unencrypted or after decryption) | Secondary; kept in case HTTP is mixed in |

**What `all_logs=True` does:** Converts every `.log` file in the directory, not just these six.
Useful for debugging (e.g., you want to see `weird.log` to understand why a connection failed).

---

## 4. `sniff_format()` — The Format Detector

```python
# zeek.py  lines 9–27
def sniff_format(log_path: Path) -> str:
    """
    Returns: "json", "zeek_tsv", or "unknown"
    """
    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for _ in range(50):
            line = f.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            if line.startswith("#fields") or line.startswith("#separator"):
                return "zeek_tsv"
            if line.startswith("{") and line.endswith("}"):
                return "json"
    return "unknown"
```

### Line-by-line walkthrough

**`log_path.open("r", encoding="utf-8", errors="ignore")`**

Opens the file as text. `errors="ignore"` means that if there are any bytes that cannot be decoded
as UTF-8 (e.g., a stray binary character in a log), they are silently dropped. This makes the
parser more robust against corrupt or partially truncated logs.

**`for _ in range(50):`**

Reads at most 50 lines. This is a "header scan" — we only need to find the format marker. Reading
the whole file to detect format would be wasteful for large logs (ssl.log from a busy network can
be gigabytes). 50 lines is generous: the `#fields` line in a Zeek TSV file always appears within
the first 8–10 lines; the first JSON object in a JSON Lines file is always line 1 (possibly after
a blank line or two).

**`line = f.readline()`**

`readline()` returns an empty string `""` at end-of-file (distinct from `"\n"` for an empty line).
The `if not line: break` check correctly stops when the file ends, not when it encounters an empty
line.

**`line.strip()`**

Removes leading/trailing whitespace including `\n`. After stripping, a truly empty line becomes
`""` which is falsy — the `if not line: continue` skips it.

**`if line.startswith("#fields") or line.startswith("#separator"):`**

Either of these markers definitively identifies Zeek TSV format:
- `#separator` is literally the first comment line in every Zeek TSV file (before `#fields`)
- `#fields` defines the columns

We check for both because technically `#separator` always appears first — but checking `#fields`
too makes the function work even if someone feeds it a partial file that is missing the separator
line.

**`if line.startswith("{") and line.endswith("}"):`**

A Zeek JSON Lines object always starts with `{` and ends with `}` on the same line.

**Why check both ends?**
- `line.startswith("{")` alone might match a line like `{  ← broken json` that has no closing `}`
- Combined check `startswith("{") and endswith("}")` is a minimal syntactic sanity check that the
  whole JSON object is on this one line

After `.strip()`, a complete JSON object like `{"ts":1.0,...}` will always start with `{` and end
with `}`. An opening-only brace (from formatted multi-line JSON) would not end with `}`.

**`return "unknown"`**

If after 50 lines no marker was found, we return `"unknown"`. The caller (`convert_zeek_logs`)
will skip the file with a warning:

```python
else:
    print(f"[WARN] Unknown format, skipping: {p.name}")
    continue
```

### Why not try `json.loads()` to detect JSON?

You could attempt to `json.loads()` the first line and catch `json.JSONDecodeError` to distinguish
JSON from non-JSON. The string heuristic (`startswith("{") and endswith("}")`) is preferred
because:
1. It is **O(1)** — no parsing cost
2. Avoids try/except overhead in the detection path
3. Is reliable enough for Zeek's well-structured output

---

## 5. `convert_json_lines_to_csv()` — JSON Lines → CSV

```python
# zeek.py  lines 29–65
def convert_json_lines_to_csv(log_path: Path, out_csv: Path):
    # First pass: collect keys (columns) safely (cap to avoid insane memory)
    keys = []
    keys_set = set()

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if not (line.startswith("{") and line.endswith("}")):
                continue
            obj = json.loads(line)
            for k in obj.keys():
                if k not in keys_set:
                    keys_set.add(k)
                    keys.append(k)

    if not keys:
        print(f"[WARN] No JSON objects found in {log_path.name}")
        return

    with out_csv.open("w", newline="", encoding="utf-8") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=keys)
        writer.writeheader()

        with log_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if not (line.startswith("{") and line.endswith("}")):
                    continue
                obj = json.loads(line)
                writer.writerow(obj)
```

### Why two passes?

This is the core design decision of this function. Let's understand why a single pass would not
work.

**The problem:** CSV requires you to write the header row (column names) **before** any data rows.
With JSON Lines, you don't know all the column names until you've seen every row (because different
rows may have different keys). You cannot go back and insert a header row after writing data rows
to a file — files are sequential writes.

**Two-pass solution:**

```
Pass 1: Read entire file → collect union of all keys → ordered list
         ┌──────────────────────────────────────────────────────┐
         │ row 1: {ts, uid, id.orig_h, id.orig_p, version}     │
         │ row 2: {ts, uid, id.orig_h, id.orig_p, curve}       │ → keys = [ts, uid, id.orig_h,
         │ row 3: {ts, uid, id.orig_h, id.orig_p, next_proto}  │           id.orig_p, version,
         └──────────────────────────────────────────────────────┘           curve, next_proto]

Pass 2: Open output CSV → write header → read file again → write rows
         header: ts, uid, id.orig_h, id.orig_p, version, curve, next_proto
         row 1:  val, val, val,       val,        val,     ,      (missing → empty)
```

### The key data structure: `keys` list + `keys_set` set

```python
keys = []        # ordered list of column names (preserves insertion order)
keys_set = set() # hash set for O(1) membership testing
```

**Why both?**

- A Python `set` has O(1) membership test (`k not in keys_set`) — crucial for performance
- A Python `set` is **unordered** — we need deterministic column order in the CSV
- A Python `list` preserves insertion order — columns appear in the order we first encounter them
- `dict` (Python 3.7+) also preserves insertion order; using a set+list is more explicit

**The update pattern:**
```python
for k in obj.keys():
    if k not in keys_set:    # O(1) check: have we seen this key before?
        keys_set.add(k)      # mark as seen
        keys.append(k)       # add to ordered list
```

The first time we see a key, it goes into both structures. On subsequent encounters, `k not in
keys_set` is False so we skip it. Result: `keys` contains every unique key, in first-encounter
order.

### `csv.DictWriter`

```python
writer = csv.DictWriter(out_f, fieldnames=keys)
writer.writeheader()
...
writer.writerow(obj)
```

`csv.DictWriter` accepts a `dict` per row instead of a list. The `fieldnames` argument defines the
column order. When you call `writer.writerow(obj)`:
- Keys in `obj` that are in `fieldnames` → written to the correct column
- Keys in `fieldnames` that are NOT in `obj` → written as empty string (the `restval` default)
- Keys in `obj` that are NOT in `fieldnames` → ignored (controlled by `extrasaction` default)

This is why the two-pass approach works: after Pass 1, `fieldnames=keys` covers every key that
can appear in any row. Pass 2 then writes each row dict and missing keys are filled with `""`.

### `newline=""` in `open()`

```python
with out_csv.open("w", newline="", encoding="utf-8") as out_f:
```

When writing CSV on Windows, Python's universal newline translation would convert `\n` to `\r\n`,
and then `csv.writer` would add its own `\r\n`, resulting in double newlines (`\r\r\n`). Passing
`newline=""` disables Python's newline translation and lets `csv.writer` handle line endings
correctly on all platforms. This is the documented best practice in Python's `csv` module docs.

### Guard: `if not (line.startswith("{") and line.endswith("}")):`

Both passes use this guard. It skips:
- Blank lines
- Lines that are part of non-JSON content (unlikely in a Zeek JSON log, but defensive)
- Any log preamble or footer lines that might not be JSON objects

---

## 6. `parse_zeek_tsv_header()` — Extracting the Schema

```python
# zeek.py  lines 67–94
def parse_zeek_tsv_header(log_path: Path):
    """
    Parses Zeek default log format and returns:
      separator (str), fields (list[str])
    """
    separator = "\t"
    fields = None

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#separator"):
                # Example: "#separator \x09"
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    sep_token = parts[1]
                    # Zeek writes \x09 for tab
                    if "\\x09" in sep_token:
                        separator = "\t"
                    else:
                        separator = sep_token.encode("utf-8").decode("unicode_escape")
            elif line.startswith("#fields"):
                parts = line.split()
                fields = parts[1:]
                break

    return separator, fields
```

### Line-by-line walkthrough

**`separator = "\t"`**

Default to tab. Zeek's default separator IS tab, so even if we fail to parse `#separator`, the
default is correct for a standard Zeek installation.

**`fields = None`**

Start with None. After parsing, `fields is None` means the file had no `#fields` line — an
indicator of a malformed or empty file.

**`line.rstrip("\n")`**

Note this is `rstrip("\n")` not `strip()`. We need to preserve spaces within the line for correct
splitting. For example, `#separator \x09` must split on space to separate `#separator` from
`\x09`. Using `strip()` would also strip leading spaces (which don't appear here, but preserving
only trailing newlines is the right approach).

**Parsing `#separator`:**

```
line = "#separator \x09"
parts = line.split(" ", 1)
→ parts = ["#separator", "\\x09"]
           [0]            [1]
```

`split(" ", 1)` splits on the first space only. `maxsplit=1` ensures that if the separator itself
contains a space, it is not further split.

**`if "\\x09" in sep_token:`**

This is a subtle Python string distinction:

- `"\x09"` (double-quote, backslash, x, 0, 9) — when Python processes this string literal, `\x09`
  is an escape sequence that becomes a single tab character. The string has 1 character: `\t`.

- `"\\x09"` (with double backslash) — the `\\` is an escaped backslash, so this is a 4-character
  string: `\`, `x`, `0`, `9`. This is the **literal text** that Zeek writes in the log file.

So in the log file, the text is literally: `#separator \x09` — the characters backslash, x, 0, 9.
When Python reads that from the file, `sep_token` is the string `\x09` (4 chars: `\`, `x`, `0`,
`9`). The check `"\\x09" in sep_token` asks: does this 4-char literal appear in sep_token?

```
File on disk:  #separator \x09
                           ^^^^  ← 4 characters: \, x, 0, 9
sep_token in Python: "\\x09"    ← 4-char Python string: \x09
"\\x09" in sep_token → True
```

When this is True, we know the separator is tab, so: `separator = "\t"` (actual tab character).

**The else branch — `unicode_escape` decode:**

```python
separator = sep_token.encode("utf-8").decode("unicode_escape")
```

For any other separator Zeek might write (e.g., `\x20` for space), this chain works:
1. `sep_token.encode("utf-8")` → bytes: `b"\\x20"` (backslash, x, 2, 0)
2. `.decode("unicode_escape")` → interprets `\x20` as a unicode escape → `" "` (space)

This is a Python trick: the `unicode_escape` codec interprets `\x09`, `\x20`, `\x2c` etc. as
their character equivalents, effectively doing what Python's own string literal parser does.

**Parsing `#fields`:**

```
line = "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p version cipher ..."
parts = line.split()
→ ["#fields", "ts", "uid", "id.orig_h", "id.orig_p", ...]
fields = parts[1:]
→ ["ts", "uid", "id.orig_h", "id.orig_p", ...]
```

`.split()` with no arguments splits on any whitespace (spaces, tabs). `parts[1:]` slices off
`"#fields"` and keeps only the column names.

After finding `#fields`, we `break` immediately. There is nothing useful in the remaining header
lines for our purposes — `#types` gives data types but we store everything as strings in CSV.

**Return value:**

```python
return separator, fields
```

A tuple of `(str, list[str] | None)`. If `fields` is None, the caller should skip the file.

---

## 7. `convert_zeek_tsv_to_csv()` — TSV → CSV

```python
# zeek.py  lines 96–115
def convert_zeek_tsv_to_csv(log_path: Path, out_csv: Path):
    sep, fields = parse_zeek_tsv_header(log_path)
    if not fields:
        print(f"[WARN] Could not find #fields in {log_path.name}")
        return

    with out_csv.open("w", newline="", encoding="utf-8") as out_f:
        writer = csv.writer(out_f)
        writer.writerow(fields)

        with log_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                row = line.split(sep)
                # Some lines may have fewer columns; pad
                if len(row) < len(fields):
                    row += [""] * (len(fields) - len(row))
                writer.writerow(row[:len(fields)])
```

### Line-by-line walkthrough

**`sep, fields = parse_zeek_tsv_header(log_path)`**

Calls our header parser to get the separator character and column names. Note that the file is
opened and closed inside `parse_zeek_tsv_header()`. We then open it a second time below for the
data rows. This is intentional — the header parse reads only comment lines and stops at `#fields`.
The data-writing loop needs to start from the beginning to skip all comment lines correctly.

**`if not fields:`**

Catches `fields = None` (no `#fields` line found). We print a warning and return without creating
any output file. The caller `convert_zeek_logs()` will simply not add this file to `written_files`.

**`csv.writer` vs `csv.DictWriter`**

Here we use `csv.writer` (not `DictWriter`). The reason:

- In `convert_json_lines_to_csv()`, each row is a `dict` — DictWriter maps keys to columns
- Here, each row is a `list[str]` — we split the line on the separator and get an ordered list
  that already matches the column order defined by `#fields`. Using `csv.writer` is simpler and faster.

**`writer.writerow(fields)`**

The first thing we write is the header row — the column names from `#fields`. This gives us a
proper CSV with named columns.

**`if not line or line.startswith("#"): continue`**

This is the key filter. In a Zeek TSV file, lines starting with `#` are comment/metadata lines
(`#separator`, `#fields`, `#types`, `#open`, `#close`, `#path`, etc.). Data rows never start
with `#`. We skip all comment lines and blank lines to get only the actual data rows.

**`row = line.split(sep)`**

Splits the data line on the separator (usually `\t`). For a connection in `conn.log`:

```
"1633046400.123\tC9ZqwX...\t192.168.1.5\t54321\t..."
→ ["1633046400.123", "C9ZqwX...", "192.168.1.5", "54321", ...]
```

Each element in `row` corresponds to one column value.

**Padding short rows:**

```python
if len(row) < len(fields):
    row += [""] * (len(fields) - len(row))
```

A row might have fewer columns than `#fields` declared if:
- The last field is optional and absent (Zeek omits trailing empty fields)
- The log entry is for a protocol that doesn't fill all fields

`[""] * (len(fields) - len(row))` creates a list of empty strings exactly long enough to pad the
row to the expected length.

Example: if `len(fields) = 20` and `len(row) = 18`, then `[""] * 2` = `["", ""]` is appended.

**`writer.writerow(row[:len(fields)])`**

`row[:len(fields)]` is a safety slice: if somehow a row has MORE values than `#fields` (a
malformed log), we truncate it to the expected column count. Combined with the padding above, this
guarantees every written row has exactly `len(fields)` values.

---

## 8. `convert_zeek_logs()` — The Orchestrator

```python
# zeek.py  lines 117–166
def convert_zeek_logs(
    zeek_dir: str | Path,
    out_dir: str | Path,
    *,
    all_logs: bool = False,
) -> list[str]:
    zeek_dir = Path(zeek_dir).expanduser().resolve()
    out_dir = Path(out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not zeek_dir.exists():
        raise FileNotFoundError(f"Zeek directory not found: {zeek_dir}")

    if all_logs:
        log_files = sorted(zeek_dir.glob("*.log"))
    else:
        log_files = [zeek_dir / name for name in LOGS_OF_INTEREST]

    log_files = [p for p in log_files if p.exists()]

    if not log_files:
        print("[ERROR] No .log files found to convert.")
        return

    print(f"Zeek dir : {zeek_dir}")
    print(f"Out dir  : {out_dir}")
    print(f"Files    : {len(log_files)}")
    print("-" * 40)

    written_files: list[str] = []
    for p in log_files:
        fmt = sniff_format(p)
        out_csv = out_dir / (p.stem + ".csv")
        print(f"Converting {p.name} -> {out_csv.name} (format={fmt})")

        try:
            if fmt == "json":
                convert_json_lines_to_csv(p, out_csv)
            elif fmt == "zeek_tsv":
                convert_zeek_tsv_to_csv(p, out_csv)
            else:
                print(f"[WARN] Unknown format, skipping: {p.name}")
                continue
        except Exception as e:
            print(f"[ERROR] Failed converting {p.name}: {e}")
            continue
        written_files.append(str(out_csv))

    print("\nDone. CSVs are in:", out_dir)
    return written_files
```

### Parameter design

**`zeek_dir: str | Path`**

Accepts both strings and Path objects. The `str | Path` union type (Python 3.10+ syntax) is a
convenience for callers that might pass a string (e.g., from argparse or a YAML config). The first
line immediately converts to a resolved Path, so the rest of the function always uses Path.

**`out_dir: str | Path`**

Same pattern. The output directory will be created if it doesn't exist (`mkdir(parents=True,
exist_ok=True)`).

**`*, all_logs: bool = False`**

The `*` makes `all_logs` keyword-only. It cannot be passed as a positional argument — callers
must write `convert_zeek_logs(z, o, all_logs=True)`. This prevents accidental positional
confusion when the function signature evolves.

### Path resolution

```python
zeek_dir = Path(zeek_dir).expanduser().resolve()
out_dir = Path(out_dir).expanduser().resolve()
```

- `.expanduser()` handles `~` in paths (e.g., `~/pcaps/zeek/`)
- `.resolve()` converts relative paths to absolute and resolves symlinks

This is the same pattern used in `DatasetArtifacts.build_dataset_artifacts()` (Tutorial 03).
Consistent: the pipeline always works with absolute paths.

### Log file selection

```python
if all_logs:
    log_files = sorted(zeek_dir.glob("*.log"))
else:
    log_files = [zeek_dir / name for name in LOGS_OF_INTEREST]
```

**`all_logs=True` path:** Uses `glob("*.log")` to find every `.log` file, sorted alphabetically.
`sorted()` gives deterministic order for reproducibility.

**`all_logs=False` (default) path:** Builds a list of specific paths:
```python
[zeek_dir / "conn.log", zeek_dir / "ssl.log", zeek_dir / "tls.log", ...]
```

The `/` operator on Path is path joining. `zeek_dir / "conn.log"` is equivalent to
`os.path.join(str(zeek_dir), "conn.log")`.

**Then, in both cases:**
```python
log_files = [p for p in log_files if p.exists()]
```

Filter to only files that actually exist. In the default path, Zeek may not produce all six logs
— for example, if the PCAP had no QUIC traffic, `quic.log` won't exist. The `.exists()` filter
handles this gracefully without errors.

### The conversion loop

```python
written_files: list[str] = []
for p in log_files:
    fmt = sniff_format(p)
    out_csv = out_dir / (p.stem + ".csv")
    ...
```

**`p.stem`**: The filename without extension. For `/path/to/ssl.log`, `p.stem = "ssl"`. So the
output path becomes `/path/to/out_dir/ssl.csv`. Clean naming.

**`try/except Exception as e:`**

The conversion of each log file is wrapped in a try/except. If `ssl.log` is corrupt and
`convert_zeek_tsv_to_csv()` raises an exception, the error is printed and we `continue` to the
next file. The pipeline can still produce `conn.csv`, `x509.csv`, etc. Partial success is better
than total failure for a research dataset builder.

**`written_files.append(str(out_csv))`**

Only files that were successfully converted are added to the return list. Callers can check
`written_files` to know exactly which CSVs were produced.

---

## 9. `main()` — The CLI Entry Point

```python
# zeek.py  lines 168–181
def main(argv: list[str] | None = None):
    ap = argparse.ArgumentParser(description="Convert Zeek .log files (JSON or default TSV) to CSV")
    ap.add_argument("--zeek-dir", required=True, help="Folder containing Zeek .log files")
    ap.add_argument("--out-dir", required=True, help="Output folder for CSV files")
    ap.add_argument("--all", action="store_true",
                    help="Convert ALL .log files in the directory (not just conn/ssl/x509/quic/http)")
    args = ap.parse_args(argv)

    written_files = convert_zeek_logs(args.zeek_dir, args.out_dir, all_logs=args.all)
    print(f"written_files={len(written_files)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

This makes `zeek.py` runnable directly as a script:

```bash
python -m tls_dataset.pipeline.zeek \
    --zeek-dir /data/zeek_output/ \
    --out-dir /data/zeek_csvs/
```

Or:
```bash
python -m tls_dataset.pipeline.zeek \
    --zeek-dir /data/zeek_output/ \
    --out-dir /data/zeek_csvs/ \
    --all
```

**`argv: list[str] | None = None`**

By defaulting `argv=None`, `argparse` reads from `sys.argv` when called from the command line.
But tests can pass `argv=["--zeek-dir", "/tmp/z", "--out-dir", "/tmp/o"]` to test the CLI without
actually invoking a subprocess.

**`raise SystemExit(main())`**

`main()` returns `0` on success. `SystemExit(0)` signals success to the OS. This pattern (as
opposed to just `main()`) ensures the exit code propagates correctly when the script is called by
shell scripts or CI systems.

---

## 10. Complete Data Flow Diagram

Here is the full picture of where `zeek.py` sits in the pipeline and what goes in and out:

```
Input (from zeek_runner.py):
  /data/benign_zeek/
      conn.log    ← Zeek TSV or JSON Lines
      ssl.log     ← Zeek TSV or JSON Lines
      tls.log     ← Zeek TSV or JSON Lines
      x509.log    ← Zeek TSV or JSON Lines
      quic.log    ← Zeek TSV or JSON Lines
      (quic.log may not exist for TCP-only traffic)

zeek.py processing:
  for each log in LOGS_OF_INTEREST that exists:
    1. sniff_format(log) → "zeek_tsv" or "json" or "unknown"
    2. if "zeek_tsv":
         parse_zeek_tsv_header() → separator, fields
         convert_zeek_tsv_to_csv() → writes CSV
    3. if "json":
         Pass 1: scan all lines → build union of keys
         Pass 2: write header + all rows as CSV
    4. if "unknown": warn + skip

Output (passed to merge_features.py):
  /data/benign_zeek_csvs/
      conn.csv    ← standard CSV with named columns
      ssl.csv     ← standard CSV with named columns
      x509.csv    ← standard CSV with named columns
```

The orchestration module (`orchestration.py`) calls:

```python
# From orchestration.py (simplified)
convert_zeek_logs(
    zeek_dir=artifacts.zeek_log_dir,      # /data/benign_zeek/
    out_dir=artifacts.zeek_csv_dir,       # /data/benign_zeek_csvs/
)
```

The `DatasetArtifacts` fields involved:
- `zeek_log_dir`: directory where `run_zeek_on_pcap()` wrote the `.log` files
- `zeek_csv_dir`: directory where `convert_zeek_logs()` writes the `.csv` files

---

## 11. What Columns Are In Each CSV?

### `conn.csv` columns (key ones)

| Column | Type | Description |
|--------|------|-------------|
| `ts` | float | Unix timestamp of connection start |
| `uid` | string | Zeek's unique connection ID — the **join key** |
| `id.orig_h` | string | Source IP address |
| `id.orig_p` | int | Source port |
| `id.resp_h` | string | Destination IP address |
| `id.resp_p` | int | Destination port |
| `proto` | string | `tcp`, `udp`, `icmp` |
| `service` | string | Application protocol (`ssl`, `http`, `dns`, `quic`) |
| `duration` | float | Connection duration in seconds |
| `orig_bytes` | int | Bytes sent by originator |
| `resp_bytes` | int | Bytes sent by responder |
| `conn_state` | string | Connection state (S0, S1, SF, REJ, etc.) |
| `orig_pkts` | int | Packets from originator |
| `resp_pkts` | int | Packets from responder |

### `ssl.csv` columns (key ones)

| Column | Type | Description |
|--------|------|-------------|
| `ts` | float | Timestamp of TLS ClientHello |
| `uid` | string | Same UID as the conn.log entry |
| `version` | string | `TLSv12`, `TLSv13` |
| `cipher` | string | Negotiated cipher suite (e.g., `TLS_AES_256_GCM_SHA384`) |
| `curve` | string | Elliptic curve used for key exchange |
| `server_name` | string | SNI — the hostname the client requested |
| `resumed` | bool | Was this session resumed (session ticket/TLS 1.3 resumption)? |
| `last_alert` | string | TLS alert message if connection failed |
| `validation_status` | string | Certificate validation result |
| `ja3` | string | JA3 fingerprint of the client |
| `ja3s` | string | JA3S fingerprint of the server |

### `x509.csv` columns (key ones)

| Column | Type | Description |
|--------|------|-------------|
| `ts` | float | Timestamp |
| `id` | string | Certificate identifier |
| `certificate.version` | int | X.509 version (usually 3) |
| `certificate.serial` | string | Serial number |
| `certificate.subject` | string | Subject DN (Common Name, Org, Country) |
| `certificate.issuer` | string | Issuer DN |
| `certificate.not_valid_before` | float | Certificate start date (Unix timestamp) |
| `certificate.not_valid_after` | float | Certificate expiry date (Unix timestamp) |
| `certificate.key_alg` | string | Public key algorithm (rsaEncryption, id-ecPublicKey) |
| `certificate.sig_alg` | string | Signature algorithm (sha256WithRSAEncryption, etc.) |
| `san.dns` | string | Subject Alternative Names (comma-sep) |
| `basic_constraints.ca` | bool | Is this a CA certificate? |

### `quic.csv` columns (key ones)

| Column | Type | Description |
|--------|------|-------------|
| `ts` | float | Timestamp |
| `uid` | string | Connection UID |
| `id.orig_h/p` | string/int | Source address/port |
| `id.resp_h/p` | string/int | Destination address/port |
| `version` | string | QUIC version (e.g., `1`) |
| `server_name` | string | SNI (QUIC also uses SNI in its TLS extension) |
| `client_initial_dcid` | string | Destination Connection ID from first packet |

---

## 12. Design Decisions and Why

### Decision 1: Format detection on every file, not once per directory

`sniff_format()` is called individually for each `.log` file, not once for the directory.

**Why:** It is theoretically possible (though unusual) for a Zeek deployment to be reconfigured
mid-capture or for logs from different Zeek versions to be mixed in one directory. Per-file
detection is robust; directory-level detection is an assumption.

### Decision 2: Two-pass approach for JSON Lines

The alternative to two passes is to buffer all rows in memory as a list of dicts, determine all
keys, then write:

```python
# ALTERNATIVE (not used):
rows = [json.loads(line) for line in f if line.strip().startswith("{")]
all_keys = list(dict.fromkeys(k for row in rows for k in row.keys()))
# write header and rows
```

This also works but holds the entire log in memory. For large captures, `ssl.log` can be hundreds
of megabytes. The two-pass approach is streaming: it reads the file twice but never holds more than
one row in memory at a time.

### Decision 3: Silently pad / truncate rows rather than fail

Short rows are padded with empty strings; long rows are truncated. The alternative would be to
raise an exception. The padding/truncation approach is chosen because:

- Zeek's own format guarantees column count consistency — mismatches indicate a minor anomaly
- Failing the entire file conversion for one malformed row is too aggressive
- Downstream ML code handles missing values (NaN/empty) as standard practice

### Decision 4: `LOGS_OF_INTEREST` as a module-level constant, not config

This list is defined in code, not YAML. The reasoning: this is not a user-tunable parameter — it
reflects the semantic decision of which Zeek logs contain features relevant to TLS/QUIC detection.
Adding a new log type requires code changes and ML re-evaluation anyway, so it should not be
configurable at runtime.

---

## 13. Real-World Observation from the Project

From `docs/findings-register.md` (the finding that also appeared in Tutorial 05):

> **CTU-13 Zeek run produced only `conn.log`** — no `ssl.log` because the PCAP was from an older
> era when TLS was less prevalent and the botnet used non-TLS communication.

When `convert_zeek_logs()` runs on the CTU-13 output:
- `log_files = [zeek_dir / name for name in LOGS_OF_INTEREST]`
- `log_files = [p for p in log_files if p.exists()]`
- Only `conn.log` passes the `.exists()` filter
- The function converts only `conn.csv`
- `written_files = ["/data/benign_zeek_csvs/conn.csv"]`

The pipeline does not fail — it converts what exists. The quality gate in `quality.py` then checks
whether the expected files are present and raises a warning if ssl.log is missing, but the
conversion step itself is tolerant.

---

## 14. Connection to the Rest of the Pipeline

```
filtering.py         → benign_filtered.pcap
zeek_runner.py       → runs Zeek on benign_sanitized.pcap → benign_zeek/ (*.log files)
zeek.py  [THIS FILE] → converts *.log → benign_zeek_csvs/ (*.csv files)
merge_features.py    → joins zeek_csvs/conn.csv + nfstream.csv on 4-tuple
quality.py           → validates zeek_csvs exist, checks merge match rate
```

In `orchestration.py`, this call appears after `run_zeek_on_pcap()`:

```python
convert_zeek_logs(
    zeek_dir=artifacts.zeek_log_dir,
    out_dir=artifacts.zeek_csv_dir,
)
```

And the `DatasetArtifacts` fields bridge the two calls:

```python
@dataclass(frozen=True)
class DatasetArtifacts:
    zeek_log_dir: Path   # → zeek_runner writes logs HERE
    zeek_csv_dir: Path   # → zeek.py converts CSVs HERE, merge_features reads from HERE
```

---

## 15. Interview Q&A

**Q: How does `sniff_format()` decide if a Zeek log is JSON or TSV?**

It reads at most 50 lines looking for format markers. A line starting with `#fields` or
`#separator` → `"zeek_tsv"`. A line starting with `{` and ending with `}` → `"json"`. If neither
is found in 50 lines → `"unknown"`. This heuristic works because Zeek TSV always puts `#separator`
within the first 2 lines, and JSON Lines always starts with `{` on line 1.

---

**Q: Why does `convert_json_lines_to_csv()` read the file twice?**

CSV requires the header row first. With JSON Lines, different rows may have different keys
(optional fields). You cannot know the complete set of column names until you've seen all rows.
The first pass collects the union of all keys; the second pass writes header + data. This is a
streaming approach that avoids loading the entire file into memory.

---

**Q: What does `#separator \x09` mean in a Zeek log?**

It tells parsers that fields are separated by ASCII character 0x09, which is the tab character.
Zeek writes the escape notation `\x09` literally (4 chars) rather than an actual tab character in
the metadata line, so parsers can unambiguously read the separator declaration.

---

**Q: What happens if a data row in a Zeek TSV file has fewer fields than `#fields` declared?**

The code pads it with empty strings:
```python
if len(row) < len(fields):
    row += [""] * (len(fields) - len(row))
```
This handles optional trailing fields that Zeek omits when they have no value.

---

**Q: What is the difference between `csv.writer` and `csv.DictWriter`, and why is each used here?**

`csv.writer` writes a list per row. `csv.DictWriter` writes a dict per row, mapping keys to
columns defined in `fieldnames`. `convert_json_lines_to_csv()` uses `DictWriter` because JSON
objects are dicts and some keys may be absent in some rows (DictWriter fills missing keys with
empty string). `convert_zeek_tsv_to_csv()` uses `csv.writer` because splitting a tab-separated
line gives a list that already matches column order — no key mapping needed.

---

**Q: What is JA3 fingerprinting and where does it appear in the pipeline?**

JA3 is a method for fingerprinting TLS clients based on the values in their ClientHello message:
TLS version, cipher suites, extensions, elliptic curves, and elliptic curve point formats. These
values are concatenated and MD5-hashed to produce a 32-character hex string. JA3 identifies the
client TLS implementation regardless of the server or certificate. Zeek computes JA3 and writes it
as the `ja3` column in `ssl.log` → `ssl.csv`. In ML training, `ja3` is a feature that can identify
malware families that use distinctive TLS configurations.

---

**Q: Why does the project convert Zeek logs to CSV instead of reading the TSV or JSON directly
downstream?**

CSV is the canonical interchange format for the pipeline. All downstream modules (merge, ML, etc.)
use pandas `pd.read_csv()`. Converting at the Zeek-output stage means: (1) a single, uniform
format regardless of Zeek configuration; (2) no TSV/JSON parsing logic scattered across the
codebase; (3) easy inspection with any spreadsheet tool for debugging.

---

**Q: What Zeek log file contains the `uid` that is used as the join key in the merge step?**

Every Zeek log file contains `uid` — it is Zeek's universal connection identifier that links
records across all log types. A single network connection might generate a row in `conn.log`, a row
in `ssl.log`, and one or more rows in `x509.log` (one per certificate in the chain), all sharing
the same `uid`. The merge step joins `conn.csv` with NFStream flows using the 4-tuple (src IP,
src port, dst IP, dst port + timestamp tolerance), and then joins `ssl.csv` using `uid` from
`conn.csv`.

---

*Next: Tutorial 07 — `pipeline/nfstream.py`: The NFStream wrapper, bidirectional flow statistics,
and what each feature column means.*
