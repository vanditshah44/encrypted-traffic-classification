# Tutorial 04 — Pipeline Filtering: `sanitize_pcap` and `filter_encrypted_pcap`

**Primary file:** `src/tls_dataset/pipeline/filtering.py`

**Also covered (connections):**
- `src/tls_dataset/pipeline/malicious.py` — calls both functions in sequence
- `src/tls_dataset/pipeline/quality.py` — `check_pcap_health()` validates the PCAP before filtering
- `src/tls_dataset/pipeline/provenance.py` — records each filtering step as a provenance entry

**Prerequisite:** Tutorial 03 (Pipeline Common)

---

## 1. Where Filtering Sits in the Pipeline

Before any feature extraction can happen, two transformations must be applied to the
raw PCAP:

```
Raw PCAP (from CTU-13, from a lab capture, from anywhere)
         │
         ▼
  [Step 1: sanitize_pcap()]
  Tool: editcap
  Fixes malformed packets, corrects timestamps, removes truncation errors
  Output: {dataset_name}_sanitized.pcapng
         │
         ▼
  [Step 2: filter_encrypted_pcap()]
  Tool: tshark
  Keeps ONLY packets that belong to TLS or QUIC connections
  Output: {dataset_name}_filtered_tls_quic.pcapng
         │
         ▼
  [Zeek + NFStream run on the filtered PCAP]
```

Both steps are in `filtering.py`. The file is small — 79 lines — but every decision in
it has a deep reason. This tutorial unpacks all of them.

---

## 2. Background Concepts You Must Know

### What is a PCAP?

A **PCAP** (Packet CAPture) file is a recording of raw network packets. Every packet
that crossed a network interface — every TCP segment, every UDP datagram, every ARP
broadcast — is stored with a timestamp, the packet's raw bytes, and metadata about the
capture interface.

A PCAP is not human-readable. It is binary. Tools like Wireshark, tshark, tcpdump,
editcap, NFStream, and Zeek all read PCAPs as input.

**PCAPNG** is the next-generation format. It supports multiple interfaces per file,
comments, packet annotations, and richer metadata. The Wireshark suite (which includes
tshark and editcap) prefers PCAPNG. Both `.pcap` and `.pcapng` are accepted by all
tools used in this project.

---

### What is editcap?

`editcap` is part of the **Wireshark suite**. Its primary job is editing and
sanitising packet capture files. It can:

- Remove duplicate packets
- Cut captures to a time range or packet count
- Convert between PCAP and PCAPNG formats
- **Fix malformed/truncated packets** (the job used here)
- Strip personal data from captures

When you run `editcap input.pcapng output.pcapng` with no other flags (exactly what this
project does), editcap reads the entire capture and writes a sanitised copy. During this
process it:
- Corrects invalid packet lengths
- Fixes out-of-range timestamps
- Converts the format to a consistent PCAPNG structure
- Reports malformed packets to stderr

This is the minimum required to make downstream tools (Zeek, NFStream) run without
crashing or skipping packets.

---

### What is tshark?

`tshark` is the command-line version of **Wireshark** — the world's most widely used
network protocol analyser. Wireshark provides a GUI; tshark exposes the same
functionality in a terminal.

tshark can:
- Read a PCAP and print a decoded summary of each packet
- Filter packets and write a subset to a new PCAP
- Decode hundreds of protocols at multiple layers
- Apply display filters using Wireshark's rich filter language

In this project, tshark is used **exclusively as a filter** — it reads a sanitised
PCAP, keeps only the packets matching a display filter, and writes those to a new PCAP.

---

### Display Filter vs BPF Filter

These two terms are frequently confused. They are completely different things:

**BPF filter (Berkeley Packet Filter):**
- Operates at the **capture** level
- Evaluated in the kernel before packets are even delivered to userspace
- Very fast, very low-level
- Can only inspect the first few bytes of a packet (IP addresses, ports, protocol number)
- Syntax: `tcp port 443`, `host 192.168.1.1`
- Used by: tcpdump, libpcap, NFStream's `bpf_filter` parameter

**Display filter (Wireshark / tshark):**
- Operates at the **application** level
- tshark fully decodes every packet first, then checks if the decoded packet matches
- Slower (full protocol dissection required), but vastly more powerful
- Can inspect deep protocol fields: `tls.handshake.type == 1`, `quic.version`
- Can match by protocol name: `tls`, `quic`, `ssl`, `http2`
- Syntax: `tls or quic`, `tls.version == 0x0304`
- Used by: tshark with `-Y` flag, Wireshark

**Why does this project use a display filter instead of BPF?**

Because `tls or quic` as a display filter is protocol-aware. tshark decodes the full
packet, determines it is a TLS record or a QUIC datagram, and keeps it. A BPF filter
like `tcp port 443` would keep ALL traffic on port 443 — including non-TLS HTTPS on
port 443, failed connections, and other protocols. It would also miss TLS on
non-standard ports and QUIC on ports other than 443/80. The display filter `tls or quic`
matches based on what the packet actually IS, not just where it is going.

---

### Why `subprocess` Instead of a Python Library?

`editcap` and `tshark` are C programs with decades of development behind them. There
is no pure-Python replacement that handles all edge cases in malformed PCAP parsing.
The correct approach is to call the real tools via `subprocess` — Python's standard
library module for spawning and communicating with child processes.

```python
import subprocess

result = subprocess.run(
    ["editcap", "input.pcapng", "output.pcapng"],
    capture_output=True,   # capture stdout and stderr
    text=True,             # decode bytes as UTF-8 strings
    check=False,           # don't raise exception on non-zero exit code
)
# result.returncode  → integer exit code (0 = success)
# result.stdout      → everything the process wrote to stdout
# result.stderr      → everything the process wrote to stderr
```

`check=False` is important here — the code manually checks the return code and output
rather than letting Python raise a `subprocess.CalledProcessError` automatically. This
gives the code control over what constitutes a real failure vs a warning.

---

### What is `shutil.which()`?

`shutil.which(name)` is Python's equivalent of the shell command `which`. It searches
the directories in the `PATH` environment variable for an executable named `name` and
returns the full path if found, or `None` if not found.

```python
import shutil

shutil.which("editcap")   # → "/usr/bin/editcap" or None
shutil.which("tshark")    # → "/usr/bin/tshark" or None
shutil.which("zeek")      # → "/opt/zeek/bin/zeek" or None
shutil.which("notaprogram") # → None
```

This is how the pipeline checks if required tools are installed before attempting to
run them — failing fast with a clear error message rather than crashing mid-operation.

---

## 3. The Full Source: `filtering.py`

```python
"""Packet sanitization and filtering helpers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
```

**`from __future__ import annotations`** — defers evaluation of type annotations. This
allows `str | Path` syntax (union types) in Python 3.10+ style even if the runtime is
an older 3.x. In Python 3.12 (this project's requirement) it is redundant but still
a common defensive import.

**`import shutil`** — for `shutil.which()` (tool discovery).

**`import subprocess`** — for running editcap and tshark as child processes.

**`from pathlib import Path`** — for path handling.

---

## 4. `_require_tool()` — The Tool Availability Guard

```python
def _require_tool(tool_name: str) -> str:
    resolved = shutil.which(tool_name)
    if resolved is None:
        raise FileNotFoundError(f"Required tool not found on PATH: {tool_name}")
    return resolved
```

**Name:** The leading underscore `_` signals this is a **private helper** — not part
of the public API of the module. Only functions within this file call it.

**`tool_name: str`** — the name of the executable, e.g., `"editcap"`, `"tshark"`.

**`shutil.which(tool_name)`** — searches `PATH`. Returns the full path string or `None`.

**`raise FileNotFoundError`** — if the tool is not found, raise `FileNotFoundError`
with a clear, actionable message. The error type `FileNotFoundError` is semantically
correct — it means "a required file (the executable) was not found" — and is the same
error Python itself raises when an executable is missing in a subprocess call.

**Why fail immediately rather than try-catch later?** The alternative would be to
attempt `subprocess.run(["editcap", ...])` and catch the `FileNotFoundError` that the
OS raises when the executable doesn't exist. That produces a confusing OS-level error
message. `_require_tool` gives a human-friendly message that tells the developer
exactly what they need to install.

**`return resolved`** — returns the full absolute path to the binary (e.g.,
`"/usr/bin/editcap"`). The returned path is used in the subprocess command instead
of just the name, avoiding any PATH ambiguity at subprocess execution time.

---

## 5. `tool_version()` — Capturing Tool Version for Provenance

```python
def tool_version(tool_name: str, version_args: list[str] | None = None) -> str:
    binary = _require_tool(tool_name)
    args = [binary] + (version_args or ["--version"])
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    version_text = result.stdout.strip() or result.stderr.strip()
    return version_text.splitlines()[0] if version_text else tool_name
```

**Purpose:** Gets the version string of a tool, used in provenance records.

**`version_args: list[str] | None = None`** — different tools use different flags for
version info:
- `editcap --version` → works
- `tshark -v` → works (tshark uses `-v`, not `--version`)
- Default is `["--version"]` when not specified

**`result.stdout.strip() or result.stderr.strip()`** — some tools print version info
to stdout, others to stderr. The `or` operator tries stdout first; if that's empty,
tries stderr. This handles both cases without branching.

**`version_text.splitlines()[0]`** — takes only the first line. Version output often
looks like:
```
TShark (Wireshark) 4.2.0 (v4.2.0-0-g54a9d5a4a1cf)

Copyright 1998-2023 Gerald Combs <gerald@wireshark.org> and contributors.
...
```
Only the first line (`"TShark (Wireshark) 4.2.0 ..."`) is stored. The rest is
boilerplate.

**`if version_text else tool_name`** — if the tool produces no output at all (which
shouldn't happen but is defensive), fall back to the tool name string.

**Where it's used:**
```python
# In sanitize_pcap():
"tool_version": tool_version("editcap", ["--version"]),

# In filter_encrypted_pcap():
"tool_version": tool_version("tshark", ["-v"]),
```

This version string ends up in `provenance.json` — creating a reproducibility record
of which exact version of each tool was used to transform the data.

---

## 6. `sanitize_pcap()` — Deep Dive

```python
def sanitize_pcap(input_pcap: str | Path, output_pcap: str | Path) -> dict[str, str]:
    input_path = Path(input_pcap).expanduser().resolve()
    output_path = Path(output_pcap).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    binary = _require_tool("editcap")
    command = [binary, str(input_path), str(output_path)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)

    if result.returncode != 0 and not output_path.exists():
        raise RuntimeError(
            f"editcap failed to sanitize {input_path}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )

    return {
        "input_pcap": str(input_path),
        "output_pcap": str(output_path),
        "command": " ".join(command),
        "stderr": result.stderr.strip(),
        "stdout": result.stdout.strip(),
        "tool_version": tool_version("editcap", ["--version"]),
    }
```

### Signature

```python
def sanitize_pcap(input_pcap: str | Path, output_pcap: str | Path) -> dict[str, str]:
```

- **`input_pcap`** — the raw source PCAP. In `malicious.py`, this is
  `artifacts.raw_pcap` (the copy of the original malicious capture).
- **`output_pcap`** — where the sanitised output goes. In `malicious.py`, this is
  `artifacts.sanitized_pcap` (e.g., `malicious_full_v2_sanitized.pcapng`).
- **`-> dict[str, str]`** — returns a dict of metadata about what was done: the command
  run, its output, the tool version. This dict is stored in provenance records and
  returned in the pipeline results.

### Path resolution

```python
input_path = Path(input_pcap).expanduser().resolve()
output_path = Path(output_pcap).expanduser().resolve()
output_path.parent.mkdir(parents=True, exist_ok=True)
```

Same pattern as `build_dataset_artifacts` — convert to absolute paths.
`output_path.parent.mkdir(parents=True, exist_ok=True)` creates the output directory
if it does not exist. Without this, the subprocess would fail with a directory-not-found
error.

**`parents=True`** — create any missing parent directories in the chain, not just the
immediate parent. So if `artifacts/runs/malicious_full_v2/` does not exist, it and any
missing ancestors are created.

**`exist_ok=True`** — do not raise an error if the directory already exists. Without
this, a second pipeline run on the same `output_dir` would crash here.

### Building the command

```python
binary = _require_tool("editcap")
command = [binary, str(input_path), str(output_path)]
```

The full command built here is:
```bash
/usr/bin/editcap /absolute/path/to/raw.pcapng /absolute/path/to/sanitized.pcapng
```

Using absolute paths for both the binary and the file arguments is intentional — the
subprocess runs in whatever the current working directory is, so relative paths would
be resolved relative to that, which could be anywhere.

The command is stored as a list (not a string) for `subprocess.run`. A list avoids
shell injection — if the path happened to contain spaces or special characters, they
are passed safely as a single argument. Passing a string would require `shell=True`,
which opens up shell injection vulnerabilities.

### Running the subprocess

```python
result = subprocess.run(command, capture_output=True, text=True, check=False)
```

- **`capture_output=True`** — captures both stdout and stderr as strings in
  `result.stdout` and `result.stderr`. Without this, both streams go to the terminal
  and are not accessible in Python.
- **`text=True`** — decode the captured bytes as UTF-8 text. Without this, `result.stdout`
  and `result.stderr` would be `bytes` objects.
- **`check=False`** — do NOT raise `subprocess.CalledProcessError` if the exit code
  is non-zero. The code manually handles failure conditions.

### Error handling — the critical subtlety

```python
if result.returncode != 0 and not output_path.exists():
    raise RuntimeError(
        f"editcap failed to sanitize {input_path}: "
        f"{result.stderr.strip() or result.stdout.strip()}"
    )
```

This is `returncode != 0 AND not output_path.exists()` — not just `returncode != 0`.

**Why this AND condition?** editcap sometimes exits with a non-zero return code even
when it successfully wrote the output file. This happens when the input PCAP has
warnings (e.g., malformed packets that editcap repaired). editcap considers those
warnings worth flagging with a non-zero exit, but the output is still valid. If the
code raised an error on any non-zero exit code, it would incorrectly fail on PCAPs
with minor formatting issues — exactly the PCAPs sanitization is meant to fix.

The contract is: **if editcap wrote a file, the sanitization succeeded**, even if
editcap complained about the input. Only raise if both conditions are true: non-zero
exit AND no output file written. That combination means editcap truly failed.

### Return value

```python
return {
    "input_pcap": str(input_path),
    "output_pcap": str(output_path),
    "command": " ".join(command),
    "stderr": result.stderr.strip(),
    "stdout": result.stdout.strip(),
    "tool_version": tool_version("editcap", ["--version"]),
}
```

Every field serves a purpose in provenance tracking. This dict is passed directly to
`build_provenance_entry()` in `malicious.py`:

```python
# In malicious.py:
sanitize_result = sanitize_pcap(raw_copy, artifacts.sanitized_pcap)

build_provenance_entry(
    stage="sanitized_capture",
    path=artifacts.sanitized_pcap,
    parent_path=raw_copy,
    tool="editcap",
    tool_version=sanitize_result["tool_version"],   # ← from return dict
    command=sanitize_result["command"],              # ← from return dict
    notes=sanitize_result["stderr"] or "Sanitized with editcap.",
)
```

The `stderr` field is particularly important — if editcap emitted warnings about
malformed packets, those warnings are stored verbatim in the provenance record. Future
analysis can check whether a given dataset had PCAP quality issues.

---

## 7. `filter_encrypted_pcap()` — Deep Dive

```python
def filter_encrypted_pcap(
    input_pcap: str | Path,
    output_pcap: str | Path,
    *,
    display_filter: str = "tls or quic",
) -> dict[str, str]:
    input_path = Path(input_pcap).expanduser().resolve()
    output_path = Path(output_pcap).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    binary = _require_tool("tshark")
    command = [binary, "-r", str(input_path), "-Y", display_filter, "-w", str(output_path)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)

    if result.returncode != 0:
        raise RuntimeError(
            f"tshark failed to filter {input_path}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    if not output_path.exists():
        raise RuntimeError(
            f"tshark did not create the expected output file: {output_path}"
        )

    return {
        "input_pcap": str(input_path),
        "output_pcap": str(output_path),
        "command": " ".join(command),
        "display_filter": display_filter,
        "stderr": result.stderr.strip(),
        "stdout": result.stdout.strip(),
        "tool_version": tool_version("tshark", ["-v"]),
    }
```

### The `*` in the signature

```python
def filter_encrypted_pcap(
    input_pcap: str | Path,
    output_pcap: str | Path,
    *,
    display_filter: str = "tls or quic",
```

The bare `*` in the parameter list means: **everything after `*` is keyword-only**.
`display_filter` cannot be passed positionally — you must write `display_filter="tls or quic"`.
This prevents accidental positional argument mistakes like:

```python
# Without *: this would silently work but is wrong (filter in wrong position)
filter_encrypted_pcap(input, output, "tls or quic")

# With *: this raises TypeError: positional after keyword-only
filter_encrypted_pcap(input, output, "tls or quic")  # TypeError
filter_encrypted_pcap(input, output, display_filter="tls or quic")  # correct
```

### `display_filter: str = "tls or quic"`

The default is `"tls or quic"`. This is a Wireshark display filter that matches any
packet that is part of a TLS session OR a QUIC session.

Let's understand exactly what `tls or quic` matches:

**`tls` matches:**
- TLS handshake records (ClientHello, ServerHello, Certificate, Finished)
- TLS application data records (encrypted payload)
- TLS alert records (connection shutdown)
- Works for TLS 1.0, 1.1, 1.2, and 1.3

**`quic` matches:**
- QUIC Initial packets (connection establishment, contains TLS ClientHello embedded)
- QUIC Handshake packets
- QUIC 1-RTT packets (application data)
- QUIC Version Negotiation packets

**What it does NOT match:**
- Plain HTTP
- DNS
- ARP
- ICMP
- SSH
- Any unencrypted TCP traffic

The `or` is a logical OR — keep the packet if it matches either `tls` or `quic`.

### The tshark command built

```python
command = [binary, "-r", str(input_path), "-Y", display_filter, "-w", str(output_path)]
```

Breaking this into the tshark flags:

| Flag | Value | Meaning |
|------|-------|---------|
| `-r` | `/path/to/sanitized.pcapng` | **Read** from this file (instead of live capture) |
| `-Y` | `"tls or quic"` | Apply this **display filter** (keeps matching packets only) |
| `-w` | `/path/to/filtered.pcapng` | **Write** matching packets to this output PCAP |

The full command looks like:
```bash
/usr/bin/tshark \
  -r /abs/path/malicious_full_v2_sanitized.pcapng \
  -Y "tls or quic" \
  -w /abs/path/malicious_full_v2_filtered_tls_quic.pcapng
```

Without `-w`, tshark would print decoded packet summaries to stdout. With `-w`, it
writes matching raw packets to a new PCAP file without decoding output.

### Error handling — stricter than `sanitize_pcap`

```python
if result.returncode != 0:
    raise RuntimeError(...)
if not output_path.exists():
    raise RuntimeError(...)
```

Notice this is TWO separate checks, not the AND condition used in `sanitize_pcap`.
tshark's behaviour is different from editcap's:

- tshark exits with code 0 on success, non-zero on any meaningful failure
- Unlike editcap, tshark does not emit spurious non-zero exits for minor warnings
- Therefore: any non-zero exit from tshark is a real failure

The second check (`not output_path.exists()`) is a safety net for a different failure
mode: tshark exiting 0 but not writing the output file. This could happen if the input
PCAP has no packets matching the filter — tshark might exit cleanly but create an
empty file or no file at all. This check catches that case.

### The `display_filter` in the return dict

```python
return {
    ...
    "display_filter": display_filter,
    ...
}
```

The display filter used is stored in the return dict and ultimately in
`provenance.json`. If you later want to know what filter was applied to produce a
specific filtered PCAP, you can look in the provenance record and find:
```json
"notes": "Display filter: tls or quic"
```

This is how the filtering step in `malicious.py` records it:
```python
build_provenance_entry(
    stage="filtered_capture",
    path=artifacts.filtered_pcap,
    parent_path=artifacts.sanitized_pcap,
    tool="tshark",
    tool_version=filter_result["tool_version"],
    command=filter_result["command"],
    notes=f"Display filter: {display_filter}",  # ← "Display filter: tls or quic"
)
```

---

## 8. How `malicious.py` Chains Both Functions

In `prepare_malicious_capture()`, the two filtering functions are called in strict sequence:

```python
# Step 1: Copy raw input to managed run directory
raw_copy = _copy_raw_capture(input_pcap, artifacts.raw_pcap)

# Step 2: Sanitize the raw copy
sanitize_result = sanitize_pcap(raw_copy, artifacts.sanitized_pcap)

# Step 3: Filter the sanitized copy to TLS/QUIC only
filter_result = filter_encrypted_pcap(
    artifacts.sanitized_pcap,      # input: sanitized PCAP
    artifacts.filtered_pcap,       # output: filtered PCAP
    display_filter=display_filter  # default: "tls or quic"
)
```

**Why must sanitization happen before filtering?**

If tshark tries to apply a display filter to a malformed PCAP, it may:
- Crash on the malformed packet
- Silently skip the malformed packet (losing data)
- Incorrectly decode and classify the packet

editcap's sanitization step normalises the PCAP into a valid structure first, so tshark
works on clean input.

---

## 9. The Quality Gate Connection: `check_pcap_health()`

After filtering, the quality gate in `quality.py` runs `check_pcap_health()` on the
original PCAP (not the sanitized one — to check if the source was problematic):

```python
def check_pcap_health(pcap_path: str | Path) -> GateOutcome:
    path = Path(pcap_path).expanduser().resolve()
    if not path.exists():
        return GateOutcome("pcap_health", "fail", f"PCAP file does not exist: {path}")

    capinfos = shutil.which("capinfos")
    if capinfos is None:
        return GateOutcome("pcap_health", "warn", "capinfos is not available; truncation check skipped", ...)

    result = subprocess.run(
        [capinfos, "-Tm", str(path)],
        capture_output=True, text=True, check=False,
    )
    truncated = is_truncation_warning(result.stderr)
    ...
```

**`capinfos`** is another Wireshark suite tool. It reads a PCAP and reports statistics:
packet count, file size, capture duration, and crucially — whether the PCAP was truncated.

**`-T`** — print output in tabular (CSV-like) format, one header row then one data row.

**`-m`** — print machine-readable output (no decorative characters).

**`is_truncation_warning(result.stderr)`** checks stderr for known truncation phrases:

```python
TRUNCATION_MARKERS = (
    "appears to have been cut short",
    "cut short in the middle of a packet",
    "middle of a packet",
)

def is_truncation_warning(stderr_text: str) -> bool:
    lowered = stderr_text.lower()
    return any(marker in lowered for marker in TRUNCATION_MARKERS)
```

A truncated PCAP is one where the recording was stopped mid-packet — the last packet
in the file is incomplete. This happened with the CTU-13 malicious PCAP used in this
project (from `docs/project-journey.md` Phase 5: "the malicious PCAP was confirmed to
be truncated in its original state"). Truncated PCAPs can cause:
- NFStream to miscount flows (incomplete flows at the end of the file)
- Zeek to miss the final connections
- Feature statistics to be slightly wrong

**`GateOutcome`** is a frozen dataclass from `quality.py`:
```python
@dataclass(frozen=True)
class GateOutcome:
    name: str     # "pcap_health"
    status: str   # "pass", "fail", or "warn"
    message: str  # human-readable description
    metrics: dict[str, object]  # key-value evidence
```

Three possible outcomes:
1. `"pass"` — PCAP exists and is not truncated
2. `"warn"` — capinfos not installed, truncation check skipped
3. `"fail"` — PCAP does not exist, OR capinfos detected truncation

The distinction between `warn` and `fail` is important: without capinfos, the pipeline
cannot verify PCAP health, but it does not stop — it continues with a warning. This
allows the pipeline to run in environments where capinfos is not installed.

---

## 10. How Filtering Interacts With the Quality Gate on Merged Data

The filtering step directly affects one of the most important quality gates:
**`max_non_tls_quic_rate`**.

After the Zeek + NFStream merge, `check_merged_dataset()` checks what fraction of rows
in the merged CSV lack any TLS or QUIC signal:

```python
def row_has_encrypted_signal(row: Mapping[str, str], fieldnames: Iterable[str]) -> bool:
    # Check TLS columns
    if any(_is_present(row.get(column)) for column in TLS_SIGNAL_COLUMNS):
        return True
    # Check QUIC columns (by token matching in column names)
    for fieldname in fieldnames:
        lowered = fieldname.lower()
        if any(token in lowered for token in QUIC_SIGNAL_TOKENS) and _is_present(row.get(fieldname)):
            return True
    return False
```

```python
TLS_SIGNAL_COLUMNS = ("version", "cipher", "server_name", "ja3", "ja3s")
QUIC_SIGNAL_TOKENS = ("quic", "cid", "scid", "dcid", "h3", "http3")
```

If the tshark filtering step worked correctly, nearly every row in the merged CSV should
have at least one of these signals populated — because the rows are flows from a
TLS/QUIC-only PCAP. If many rows lack these signals, it means:
1. The display filter did not work correctly, OR
2. The Zeek-NFStream merge lost the Zeek protocol metadata

The quality gate enforces: `non_tls_quic_rate ≤ max_non_tls_quic_rate` (default 5%).
If more than 5% of merged rows lack TLS/QUIC signals, the pipeline fails.

**This is why filtering and quality gates are deeply linked.** The filtering step at
the PCAP level is verified downstream at the feature level.

---

## 11. What Survives the Filter — a Concrete Example

Given a typical home network PCAP with 10,000 packets:

```
Protocol breakdown before filtering:
  DNS:              2,100 packets  (21%)  ← dropped by "tls or quic" filter
  HTTP (port 80):     850 packets  ( 8%)  ← dropped
  ARP:                320 packets  ( 3%)  ← dropped
  ICMP:               180 packets  ( 2%)  ← dropped
  NTP:                 90 packets  ( 1%)  ← dropped
  TLS (HTTPS):      5,800 packets  (58%)  ← KEPT
  QUIC (HTTP/3):      660 packets  ( 7%)  ← KEPT
  ────────────────────────────────────────
  After filter:     6,460 packets  (65%)
```

The filtered PCAP is 35% smaller. NFStream and Zeek run faster, extract more focused
features, and do not produce flow records for irrelevant protocols.

---

## 12. The Full Call Chain for One Malicious PCAP

```
CLI: tls-dataset run-malicious-pipeline
     --dataset-name malicious_full_v2
     --input-pcap BotnetCapture/malicious.pcapng
     --output-dir artifacts/runs/malicious_full_v2
     --prepare-only
          │
          ▼
malicious.py: run_malicious_pipeline()
          │
          ├── prepare_malicious_capture()
          │       │
          │       ├── build_dataset_artifacts("malicious_full_v2", ...)
          │       │     → artifacts.raw_pcap, artifacts.sanitized_pcap,
          │       │       artifacts.filtered_pcap, artifacts.provenance_json
          │       │
          │       ├── _copy_raw_capture(input_pcap → artifacts.raw_pcap)
          │       │     shutil.copy2(source, target)
          │       │     → malicious_full_v2_raw.pcapng
          │       │
          │       ├── filtering.sanitize_pcap(raw_pcap → sanitized_pcap)
          │       │     _require_tool("editcap")   → /usr/bin/editcap
          │       │     subprocess.run(["editcap", raw, sanitized])
          │       │     returns {command, stderr, stdout, tool_version}
          │       │     → malicious_full_v2_sanitized.pcapng
          │       │
          │       ├── filtering.filter_encrypted_pcap(sanitized → filtered)
          │       │     _require_tool("tshark")    → /usr/bin/tshark
          │       │     subprocess.run(["tshark", "-r", sanitized,
          │       │                    "-Y", "tls or quic",
          │       │                    "-w", filtered])
          │       │     returns {command, display_filter, stderr, stdout, tool_version}
          │       │     → malicious_full_v2_filtered_tls_quic.pcapng
          │       │
          │       └── write_provenance([raw_entry, sanitized_entry, filtered_entry],
          │                            artifacts.provenance_json)
          │             → malicious_full_v2_provenance.json
          │
          └── (if not prepare_only: run_dataset_pipeline on sanitized PCAP)
```

---

## 13. Design Decisions Worth Knowing for Interviews

### Decision 1: Why sanitize AND filter as two separate steps?

They could theoretically be combined: editcap has some filtering capabilities, and
tshark can sanitise while filtering. The project keeps them separate because:

- **Single responsibility:** `sanitize_pcap` is about correctness. `filter_encrypted_pcap`
  is about scope. Each function does one thing.
- **Separate provenance entries:** Two steps = two entries in `provenance.json`, each
  with its own command, tool version, and output hash. The lineage chain is explicit.
- **Debuggability:** If the filtered PCAP is wrong, you can inspect the sanitized PCAP
  independently to determine if sanitization introduced the issue.
- **Reusability:** You might want the sanitised PCAP for inspection even without the
  filter applied (e.g., to check the full protocol distribution before filtering).

### Decision 2: Why `check=False` in subprocess.run?

Using `check=True` would automatically raise `subprocess.CalledProcessError` on any
non-zero exit code. That would produce a generic traceback without the tool's own error
message. Using `check=False` lets the code:
1. Capture the tool's actual error output (`result.stderr`)
2. Embed it directly in a `RuntimeError` with context about which file failed

The resulting error message is far more actionable:
```
RuntimeError: editcap failed to sanitize /path/to/raw.pcapng:
  Can't open /path/to/raw.pcapng: No such file or directory
```
vs:
```
subprocess.CalledProcessError: Command '['editcap', ...]' returned non-zero exit status 1
```

### Decision 3: Why `"tls or quic"` as the default, not just `"tls"`?

QUIC is the transport for HTTP/3 and carries encrypted application data exactly like
TLS over TCP. Botnets and malware increasingly use QUIC to evade TLS-inspection
appliances (since QUIC is encrypted from the very first packet and harder to inspect
than TLS on TCP). The project is designed to detect malicious activity in both TLS and
QUIC traffic, so both must be included in the filter.

---

## 14. Interview Questions & Answers for Tutorial 04

**Q: What is the difference between a BPF filter and a tshark display filter?**
> A BPF filter operates at capture time in the kernel — it is evaluated before packets
> reach userspace and can only inspect basic header fields (IP, port, protocol number).
> A display filter operates after full protocol dissection — tshark decodes every packet
> then checks if it matches. Display filters are slower but vastly more expressive.
> `tls or quic` as a display filter matches packets that Wireshark has identified as TLS
> or QUIC at the application layer, regardless of which port they use. A BPF filter
> `tcp port 443` would match everything on port 443, including non-TLS traffic.

**Q: Why is the error condition for `sanitize_pcap` `returncode != 0 AND not output_path.exists()` instead of just `returncode != 0`?**
> editcap exits non-zero when it encounters warnings during processing — for example,
> when it repairs malformed packets. In those cases, it still writes a valid output file.
> Failing on any non-zero exit would incorrectly abort the pipeline on PCAPs with minor
> formatting issues, which is exactly the use case sanitization is designed to handle.
> The AND condition means: only fail if editcap both exited non-zero AND produced no
> output, which indicates a genuine failure rather than a fixable warning.

**Q: What does `shutil.which()` do and why is it used instead of hardcoding `/usr/bin/editcap`?**
> `shutil.which(name)` searches the `PATH` environment variable for an executable named
> `name`, returning its full path or `None`. It is used because tool locations vary
> across systems — editcap might be at `/usr/bin/editcap`, `/usr/local/bin/editcap`, or
> `/opt/wireshark/bin/editcap`. Using `which` finds the correct location on the current
> system. Hardcoding the path would break on any system where the tool is installed in
> a non-standard location.

**Q: Why must sanitization happen before filtering?**
> Malformed packets in a raw PCAP can cause tshark's display filter engine to crash,
> skip packets, or misclassify them. editcap normalises the PCAP into a valid structure
> so tshark processes clean input. The ordering — sanitize then filter — is also
> preserved in provenance as two separate transformation stages with separate hashes.

**Q: What does the `*` in `filter_encrypted_pcap(input_pcap, output_pcap, *, display_filter=...)` do?**
> The bare `*` makes everything after it keyword-only. `display_filter` cannot be passed
> as a positional argument — you must explicitly write `display_filter="tls or quic"`.
> This prevents bugs where a caller passes arguments in the wrong order and the filter
> string ends up in the wrong parameter without raising an error.

**Q: Why is `tool_version()` called inside the return statement of each function?**
> The version of the tool used to produce an artifact is recorded in provenance for
> reproducibility. If Wireshark releases a version with a different dissector that
> classifies some packets differently, knowing which version was used allows you to
> attribute differences in output to tool changes. Calling `tool_version()` at return
> time (not at module import) means the version is captured at the exact moment the
> tool ran, not when the module was loaded.

**Q: What is the purpose of the `display_filter` field in `filter_encrypted_pcap`'s return dict?**
> The filter string used is returned so it can be stored in provenance. In `malicious.py`,
> it becomes the `notes` field of the filtered capture's provenance entry:
> `"Display filter: tls or quic"`. This means anyone reading the provenance record for a
> filtered PCAP knows exactly what filter was applied, without having to re-examine the
> code.

**Q: What is `check_pcap_health()` checking for and which tool does it use?**
> It checks whether the PCAP was truncated — cut off mid-packet during capture. It uses
> `capinfos` (part of the Wireshark suite) with `-Tm` flags (tabular, machine-readable
> output). capinfos reports warnings to stderr when it detects truncation markers.
> `is_truncation_warning()` scans that stderr for known phrases like "appears to have
> been cut short". The CTU-13 malicious PCAP in this project was confirmed truncated
> at this stage. A truncated PCAP is flagged as `fail` in the quality report.

---

*Previous: [03_pipeline_common.md](03_pipeline_common.md)*
*Next: [05_pipeline_zeek_runner.md](05_pipeline_zeek_runner.md)*
