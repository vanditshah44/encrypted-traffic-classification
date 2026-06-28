# Tutorial 05 — Pipeline Zeek Runner: Finding and Executing Zeek

**Primary file:** `src/tls_dataset/pipeline/zeek_runner.py`

**Also covered (connections):**
- `src/tls_dataset/pipeline/zeek.py` — converts Zeek's output logs to CSV (covered fully in Tutorial 06)
- `src/tls_dataset/pipeline/malicious.py` — calls `zeek_available()` and `run_zeek_on_pcap()`
- `src/tls_dataset/pipeline/orchestration.py` — calls `convert_zeek_logs()` (which reads from the directory `run_zeek_on_pcap` writes to)
- `tests/test_zeek_runner.py` — tests binary resolution
- `tests/test_zeek_compatibility.py` — tests Zeek output validation

**Prerequisite:** Tutorial 04 (Pipeline Filtering)

---

## 1. What This File Does in One Sentence

`zeek_runner.py` finds the Zeek binary on the system (wherever it may be installed),
runs it against a filtered PCAP, and captures the resulting log directory — all as a
Python-callable function that returns metadata for provenance tracking.

---

## 2. What Zeek Is — Deep Background

**Zeek** (formerly called Bro) is an open-source **network security monitor** and
analysis framework. It is not just a packet sniffer — it is a full protocol analysis
engine with its own scripting language, event system, and log format.

When Zeek processes a PCAP, it:

1. **Reads every packet** at the network level
2. **Reconstructs sessions** — understands TCP handshakes, connection states, retransmits
3. **Dissects application protocols** — TLS, HTTP, DNS, SSH, SMTP, QUIC and dozens more
4. **Extracts semantic fields** from each protocol — for TLS, that means the cipher suite,
   the certificate, the SNI (server name), the TLS version, the JA3 fingerprint
5. **Writes structured log files** — one log file per protocol, one row per connection

This is fundamentally different from what NFStream does. NFStream counts packets and
bytes. Zeek *understands* what those packets mean at the protocol level.

### The Zeek logs this project cares about

| Log file | What it contains | Key columns |
|----------|-----------------|-------------|
| `conn.log` | Every TCP/UDP connection summary | `uid`, `id.orig_h` (src_ip), `id.resp_h` (dst_ip), `id.orig_p` (src_port), `id.resp_p` (dst_port), `duration`, `orig_bytes`, `resp_bytes`, `conn_state` |
| `ssl.log` | TLS session metadata (TLS 1.2 and earlier uses this) | `uid`, `version`, `cipher`, `server_name` (SNI), `subject` (cert CN), `ja3`, `ja3s` |
| `tls.log` | TLS 1.3 specific events | `uid`, `version`, `cipher`, `client_hello_extensions`, `established` |
| `x509.log` | X.509 certificate details | `uid`, `certificate.subject`, `certificate.issuer`, `certificate.not_valid_after`, `certificate.key_alg` |
| `quic.log` | QUIC session metadata | `uid`, `version`, `client_scid`, `server_scid` |

**The `uid` field is critical.** Every row in every Zeek log has a `uid` — a unique
session identifier that Zeek assigns to each connection. This `uid` is the join key
used in `merge_features.py` to link NFStream flow statistics with Zeek protocol data.
Without the `uid`, the merge cannot happen.

### What a TLS 1.3 connection looks like in Zeek's ssl.log

A single HTTPS connection from your browser to a server produces one row in `ssl.log`:

```
uid             version  cipher                         server_name        ja3                              ja3s
CnKyMV3...      TLSv13   TLS_AES_256_GCM_SHA384         google.com         771,4866-4867-...,0-23-65281-... abc123...
```

The `ja3` column is a fingerprint of the TLS ClientHello. It hashes the TLS version,
ciphersuites, extensions, elliptic curves, and elliptic curve formats into a short MD5
string. Malware and legitimate software have different JA3 fingerprints, even if both
use TLS. JA3 fingerprinting is a standard technique in network threat intelligence.

### Why Zeek is not a Python package

Zeek is written in **C++** and has its own scripting language (Zeek Script). It does not
have a Python API. The only way to use it from Python is to invoke it as an external
subprocess — exactly what `zeek_runner.py` does. This is the same pattern used in
Tutorial 04 for editcap and tshark.

---

## 3. The Installation Problem — Why Zeek Is Hard to Find

Unlike editcap and tshark (which are part of the Wireshark suite and typically installed
at standard system paths like `/usr/bin/`), Zeek is a specialist security tool with
**multiple non-standard installation locations** depending on the system:

| Installation method | Typical binary location |
|--------------------|------------------------|
| Package manager (apt/yum) | `/usr/bin/zeek` |
| Official Zeek installer | `/opt/zeek/bin/zeek` |
| Manual build from source | `/usr/local/zeek/bin/zeek` |
| Custom prefix build | `/opt/zeek-5.x/bin/zeek` (version-specific) |
| Docker container (this project) | Specified via `ZEEK_BIN` env var |
| Conda environment | `~/.conda/envs/security/bin/zeek` |

A simple `shutil.which("zeek")` only finds Zeek if it is in `PATH`. In many
environments — particularly Docker containers and research servers — Zeek is installed
in a non-standard location that is not in `PATH`. The `resolve_zeek_binary()` function
handles this reality.

---

## 4. The Full Source: `zeek_runner.py`

```python
"""Local Zeek execution helpers."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


DEFAULT_ZEEK_CANDIDATES = (
    "/opt/zeek/bin/zeek",
    "/usr/local/zeek/bin/zeek",
    "/usr/bin/zeek",
)


def resolve_zeek_binary() -> str | None:
    ...

def zeek_available() -> bool:
    ...

def run_zeek_on_pcap(
    input_pcap: str | Path,
    output_dir: str | Path,
    *,
    extra_args: list[str] | None = None,
) -> dict[str, str]:
    ...
```

Three public names, one private constant. The file is 69 lines total.

---

## 5. `DEFAULT_ZEEK_CANDIDATES` — The Hardcoded Fallback List

```python
DEFAULT_ZEEK_CANDIDATES = (
    "/opt/zeek/bin/zeek",
    "/usr/local/zeek/bin/zeek",
    "/usr/bin/zeek",
)
```

This is a **tuple** (not a list) of paths where Zeek is commonly installed.

**Why a tuple?** It is module-level, immutable, and used as a read-only sequence.
Tuples convey immutability by convention in Python — this list of candidates is a
constant that should never be modified at runtime.

**The three paths and why:**

- **`/opt/zeek/bin/zeek`** — the Zeek Project's recommended installation prefix. Their
  official packages and installer target `/opt/zeek`. This is the most common location
  for a correctly installed Zeek on a Linux server. Listed first among hardcoded paths
  because it's the most likely.

- **`/usr/local/zeek/bin/zeek`** — the traditional Unix location for locally-compiled
  software. If someone built Zeek from source with the default prefix, it ends up here.

- **`/usr/bin/zeek`** — where package managers like `apt` put Zeek when installed via
  `apt install zeek`. Listed last because package-manager versions are often older and
  behind the official distribution.

**These are fallbacks.** If Zeek is in `PATH` or specified via `ZEEK_BIN`, the
candidates list is never checked.

---

## 6. `resolve_zeek_binary()` — The Priority Chain

```python
def resolve_zeek_binary() -> str | None:
    env_binary = os.environ.get("ZEEK_BIN")
    candidates = [env_binary] if env_binary else []
    path_binary = shutil.which("zeek")
    if path_binary:
        candidates.append(path_binary)
    candidates.extend(DEFAULT_ZEEK_CANDIDATES)

    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.exists() and path.is_file():
            return str(path.resolve())
    return None
```

### Return type: `str | None`

Returns the **full absolute path** to the Zeek binary as a string, or `None` if Zeek
cannot be found anywhere. The caller decides what to do with `None` — this function
only discovers, never raises.

### Building the candidate list — priority order

The function builds a priority-ordered list of paths to try:

```
Priority 1: ZEEK_BIN environment variable  (explicit override — highest priority)
Priority 2: shutil.which("zeek")            (PATH search — second priority)
Priority 3: DEFAULT_ZEEK_CANDIDATES         (hardcoded fallbacks — last resort)
```

**Step 1: Check `ZEEK_BIN` environment variable**
```python
env_binary = os.environ.get("ZEEK_BIN")
candidates = [env_binary] if env_binary else []
```

`os.environ.get("ZEEK_BIN")` reads the `ZEEK_BIN` variable from the process environment.
This is the same variable declared in `configs/backend.env.example`:
```bash
ZEEK_BIN=/opt/zeek/bin/zeek
```

If set, it is added first — it beats everything else. This gives operators and Docker
deployments a reliable way to specify exactly which Zeek to use without modifying PATH
or file permissions.

If `ZEEK_BIN` is not set, `os.environ.get()` returns `None`, and the conditional
`[env_binary] if env_binary else []` correctly produces an empty list (not `[None]`,
which would cause a bug in the candidate loop).

**Step 2: Check `PATH`**
```python
path_binary = shutil.which("zeek")
if path_binary:
    candidates.append(path_binary)
```

`shutil.which("zeek")` searches the directories in `PATH` for an executable named
`zeek`. If found, its full path is appended as the second candidate.

Note: this only appends if `path_binary` is truthy — `shutil.which` returns `None`
when not found, and `None` must not be added to the candidate list.

**Step 3: Add hardcoded candidates**
```python
candidates.extend(DEFAULT_ZEEK_CANDIDATES)
```

The three hardcoded paths are appended at the end. They will only be tried if both
`ZEEK_BIN` and `PATH` searches failed.

### Walking the candidate list

```python
for candidate in candidates:
    if not candidate:
        continue
    path = Path(candidate).expanduser()
    if path.exists() and path.is_file():
        return str(path.resolve())
return None
```

**`if not candidate: continue`** — defensive guard. If any candidate in the list is an
empty string or `None` (which shouldn't happen given the construction above, but is
safe to handle), skip it.

**`Path(candidate).expanduser()`** — handles `~` in paths. If someone sets
`ZEEK_BIN=~/tools/zeek`, `expanduser()` resolves `~` to the home directory.

**`path.exists() and path.is_file()`** — the crucial check. Both conditions must be
true:
- `path.exists()` — the path actually exists on the filesystem
- `path.is_file()` — it is a regular file, not a directory or symlink to a directory

Why both? A directory named `zeek` at one of the candidate paths would pass `exists()`
but fail `is_file()`. A dangling symlink would fail `exists()`. This check ensures the
candidate is an actual executable file.

**`return str(path.resolve())`** — the first valid candidate wins. `.resolve()` converts
the path to an absolute path, resolving any symlinks. This means if `/opt/zeek/bin/zeek`
is actually a symlink to `/opt/zeek-5.2.0/bin/zeek`, the resolved path is returned,
giving a precise record of which binary was actually used.

**`return None`** at the end — if all candidates are exhausted without finding a valid
executable, return `None`. The caller handles this.

---

## 7. `zeek_available()` — The Simple Sentinel

```python
def zeek_available() -> bool:
    return resolve_zeek_binary() is not None
```

A **one-liner predicate**. Returns `True` if Zeek can be found, `False` otherwise.

**Why have this function at all?** Because the calling code in `malicious.py` reads
more clearly with a named predicate:

```python
# In malicious.py:
if not zeek_available():
    raise FileNotFoundError(
        "zeek binary not found on PATH. Provide --zeek-log-dir/--zeek-csv-dir "
        "or run on a host with Zeek installed."
    )
resolved_zeek_log_dir = artifacts.zeek_log_dir
zeek_stage = run_zeek_on_pcap(processing_pcap, resolved_zeek_log_dir)
```

This guard in `malicious.py` is the **only place** where failing to find Zeek raises
an exception. The function `resolve_zeek_binary()` itself returns `None` silently.
The error message is specifically informative — it tells the user what they can do
instead of just saying "Zeek not found":
- Provide `--zeek-log-dir` to reuse an existing Zeek output directory
- Provide `--zeek-csv-dir` to reuse already-converted Zeek CSVs
- Or run on a machine with Zeek installed

This design lets the pipeline run without Zeek in environments where Zeek logs were
pre-generated elsewhere — the runner only executes Zeek if explicitly asked to and
if it can be found.

---

## 8. `run_zeek_on_pcap()` — The Core Function

```python
def run_zeek_on_pcap(
    input_pcap: str | Path,
    output_dir: str | Path,
    *,
    extra_args: list[str] | None = None,
) -> dict[str, str]:
    binary = resolve_zeek_binary()
    if binary is None:
        raise FileNotFoundError("zeek binary not found on PATH or in standard install locations")

    input_path = Path(input_pcap).expanduser().resolve()
    out_dir = Path(output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    command = [binary, "-C", "-r", str(input_path)] + (extra_args or [])
    result = subprocess.run(command, cwd=out_dir, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Zeek failed on {input_path}: {result.stderr.strip() or result.stdout.strip()}")

    version_result = subprocess.run([binary, "--version"], capture_output=True, text=True, check=False)
    version_text = version_result.stdout.strip() or version_result.stderr.strip()

    return {
        "input_pcap": str(input_path),
        "output_dir": str(out_dir),
        "command": " ".join(command),
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "tool_version": version_text.splitlines()[0] if version_text else "zeek",
    }
```

### Parameters

**`input_pcap: str | Path`** — the filtered PCAP to analyse. In `malicious.py`, this
is `artifacts.sanitized_pcap` (the sanitized capture — NOT the TLS/QUIC-filtered one,
because NFStream also needs the full sanitized capture to extract flow statistics for
all flows).

**`output_dir: str | Path`** — the directory where Zeek writes its log files. In
`malicious.py`, this is `artifacts.zeek_log_dir` (e.g.,
`malicious_full_v2_zeek_logs/`). Zeek does not write to a single file — it writes one
file per protocol.

**`extra_args: list[str] | None = None`** — optional additional command-line arguments
to pass to Zeek. The `*` before it makes it keyword-only. This escape hatch allows
callers to pass Zeek script arguments, policy options, or package flags without
modifying `zeek_runner.py`. Currently used nowhere in the codebase but designed for
extensibility.

### Resolve and guard

```python
binary = resolve_zeek_binary()
if binary is None:
    raise FileNotFoundError("zeek binary not found on PATH or in standard install locations")
```

`resolve_zeek_binary()` is called again here. This is the guard inside the function —
`zeek_available()` is a pre-flight check in the calling code, but `run_zeek_on_pcap`
also checks itself in case it is called directly without going through `malicious.py`'s
guard. Defense in depth.

### Prepare the output directory

```python
input_path = Path(input_pcap).expanduser().resolve()
out_dir = Path(output_dir).expanduser().resolve()
out_dir.mkdir(parents=True, exist_ok=True)
```

The output directory is created before running Zeek. Zeek writes its logs to whatever
directory it is run from (its **working directory**), not to a path specified on the
command line. This is fundamental to understanding the `cwd` parameter below.

### Building the Zeek command

```python
command = [binary, "-C", "-r", str(input_path)] + (extra_args or [])
```

The full command looks like:
```bash
/opt/zeek/bin/zeek -C -r /abs/path/to/malicious_full_v2_sanitized.pcapng
```

**Breaking down the Zeek flags:**

| Flag | Meaning | Why used |
|------|---------|---------|
| `-C` | **Ignore IP checksum errors.** Don't validate TCP/IP checksums. | Many PCAPs captured in virtualised environments (VMs, Docker) have incorrect checksums because the hypervisor offloads checksum computation to the NIC. Without `-C`, Zeek silently drops packets with bad checksums, producing incomplete logs. |
| `-r` | **Read from file.** Process a PCAP file instead of live traffic. | Without `-r`, Zeek listens on a network interface for live traffic. `-r` puts it in offline (offline replay) mode. |

**`extra_args or []`** — if `extra_args` is `None`, substitute an empty list, so the
`+` operator has a list on both sides. This avoids a `TypeError` if `extra_args` is
not provided.

### Running Zeek with `cwd=out_dir`

```python
result = subprocess.run(command, cwd=out_dir, capture_output=True, text=True, check=False)
```

**`cwd=out_dir`** — this is the most important parameter. `cwd` sets the **working
directory** of the subprocess. Zeek writes all its output log files to its current
working directory. There is no Zeek command-line flag that says "write logs to this
specific directory" for all log types simultaneously.

By setting `cwd=out_dir`, Python tells the OS: "start the Zeek process with its working
directory set to `out_dir`". Zeek then creates `conn.log`, `ssl.log`, `tls.log`, etc.
directly in `out_dir`. After Zeek finishes, the directory looks like:

```
malicious_full_v2_zeek_logs/
├── conn.log
├── ssl.log         (or tls.log for TLS 1.3)
├── x509.log
├── files.log
├── packet_filter.log
├── loaded_scripts.log
└── weird.log       (Zeek's log for anomalies it noticed)
```

**Why `cwd` instead of redirecting output?** Some Zeek log files (especially `conn.log`)
can be gigabytes. Piping them through Python's stdin would be impractical. Using `cwd`
lets Zeek write directly to disk at full speed.

### Error handling

```python
if result.returncode != 0:
    raise RuntimeError(f"Zeek failed on {input_path}: {result.stderr.strip() or result.stdout.strip()}")
```

Unlike `sanitize_pcap()` (which had the AND condition with `output_path.exists()`),
Zeek's error handling is strict: **any non-zero return code is a failure**. Zeek is
designed to exit 0 on success and non-zero on any error. If Zeek cannot read the PCAP,
cannot write to the output directory, or crashes on a malformed packet, it exits
non-zero and the error message from `result.stderr` tells you why.

### Getting the version separately

```python
version_result = subprocess.run([binary, "--version"], capture_output=True, text=True, check=False)
version_text = version_result.stdout.strip() or version_result.stderr.strip()
```

Notice that the version is obtained by running Zeek a **second time** with `--version`
rather than parsing it from the processing run's output. Why?

When Zeek processes a PCAP (`zeek -r file.pcap`), its stdout/stderr contains log
messages about the analysis — how many connections were processed, any warnings about
packets, etc. The version string would be buried in that output. By running
`zeek --version` separately, the version string is cleanly isolated.

This is the same pattern as `tool_version()` in `filtering.py`, but here it's done
inline rather than through the helper function. Both approaches produce the same result.

**Zeek's `--version` output looks like:**
```
Zeek 5.2.0 (version/5.2.0/master)
```

`version_text.splitlines()[0]` takes just the first line.

### Return value

```python
return {
    "input_pcap": str(input_path),
    "output_dir": str(out_dir),
    "command": " ".join(command),
    "stdout": result.stdout.strip(),
    "stderr": result.stderr.strip(),
    "tool_version": version_text.splitlines()[0] if version_text else "zeek",
}
```

This dict is used in `malicious.py` to:
1. Append a `"zeek_logs"` entry to the provenance JSON
2. Return the Zeek stage results in the overall `run_malicious_pipeline()` return dict

The `stderr` field is particularly important — if Zeek encountered problems (weird
packets, truncated connections), those warnings appear in stderr and are preserved in
the provenance record.

---

## 9. How `malicious.py` Uses Both Functions

In `run_malicious_pipeline()`, the Zeek functions are called as follows:

```python
zeek_stage: dict[str, str] | None = None
resolved_zeek_log_dir: str | Path | None = zeek_log_dir

if run_zeek:
    # Guard: fail fast with actionable message if Zeek not installed
    if not zeek_available():
        raise FileNotFoundError(
            "zeek binary not found on PATH. Provide --zeek-log-dir/--zeek-csv-dir "
            "or run on a host with Zeek installed."
        )

    # Run Zeek on the SANITIZED pcap (not filtered — full traffic context for Zeek)
    resolved_zeek_log_dir = artifacts.zeek_log_dir
    zeek_stage = run_zeek_on_pcap(processing_pcap, resolved_zeek_log_dir)

    # Append the Zeek stage to provenance JSON that was already written
    existing = Path(artifacts.provenance_json).expanduser().resolve()
    payload = existing.read_text(encoding="utf-8")
    import json
    data = json.loads(payload)
    data["entries"].append({
        "stage": "zeek_logs",
        "path": str(Path(resolved_zeek_log_dir).expanduser().resolve()),
        "sha256": "",
        "size_bytes": 0,
        "parent_path": str(Path(processing_pcap).expanduser().resolve()),
        "tool": "zeek",
        "tool_version": zeek_stage["tool_version"],
        "command": zeek_stage["command"],
        "notes": "Zeek log directory generated from the sanitized malicious capture.",
    })
    existing.write_text(json.dumps(data, indent=2), encoding="utf-8")
```

**Important observation:** Zeek runs on `artifacts.sanitized_pcap`, not
`artifacts.filtered_pcap`. The sanitized PCAP contains all protocols (not just TLS/QUIC).
Why? Because Zeek needs full TCP/UDP session context to correctly dissect TLS sessions.
TLS runs on top of TCP — if Zeek only sees the application-layer TLS packets without the
underlying TCP connection records, it may miss session correlation or misclassify
connection states. The `conn.log` (which records all connections) must cover the full
network context, not just the encrypted traffic.

After Zeek runs, the pipeline calls `convert_zeek_logs()` (from `zeek.py`) to convert
the `.log` files to `.csv` files. The log directory (`artifacts.zeek_log_dir`) is the
input, and the CSV directory (`artifacts.zeek_csv_dir`) is the output.

---

## 10. The `convert_zeek_logs()` Connection — What Happens After `run_zeek_on_pcap`

`zeek_runner.py` produces raw `.log` files. `zeek.py`'s `convert_zeek_logs()` converts
them to `.csv`. The connection is:

```
run_zeek_on_pcap(pcap, artifacts.zeek_log_dir)
    → writes: malicious_full_v2_zeek_logs/conn.log
               malicious_full_v2_zeek_logs/ssl.log
               malicious_full_v2_zeek_logs/tls.log
               ...

convert_zeek_logs(zeek_dir=artifacts.zeek_log_dir, out_dir=artifacts.zeek_csv_dir)
    → reads:  malicious_full_v2_zeek_logs/conn.log   → malicious_full_v2_zeek_csv/conn.csv
              malicious_full_v2_zeek_logs/ssl.log    → malicious_full_v2_zeek_csv/ssl.csv
              malicious_full_v2_zeek_logs/tls.log    → malicious_full_v2_zeek_csv/tls.csv
              ...
```

The six logs that `zeek.py` processes by default:
```python
LOGS_OF_INTEREST = ["conn.log", "ssl.log", "tls.log", "x509.log", "quic.log", "http.log"]
```

Only logs that actually exist in `zeek_log_dir` are converted — the code filters:
```python
log_files = [p for p in log_files if p.exists()]
```

---

## 11. The Real-World Finding: What Zeek Produced for the Malicious PCAP

From `docs/findings-register.md` Finding #5:

> **Zeek still produced only `conn.csv`, not `ssl.csv`, `tls.csv`, or `quic.csv`**
> for the malicious CTU-13 capture.

This is not a bug. It is a **data quality issue** with the source PCAP.

Here is what happened: the CTU-13 botnet capture available in the project is truncated
(as detected by `check_pcap_health()`). The TLS sessions in that capture were
incomplete — the handshakes were cut off before Zeek could extract TLS session data.
Zeek recorded that the TCP connections existed (in `conn.log`) but could not identify
them as TLS because it never saw a complete TLS ClientHello.

The evidence is in `malicious_full_v2_zeek_logs/weird.log` — Zeek's log for protocol
anomalies it encountered. Entries there describe malformed or truncated packets that
could not be fully dissected.

**Impact on the project:**
- All 30,172 malicious flows have NFStream features but lack Zeek TLS metadata
- The `quality_status` for all malicious rows is `"fail"` in the canonical dataset
- The ML models are trained primarily on NFStream flow statistics for malicious traffic,
  not on TLS handshake fields like cipher, JA3, or SNI
- This is acknowledged as the biggest scientific weakness in `findings-register.md`

**What the `zeek_outputs` quality gate catches:**

```python
def check_zeek_outputs(zeek_csv_dir: str | Path) -> GateOutcome:
    required = {"conn.csv"}
    encrypted_evidence = {"ssl.csv", "tls.csv", "quic.csv"}
    ...
    if not has_encrypted_evidence:
        return GateOutcome("zeek_outputs", "fail",
                           "None of ssl.csv, tls.csv, or quic.csv is present", metrics)
```

The malicious pipeline would fail this gate — which is why the project's canonical
dataset shows `quality_status=fail` for all malicious rows. The pipeline is designed
to detect and flag exactly this kind of data quality issue.

---

## 12. The Test File: `test_zeek_runner.py`

```python
class ZeekRunnerTests(unittest.TestCase):
    def test_resolve_zeek_binary_prefers_env_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            zeek_path = Path(tmp_dir) / "zeek"
            zeek_path.write_text("#!/bin/sh\n", encoding="utf-8")

            with patch.dict("os.environ", {"ZEEK_BIN": str(zeek_path)}, clear=False):
                with patch("shutil.which", return_value=None):
                    self.assertEqual(resolve_zeek_binary(), str(zeek_path.resolve()))
```

This test verifies the **priority rule**: `ZEEK_BIN` beats `PATH`.

**How it works:**

1. `tempfile.TemporaryDirectory()` — creates a real temporary directory that is cleaned
   up automatically after the `with` block. This is how tests create real filesystem
   state without polluting the project directory.

2. `zeek_path.write_text("#!/bin/sh\n", ...)` — creates a fake "Zeek binary" — just a
   shell script with a shebang line. It does not need to be runnable; `resolve_zeek_binary`
   only checks `path.exists()` and `path.is_file()`, not whether the file is executable
   or actually runs correctly.

3. `patch.dict("os.environ", {"ZEEK_BIN": str(zeek_path)}, clear=False)` — temporarily
   adds `ZEEK_BIN` to the environment for the duration of the `with` block. `clear=False`
   means the rest of the environment is preserved.

4. `patch("shutil.which", return_value=None)` — makes `shutil.which` return `None` for
   any input. This simulates Zeek not being in `PATH`, isolating the test to only the
   `ZEEK_BIN` path.

5. `self.assertEqual(resolve_zeek_binary(), str(zeek_path.resolve()))` — asserts that
   `resolve_zeek_binary()` returns the `ZEEK_BIN` path, proving it takes priority.

**The `test_zeek_compatibility.py` file** tests the quality gate — that `check_zeek_outputs`
passes when `conn.csv` and `tls.csv` are present, and that the merge step prefers
`ssl.csv` over `tls.csv` when both exist.

---

## 13. How `run_zeek_on_pcap` Fits Into the Pipeline's Two Entry Points

The orchestration layer (`orchestration.py`) and the malicious layer (`malicious.py`)
handle Zeek differently:

### Via `malicious.py` (active Zeek execution)

```python
# malicious.py calls zeek_runner directly
zeek_stage = run_zeek_on_pcap(processing_pcap, resolved_zeek_log_dir)
# Then calls convert_zeek_logs via orchestration.py's run_dataset_pipeline
```

### Via `orchestration.py` (assumes Zeek already ran, just converts logs)

```python
# orchestration.py never calls run_zeek_on_pcap
# It only calls convert_zeek_logs (from zeek.py)
if convert_zeek:
    convert_zeek_logs(zeek_dir=zeek_log_dir, out_dir=resolved_zeek_csv_dir, ...)
```

`orchestration.py` handles the case where Zeek was run externally (by the user, by a
separate system) and the log files already exist. You point it at the log directory
with `--zeek-log-dir`, and it converts those logs to CSV without running Zeek again.
This is useful when:
- Zeek is not installed on the machine running the Python pipeline
- Zeek was run on a dedicated security appliance
- Zeek was run on the raw capture before it was filtered

This separation is intentional: **Zeek execution** and **Zeek log conversion** are
two separate concerns, handled by two separate modules.

---

## 14. Full Data Flow — From PCAP to Zeek CSV

```
artifacts.sanitized_pcap
(.../malicious_full_v2_sanitized.pcapng)
        │
        ▼
zeek_runner.py: run_zeek_on_pcap(sanitized_pcap, artifacts.zeek_log_dir)
    subprocess.run(
        ["/opt/zeek/bin/zeek", "-C", "-r", "malicious_full_v2_sanitized.pcapng"],
        cwd="malicious_full_v2_zeek_logs/"
    )
        │
        ▼
artifacts.zeek_log_dir/
    malicious_full_v2_zeek_logs/
        ├── conn.log      (all TCP/UDP connections)
        ├── ssl.log       (TLS sessions — IF handshakes were complete)
        ├── tls.log       (TLS 1.3 events — IF present)
        ├── x509.log      (certificates — IF TLS sessions established)
        ├── quic.log      (QUIC sessions — IF QUIC traffic present)
        └── weird.log     (anomalies Zeek noticed)
        │
        ▼
zeek.py: convert_zeek_logs(zeek_log_dir, artifacts.zeek_csv_dir)
    sniff_format(conn.log)  → "zeek_tsv" or "json"
    convert_zeek_tsv_to_csv(conn.log → conn.csv)
    convert_zeek_tsv_to_csv(ssl.log  → ssl.csv)
    ...
        │
        ▼
artifacts.zeek_csv_dir/
    malicious_full_v2_zeek_csv/
        ├── conn.csv
        ├── ssl.csv
        └── tls.csv
        │
        ▼
merge_features.py: merge_nfstream_with_zeek(nfstream_csv, zeek_csv_dir → merged_csv)
```

---

## 15. Interview Questions & Answers for Tutorial 05

**Q: What does Zeek produce that NFStream cannot?**
> Zeek performs full protocol dissection and extracts semantic fields from the TLS
> handshake: cipher suite, TLS version, server name indication (SNI), JA3/JA3s
> fingerprints, X.509 certificate subject and issuer, and session UIDs that link
> all Zeek log entries for the same connection. NFStream counts packets and bytes at
> the flow level but does not decode application-layer protocol fields. The join between
> Zeek and NFStream gives both flow statistics AND protocol metadata in one row.

**Q: Why does `resolve_zeek_binary()` return `None` instead of raising an exception?**
> The function is a pure discovery function — it finds, it does not decide. Raising
> or not raising on failure is a policy decision that belongs in the caller. The caller
> (`malicious.py`) uses `zeek_available()` as a pre-flight check and raises a
> `FileNotFoundError` with a specific, actionable message — including the alternative
> of providing `--zeek-log-dir` instead of running Zeek. Separating discovery from error
> policy makes the discovery function reusable in contexts where a missing Zeek is not
> an error (e.g., testing, dry-run modes).

**Q: What does the `-C` flag do when running Zeek and why is it needed?**
> `-C` tells Zeek to ignore IP checksum errors and process packets even if their
> checksums are invalid. In virtualised environments (VMs, Docker containers) and when
> using hardware offloaded checksums, packet checksums in PCAPs are often wrong because
> the NIC was supposed to compute them but the PCAP was captured before that happened.
> Without `-C`, Zeek silently drops such packets, producing incomplete or empty logs.

**Q: Why does Zeek run on the sanitized PCAP rather than the TLS/QUIC-filtered PCAP?**
> Zeek needs full TCP session context to correctly dissect TLS. A TLS session runs over
> TCP — Zeek must see the TCP handshake (SYN, SYN-ACK, ACK) before it can correlate
> the subsequent TLS records to a session and assign a `uid`. If Zeek only saw TLS
> packets without the underlying TCP connections, it could not correctly establish
> session identity or compute connection-level statistics in `conn.log`. The filtered
> PCAP (TLS/QUIC only) is used by NFStream for feature extraction, while Zeek operates
> on the full sanitized traffic.

**Q: Why is `cwd=out_dir` used in `subprocess.run()` instead of a Zeek flag?**
> Zeek writes all its log files to its current working directory. There is no single
> command-line flag that redirects all log output to a specific directory (unlike, say,
> tshark's `-w` flag). Setting `cwd=out_dir` makes the OS start the Zeek process with
> that directory as its working directory, so all logs land there automatically.

**Q: What happened when Zeek processed the CTU-13 malicious PCAP in this project?**
> Zeek only produced `conn.log` — not `ssl.log`, `tls.log`, or `quic.csv`. This is
> because the malicious PCAP was truncated — the TLS handshakes were cut off before
> completion, so Zeek could see that TCP connections existed but could not identify
> them as TLS sessions. The `check_zeek_outputs()` quality gate catches this: it fails
> if none of `ssl.csv`, `tls.csv`, or `quic.csv` is present. All 30,172 malicious rows
> in the canonical dataset carry `quality_status="fail"` as a result.

**Q: What is the priority order in `resolve_zeek_binary()` and why?**
> Priority 1: `ZEEK_BIN` environment variable — explicit operator override, highest
> authority. Priority 2: `shutil.which("zeek")` — respects the system's PATH, which
> system administrators configure. Priority 3: `DEFAULT_ZEEK_CANDIDATES` hardcoded paths
> — last resort for common installation locations. The ordering reflects decreasing
> specificity: an explicit environment variable is more specific than PATH, which is more
> specific than a guess based on known installation patterns.

**Q: How does the test for `resolve_zeek_binary` verify the priority rule without Zeek installed?**
> It uses `unittest.mock.patch`. `patch.dict("os.environ", {"ZEEK_BIN": str(fake_zeek)})` 
> injects `ZEEK_BIN` into the environment for the test. `patch("shutil.which", return_value=None)`
> makes `shutil.which` return `None`, simulating Zeek not being in `PATH`. The fake Zeek
> binary is a real file (created with `write_text("#!/bin/sh\n")`) so `path.exists()`
> and `path.is_file()` return `True`. The test asserts the env var path is returned,
> proving it has higher priority than PATH.

---

*Previous: [04_pipeline_filtering.md](04_pipeline_filtering.md)*
*Next: [06_pipeline_zeek_parser.md](06_pipeline_zeek_parser.md)*
