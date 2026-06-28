# Tutorial 34 — PCAP Downloader (`pipeline/download.py`)

## Prerequisites

- Tutorial 16 (`pipeline/malicious.py`) — the manifest CSV produced by this downloader feeds
  into `run_malicious_pipeline` as provenance metadata. Understanding what the manifest records
  and why clarifies the design decisions here.
- Tutorial 04 (`pipeline/filtering.py`) — the PCAPs downloaded by this tool are the raw input
  to the filtering stage.

---

## 1. Why This File Exists

The malicious captures in this dataset come from the **MCFP (Malware Capture Facility Project)**
at CTU University in Prague. CTU-13 and related captures are published at:
`https://mcfp.felk.cvut.cz/publicDatasets/`

The server is an Apache directory listing — no download API, no torrent, no S3 bucket. The only
way to enumerate and retrieve files is to parse the HTML index pages recursively, identify
`.pcap`-like files, and download them one at a time.

This file is a self-contained tool for that task. It has four responsibilities:

1. **Crawl** — recursively traverse Apache index pages to build a list of PCAP URLs
2. **Filter** — apply directory regex filters so only botnet captures (not benign or other
   categories) are downloaded
3. **Download with resume** — if a download is interrupted mid-file, pick up from the byte
   offset already written rather than restarting
4. **Record a manifest** — write a CSV of every file attempted, its status, and its size, so
   the malicious pipeline has provenance for every capture

---

## 2. `PCAP_EXTS` — Why 18 Extensions

```python
PCAP_EXTS = (
    ".pcap", ".pcapng", ".cap",
    ".pcap.gz", ".pcap.bz2", ".pcap.xz", ".pcap.zst",
    ".pcapng.gz", ".pcapng.bz2", ".pcapng.xz", ".pcapng.zst",
    ".cap.gz", ".cap.bz2", ".cap.xz", ".cap.zst",
    ".pcap.zip", ".pcapng.zip", ".cap.zip",
    ".pcap.tar.gz", ".pcapng.tar.gz", ".cap.tar.gz",
)
```

CTU-13 captures are published in multiple compression formats depending on the capture date and
uploader preference. Some directories have `.pcap`, others have `.pcap.gz`, others `.pcapng.bz2`.
The extension list covers all three base formats (`.pcap`, `.pcapng`, `.cap`) cross all
common compression schemes (`gz`, `bz2`, `xz`, `zst`, `zip`, `tar.gz`). `looks_like_pcap`
checks `filename.lower().endswith(ext)` — using `endswith` rather than splitting on `.` correctly
handles double extensions like `.pcap.tar.gz` where `os.path.splitext` would only see `.gz`.

---

## 3. `build_session` — Retry Strategy (lines 56–69)

```python
retry = Retry(
    total=6,
    backoff_factor=0.8,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=("GET", "HEAD"),
    raise_on_status=False,
)
adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
session.mount("http://", adapter)
session.mount("https://", adapter)
```

**`total=6` with `backoff_factor=0.8`**: urllib3 applies exponential backoff between retries
with the formula `backoff_factor × (2 ^ (attempt - 1))`. After the first failure, it waits
0.8s; after the second, 1.6s; after the third, 3.2s; and so on. Six retries with this factor
means the last retry happens after roughly 25 seconds of cumulative waiting. This is appropriate
for a research scraper targeting a university server that may be temporarily overloaded or
applying rate limiting.

**`status_forcelist=(429, 500, 502, 503, 504)`**: these are the HTTP status codes that indicate
a transient server-side problem worth retrying. `404` is not in the list — a file that doesn't
exist won't appear on retry. `429 Too Many Requests` is critical for university servers that
throttle crawlers.

**`raise_on_status=False`**: the retry policy itself does not raise after all retries are
exhausted — that is left to the calling code (`r.raise_for_status()`). This gives the caller
control over how to handle permanent failures.

**`pool_connections=20, pool_maxsize=20`**: these control the urllib3 connection pool. Each
unique `(scheme, host)` pair gets its own pool of up to 20 connections. Since all requests go
to the same host, this effectively allows 20 concurrent connections — useful if the caller ever
parallellises downloads (it currently doesn't, but the pool is pre-sized for it).

---

## 4. `is_within_base` — Scope Enforcement (lines 72–75)

```python
def is_within_base(url: str, base_url: str) -> bool:
    u = urlparse(url)
    b = urlparse(base_url)
    return (u.scheme, u.netloc) == (b.scheme, b.netloc) and u.path.startswith(b.path)
```

Apache index pages contain links of three kinds:
1. Relative links to subdirectories: `CTU-Malware-Capture-Botnet-42/`
2. Relative links to parent directory: `../` (skipped separately by `apache_index_links`)
3. Absolute links to unrelated domains: navigation links in Apache's default template that
   point to the Apache project website, for example

Without `is_within_base`, the crawler would follow absolute links to external sites. The check
compares `(scheme, netloc)` so that an HTTPS link to a different domain fails, and `u.path.startswith(b.path)` so that a link to `/publicDatasets_mirror/` on the same host (same netloc) is still excluded if the base URL is `/publicDatasets/`.

---

## 5. `safe_join` — Path Traversal Prevention (lines 111–119)

```python
def safe_join(out_dir: Path, rel_path: str) -> Path:
    rel_path = rel_path.replace("\\", "/").lstrip("/")
    target = (out_dir / rel_path).resolve()
    out_root = out_dir.resolve()
    if not str(target).startswith(str(out_root)):
        raise ValueError(f"Refusing to write outside output dir: {target}")
    return target
```

`rel_path` comes from `url_to_rel_path`, which strips the base URL prefix from an absolute URL.
If the server returns a URL whose path, after stripping the base, resolves to `../../etc/passwd`,
a naive `out_dir / rel_path` would write outside the intended output directory (a path traversal
attack). `.resolve()` calls `os.path.realpath` — it resolves `..` components and symlinks,
giving the canonical absolute path. Checking `str(target).startswith(str(out_root))` after
resolution ensures the canonical path is still under the output directory even after all
traversal is resolved.

The `replace("\\", "/")` normalises Windows-style separators that might appear in URL paths
on a Windows host.

---

## 6. `head_metadata` — Range Request Capability (lines 128–143)

```python
accept_ranges = (r.headers.get("Accept-Ranges", "").lower() == "bytes")
return (int(cl) if cl and cl.isdigit() else None), accept_ranges
```

An HTTP range request (`Range: bytes=N-`) allows the client to request bytes starting at offset
N, enabling resume of a partial download. The server signals support by returning
`Accept-Ranges: bytes` in any response header (including a HEAD response). Without this header,
the server may ignore the `Range` header and return the full file from the beginning — the
client would then be appending the full file to the partial file, producing a corrupt result.

`Content-Length` may be absent (`None`) when the server uses chunked transfer encoding or
does not know the file size in advance. The code handles `None` gracefully: without a known
size, the "skip if same size" optimisation is unavailable, but downloading still proceeds.

`cl.isdigit()` guards against malformed `Content-Length` headers that contain non-numeric
characters (rare but possible with misconfigured servers).

---

## 7. `download_with_resume` — Three Download Modes (lines 145–213)

The function branches into three paths based on what already exists locally:

**Path 1 — Skip (lines 164–173)**:
```python
if target.exists() and remote_size is not None and target.stat().st_size == remote_size:
    return {"status": "skipped_exists_same_size", ...}
```
The file is complete. No HTTP GET is issued. This makes re-running the downloader after a
partial run cheap: completed files are checked via a HEAD request and a `st_size` comparison
in microseconds, not re-downloaded.

**Path 2 — Resume (lines 179–183)**:
```python
if target.exists() and accept_ranges:
    resume_from = target.stat().st_size
    if remote_size is None or resume_from < remote_size:
        headers["Range"] = f"bytes={resume_from}-"
        mode = "ab"
```
The file exists, is smaller than the remote file, and the server supports range requests. The
GET request includes `Range: bytes={resume_from}-`, which tells the server to begin the
response body at byte `resume_from`. The file is opened in `"ab"` (append binary) — new bytes
are appended after the already-downloaded content.

The `resume_from < remote_size` check guards against the edge case where a local file is
*larger* than the remote file — possible if the remote file was replaced with a smaller version.
In that case, `resume_from = 0` and `mode = "wb"` resets to a full re-download.

**Path 3 — Full download**:
All other cases. `mode = "wb"` overwrites any partial file.

**`time.sleep(sleep_s)`** at the end of every download is server politeness — the default 0.2s
between requests prevents hammering the CTU server with back-to-back connections. University
servers often have rate limiting or abuse detection; a consistent small delay avoids triggering
it.

**Chunk-based streaming**:
```python
for chunk in r.iter_content(chunk_size=1024 * 1024):
```
`iter_content` streams the response body in 1 MB chunks rather than loading the full file
into memory. PCAP files can be several gigabytes; loading them fully into a bytes object would
exhaust RAM on a typical research machine.

---

## 8. `crawl_for_pcaps` — BFS Crawler (lines 216–273)

```python
queue: List[str] = [base_url]
visited: Set[str] = set()
found: List[DownloadItem] = []

while queue:
    page = queue.pop(0)
    if page in visited:
        continue
    visited.add(page)
    ...
```

`queue.pop(0)` implements BFS (breadth-first search). BFS processes all directories at depth 1
before depth 2, so the discovery order follows directory hierarchy. For CTU-13, this means all
top-level dataset directories are discovered before any subdirectory is crawled. DFS
(`queue.pop()`) would fully exhaust one dataset directory before moving to the next —
acceptable but makes progress reporting less useful.

`visited` prevents re-crawling a directory discovered through multiple paths (e.g., symlinks
within an Apache directory index).

**Directory filter applied at the top level only**:
```python
top = rel.split("/", 1)[0] if rel else ""
if include_re and not include_re.search(top):
    continue
```
`rel.split("/", 1)[0]` extracts the first path segment — the top-level directory name. If
`include_dirs_regex="CTU-Malware-Capture-Botnet-"`, only directories whose first segment
matches that pattern are crawled. Subdirectories within matching directories are crawled
unconditionally. This means `--include-dirs CTU-Malware-Capture-Botnet-` crawls all files
inside any botnet capture directory, not just files in directories whose *full path* matches
the pattern.

**`max_pages` safety limit**:
```python
if max_pages is not None and len(visited) > max_pages:
    break
```
In development or debugging, crawling the entire CTU-13 index without a page limit would issue
hundreds of HTTP requests. `--max-pages 10` lets a developer verify the crawl logic against a
small subset of the site.

---

## 9. `seed_from_datasets_html` — Curated Dataset Discovery (lines 276–300)

The main `crawl_for_pcaps` approach starts at the root index and discovers directories by
traversal. The alternative: CTU publishes `datasets.html`, a curated list of dataset entries
with dates. This page lists datasets that may not all appear directly in the root index.

```python
pat = re.compile(r'(\d{4}-\d{2}-\d{2}).*?(https://mcfp\.felk\.cvut\.cz/publicDatasets/[^\s]+)', re.IGNORECASE)
```

The regex extracts `(date, url)` pairs from the rendered text of `datasets.html`. The date
allows date-range filtering via `--min-date`:

```python
if min_date:
    rows = [r for r in rows if r[0] >= min_date]
```

ISO 8601 dates (`YYYY-MM-DD`) sort and compare correctly as strings — `"2019-01-15" >= "2019-01-01"` is true without parsing. `--min-date 2019-01-01` restricts to datasets published on or after that date, avoiding older captures that may have different protocol compositions.

`sorted(set(urls))` deduplicates URLs (the same dataset URL might appear multiple times in
`datasets.html` across different listing formats) and sorts them for deterministic processing order.

---

## 10. Two Seeding Modes and the Scope Narrowing Pattern (main, lines 342–383)

```python
if args.seed == "crawl":
    items = crawl_for_pcaps(session, base_url, ...)
else:
    dataset_dirs = seed_from_datasets_html(...)
    for d in dataset_dirs:
        sub_items = crawl_for_pcaps(
            session=session,
            base_url=d,        # ← scope limited to this single dataset directory
            include_dirs_regex=None,
            ...
        )
```

In `datasets_html` mode, `crawl_for_pcaps` is called with `base_url=d` — the specific dataset
directory URL — not the root. This narrows the crawl scope to one directory at a time. The
`include_dirs_regex` is disabled because directory filtering was already applied in the outer
loop (`if include_re and not include_re.search(top): continue`). The relative paths from the
sub-crawl are relative to `d`, not to the global base URL, so they are rewritten:

```python
d_rel = url_to_rel_path(d, base_url).rstrip("/") + "/"
items.append(DownloadItem(url=it.url, rel_path=d_rel + it.rel_path))
```

This ensures the output directory structure mirrors the original URL tree: a file at
`CTU-Malware-Capture-Botnet-42/2013-09-01/botnet-capture-20130901.pcap.gz` on the server is
written to the same relative path under `--out`, not flattened into the root.

---

## 11. Download Budget (`--max-total-gb`, lines 441–455)

```python
max_total_bytes = None if args.max_total_gb is None else int(args.max_total_gb * (1024 ** 3))
...
total_downloaded_bytes += dl
if max_total_bytes is not None and total_downloaded_bytes >= max_total_bytes:
    meta["status"] = f"{meta.get('status', '')}|stopped_budget_reached"
    ...
    break
```

CTU-13 contains several hundred gigabytes across all captures. A researcher on a laptop or
with limited disk quota cannot download everything in one run. `--max-total-gb 50` stops after
50 GB have been downloaded in this session.

**The budget counts only bytes actually downloaded in the current run** — resumed bytes from a
previous run (`resume_from > 0`) are excluded. `meta.get("downloaded_bytes")` is the bytes
written in this execution, not the final file size. This means `--max-total-gb` is a
session budget, not a total-on-disk limit. Re-running with the same budget after a partial run
downloads the next 50 GB of not-yet-downloaded files.

The status field uses `|stopped_budget_reached` as a suffix rather than replacing the
status entirely — the previous status (`downloaded` or `skipped_exists_same_size`) is
preserved. The manifest row for the file that triggered the budget stop is still written before
the loop breaks, so the manifest is complete through the last file processed.

---

## 12. Progressive Manifest Writing (lines 396–462)

```python
with open(manifest_path, "w", newline="", encoding="utf-8") as mf:
    w = csv.DictWriter(mf, fieldnames=[...])
    w.writeheader()
    for idx, it in enumerate(items, start=1):
        ...
        w.writerow(meta)
```

The manifest CSV file is opened once before the download loop and `w.writerow(meta)` is called
inside the loop after each download. This means the manifest is updated progressively — if the
process is killed (power loss, keyboard interrupt, OOM), every file successfully processed
before the kill has a manifest row. The alternative — collecting all results in a list and
writing once at the end — would lose all records on an unexpected exit.

The `for k in w.fieldnames: meta.setdefault(k, "")` pattern ensures every row has all columns,
even in the error case where the exception handler only sets a subset of fields. `DictWriter`
with `extrasaction="raise"` (the default) would fail if an unexpected key appeared; `setdefault`
ensures no key is missing without removing any key that was set.

---

## 13. Interview Questions and Answers

**Q: How does `download_with_resume` ensure that a file resumed with `Range: bytes=N-` is not
corrupted if the remote file has changed between runs?**

A: The size check in Path 1 (`target.stat().st_size == remote_size`) detects a replaced file
only if the replacement has a different size. If the remote file is replaced with a file of the
same size, the corrupted partial file would be silently skipped. The code does not use ETags or
`Last-Modified` headers for full integrity verification. For a research dataset on a stable
university server, this is an acceptable trade-off: CTU captures are not edited after
publication. A production-grade downloader would compare ETag or Content-MD5 headers. The
manifest records `remote_size` and `final_size`, so a mismatch can be detected post-hoc by
comparing manifest rows.

---

**Q: Why does `crawl_for_pcaps` apply the directory regex only to the top-level path segment
rather than the full relative path?**

A: The CTU dataset structure is `DatasetName/date/files`. The regex pattern
`CTU-Malware-Capture-Botnet-` describes dataset names, not subdirectory paths inside a dataset.
Applying the regex to the full path would require writing `CTU-Malware-Capture-Botnet-.*` to
avoid filtering out subdirectories like `CTU-Malware-Capture-Botnet-42/2013-09-01/`, because
`CTU-Malware-Capture-Botnet-` does not match `2013-09-01`. The top-level filter applies intent:
"only crawl directories whose name matches the pattern." Everything inside a matching directory
is fair game. This follows the directory hierarchy semantics of the site rather than treating
the full URL path as an opaque string.

---

**Q: Why is `time.sleep(sleep_s)` placed after the file write completes rather than before each
request?**

A: The sleep is a politeness delay between completed downloads — it paces the number of requests
per second to the server. Placing it before the request would delay the first download
unnecessarily. Placing it after ensures that even if the download is very fast (e.g., a small
file or a cache hit), the server still gets a consistent breathing window between
connections. For a resume (where the file download is instant because the file already exists
and was skipped), the sleep is not called — only the successful `download_with_resume` call
in the loop body triggers the sleep, and skipped files return before reaching the sleep.

---

**Q: `seed_from_datasets_html` sorts and deduplicates the dataset URLs. Why does it deduplicate?**

A: `datasets.html` is a hand-maintained HTML page on the CTU website. The same dataset
directory may appear multiple times in the page — once in a "recent datasets" section, once in
a full chronological list, and once as a cross-reference. Processing the same directory URL
twice would either duplicate the crawl work (re-fetching pages already visited) or produce
duplicate manifest entries. `set(urls)` deduplicates before `sorted()` restores a deterministic
order for reproducible runs.

---

*Next: [Tutorial 35 — ...](35_.md)*
