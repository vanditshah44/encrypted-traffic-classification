# Tutorial 32 — Static Site Export (`static_site/export_static_snapshot.py`)

## Prerequisites

- Tutorial 31 (`reporting/snapshot.py`) — `build_dashboard_summary`, `build_graph_view`,
  `query_flow_explorer`, and `resolve_dashboard_artifacts` are all called here. This file's
  entire job is to transform their output into display-ready JSON.
- Tutorial 20 (`detection/multitier.py`) — `tiered_flow_scores.csv`, `suspicious_clusters.csv`,
  `graph_nodes.csv`, `graph_edges.csv` are the source files read through `snapshot.py`.
- Tutorial 26 (`backend/registry.py`) — `resolve_model_bundle_dir` is called by
  `resolve_dashboard_artifacts` under the hood.

---

## 1. Why This File Exists

`snapshot.py` (Tutorial 31) is a read-only aggregator: it reads CSVs and JSON files and returns
a dict of raw numerical counts, raw IP addresses, raw column values. That output is correct for
a live backend API — the API consumer can format numbers itself. It is wrong for a static site,
where there is no server-side rendering and no JS formatter that knows how the data was
structured.

This file is the **presenter layer**. It sits between `snapshot.py` and the HTML page:

```
[ CSV / JSON artifacts ]
        ↓
[ snapshot.py  ]     ← aggregation: counts, filters, pagination
        ↓
[ export_static_snapshot.py ]  ← decoration: display names, formatted numbers, editorial copy
        ↓
[ data.json / data.js ]  ← what the static site actually reads
```

A live backend can apply formatting per-request based on user locale or preferences.
A static export cannot — the display strings must be baked in at export time. Every `display_*`
field, every human-readable label, every editorial headline in the final JSON comes from this
file, not from `snapshot.py`.

The second reason this file exists separately from `snapshot.py`: the static export must work
without a live database. `build_dashboard_summary` accepts an optional `session` argument for
the job status query; when called here it is always called without one, so `_job_status_counts`
returns `{}`. The entire export is pure filesystem reads.

---

## 2. Defensive Coercion Utilities (lines 51–84)

### `_safe_int` and `_safe_float`

Both wrap two failure modes in sequence:

1. `pd.isna(value)` catches `NaN`, `NaT`, `pd.NA`, and `float("nan")` — all the ways a numeric
   cell can be missing after a CSV round-trip.
2. `if value is None` catches Python `None` explicitly, because `pd.isna(None)` raises
   `TypeError` in some pandas versions when `None` is inside a non-scalar context.

The `try/except Exception` around the `pd.isna` call mirrors the same pattern in `snapshot.py`
(`_json_safe_value`, step 6) — `pd.isna` raises `ValueError` on array-like inputs, so the guard
makes the call safe regardless of what arrives.

### `_clean_text`

Beyond `None` and `pd.isna`, CSV reads produce the string `"nan"`, `"none"`, and `"null"` when
a column had missing values of different types across different pipeline runs. `_clean_text`
normalises all of these to empty string. Every function that produces a string for display goes
through `_clean_text` rather than `str(value).strip()` alone, so the static site never renders
the literal string `"nan"` in a label.

---

## 3. Slug and Alias Infrastructure (lines 87–105)

### `_slugify`

```python
def _slugify(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized or "node"
```

Graph renderers (D3-force, Cytoscape.js) use node IDs as string keys in their internal
structures. A raw IP like `192.168.1.1` contains dots and would be treated as a nested property
path in some JavaScript contexts, and would break CSS attribute selectors. A slug like
`internal-gateway-alpha` is safe as a DOM ID, a CSS selector, a URL fragment, and a JSON key.
`strip("-")` removes leading/trailing hyphens that arise when the input starts or ends with
non-alphanumeric characters. The `or "node"` fallback handles the empty-after-strip case.

### `_alpha_name`

```python
["Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta"]
```

Private IP addresses (`10.x`, `172.16-31.x`, `192.168.x`) are internal lab infrastructure.
Showing raw IPs in a static dashboard that might be shared publicly exposes network topology.
Greek alphabet names are used because they are memorable, pronounceable, unambiguous in
alphabetical order, and carry no numeric information about the underlying IP. The function caps
at eight names (indices 0–7) and falls back to `f"Node {index + 1:02d}"` for networks larger
than eight internal hubs.

---

## 4. Service Resolution Pipeline (lines 108–215)

This is the most layered piece of the utility layer. Four functions form a resolution chain:

```
_match_service_label(text)                   → known brand or ""
_service_family_from_domain(domain)          → brand > SLD title > "Encrypted Service"
_service_family_from_application(app_name)   → "TLS" → special-cased, then brand > cleaned name
_display_service_name(domain, app_name)      → exact pretty-map > domain-family > app-family > fallback
```

### `_is_private_endpoint`

Uses the standard library `ipaddress.ip_address(text).is_private`. This covers RFC 1918
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback, link-local, and IANA-reserved
ranges — the full set of "not a public internet address." A hostname that is not a valid IP
(e.g., a domain name in `src_ip` due to DNS enrichment) causes `ValueError`, which is caught
and returns `False` (treat it as public by default).

### `_match_service_label`

A linear scan over a tuple of `(needle, label)` pairs. Linear because the list is short (24
entries) and the order matters — `"fbstatic"` must appear before `"facebook"` because
`"fbstatic"` is a substring of nothing, but `"facebook"` would match both Facebook domains and
Facebook CDN domains equally. The order encodes specificity: narrow patterns before broad ones.

### `_service_family_from_domain`

```python
filtered = [part for part in parts if part not in ignored and len(part) > 2]
if len(filtered) >= 2:
    return filtered[-2].title()
```

`filtered[-2]` is the second-level domain (SLD): for `api.instagram.com`, `filtered` is
`["instagram", "com"]`, so `filtered[-2]` is `"instagram"`. For
`bam.nr-data.net`, `filtered` is `["nr-data", "net"]`, so `filtered[-2]` is `"nr-data"` →
`"Nr-Data"` — not great, but better than "Encrypted Service". The `ignored` set strips common
subdomains (`www`, `api`, `cdn`, `static`, `mail`, etc.) that carry no brand information, and
the `len(part) > 2` filter removes two-character TLDs and country-code SLDs from appearing as
the service name.

### `_display_service_name`

Prioritises in order:
1. **Exact match in `pretty_map`** — a hardcoded table of canonical display names for specific
   FQDNs (`translate.google.com` → `"Google Translate"`). Used when a generic brand derivation
   would be ambiguous across Google services.
2. **Domain-family fallback** — `_service_family_from_domain` on the SNI field.
3. **Application-family fallback** — `_service_family_from_application` on the NFStream
   application identifier (e.g., `TLS.Google` → `"Google"`).
4. **Final fallback** — `"Encrypted Session"` when all three fail.

The priority order reflects data quality: the SNI (`requested_server_name`) is the most
accurate signal, the NFStream label is a classifier output and may be wrong, and the fallback
acknowledges that TLS without SNI is genuinely opaque.

---

## 5. The Endpoint Catalog (lines 237–308)

`_build_endpoint_catalog` is called once per export, over the suspicious-only DataFrame. It
iterates every row and accumulates per-IP statistics:

```python
for endpoint_column in ("src_ip", "dst_ip"):
    endpoint = _clean_text(row.get(endpoint_column))
    stats = endpoint_stats.setdefault(endpoint, {
        "count": 0, "services": Counter(), "service_labels": Counter(),
        "protocols": Counter(), "is_private": _is_private_endpoint(endpoint),
    })
    stats["count"] += 1
    stats["services"][family] += 1
    ...
```

Both `src_ip` and `dst_ip` are added in the same pass, so an IP that appears as both a source
and a destination is counted for both roles. This is deliberate: the catalog is used for display
labeling, not directionality analysis. The dominant family is whatever service family accounts
for the most flows through that IP, regardless of direction.

After building statistics, the catalog assigns display names:

```python
sorted_items = sorted(endpoint_stats.items(), key=lambda item: (-int(item[1]["count"]), item[0]))
```

Sort by descending count first, then IP string for tie-breaking. This ensures the most active
endpoints get the lowest-numbered display names (e.g., `External Node 01` is the most active
public IP, not an arbitrary one). The sort also makes the assignment deterministic: two exports
from the same data always produce the same display names.

Private IPs get `"Internal Gateway Alpha"` (first private IP seen), `"Internal Gateway Beta"`,
etc. Public IPs get `"External Node 01"`, `"External Node 02"`, etc.

The `alias_id` collision loop:

```python
while unique_alias_id in alias_ids_seen:
    unique_alias_id = f"{alias_id}-{suffix}"
    suffix += 1
```

Two different IPs that slugify to the same string (unlikely but possible if the display names
collide, e.g., `"External Node 01"` and `"External Node 01"` if there were a bug) would produce
the same `alias_id`. The suffix loop ensures uniqueness.

---

## 6. Distribution Builders (lines 366–430)

### `_top_distribution`

```python
counts = df[column].dropna().astype(str).str.strip()
    .replace("", pd.NA).dropna()
    .value_counts().head(limit)
```

`.replace("", pd.NA).dropna()` removes empty strings that survive `dropna()` (because an empty
string is not `NaN`). Without this, empty strings would appear as a top value with a high count,
polluting the distribution.

Each entry includes `share` (float 0.0–1.0) and pre-formatted `display_count`/`display_share`
strings. The frontend can use either the raw float for chart scaling or the pre-formatted string
for display — no JS formatting required.

### `_group_distribution`

Takes `key_builder` and `member_builder` callables instead of column names. This supports
cross-column grouping: for `domain_pressure`, the key is the service family derived from
`requested_server_name` AND `application_name`, while the member is the exact display service
name. A column name approach would require the caller to materialize a derived column first;
the callable approach keeps the derivation logic inside the distribution builder.

```python
"subtitle": " · ".join(item for item, _ in members[key].most_common(3))
```

`members[key]` is a `Counter` of display service names seen under this service family. `.most_common(3)` gives the three most frequent specific services within the family. The subtitle gives the frontend a one-line hint like `"Google Translate · Google Accounts · Google APIs"` under the `"Google"` group label.

---

## 7. Spotlight Flow Deduplication (lines 433–505)

`_dedupe_spotlight_flows` selects the ten most notable suspicious flows for the dashboard
"spotlight" section.

### Deduplication key

```python
endpoint_pair = tuple(sorted((str(row.get("src_ip", "")), str(row.get("dst_ip", "")))))
key = (str(row.get("window_id", "")), endpoint_pair, service_family)
```

The deduplication unit is `(window, endpoint_pair, service_family)`. The endpoint pair is
sorted before tupling so that `(A→B)` and `(B→A)` are the same key — a bidirectional flow
appears only once. Without this, both the upload and download halves of the same TLS session
would compete for spotlight slots.

Why `service_family` in the key but not `record_id`? Because the goal is editorial diversity:
the spotlight should show different *services* being contacted by different *endpoint pairs*,
not ten flows that happen to have the highest score regardless of redundancy. A botnet phoning
home to the same C2 IP across multiple windows would produce identical service families —
keeping only one per `(window, pair, family)` ensures the reader sees the breadth of suspicious
activity, not a one-dimensional top-10 list.

### Row assembly

Each spotlight row replaces the raw IP addresses with display-friendly strings:

```python
src_display = (
    src_meta.get("display_name", "Internal Gateway")
    if src_meta.get("role") == "Internal hub"
    else ("QUIC Peer" if service_family == "QUIC Session" else f"{service_family} Peer")
)
```

Internal hubs get their catalog display name (`"Internal Gateway Alpha"`). External peers get a
service-aware label: `"Google Peer"`, `"QUIC Peer"`, `"Cloudflare Peer"`. The `path` field
becomes `"Internal Gateway Alpha -> Google Peer"` — readable in a dashboard without exposing
the underlying IPs.

---

## 8. Decoration Functions (lines 545–746)

Each `_decorate_*` function takes raw snapshot output and adds display fields. They follow
the same pattern: iterate the raw list, call safe coercers, add formatted strings, return a new
list. None of them modify the input in place.

### `_decorate_alert_timeline`

```python
"conversion_rate": float(suspicious_flows / candidate_flows) if candidate_flows else 0.0,
```

`conversion_rate` is the fraction of candidates that cleared the consensus gate within this
window. A window where 500 flows were candidates but only 2 were suspicious has a 0.4%
conversion rate — a useful signal that the stage-one screen is casting a wide net in that
window. The raw counts are already in the input; this adds the derived ratio.

### `_decorate_models`

```python
ranking = sorted(models, key=lambda item: _safe_float(item.get("test_optimized_f1")), reverse=True)
```

Models are re-ranked by F1 score here, not taken in whatever order `snapshot.py` returned them.
The `rank` field (1-indexed) tells the frontend which model is primary vs. supporting. `rank=1`
gets `"Primary scoring model"`, all others get `"Supporting evidence model"`. This is a display
decision: the dashboard header can say "scored by Random Forest (primary)" without the frontend
needing to sort models itself.

### `_decorate_graph` — Node Size Normalization

```python
normalized_size = max(8.0, 12.0 + 28.0 * math.sqrt(suspicious_flow_count / max_flow))
```

Node size ranges from 8 (floor) to 40 (when `suspicious_flow_count == max_flow`).

**Why `math.sqrt`?** If size scaled linearly with flow count and one hub had 1000 flows while
leaf nodes had 10, the hub would be 100× larger — visually overwhelming and making leaf nodes
impossible to click. `sqrt` compresses the range: the hub becomes only `sqrt(100)` = 10×
larger than a leaf. The formula keeps a minimum size of 8 so leaf nodes remain clickable even
if they have only 1 suspicious flow.

### Node type assignment

```python
node_type = "hub" if is_private and _safe_int(node.get("unique_neighbors")) > 10 else (
    "private" if is_private else "public"
)
```

Three types: `"hub"` (private IP, fanout > 10 — a NAT gateway or router), `"private"` (private
IP, low fanout — a workstation or server), `"public"` (external IP). The frontend can colour
these three types differently: hub nodes as filled circles, private as hollow circles, public
as squares, for example. The threshold of 10 unique neighbours distinguishes routing
infrastructure from endpoint machines.

### Node label suppression

```python
labeled_nodes = {str(node.get("endpoint")) for node in ranked_nodes[:8]}
...
"label": endpoint_meta.get("display_name", endpoint)
    if endpoint in labeled_nodes or node_type != "public"
    else "",
```

Only the 8 most suspicious nodes and all non-public (private/hub) nodes get visible labels in
the graph. Public nodes ranked 9 and below have their label set to `""`. This prevents label
overplotting in dense clusters where dozens of external IPs each have labels that collide
visually. The 8-node threshold is a UI design choice: the first 8 nodes in the ranked order are
the ones worth naming; the rest are context.

---

## 9. `build_static_dashboard_snapshot` (lines 749–971)

This is the orchestrator. Its relationship to `snapshot.py`'s `build_dashboard_summary` is
worth understanding precisely: `build_dashboard_summary` returns raw section data
(counts, raw IPs, raw labels). `build_static_dashboard_snapshot` calls it, then:

1. Builds `endpoint_catalog` from `suspicious_df` only — not from all flows. This matters
   because `_decorate_graph`, `_decorate_endpoints`, and `_dedupe_spotlight_flows` all operate
   on suspicious data. Building the catalog from all 50k+ flows would add entries for benign IPs
   that never appear in any decorated section, wasting memory and adding no information.

2. Derives editorial sections that are *not* in `snapshot.py`:

   - **`storyline`** — three editorial "cards" summarising the run in one statistic each.
     `primary_endpoint` is looked up through the catalog so the headline shows
     `"Internal Gateway Alpha"` rather than `"192.168.0.1"`.
   - **`hero_cluster_copy`** — a pre-written sentence about the primary cluster, populated from
     `cluster_summary` statistics.
   - **`research_boundaries`** — combines `model_quality.warnings` (from `snapshot.py`) with
     QUIC-specific observations derived from `protocol_mix`. The QUIC check is:
     ```python
     if quic_highlight and _safe_int(quic_highlight.get("suspicious_flows")) == 0:
         research_boundaries.append("QUIC remains low-noise...")
     ```
     If QUIC flows exist in the capture but none cleared the consensus gate, this is a notable
     finding — possibly the QUIC classifier was not well-trained on QUIC traffic in this dataset.
     The boundary note surfaces it as an editorial caveat rather than burying it in raw numbers.
   - **`methodology`** — four static steps describing the pipeline. These do not change per-run;
     they describe the architecture. Keeping them in the Python export (not in the HTML) means
     the static site HTML can be generic, and a future pipeline change only requires updating
     this file.
   - **`kpis`** — five KPI cards with `value` (raw int/float for chart scaling), `display_value`
     (pre-formatted string), `supporting` (subtitle), `accent` (CSS colour token). The colour
     tokens (`"steel"`, `"coral"`, `"cyan"`, `"gold"`, `"teal"`) are semantic tokens — the
     frontend CSS maps them to actual colours. This decouples the data from the design system.

3. Assembles `stage_metrics` from `workflow_summary.json` (written by the multi-tier workflow,
   Tutorial 20) to populate recall and F1 annotations on the funnel nodes. If
   `workflow_summary.json` does not exist, `_build_stage_funnel` skips the metric annotations.

---

## 10. `export_static_dashboard_bundle` and the Two-File Strategy (lines 974–1002)

```python
data_json_path.write_text(json_text + "\n", encoding="utf-8")
data_js_path.write_text(
    "window.TLS_DATASET_STATIC_DASHBOARD = " + json_text + ";\n",
    encoding="utf-8",
)
nojekyll_path.write_text("", encoding="utf-8")
```

**Why two output files?**

`data.json` is the standard format — it can be fetched by a server, loaded by a test, or read
by another tool.

`data.js` uses a global variable assignment:
`window.TLS_DATASET_STATIC_DASHBOARD = { ... };`. When a user opens the static dashboard HTML
file locally (`file://`), the browser's security model blocks `fetch()` of a local file due to
the same-origin policy. A `<script src="data.js">` tag is not a `fetch` — it is a script
execution, which is allowed from `file://`. The JS assignment runs synchronously during page
load, populating `window.TLS_DATASET_STATIC_DASHBOARD` before any component code runs.
On GitHub Pages (or any HTTP server), both work; `data.json` via fetch is more elegant.
`data.js` ensures offline use.

**Why `.nojekyll`?**

GitHub Pages runs Jekyll by default. Jekyll ignores files and directories whose names start
with `_`. If the static site referenced any asset path starting with `_` (e.g., `_data/`,
`_assets/`), Jekyll would strip it from the output. An empty `.nojekyll` file in the root
disables Jekyll processing entirely, ensuring GitHub Pages serves the directory as-is.

**Why `destination.mkdir(parents=True, exist_ok=True)` instead of checking first?**

The TOCTOU (Time-of-Check-Time-of-Use) anti-pattern: checking `if not dir.exists(): dir.mkdir()`
has a race condition — the directory can be created by another process between the check and the
creation. `mkdir(parents=True, exist_ok=True)` is atomic: it creates the directory and all
parents if they do not exist, and silently succeeds if they already do.

---

## 11. CLI Entry Point (lines 1005–1032)

```python
for key, value in result.items():
    print(f"{key}={value}")
```

The CLI prints `key=value` pairs (not JSON) so the output can be parsed by shell scripts with
`grep` or `cut`. In a CI pipeline step that runs the export and then uploads the showcase
directory, a shell script can extract `output_dir=$(python -m tls_dataset... | grep output_dir
| cut -d= -f2)` without requiring a JSON parser.

`argparse` uses `argv: list[str] | None = None`, passing `None` means argparse reads from
`sys.argv[1:]` at runtime. Passing an explicit list is used in tests to call `main(["--output-dir", "/tmp/test"])` without subprocess overhead.

---

## 12. Relationship to `snapshot.py` in the Static-Site Use Case

Tutorial 31 noted that `_job_status_counts` accepts `session: Session | None` specifically to
support this use case. Here, `build_dashboard_summary` is called without a session:
`build_dashboard_summary(settings=settings)`. The result is that `job_status_counts` is `{}`
in the snapshot, and the dashboard does not show a live job queue panel. For the static site,
that is correct behaviour: there is no backend running, so job queue status is meaningless.

The static export is designed to work at any time, even on a machine without the database
running, without the FastAPI server running, and without any ML model loaded in memory. The only
requirement is that the CSV artifacts exist on disk.

---

## 13. Interview Questions and Answers

**Q: Why does `export_static_dashboard_bundle` write both `data.json` and `data.js`?**

A: When the HTML page is opened from a local filesystem (`file://`), browser security policy
blocks `XMLHttpRequest` and `fetch()` from loading other local files due to the same-origin
restriction. A `<script src="data.js">` bypasses this because script tags execute code rather
than making network requests. `data.js` assigns the snapshot to a global variable that the page
reads synchronously at load time. `data.json` is provided for server-hosted use cases where
fetch works normally and for programmatic consumption.

---

**Q: Why is `endpoint_catalog` built from `suspicious_df` (tier2_pass only) rather than all flows?**

A: The catalog is used exclusively by the decorator functions that operate on suspicious data:
`_decorate_graph`, `_decorate_endpoints`, `_dedupe_spotlight_flows`. A benign flow's IPs will
never appear in any of those sections. Building the catalog from all flows would include tens of
thousands of benign IPs, each consuming a `Counter` object and a catalog entry, for no
downstream use. More critically, it would change the display name assignments: the most active
IP overall might be a benign CDN that gets `"External Node 01"`, pushing the most suspicious
IP to `"External Node 07"` — the display names would no longer reflect suspiciousness rank.

---

**Q: Why does `_decorate_graph` use `math.sqrt` for node size normalization rather than linear scaling?**

A: In a suspicious-flow graph, hub nodes (NAT gateways, internal routers) may have hundreds of
times more flows than leaf nodes. Linear scaling would make hub nodes visually dominate the
graph — a hub with 1000 flows would be 100× larger than a node with 10 flows, making leaf
nodes invisible. `sqrt` compression reduces that ratio to ~10×, keeping leaf nodes visible and
clickable. The floor of 8px ensures every node has a minimum clickable area regardless of flow
count.

---

**Q: The deduplication key in `_dedupe_spotlight_flows` uses `service_family` rather than `dst_ip`. Why?**

A: Using `dst_ip` would deduplicate at the IP level — two flows to the same external IP would
produce at most one spotlight entry. But the goal is editorial diversity: if a single suspicious
IP serves multiple brands (e.g., a CDN IP serving both Instagram and Facebook CDN assets), each
brand-IP combination carries distinct analytical meaning. `service_family` captures the brand-
level distinction without requiring the frontend to know which IPs correspond to which services.
Conversely, if ten flows all go to the same `(window, IP pair, service)` combination but with
different scores, showing all ten is redundant — the dedup collapses them into the one with the
highest score (which arrives first after the sort).

---

**Q: `_parse_maybe_list` uses `ast.literal_eval` instead of `json.loads`. Why?**

A: List-valued columns written by Python code (e.g., `df["top_protocols"] = [["TLS", "QUIC"],
...]` followed by `df.to_csv()`) are serialised as Python list literals:
`"['TLS', 'QUIC']"`, not JSON: `"[\"TLS\", \"QUIC\"]"`. Python list literals use single quotes;
`json.loads` requires double quotes and would raise `JSONDecodeError`. `ast.literal_eval` parses
Python literal syntax — lists, tuples, strings with single or double quotes, numbers — without
executing arbitrary code. It is the correct tool for deserialising Python-repr'd values from
CSV cells.

---

*Next: [Tutorial 33 — ...](33_.md)*
