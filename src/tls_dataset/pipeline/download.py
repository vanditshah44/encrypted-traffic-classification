#!/usr/bin/env python3
"""
MCFP PCAP downloader (recursive crawler for Apache directory listings)

Typical usage:
  # Dry-run list (recommended first)
  python3 mcfp_pcap_downloader.py --list-only --include-dirs "CTU-Malware-Capture-Botnet-"

  # Download only CTU botnet capture folders (safer scope)
  python3 mcfp_pcap_downloader.py --include-dirs "CTU-Malware-Capture-Botnet-" --out ./mcfp_pcaps

  # Seed from datasets.html (CTU Botnet list page), then crawl each dataset folder
  python3 mcfp_pcap_downloader.py --seed datasets_html --include-dirs "CTU-Malware-Capture-Botnet-" --out ./mcfp_pcaps
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Set, Tuple, List
from urllib.parse import urljoin, urlparse, unquote

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


DEFAULT_BASE_URL = "https://mcfp.felk.cvut.cz/publicDatasets/"
DEFAULT_DATASETS_HTML = urljoin(DEFAULT_BASE_URL, "datasets.html")

# Extensions we treat as "pcap-like"
PCAP_EXTS = (
    ".pcap", ".pcapng", ".cap",
    ".pcap.gz", ".pcap.bz2", ".pcap.xz", ".pcap.zst",
    ".pcapng.gz", ".pcapng.bz2", ".pcapng.xz", ".pcapng.zst",
    ".cap.gz", ".cap.bz2", ".cap.xz", ".cap.zst",
    ".pcap.zip", ".pcapng.zip", ".cap.zip",
    ".pcap.tar.gz", ".pcapng.tar.gz", ".cap.tar.gz",
)



@dataclass(frozen=True)
class DownloadItem:
    url: str
    rel_path: str  # path relative to base url


def build_session() -> requests.Session:
    session = requests.Session()

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
    return session


def is_within_base(url: str, base_url: str) -> bool:
    u = urlparse(url)
    b = urlparse(base_url)
    return (u.scheme, u.netloc) == (b.scheme, b.netloc) and u.path.startswith(b.path)


def is_dir_link(href: str) -> bool:
    return href.endswith("/")


def looks_like_pcap(filename: str, exts: Tuple[str, ...] = PCAP_EXTS) -> bool:
    f = filename.lower()
    return any(f.endswith(ext) for ext in exts)


def apache_index_links(html: str, page_url: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a in soup.find_all("a"):
        href = a.get("href")
        if not href:
            continue
        # skip parent dir and anchors
        if href in ("../", "./") or href.startswith("#"):
            continue
        abs_url = urljoin(page_url, href)
        links.append(abs_url)
    return links


def url_to_rel_path(url: str, base_url: str) -> str:
    """Convert absolute URL to a filesystem-friendly relative path under base_url."""
    u = urlparse(url)
    b = urlparse(base_url)
    rel = u.path[len(b.path):].lstrip("/")
    rel = unquote(rel)
    return rel


def safe_join(out_dir: Path, rel_path: str) -> Path:
    # prevent weird paths
    rel_path = rel_path.replace("\\", "/")
    rel_path = rel_path.lstrip("/")
    target = (out_dir / rel_path).resolve()
    out_root = out_dir.resolve()
    if not str(target).startswith(str(out_root)):
        raise ValueError(f"Refusing to write outside output dir: {target}")
    return target


def fetch_text(session: requests.Session, url: str, timeout: int = 30) -> str:
    r = session.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text


def head_metadata(session: requests.Session, url: str, timeout: int = 30) -> Tuple[Optional[int], bool]:
    """
    Returns (content_length, accept_ranges)
    content_length may be None if missing.
    accept_ranges indicates server supports Range requests.
    """
    try:
        r = session.head(url, timeout=timeout, allow_redirects=True)
        if r.status_code >= 400:
            return None, False
        cl = r.headers.get("Content-Length")
        accept_ranges = (r.headers.get("Accept-Ranges", "").lower() == "bytes")
        return (int(cl) if cl and cl.isdigit() else None), accept_ranges
    except requests.RequestException:
        return None, False


def download_with_resume(
    session: requests.Session,
    item: DownloadItem,
    out_dir: Path,
    base_url: str,
    sleep_s: float = 0.2,
    timeout: int = 60,
    chunk_size: int = 1024 * 1024,
) -> dict:
    """
    Downloads one file with resume support if possible.
    Returns dict metadata for manifest.
    """
    target = safe_join(out_dir, item.rel_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    remote_size, accept_ranges = head_metadata(session, item.url, timeout=timeout)

    # If file exists and matches size, skip
    if target.exists() and remote_size is not None and target.stat().st_size == remote_size:
        return {
            "url": item.url,
            "rel_path": item.rel_path,
            "local_path": str(target),
            "status": "skipped_exists_same_size",
            "remote_size": remote_size,
            "downloaded_bytes": 0,
            "accept_ranges": accept_ranges,
        }

    # Determine resume position
    resume_from = 0
    mode = "wb"
    headers = {}
    if target.exists() and accept_ranges:
        resume_from = target.stat().st_size
        if remote_size is None or resume_from < remote_size:
            headers["Range"] = f"bytes={resume_from}-"
            mode = "ab"
        else:
            # remote size unknown; if file exists, still attempt re-download safely
            resume_from = 0
            mode = "wb"

    r = session.get(item.url, stream=True, headers=headers, timeout=timeout)
    r.raise_for_status()

    downloaded = 0
    with open(target, mode) as f:
        for chunk in r.iter_content(chunk_size=chunk_size):
            if not chunk:
                continue
            f.write(chunk)
            downloaded += len(chunk)

    time.sleep(sleep_s)

    final_size = target.stat().st_size if target.exists() else None
    return {
        "url": item.url,
        "rel_path": item.rel_path,
        "local_path": str(target),
        "status": "downloaded",
        "remote_size": remote_size,
        "downloaded_bytes": downloaded,
        "final_size": final_size,
        "accept_ranges": accept_ranges,
        "resumed_from": resume_from,
    }


def crawl_for_pcaps(
    session: requests.Session,
    base_url: str,
    include_dirs_regex: Optional[str] = None,
    exclude_dirs_regex: Optional[str] = None,
    exts: Tuple[str, ...] = PCAP_EXTS,
    max_pages: Optional[int] = None,
) -> List[DownloadItem]:
    """
    Recursively crawl Apache index listings under base_url and return pcap-like file URLs.
    """
    include_re = re.compile(include_dirs_regex) if include_dirs_regex else None
    exclude_re = re.compile(exclude_dirs_regex) if exclude_dirs_regex else None

    queue: List[str] = [base_url]
    visited: Set[str] = set()
    found: List[DownloadItem] = []

    while queue:
        page = queue.pop(0)
        if page in visited:
            continue
        visited.add(page)

        if max_pages is not None and len(visited) > max_pages:
            break

        try:
            html = fetch_text(session, page)
        except Exception as e:
            print(f"[WARN] Failed to fetch {page}: {e}", file=sys.stderr)
            continue

        for link in apache_index_links(html, page):
            if not is_within_base(link, base_url):
                continue

            rel = url_to_rel_path(link, base_url)

            if link.endswith("/"):
                # directory filter: check top-level directory name (first segment)
                top = rel.split("/", 1)[0] if rel else ""
                if top:
                    if include_re and not include_re.search(top):
                        continue
                    if exclude_re and exclude_re.search(top):
                        continue
                queue.append(link)
            else:
                filename = os.path.basename(urlparse(link).path)
                if looks_like_pcap(filename, exts=exts):
                    found.append(DownloadItem(url=link, rel_path=rel))

    # De-dup by URL
    unique = {}
    for it in found:
        unique[it.url] = it
    return list(unique.values())


def seed_from_datasets_html(session: requests.Session, datasets_html_url: str, base_url: str,
                           min_date: Optional[str] = None,
                           max_datasets: Optional[int] = None) -> List[str]:
    html = fetch_text(session, datasets_html_url)
    text = BeautifulSoup(html, "html.parser").get_text("\n")
    # Capture: YYYY-MM-DD ... https://mcfp.felk.cvut.cz/publicDatasets/<DIR>
    pat = re.compile(r'(\d{4}-\d{2}-\d{2}).*?(https://mcfp\.felk\.cvut\.cz/publicDatasets/[^\s]+)', re.IGNORECASE)

    rows = []
    for m in pat.finditer(text):
        d = m.group(1)
        url = m.group(2).rstrip("/")
        # keep only dataset directories
        if not url.startswith(base_url):
            continue
        rows.append((d, url + "/"))

    rows.sort(key=lambda x: x[0])  # sort by date
    if min_date:
        rows = [r for r in rows if r[0] >= min_date]

    urls = [u for _, u in rows]
    if max_datasets is not None:
        urls = urls[:max_datasets]
    return sorted(set(urls))



def main() -> int:
    ap = argparse.ArgumentParser(description="Download all PCAP-like files from MCFP publicDatasets (recursive crawler).")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"Base URL to crawl (default: {DEFAULT_BASE_URL})")
    ap.add_argument("--out", default="./mcfp_downloads", help="Output directory")
    ap.add_argument("--include-dirs", default=None, help="Regex: only crawl top-level dirs matching this (HIGHLY recommended)")
    ap.add_argument("--exclude-dirs", default=None, help="Regex: skip top-level dirs matching this")
    ap.add_argument("--list-only", action="store_true", help="Only list matches, do not download")
    ap.add_argument("--manifest", default="manifest.csv", help="Write a CSV manifest (default: manifest.csv)")
    ap.add_argument("--sleep", type=float, default=0.2, help="Seconds to sleep between downloads (politeness)")
    ap.add_argument("--max-pages", type=int, default=None, help="Safety limit on crawled pages (debug)")
    ap.add_argument("--min-date", default=None, help="Only for --seed datasets_html. Keep datasets with date >= YYYY-MM-DD")
    ap.add_argument("--max-datasets", type=int, default=None, help="Only for --seed datasets_html. Limit number of dataset dirs")
    ap.add_argument(
    "--max-total-gb",
    type=float,
    default=None,
    help="Stop downloading after this many GB have been downloaded in this run (e.g. 150).",
)

    ap.add_argument(
        "--seed",
        choices=["crawl", "datasets_html"],
        default="crawl",
        help="How to discover dataset directories: crawl base index, or seed from datasets.html then crawl each",
    )
    ap.add_argument("--datasets-html-url", default=DEFAULT_DATASETS_HTML, help=f"datasets.html URL (default: {DEFAULT_DATASETS_HTML})")
    args = ap.parse_args()

    base_url = args.base_url
    out_dir = Path(args.out)
    total_downloaded_bytes = 0
    max_total_bytes = None if args.max_total_gb is None else int(args.max_total_gb * (1024 ** 3))


    session = build_session()

    items: List[DownloadItem] = []

    if args.seed == "crawl":
        items = crawl_for_pcaps(
            session=session,
            base_url=base_url,
            include_dirs_regex=args.include_dirs,
            exclude_dirs_regex=args.exclude_dirs,
            max_pages=args.max_pages,
        )
    else:
        # seed from datasets.html (CTU malware list), then crawl each dataset directory
        dataset_dirs = seed_from_datasets_html(session, args.datasets_html_url, base_url)
        include_re = re.compile(args.include_dirs) if args.include_dirs else None
        exclude_re = re.compile(args.exclude_dirs) if args.exclude_dirs else None

        for d in dataset_dirs:
            rel = url_to_rel_path(d, base_url)
            top = rel.split("/", 1)[0] if rel else ""
            if top:
                if include_re and not include_re.search(top):
                    continue
                if exclude_re and exclude_re.search(top):
                    continue

            # crawl starting from this directory (not the whole root)
            sub_items = crawl_for_pcaps(
                session=session,
                base_url=d,  # limit scope to that dataset folder
                include_dirs_regex=None,
                exclude_dirs_regex=None,
                max_pages=args.max_pages,
            )
            # convert rel paths to be under the global base url path
            for it in sub_items:
                # it.rel_path is relative to d; make it relative to global base_url
                d_rel = url_to_rel_path(d, base_url).rstrip("/") + "/"
                items.append(DownloadItem(url=it.url, rel_path=d_rel + it.rel_path))

        # de-dup
        uniq = {}
        for it in items:
            uniq[it.url] = it
        items = list(uniq.values())

    items.sort(key=lambda x: x.rel_path)

    if args.list_only:
        for it in items:
            print(it.url)
        print(f"\nFound {len(items)} pcap-like files.")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = out_dir / args.manifest
    with open(manifest_path, "w", newline="", encoding="utf-8") as mf:
        w = csv.DictWriter(
            mf,
            fieldnames=[
                "url", "rel_path", "local_path", "status",
                "remote_size", "downloaded_bytes", "final_size",
                "accept_ranges", "resumed_from", "budget_bytes", "total_downloaded_bytes",

            ],
        )
        w.writeheader()

        for idx, it in enumerate(items, start=1):
            print(f"[{idx}/{len(items)}] {it.rel_path}")
            try:
                meta = download_with_resume(
                    session=session,
                    item=it,
                    out_dir=out_dir,
                    base_url=base_url,
                    sleep_s=args.sleep,
                )
            
            except Exception as e:
                meta = {
                    "url": it.url,
                    "rel_path": it.rel_path,
                    "local_path": "",
                    "status": f"error: {type(e).__name__}: {e}",
                    "remote_size": "",
                    "downloaded_bytes": "",
                    "final_size": "",
                    "accept_ranges": "",
                    "resumed_from": "",
                }
                print(f"[ERROR] {it.url} -> {e}", file=sys.stderr)
            # Add only bytes actually downloaded in this run
            dl = meta.get("downloaded_bytes") or 0
            try:
                dl = int(dl)
            except Exception:
                dl = 0

            total_downloaded_bytes += dl

            if max_total_bytes is not None and total_downloaded_bytes >= max_total_bytes:
                meta["status"] = f"{meta.get('status', '')}|stopped_budget_reached"
                meta["budget_bytes"] = max_total_bytes
                meta["total_downloaded_bytes"] = total_downloaded_bytes

                # write this row, then stop
                for k in w.fieldnames:
                    meta.setdefault(k, "")
                w.writerow(meta)

                print(
                    f"\n[STOP] Download budget reached: {total_downloaded_bytes / (1024**3):.2f} GB "
                    f"(limit {args.max_total_gb} GB)."
                )
                break


            # Ensure all keys exist
            for k in w.fieldnames:
                meta.setdefault(k, "")
            w.writerow(meta)

    print(f"\nDone. Manifest written to: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
