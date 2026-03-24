#!/usr/bin/env python3
import argparse
import pandas as pd
import numpy as np
from pathlib import Path

def proto_to_num(p):
    if isinstance(p, str):
        p = p.lower()
        if p == "tcp": return 6
        if p == "udp": return 17
        if p == "icmp": return 1
    return np.nan

def safe_read_csv(path):
    return pd.read_csv(path, low_memory=False)

def pick_first_per_uid(df):
    # Keep first row per uid (ssl/quic are usually 1:1 anyway)
    if df is None or df.empty or "uid" not in df.columns:
        return df
    return df.sort_values(df.columns[0]).drop_duplicates("uid", keep="first")

def aggregate_x509(x509):
    """
    x509.csv can have multiple rows per uid.
    We aggregate numeric columns (mean/max/min) + count.
    For string columns, we add *_len_mean and *_len_max.
    """
    if x509 is None or x509.empty or "uid" not in x509.columns:
        return x509

    df = x509.copy()

    # Convert obvious numeric columns where possible
    for c in df.columns:
        if c == "uid":
            continue
        # Try numeric conversion; non-numeric becomes NaN
        df[c + "__num"] = pd.to_numeric(df[c], errors="coerce")

    num_cols = [c for c in df.columns if c.endswith("__num")]
    base_cols = [c[:-5] for c in num_cols]

    # String length features
    str_cols = [c for c in x509.columns if c != "uid" and x509[c].dtype == "object"]
    for c in str_cols:
        df[c + "__len"] = x509[c].astype("string").str.len()

    agg_dict = {}

    # numeric aggregates
    for c in num_cols:
        base = c[:-5]
        agg_dict[c] = ["mean", "max", "min"]

    # string length aggregates
    len_cols = [c for c in df.columns if c.endswith("__len")]
    for c in len_cols:
        base = c[:-5]
        agg_dict[c] = ["mean", "max"]

    # always count rows per uid
    grouped = df.groupby("uid").agg(agg_dict)
    grouped["x509_record_count"] = df.groupby("uid").size()

    # flatten columns
    grouped.columns = ["x509_" + "_".join([str(a) for a in col if a]) for col in grouped.columns.to_flat_index()]
    grouped = grouped.reset_index()

    return grouped


def resolve_tls_csv_path(zeek_dir: str | Path) -> Path:
    base_dir = Path(zeek_dir).expanduser().resolve()
    ssl_path = base_dir / "ssl.csv"
    tls_path = base_dir / "tls.csv"
    if ssl_path.exists():
        return ssl_path
    return tls_path

def merge_nfstream_with_zeek(
    nfstream_csv: str | Path,
    zeek_dir: str | Path,
    out_csv: str | Path,
    *,
    tolerance_sec: float = 2.0,
) -> dict[str, str | int | float]:
    zeek_dir = Path(zeek_dir).expanduser().resolve()
    out_path = Path(out_csv).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    nf = safe_read_csv(nfstream_csv)

    # ---- NFStream required columns check ----
    required_nf = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bidirectional_first_seen_ms"]
    missing = [c for c in required_nf if c not in nf.columns]
    if missing:
        raise RuntimeError(f"NFStream CSV missing required columns: {missing}")

    # Convert nf timestamp to seconds
    nf = nf.copy()
    nf["ts"] = nf["bidirectional_first_seen_ms"] / 1000.0
    nf["proto_num"] = pd.to_numeric(nf["protocol"], errors="coerce")

    # ---- Read Zeek CSVs (whatever exists) ----
    conn_path = zeek_dir / "conn.csv"
    tls_or_ssl_path = resolve_tls_csv_path(zeek_dir)
    x509_path = zeek_dir / "x509.csv"
    quic_path = zeek_dir / "quic.csv"

    if not conn_path.exists():
        raise FileNotFoundError(f"conn.csv not found in {zeek_dir} (needed for merging)")

    conn = safe_read_csv(conn_path)

    ssl  = safe_read_csv(tls_or_ssl_path) if tls_or_ssl_path.exists() else None
    x509 = safe_read_csv(x509_path) if x509_path.exists() else None
    quic = safe_read_csv(quic_path) if quic_path.exists() else None

    # ---- Normalize Zeek conn field names ----
    # Expected Zeek fields: uid, ts, id.orig_h, id.resp_h, id.orig_p, id.resp_p, proto
    needed_conn = ["uid", "ts", "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p", "proto"]
    missing_conn = [c for c in needed_conn if c not in conn.columns]
    if missing_conn:
        raise RuntimeError(f"conn.csv missing required fields: {missing_conn}")

    conn = conn.copy()
    conn["proto_num"] = conn["proto"].apply(proto_to_num)

    # Build two orientations so we can match NFStream src/dst regardless of Zeek orig/resp direction
    conn_a = conn.rename(columns={
        "id.orig_h": "src_ip",
        "id.resp_h": "dst_ip",
        "id.orig_p": "src_port",
        "id.resp_p": "dst_port",
    })[["uid","ts","src_ip","dst_ip","src_port","dst_port","proto_num"]]

    conn_b = conn.rename(columns={
        "id.orig_h": "dst_ip",
        "id.resp_h": "src_ip",
        "id.orig_p": "dst_port",
        "id.resp_p": "src_port",
    })[["uid","ts","src_ip","dst_ip","src_port","dst_port","proto_num"]]

    conn_expanded = pd.concat([conn_a, conn_b], ignore_index=True).dropna(subset=["proto_num","ts"])

    # Ensure types for join
    conn_expanded["src_port"] = pd.to_numeric(conn_expanded["src_port"], errors="coerce")
    conn_expanded["dst_port"] = pd.to_numeric(conn_expanded["dst_port"], errors="coerce")
    conn_expanded["proto_num"] = pd.to_numeric(conn_expanded["proto_num"], errors="coerce")

    nf["src_port"] = pd.to_numeric(nf["src_port"], errors="coerce")
    nf["dst_port"] = pd.to_numeric(nf["dst_port"], errors="coerce")

    # Sort for merge_asof
    nf_sorted = nf.sort_values("ts")
    conn_sorted = conn_expanded.sort_values("ts")

    # ---- Time-nearest merge on 5-tuple ----
    merged = pd.merge_asof(
        nf_sorted,
        conn_sorted,
        on="ts",
        by=["src_ip","dst_ip","src_port","dst_port","proto_num"],
        direction="nearest",
        tolerance=tolerance_sec
    )

    matched = merged["uid"].notna().sum()
    print(f"[OK] NFStream flows: {len(nf)}")
    print(f"[OK] Zeek conn rows (expanded): {len(conn_expanded)}")
    print(f"[OK] Matched flows with Zeek uid: {matched} ({matched/len(nf)*100:.2f}%)")

    # ---- Merge SSL / QUIC / X509 on uid ----
    if ssl is not None and "uid" in ssl.columns:
        ssl = pick_first_per_uid(ssl)
        merged = merged.merge(ssl, on="uid", how="left", suffixes=("", "_zeek_ssl"))
        print(f"[OK] Merged {tls_or_ssl_path.name} rows: {len(ssl)}")

    if quic is not None and "uid" in quic.columns:
        quic = pick_first_per_uid(quic)
        merged = merged.merge(quic, on="uid", how="left", suffixes=("", "_zeek_quic"))
        print(f"[OK] Merged quic.csv rows: {len(quic)}")

    if x509 is not None and "uid" in x509.columns:
        x509_agg = aggregate_x509(x509)
        merged = merged.merge(x509_agg, on="uid", how="left")
        print(f"[OK] Merged x509 aggregated rows: {len(x509_agg)}")

    merged.to_csv(out_path, index=False)
    print(f"[DONE] Saved merged CSV: {out_path}")
    return {
        "nfstream_csv": str(Path(nfstream_csv).expanduser().resolve()),
        "zeek_dir": str(zeek_dir),
        "out_csv": str(out_path),
        "nfstream_rows": int(len(nf)),
        "conn_rows_expanded": int(len(conn_expanded)),
        "matched_rows": int(matched),
        "matched_pct": float((matched / len(nf) * 100.0) if len(nf) else 0.0),
    }

def main(argv: list[str] | None = None):
    ap = argparse.ArgumentParser(description="Merge NFStream CSV with Zeek conn/ssl/x509/quic CSVs")
    ap.add_argument("--nfstream", required=True, help="Input NFStream CSV")
    ap.add_argument("--zeek-dir", required=True, help="Folder containing conn.csv / ssl.csv|tls.csv / x509.csv / quic.csv")
    ap.add_argument("--out", required=True, help="Output merged CSV")
    ap.add_argument("--tolerance-sec", type=float, default=2.0, help="Time tolerance for matching (seconds)")
    args = ap.parse_args(argv)

    results = merge_nfstream_with_zeek(
        nfstream_csv=args.nfstream,
        zeek_dir=args.zeek_dir,
        out_csv=args.out,
        tolerance_sec=args.tolerance_sec,
    )
    print(f"matched_rows={results['matched_rows']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
