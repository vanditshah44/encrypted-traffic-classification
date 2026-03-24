"""Export a frozen data bundle for the static analytical dashboard."""

from __future__ import annotations

import argparse
import ast
import ipaddress
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

from tls_dataset.reporting.snapshot import (
    build_dashboard_summary,
    build_graph_view,
    query_flow_explorer,
    resolve_dashboard_artifacts,
)
from tls_dataset.backend.config import BackendSettings


def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path, low_memory=False)


def _bool_series(df: pd.DataFrame, column: str) -> pd.Series:
    if column not in df.columns:
        return pd.Series(False, index=df.index)
    series = df[column]
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    return series.astype(str).str.lower().isin({"true", "1", "yes"})


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if pd.isna(value):
            return default
    except Exception:
        pass
    if value is None:
        return default
    return int(value)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if pd.isna(value):
            return default
    except Exception:
        pass
    if value is None:
        return default
    return float(value)


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return ""
    return text


def _slugify(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized or "node"


def _alpha_name(index: int) -> str:
    alphabet = [
        "Alpha",
        "Beta",
        "Gamma",
        "Delta",
        "Epsilon",
        "Zeta",
        "Eta",
        "Theta",
    ]
    if 0 <= index < len(alphabet):
        return alphabet[index]
    return f"Node {index + 1:02d}"


def _is_private_endpoint(endpoint: str) -> bool:
    text = _clean_text(endpoint)
    if not text:
        return False
    try:
        return bool(ipaddress.ip_address(text).is_private)
    except ValueError:
        return False


def _match_service_label(text: str) -> str:
    lowered = text.lower()
    label_rules = [
        ("instagram", "Instagram"),
        ("facebook", "Facebook"),
        ("fbstatic", "Facebook CDN"),
        ("fbcdn", "Facebook CDN"),
        ("twitter", "Twitter"),
        ("doubleclick", "DoubleClick"),
        ("google", "Google"),
        ("gstatic", "Google Static"),
        ("gmail", "Google Mail"),
        ("youtube", "YouTube"),
        ("qiwi", "Qiwi"),
        ("yandex", "Yandex"),
        ("marathonbet", "Marathonbet"),
        ("bebee", "beBee"),
        ("pusher", "Pusher"),
        ("indeed", "Indeed"),
        ("newrelic", "New Relic"),
        ("mail.ru", "Mail.ru"),
        ("akamai", "Akamai Edge"),
        ("amazonaws", "Amazon AWS"),
        ("alibaba", "Alibaba"),
        ("microsoft", "Microsoft"),
        ("playstation", "PlayStation"),
        ("cloudflare", "Cloudflare"),
    ]
    for needle, label in label_rules:
        if needle in lowered:
            return label
    return ""


def _service_family_from_domain(domain: Any) -> str:
    text = _clean_text(domain)
    if not text:
        return ""
    label = _match_service_label(text)
    if label:
        return label
    parts = [part for part in text.lower().split(".") if part]
    ignored = {
        "www",
        "api",
        "static",
        "cdn",
        "mail",
        "m",
        "ws",
        "csp",
        "ogads-pa",
        "clients6",
        "stats",
        "mc",
        "main",
    }
    filtered = [part for part in parts if part not in ignored and len(part) > 2]
    if len(filtered) >= 2:
        return filtered[-2].title()
    if filtered:
        return filtered[0].title()
    return "Encrypted Service"


def _service_family_from_application(application_name: Any) -> str:
    text = _clean_text(application_name)
    if not text:
        return ""
    if text.upper() == "TLS":
        return "Encrypted Session"
    if text.upper() == "QUIC":
        return "QUIC Session"
    if "." in text:
        text = text.split(".", 1)[1]
    label = _match_service_label(text)
    if label:
        return label
    return text.replace("_", " ").strip() or "Encrypted Session"


def _display_service_name(domain: Any, application_name: Any) -> str:
    requested = _clean_text(domain)
    if requested:
        pretty_map = {
            "translate.google.com": "Google Translate",
            "accounts.google.com": "Google Accounts",
            "apis.google.com": "Google APIs",
            "mail.google.com": "Google Mail",
            "api.instagram.com": "Instagram API",
            "twitter.com": "Twitter",
            "static.qiwi.com": "Qiwi Static Services",
            "bam.nr-data.net": "New Relic Beacon",
            "mc.yandex.ru": "Yandex Analytics",
        }
        return pretty_map.get(requested.lower(), requested)
    application_family = _service_family_from_application(application_name)
    return application_family or "Encrypted Session"


def _route_endpoint_label(endpoint: str, endpoint_catalog: dict[str, dict[str, Any]]) -> str:
    endpoint_meta = endpoint_catalog.get(endpoint, {})
    if endpoint_meta.get("role") == "Internal hub":
        return endpoint_meta.get("display_name", "Internal Gateway")
    dominant_family = endpoint_meta.get("dominant_family", "")
    if dominant_family and dominant_family not in {"Encrypted Session", "QUIC Session"}:
        return f"{dominant_family} Peer"
    if endpoint_meta.get("protocol_label") == "QUIC":
        return "QUIC Peer"
    return "Encrypted Peer"


def _protocol_family_label(value: Any) -> str:
    text = _clean_text(value).lower()
    if text == "quic":
        return "QUIC"
    return "TLS"


def _build_endpoint_catalog(df: pd.DataFrame) -> dict[str, dict[str, Any]]:
    endpoint_stats: dict[str, dict[str, Any]] = {}
    for _, row in df.iterrows():
        domain_family = _service_family_from_domain(row.get("requested_server_name"))
        application_family = _service_family_from_application(row.get("application_name"))
        family = domain_family or application_family or "Encrypted Session"
        display_service = _display_service_name(
            row.get("requested_server_name"),
            row.get("application_name"),
        )
        protocol_family = _protocol_family_label(row.get("protocol_family"))
        for endpoint_column in ("src_ip", "dst_ip"):
            endpoint = _clean_text(row.get(endpoint_column))
            if not endpoint:
                continue
            stats = endpoint_stats.setdefault(
                endpoint,
                {
                    "count": 0,
                    "services": Counter(),
                    "service_labels": Counter(),
                    "protocols": Counter(),
                    "is_private": _is_private_endpoint(endpoint),
                },
            )
            stats["count"] += 1
            stats["services"][family] += 1
            stats["service_labels"][display_service] += 1
            stats["protocols"][protocol_family] += 1

    sorted_items = sorted(
        endpoint_stats.items(),
        key=lambda item: (-int(item[1]["count"]), item[0]),
    )
    catalog: dict[str, dict[str, Any]] = {}
    public_index = 0
    alias_ids_seen: set[str] = set()
    private_index = 0

    for endpoint, stats in sorted_items:
        dominant_family = stats["services"].most_common(1)[0][0] if stats["services"] else "Encrypted Session"
        dominant_label = stats["service_labels"].most_common(1)[0][0] if stats["service_labels"] else dominant_family
        protocol_label = stats["protocols"].most_common(1)[0][0] if stats["protocols"] else "TLS"

        if stats["is_private"]:
            display_name = f"Internal Gateway {_alpha_name(private_index)}"
            role = "Internal hub"
            private_index += 1
        else:
            public_index += 1
            display_name = f"External Node {public_index:02d}"
            role = "External peer"

        alias_id = _slugify(display_name)
        suffix = 2
        unique_alias_id = alias_id
        while unique_alias_id in alias_ids_seen:
            unique_alias_id = f"{alias_id}-{suffix}"
            suffix += 1
        alias_ids_seen.add(unique_alias_id)

        catalog[endpoint] = {
            "display_name": display_name,
            "alias_id": unique_alias_id,
            "role": role,
            "dominant_family": dominant_family,
            "dominant_label": dominant_label,
            "protocol_label": protocol_label,
            "count": int(stats["count"]),
        }

    return catalog


def _capture_display_name(capture_id: str) -> str:
    lowered = str(capture_id).lower()
    if "malicious" in lowered or "botnet" in lowered:
        return "Campaign"
    if "benign" in lowered or "lab" in lowered:
        return "Baseline"
    return "Segment"


def _friendly_window_label(window_id: str) -> str:
    if not window_id:
        return "Window"
    capture_id, _, suffix = str(window_id).partition(":")
    match = re.search(r"w(\d+)", suffix)
    window_number = int(match.group(1)) + 1 if match else 1
    return f"{_capture_display_name(capture_id)} {window_number:02d}"


def _parse_maybe_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    text = str(value).strip()
    if not text:
        return []
    if not text.startswith("["):
        return [text]
    try:
        parsed = ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return [text]
    if isinstance(parsed, list):
        return [str(item) for item in parsed]
    return [str(parsed)]


def _pretty_model_name(model_name: str) -> str:
    return {
        "random_forest": "Random Forest",
        "gradient_boosting": "Gradient Boosting",
        "gaussian_nb": "Gaussian Naive Bayes",
    }.get(model_name, str(model_name).replace("_", " ").title())


def _display_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return f"{value:.2f}"
    return f"{int(value):,}"


def _display_percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _top_distribution(
    df: pd.DataFrame,
    *,
    column: str,
    limit: int,
    total: int,
) -> list[dict[str, Any]]:
    if df.empty or column not in df.columns or total <= 0:
        return []
    counts = (
        df[column]
        .dropna()
        .astype(str)
        .str.strip()
        .replace("", pd.NA)
        .dropna()
        .value_counts()
        .head(limit)
    )
    return [
        {
            "name": str(name),
            "count": int(count),
            "share": float(count / total),
            "display_count": _display_number(int(count)),
            "display_share": _display_percent(float(count / total)),
        }
        for name, count in counts.items()
    ]


def _group_distribution(
    df: pd.DataFrame,
    *,
    key_builder,
    member_builder,
    limit: int,
) -> list[dict[str, Any]]:
    if df.empty:
        return []

    counts: Counter[str] = Counter()
    members: defaultdict[str, Counter[str]] = defaultdict(Counter)
    total = int(len(df))
    for _, row in df.iterrows():
        key = _clean_text(key_builder(row))
        if not key:
            continue
        counts[key] += 1
        member = _clean_text(member_builder(row))
        if member:
            members[key][member] += 1

    grouped = counts.most_common(limit)
    return [
        {
            "name": key,
            "count": int(count),
            "share": float(count / total) if total else 0.0,
            "display_count": _display_number(int(count)),
            "display_share": _display_percent(float(count / total) if total else 0.0),
            "subtitle": " · ".join(item for item, _ in members[key].most_common(3)),
        }
        for key, count in grouped
    ]


def _dedupe_spotlight_flows(df: pd.DataFrame, limit: int = 10) -> list[dict[str, Any]]:
    if df.empty:
        return []

    working = df.copy()
    working["tier2_consensus_score"] = pd.to_numeric(
        working.get("tier2_consensus_score"), errors="coerce"
    )
    working["bidirectional_packets"] = pd.to_numeric(
        working.get("bidirectional_packets"), errors="coerce"
    )
    working["bidirectional_duration_ms"] = pd.to_numeric(
        working.get("bidirectional_duration_ms"), errors="coerce"
    )
    working = working.sort_values(
        ["tier2_consensus_score", "bidirectional_packets"],
        ascending=[False, False],
        kind="stable",
    )

    endpoint_catalog = _build_endpoint_catalog(working)
    seen: set[tuple[str, tuple[str, str], str]] = set()
    spotlight: list[dict[str, Any]] = []
    for _, row in working.iterrows():
        endpoint_pair = tuple(sorted((str(row.get("src_ip", "")), str(row.get("dst_ip", "")))))
        service_family = (
            _service_family_from_domain(row.get("requested_server_name"))
            or _service_family_from_application(row.get("application_name"))
            or "Encrypted Session"
        )
        key = (
            str(row.get("window_id", "")),
            endpoint_pair,
            service_family,
        )
        if key in seen:
            continue
        seen.add(key)
        src_endpoint = _clean_text(row.get("src_ip"))
        dst_endpoint = _clean_text(row.get("dst_ip"))
        src_meta = endpoint_catalog.get(src_endpoint, {})
        dst_meta = endpoint_catalog.get(dst_endpoint, {})
        src_display = (
            src_meta.get("display_name", "Internal Gateway")
            if src_meta.get("role") == "Internal hub"
            else ("QUIC Peer" if service_family == "QUIC Session" else f"{service_family} Peer")
        )
        dst_display = (
            dst_meta.get("display_name", "Internal Gateway")
            if dst_meta.get("role") == "Internal hub"
            else ("QUIC Peer" if service_family == "QUIC Session" else f"{service_family} Peer")
        )
        spotlight.append(
            {
                "record_id": str(row.get("record_id", ""))[:10],
                "window_label": _friendly_window_label(str(row.get("window_id", ""))),
                "capture_id": str(row.get("capture_id", "")),
                "service": _display_service_name(
                    row.get("requested_server_name"),
                    row.get("application_name"),
                ),
                "path": f"{src_display} -> {dst_display}",
                "path_detail": f"Ports {_safe_int(row.get('src_port'), 0)} -> {_safe_int(row.get('dst_port'), 0)}",
                "application_name": _service_family_from_application(row.get("application_name")) or "Encrypted Session",
                "score": _safe_float(row.get("tier2_consensus_score")),
                "alert_level": str(row.get("alert_level") or "candidate"),
                "packets": _safe_int(row.get("bidirectional_packets")),
                "duration_ms": _safe_int(row.get("bidirectional_duration_ms")),
            }
        )
        if len(spotlight) >= limit:
            break
    return spotlight


def _build_stage_funnel(
    overview: dict[str, Any],
    stage_metrics: dict[str, Any],
) -> list[dict[str, Any]]:
    total = max(_safe_int(overview.get("total_flows")), 1)
    funnel = [
        {
            "label": "Ingested telemetry",
            "value": _safe_int(overview.get("total_flows")),
            "share": 1.0,
            "note": "Normalized encrypted flow inventory",
            "accent": "steel",
        },
        {
            "label": "Escalation candidates",
            "value": _safe_int(overview.get("candidate_flows")),
            "share": _safe_int(overview.get("candidate_flows")) / total,
            "note": "Stage-one probabilistic filter",
            "accent": "cyan",
        },
        {
            "label": "Prioritized alerts",
            "value": _safe_int(overview.get("suspicious_flows")),
            "share": _safe_int(overview.get("suspicious_flows")) / total,
            "note": "Consensus scoring across deep classifiers",
            "accent": "coral",
        },
    ]
    tier1 = stage_metrics.get("tier1", {})
    tier2 = stage_metrics.get("tier2", {})
    if tier1:
        funnel[1]["metric"] = f"Recall {_display_percent(_safe_float(tier1.get('recall')))}"
    if tier2:
        funnel[2]["metric"] = f"F1 {_display_percent(_safe_float(tier2.get('f1')))}"
    return funnel


def _decorate_protocol_trend(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    trend: list[dict[str, Any]] = []
    for item in items:
        tls_flows = _safe_int(item.get("tls"))
        quic_flows = _safe_int(item.get("quic"))
        total = tls_flows + quic_flows
        trend.append(
            {
                "window_id": str(item.get("window_id", "")),
                "label": _friendly_window_label(str(item.get("window_id", ""))),
                "window_start_ms": _safe_int(item.get("window_start_ms")),
                "tls_flows": tls_flows,
                "quic_flows": quic_flows,
                "total_flows": total,
                "tls_share": float(tls_flows / total) if total else 0.0,
            }
        )
    return trend


def _decorate_alert_timeline(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    for item in items:
        candidate_flows = _safe_int(item.get("candidate_flows"))
        suspicious_flows = _safe_int(item.get("suspicious_flows"))
        mean_score = _safe_float(item.get("mean_score"))
        timeline.append(
            {
                "window_id": str(item.get("window_id", "")),
                "label": _friendly_window_label(str(item.get("window_id", ""))),
                "candidate_flows": candidate_flows,
                "suspicious_flows": suspicious_flows,
                "mean_score": mean_score,
                "high_alerts": _safe_int(item.get("high_alerts")),
                "conversion_rate": float(suspicious_flows / candidate_flows) if candidate_flows else 0.0,
            }
        )
    return timeline


def _decorate_protocol_mix(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mix: list[dict[str, Any]] = []
    for item in items:
        protocol_family = str(item.get("protocol_family", "unknown")).upper()
        suspicious_rate = _safe_float(item.get("suspicious_rate"))
        highlights = []
        for entry in item.get("top_requested_server_names", []):
            label = _service_family_from_domain(entry) or _display_service_name(entry, "")
            if label not in highlights:
                highlights.append(label)
        mix.append(
            {
                "protocol_family": protocol_family,
                "total_flows": _safe_int(item.get("total_flows")),
                "candidate_flows": _safe_int(item.get("candidate_flows")),
                "suspicious_flows": _safe_int(item.get("suspicious_flows")),
                "suspicious_rate": suspicious_rate,
                "display_rate": _display_percent(suspicious_rate),
                "subtitle": " · ".join(highlights[:3]),
            }
        )
    return mix


def _decorate_models(models: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranking = sorted(
        models,
        key=lambda item: _safe_float(item.get("test_optimized_f1")),
        reverse=True,
    )
    decorated: list[dict[str, Any]] = []
    for index, item in enumerate(ranking):
        decorated.append(
            {
                "model": str(item.get("model", "")),
                "display_name": _pretty_model_name(str(item.get("model", ""))),
                "rank": index + 1,
                "selected_threshold": _safe_float(item.get("selected_threshold")),
                "threshold_metric": str(item.get("threshold_metric", "f1")).upper(),
                "test_optimized_f1": _safe_float(item.get("test_optimized_f1")),
                "test_optimized_roc_auc": _safe_float(item.get("test_optimized_roc_auc")),
                "test_optimized_precision": _safe_float(item.get("test_optimized_precision")),
                "test_optimized_recall": _safe_float(item.get("test_optimized_recall")),
                "summary_note": "Primary scoring model"
                if index == 0
                else "Supporting evidence model",
            }
        )
    return decorated


def _decorate_endpoints(
    items: list[dict[str, Any]],
    endpoint_catalog: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    decorated: list[dict[str, Any]] = []
    for item in items:
        endpoint = _clean_text(item.get("endpoint"))
        endpoint_meta = endpoint_catalog.get(endpoint, {})
        role = endpoint_meta.get("role", "External peer")
        decorated.append(
            {
                "endpoint": endpoint_meta.get("display_name", endpoint),
                "cluster_id": str(item.get("cluster_id", "")),
                "role": role,
                "service_label": endpoint_meta.get("dominant_family", ""),
                "suspicious_flow_count": _safe_int(item.get("suspicious_flow_count")),
                "unique_neighbors": _safe_int(item.get("unique_neighbors")),
                "risk_mass": round(_safe_float(item.get("risk_mass")), 2),
            }
        )
    return decorated


def _decorate_graph(
    graph: dict[str, Any],
    endpoint_catalog: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    summary = graph.get("cluster_summary") or {}
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    if not nodes:
        return {
            "cluster_id": str(graph.get("cluster_id", "")),
            "summary": {},
            "nodes": [],
            "edges": [],
        }

    max_flow = max(_safe_int(node.get("suspicious_flow_count")) for node in nodes) or 1
    ranked_nodes = sorted(
        nodes,
        key=lambda item: (
            _safe_int(item.get("suspicious_flow_count")),
            _safe_int(item.get("unique_neighbors")),
        ),
        reverse=True,
    )
    labeled_nodes = {str(node.get("endpoint")) for node in ranked_nodes[:8]}
    decorated_nodes = []
    for node in nodes:
        suspicious_flow_count = _safe_int(node.get("suspicious_flow_count"))
        normalized_size = max(8.0, 12.0 + 28.0 * math.sqrt(suspicious_flow_count / max_flow))
        endpoint = str(node.get("endpoint", ""))
        endpoint_meta = endpoint_catalog.get(endpoint, {})
        is_private = bool(node.get("is_private"))
        node_type = "hub" if is_private and _safe_int(node.get("unique_neighbors")) > 10 else (
            "private" if is_private else "public"
        )
        decorated_nodes.append(
            {
                "id": endpoint_meta.get("alias_id", _slugify(endpoint)),
                "endpoint": endpoint_meta.get("display_name", endpoint),
                "type": node_type,
                "label": endpoint_meta.get("display_name", endpoint)
                if endpoint in labeled_nodes or node_type != "public"
                else "",
                "service_label": endpoint_meta.get("dominant_family", ""),
                "suspicious_flow_count": suspicious_flow_count,
                "unique_neighbors": _safe_int(node.get("unique_neighbors")),
                "max_incident_score": _safe_float(node.get("max_incident_score")),
                "size": round(normalized_size, 2),
            }
        )

    decorated_edges = [
        {
            "source": endpoint_catalog.get(str(edge.get("endpoint_a", "")), {}).get(
                "alias_id",
                _slugify(str(edge.get("endpoint_a", ""))),
            ),
            "target": endpoint_catalog.get(str(edge.get("endpoint_b", "")), {}).get(
                "alias_id",
                _slugify(str(edge.get("endpoint_b", ""))),
            ),
            "weight": _safe_int(edge.get("suspicious_flow_count"), 1),
            "score": _safe_float(edge.get("mean_consensus_score")),
        }
        for edge in edges
    ]

    return {
        "cluster_id": str(graph.get("cluster_id", "")),
        "returned_node_count": _safe_int(graph.get("returned_node_count")),
        "returned_edge_count": _safe_int(graph.get("returned_edge_count")),
        "summary": {
            "cluster_id": str(summary.get("cluster_id", "")),
            "suspicious_flow_count": _safe_int(summary.get("suspicious_flow_count")),
            "edge_count": _safe_int(summary.get("edge_count")),
            "endpoint_count": _safe_int(summary.get("endpoint_count")),
            "unique_windows": _safe_int(summary.get("unique_windows")),
            "private_endpoint_count": _safe_int(summary.get("private_endpoint_count")),
            "public_endpoint_count": _safe_int(summary.get("public_endpoint_count")),
            "top_requested_server_names": _parse_maybe_list(
                summary.get("top_requested_server_names")
            ),
            "top_protocol_families": _parse_maybe_list(summary.get("top_protocol_families")),
        },
        "nodes": decorated_nodes,
        "edges": decorated_edges,
    }


def build_static_dashboard_snapshot(
    *,
    settings: BackendSettings | None = None,
    max_graph_nodes: int = 36,
) -> dict[str, Any]:
    summary = build_dashboard_summary(settings=settings)
    graph = build_graph_view(settings=settings, max_nodes=max_graph_nodes)
    artifacts = resolve_dashboard_artifacts(settings)
    multitier_summary = _read_json(artifacts.multi_tier_dir / "workflow_summary.json")
    tiered_df = _read_csv(artifacts.multi_tier_dir / "tiered_flow_scores.csv")
    tiered_df["tier1_pass"] = _bool_series(tiered_df, "tier1_pass")
    tiered_df["tier2_pass"] = _bool_series(tiered_df, "tier2_pass")
    suspicious_df = tiered_df[tiered_df["tier2_pass"]].copy()
    endpoint_catalog = _build_endpoint_catalog(suspicious_df)

    overview = summary.get("overview", {})
    protocol_trend = _decorate_protocol_trend(summary.get("protocol_trend", []))
    alert_timeline = _decorate_alert_timeline(summary.get("alert_timeline", []))
    protocol_mix = _decorate_protocol_mix(summary.get("protocol_breakdown", []))
    domain_pressure = _group_distribution(
        suspicious_df,
        key_builder=lambda row: _service_family_from_domain(row.get("requested_server_name"))
        or _service_family_from_application(row.get("application_name")),
        member_builder=lambda row: _display_service_name(
            row.get("requested_server_name"),
            row.get("application_name"),
        ),
        limit=10,
    )
    application_pressure = _group_distribution(
        suspicious_df,
        key_builder=lambda row: _service_family_from_application(row.get("application_name")),
        member_builder=lambda row: _clean_text(row.get("application_name")).replace("TLS.", "").replace("QUIC.", ""),
        limit=10,
    )
    spotlight_flows = _dedupe_spotlight_flows(suspicious_df, limit=10)
    feature_importance = summary.get("feature_importance", {})
    model_quality = {
        "warnings": summary.get("model_quality", {}).get("warnings", []),
        "models": _decorate_models(summary.get("model_quality", {}).get("models", [])),
    }
    graph_payload = _decorate_graph(graph, endpoint_catalog)
    cluster_summary = graph_payload.get("summary", {})

    suspicious_windows = [
        item["label"]
        for item in alert_timeline
        if item.get("suspicious_flows", 0) > 0
    ]

    dominant_domain = domain_pressure[0]["name"] if domain_pressure else "Mixed encrypted services"
    raw_primary_endpoint = (
        summary.get("top_endpoints", [{}])[0].get("endpoint")
        if summary.get("top_endpoints")
        else "Internal pivot"
    )
    primary_endpoint = endpoint_catalog.get(
        _clean_text(raw_primary_endpoint),
        {"display_name": "Internal Gateway Alpha"},
    ).get("display_name", "Internal Gateway Alpha")
    protocol_highlight = protocol_mix[0] if protocol_mix else {}
    quic_highlight = next(
        (item for item in protocol_mix if item.get("protocol_family") == "QUIC"),
        None,
    )

    stage_metrics = multitier_summary.get("stage_metrics", {})
    storyline = [
        {
            "title": "Prioritized alert volume",
            "value": _display_number(_safe_int(overview.get("suspicious_flows"))),
            "detail": "Encrypted flows that cleared the consensus gate after staged scoring.",
        },
        {
            "title": "Dominant communications hub",
            "value": primary_endpoint,
            "detail": f"One internal hub fans out across {_display_number(cluster_summary.get('public_endpoint_count', 0))} external peers.",
        },
        {
            "title": "Most active encrypted service",
            "value": dominant_domain,
            "detail": "Highest-frequency requested server inside the peak-pressure communications set.",
        },
    ]

    hero_cluster_copy = (
        f"Primary communications hub spanning {_display_number(cluster_summary.get('endpoint_count', 0))} "
        f"endpoints across {_display_number(cluster_summary.get('unique_windows', 0))} active windows."
        if cluster_summary
        else "Cluster evidence unavailable."
    )

    research_boundaries = list(model_quality["warnings"])
    if quic_highlight and _safe_int(quic_highlight.get("suspicious_flows")) == 0:
        research_boundaries.append(
            "QUIC remains low-noise in the current active bundle, so expanded coverage will be important for broader validation."
        )

    methodology = [
        {
            "step": "01",
            "title": "Unified flow telemetry",
            "detail": "Encrypted traffic features are normalized into one operational schema with stable flow identifiers, protocol families, and time windows.",
        },
        {
            "step": "02",
            "title": "Stage-one screening",
            "detail": "A lightweight Naive Bayes filter narrows the candidate space before higher-cost scoring is applied.",
        },
        {
            "step": "03",
            "title": "Consensus scoring",
            "detail": "Random Forest and Gradient Boosting combine to prioritize high-confidence encrypted traffic alerts.",
        },
        {
            "step": "04",
            "title": "Endpoint enrichment",
            "detail": "Prioritized flows are transformed into endpoint topology so hub pressure, peer spread, and cluster structure can be explored directly.",
        },
    ]

    kpis = [
        {
            "label": "Scored flows",
            "value": _safe_int(overview.get("total_flows")),
            "display_value": _display_number(_safe_int(overview.get("total_flows"))),
            "supporting": "Normalized encrypted telemetry rows",
            "accent": "steel",
        },
        {
            "label": "Consensus alerts",
            "value": _safe_int(overview.get("suspicious_flows")),
            "display_value": _display_number(_safe_int(overview.get("suspicious_flows"))),
            "supporting": "High-confidence prioritized flows",
            "accent": "coral",
        },
        {
            "label": "TLS share",
            "value": _safe_float(
                _safe_int(overview.get("tls_flows")) / max(_safe_int(overview.get("total_flows")), 1)
            ),
            "display_value": _display_percent(
                _safe_int(overview.get("tls_flows")) / max(_safe_int(overview.get("total_flows")), 1)
            ),
            "supporting": "Encrypted traffic dominated by TLS",
            "accent": "cyan",
        },
        {
            "label": "Suspicious clusters",
            "value": _safe_int(overview.get("cluster_count")),
            "display_value": _display_number(_safe_int(overview.get("cluster_count"))),
            "supporting": "Graph-enriched communications structures",
            "accent": "gold",
        },
        {
            "label": "Model family",
            "value": _safe_int(overview.get("model_count")),
            "display_value": _display_number(_safe_int(overview.get("model_count"))),
            "supporting": "Multi-model scoring stack",
            "accent": "teal",
        },
    ]

    return {
        "meta": {
            "project_title": "Encrypted Traffic Intelligence for TLS 1.3 and QUIC",
            "project_tagline": "Encrypted traffic analytics platform",
            "hero_summary": "A production-style analytical surface built from the repository's encrypted telemetry, model evidence, and graph enrichment outputs.",
            "artifact_bundle": str(overview.get("active_model_bundle", "latest")),
            "dataset_mode": str(overview.get("dataset_mode", "benchmark_corpus")),
            "quality_signal": str(overview.get("quality_signal", "quality_caveat_present")),
            "stack": [
                "Zeek + NFStream",
                "Unified telemetry schema",
                "Gaussian Naive Bayes",
                "Random Forest",
                "Gradient Boosting",
                "Graph-based enrichment",
                "Analyst-ready interface",
            ],
        },
        "hero": {
            "title": "Encrypted Traffic Intelligence for TLS 1.3 and QUIC",
            "lede": "Encrypted traffic analytics with staged scoring, cluster enrichment, and model evidence designed for serious security presentation and product-grade communication.",
            "cluster_headline": primary_endpoint,
            "cluster_copy": hero_cluster_copy,
            "cluster_stats": [
                {
                    "label": "Alerts",
                    "value": _display_number(cluster_summary.get("suspicious_flow_count", 0)),
                },
                {
                    "label": "Nodes",
                    "value": _display_number(cluster_summary.get("endpoint_count", 0)),
                },
                {
                    "label": "Windows",
                    "value": _display_number(cluster_summary.get("unique_windows", 0)),
                },
            ],
        },
        "kpis": kpis,
        "storyline": storyline,
        "stage_funnel": _build_stage_funnel(overview, stage_metrics),
        "protocol_trend": protocol_trend,
        "alert_timeline": alert_timeline,
        "protocol_mix": protocol_mix,
        "domain_pressure": domain_pressure,
        "application_pressure": application_pressure,
        "graph": graph_payload,
        "top_endpoints": _decorate_endpoints(summary.get("top_endpoints", []), endpoint_catalog),
        "spotlight_flows": spotlight_flows,
        "model_quality": model_quality,
        "feature_importance": feature_importance,
        "methodology": methodology,
        "research_boundaries": research_boundaries,
        "supporting_notes": [
            f"{_display_number(_safe_int(overview.get('candidate_flows')))} encrypted flows crossed the stage-one screen before consensus scoring.",
            f"{protocol_highlight.get('protocol_family', 'TLS')} carries the highest prioritized alert share at {protocol_highlight.get('display_rate', '0.0%')}.",
            f"Primary pressure concentrates on {primary_endpoint} across {_display_number(cluster_summary.get('public_endpoint_count', 0))} external peers.",
            f"Peak activity is concentrated in windows: {', '.join(suspicious_windows[:4]) or 'none'}.",
        ],
    }


def export_static_dashboard_bundle(
    *,
    output_dir: str | Path | None = None,
    settings: BackendSettings | None = None,
    max_graph_nodes: int = 36,
) -> dict[str, Any]:
    destination = Path(output_dir) if output_dir is not None else project_root() / "showcase"
    destination.mkdir(parents=True, exist_ok=True)

    snapshot = build_static_dashboard_snapshot(settings=settings, max_graph_nodes=max_graph_nodes)
    json_text = json.dumps(snapshot, indent=2, ensure_ascii=False)
    data_json_path = destination / "data.json"
    data_js_path = destination / "data.js"
    nojekyll_path = destination / ".nojekyll"

    data_json_path.write_text(json_text + "\n", encoding="utf-8")
    data_js_path.write_text(
        "window.TLS_DATASET_STATIC_DASHBOARD = " + json_text + ";\n",
        encoding="utf-8",
    )
    nojekyll_path.write_text("", encoding="utf-8")

    return {
        "output_dir": str(destination.resolve()),
        "data_json": str(data_json_path.resolve()),
        "data_js": str(data_js_path.resolve()),
        "cluster_id": snapshot.get("graph", {}).get("cluster_id"),
        "scored_flows": snapshot.get("kpis", [{}])[0].get("value", 0),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export a static analytical dashboard data bundle from the current repository artifacts.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(project_root() / "showcase"),
        help="Directory where data.json and data.js should be written",
    )
    parser.add_argument(
        "--max-graph-nodes",
        type=int,
        default=36,
        help="Maximum nodes to include in the exported graph",
    )
    args = parser.parse_args(argv)

    result = export_static_dashboard_bundle(
        output_dir=args.output_dir,
        max_graph_nodes=args.max_graph_nodes,
    )
    for key, value in result.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
