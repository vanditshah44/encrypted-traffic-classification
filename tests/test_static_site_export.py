from __future__ import annotations

import json
import os
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import pandas as pd

from tls_dataset.backend.config import clear_backend_settings_cache, get_backend_settings
from tls_dataset.static_site.export_static_snapshot import (
    build_static_dashboard_snapshot,
    export_static_dashboard_bundle,
)


class StaticSiteExportTests(TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.env_patch = patch.dict(
            os.environ,
            {
                "TLS_BACKEND_DATABASE_URL": f"sqlite:///{self.root / 'backend.sqlite3'}",
                "TLS_BACKEND_QUEUE_BACKEND": "inline",
                "TLS_BACKEND_OBJECT_STORE_BACKEND": "local",
                "TLS_BACKEND_OBJECT_STORE_LOCAL_ROOT": str(self.root / "object_store"),
                "TLS_BACKEND_JOB_RUN_ROOT": str(self.root / "job_runs"),
            },
            clear=False,
        )
        self.env_patch.start()
        clear_backend_settings_cache()
        self._write_fixture()
        base_settings = get_backend_settings()
        self.settings = replace(
            base_settings,
            project_root=self.root,
            model_bundle_root=self.root / "artifacts" / "ml_workflow",
            default_model_bundle_dir=self.root / "artifacts" / "ml_workflow" / "latest",
            job_run_root=self.root / "job_runs",
            object_store_local_root=self.root / "object_store",
        )

    def tearDown(self) -> None:
        clear_backend_settings_cache()
        self.env_patch.stop()
        self.temp_dir.cleanup()

    def _write_json(self, path: Path, payload: dict[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _write_fixture(self) -> None:
        canonical_root = self.root / "artifacts" / "canonical"
        ml_root = self.root / "artifacts" / "ml_workflow" / "latest"
        multi_root = self.root / "artifacts" / "multi_tier" / "latest"
        runs_root = self.root / "artifacts" / "runs" / "sample_run"
        canonical_root.mkdir(parents=True, exist_ok=True)
        ml_root.mkdir(parents=True, exist_ok=True)
        multi_root.mkdir(parents=True, exist_ok=True)
        runs_root.mkdir(parents=True, exist_ok=True)

        canonical_rows = [
            {
                "record_id": "benign-flow",
                "sample_id": "benign-flow",
                "label": "benign",
                "label_id": 0,
                "attack_family": "benign",
                "capture_id": "benign_filtered_primary",
                "protocol_family": "tls",
                "window_id": "benign_filtered_primary:w000000",
                "window_start_ms": 1000,
                "source_name": "benign_lab_nfstream",
                "quality_status": "unknown",
                "src_ip": "10.0.0.2",
                "dst_ip": "142.250.0.1",
                "requested_server_name": "mail.google.com",
                "application_name": "TLS",
                "bidirectional_packets": 100,
                "bidirectional_duration_ms": 200,
            },
            {
                "record_id": "malicious-flow-1",
                "sample_id": "malicious-flow-1",
                "label": "malicious",
                "label_id": 1,
                "attack_family": "botnet",
                "capture_id": "malicious_ready_primary",
                "protocol_family": "tls",
                "window_id": "malicious_ready_primary:w000000",
                "window_start_ms": 2000,
                "source_name": "malicious_ctu_nfstream",
                "quality_status": "fail",
                "src_ip": "10.0.0.9",
                "dst_ip": "45.12.1.9",
                "requested_server_name": "bad.example",
                "application_name": "TLS.Facebook",
                "bidirectional_packets": 240,
                "bidirectional_duration_ms": 510,
            },
            {
                "record_id": "malicious-flow-2",
                "sample_id": "malicious-flow-2",
                "label": "malicious",
                "label_id": 1,
                "attack_family": "botnet",
                "capture_id": "malicious_ready_primary",
                "protocol_family": "quic",
                "window_id": "malicious_ready_primary:w000001",
                "window_start_ms": 62000,
                "source_name": "malicious_ctu_nfstream",
                "quality_status": "fail",
                "src_ip": "10.0.0.9",
                "dst_ip": "52.10.10.10",
                "requested_server_name": "evil.example",
                "application_name": "QUIC",
                "bidirectional_packets": 180,
                "bidirectional_duration_ms": 420,
            },
        ]
        pd.DataFrame(canonical_rows).to_csv(
            canonical_root / "canonical_labeled_flows.csv",
            index=False,
        )
        self._write_json(
            canonical_root / "canonical_labeled_flows_summary.json",
            {
                "rows": 3,
                "columns": 16,
                "quality_status_counts": {"fail": 2, "unknown": 1},
                "source_counts": {"malicious_ctu_nfstream": 2, "benign_lab_nfstream": 1},
                "capture_counts": {"malicious_ready_primary": 2, "benign_filtered_primary": 1},
            },
        )

        self._write_json(
            ml_root / "workflow_summary.json",
            {
                "warnings": [
                    "At least one source is quality-failed.",
                    "Capture diversity is still limited.",
                ]
            },
        )
        pd.DataFrame(
            [
                {
                    "model": "random_forest",
                    "threshold_metric": "f1",
                    "selected_threshold": 0.51,
                    "test_optimized_f1": 0.99,
                    "test_optimized_roc_auc": 1.0,
                    "test_optimized_precision": 1.0,
                    "test_optimized_recall": 0.98,
                },
                {
                    "model": "gaussian_nb",
                    "threshold_metric": "f1",
                    "selected_threshold": 1.0,
                    "test_optimized_f1": 0.79,
                    "test_optimized_roc_auc": 0.60,
                    "test_optimized_precision": 0.66,
                    "test_optimized_recall": 0.99,
                },
            ]
        ).to_csv(ml_root / "model_comparison.csv", index=False)
        for model_name in ("gaussian_nb", "random_forest"):
            model_dir = ml_root / model_name
            model_dir.mkdir(parents=True, exist_ok=True)
            pd.DataFrame(
                [
                    {"feature": "bidirectional_packets", "importance": 0.72},
                    {"feature": "bidirectional_duration_ms", "importance": 0.28},
                ]
            ).to_csv(model_dir / "feature_importance_native.csv", index=False)

        tiered_rows = [
            {
                **canonical_rows[0],
                "tier1_probability": 0.04,
                "tier1_pass": False,
                "tier2_consensus_score": None,
                "tier2_pass_count": 0,
                "tier2_pass": False,
                "alert_level": "none",
            },
            {
                **canonical_rows[1],
                "tier1_probability": 0.97,
                "tier1_pass": True,
                "tier2_consensus_score": 0.97,
                "tier2_pass_count": 2,
                "tier2_pass": True,
                "alert_level": "high",
                "src_port": 51234,
                "dst_port": 443,
            },
            {
                **canonical_rows[2],
                "tier1_probability": 0.83,
                "tier1_pass": True,
                "tier2_consensus_score": 0.66,
                "tier2_pass_count": 2,
                "tier2_pass": True,
                "alert_level": "medium",
                "src_port": 52000,
                "dst_port": 443,
            },
        ]
        pd.DataFrame(tiered_rows).to_csv(multi_root / "tiered_flow_scores.csv", index=False)
        pd.DataFrame(
            [
                {
                    "cluster_id": "cluster-1",
                    "suspicious_flow_count": 2,
                    "mean_consensus_score": 0.81,
                    "max_consensus_score": 0.97,
                    "unique_captures": 1,
                    "unique_windows": 2,
                    "edge_count": 2,
                    "endpoint_count": 3,
                    "private_endpoint_count": 1,
                    "public_endpoint_count": 2,
                    "top_protocol_families": ["tls", "quic"],
                    "top_requested_server_names": ["bad.example", "evil.example"],
                }
            ]
        ).to_csv(multi_root / "suspicious_clusters.csv", index=False)
        pd.DataFrame(
            [
                {"cluster_id": "cluster-1", "window_id": "malicious_ready_primary:w000000", "suspicious_flow_count": 1},
                {"cluster_id": "cluster-1", "window_id": "malicious_ready_primary:w000001", "suspicious_flow_count": 1},
            ]
        ).to_csv(multi_root / "cluster_window_summary.csv", index=False)
        pd.DataFrame(
            [
                {"cluster_id": "cluster-1", "endpoint": "10.0.0.9", "is_private": True, "suspicious_flow_count": 2, "unique_neighbors": 2, "max_incident_score": 0.97, "risk_mass": 1.63},
                {"cluster_id": "cluster-1", "endpoint": "45.12.1.9", "is_private": False, "suspicious_flow_count": 1, "unique_neighbors": 1, "max_incident_score": 0.97, "risk_mass": 0.97},
                {"cluster_id": "cluster-1", "endpoint": "52.10.10.10", "is_private": False, "suspicious_flow_count": 1, "unique_neighbors": 1, "max_incident_score": 0.66, "risk_mass": 0.66},
            ]
        ).to_csv(multi_root / "graph_nodes.csv", index=False)
        pd.DataFrame(
            [
                {"cluster_id": "cluster-1", "endpoint_a": "10.0.0.9", "endpoint_b": "45.12.1.9", "suspicious_flow_count": 1, "mean_consensus_score": 0.97},
                {"cluster_id": "cluster-1", "endpoint_a": "10.0.0.9", "endpoint_b": "52.10.10.10", "suspicious_flow_count": 1, "mean_consensus_score": 0.66},
            ]
        ).to_csv(multi_root / "graph_edges.csv", index=False)
        self._write_json(
            multi_root / "workflow_summary.json",
            {
                "stage_metrics": {
                    "tier1": {"recall": 0.99},
                    "tier2": {"f1": 0.95},
                }
            },
        )
        self._write_json(
            runs_root / "sample_quality_report.json",
            {
                "dataset_name": "malicious_ready_primary",
                "failed": True,
                "outcomes": [{"name": "zeek_outputs", "status": "fail"}],
            },
        )

    def test_build_static_dashboard_snapshot_returns_static_story_payload(self) -> None:
        payload = build_static_dashboard_snapshot(settings=self.settings, max_graph_nodes=3)
        self.assertEqual(payload["meta"]["project_tagline"], "Encrypted traffic analytics platform")
        self.assertEqual(payload["kpis"][0]["value"], 3)
        self.assertEqual(payload["graph"]["cluster_id"], "cluster-1")
        self.assertEqual(payload["graph"]["returned_node_count"], 3)
        self.assertTrue(payload["spotlight_flows"])
        self.assertEqual(payload["model_quality"]["models"][0]["display_name"], "Random Forest")
        self.assertEqual(payload["hero"]["cluster_headline"], "Internal Gateway Alpha")
        self.assertNotIn("10.0.0.9", payload["hero"]["cluster_copy"])
        self.assertTrue(payload["spotlight_flows"][0]["path"].startswith("Internal") or "Gateway" in payload["spotlight_flows"][0]["path"])

    def test_export_static_dashboard_bundle_writes_json_and_js_bundle(self) -> None:
        output_dir = self.root / "static_site"
        result = export_static_dashboard_bundle(
            output_dir=output_dir,
            settings=self.settings,
            max_graph_nodes=3,
        )
        self.assertTrue((output_dir / "data.json").exists())
        self.assertTrue((output_dir / "data.js").exists())
        self.assertTrue((output_dir / ".nojekyll").exists())
        payload = json.loads((output_dir / "data.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["graph"]["returned_node_count"], 3)
        self.assertIn("window.TLS_DATASET_STATIC_DASHBOARD", (output_dir / "data.js").read_text(encoding="utf-8"))
        self.assertEqual(result["cluster_id"], "cluster-1")
        self.assertNotIn("10.0.0.9", (output_dir / "data.json").read_text(encoding="utf-8"))
