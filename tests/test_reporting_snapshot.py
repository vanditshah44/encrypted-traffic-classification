from __future__ import annotations

import json
import os
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import pandas as pd

from tls_dataset.reporting.snapshot import build_dashboard_summary, build_graph_view, query_flow_explorer
from tls_dataset.backend.config import clear_backend_settings_cache, get_backend_settings
from tls_dataset.backend.db import clear_db_caches, init_database, session_scope
from tls_dataset.backend.registry import resolve_model_bundle_dir


class ReportingSnapshotTests(TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        database_path = self.root / "backend.sqlite3"
        object_root = self.root / "object_store"
        job_root = self.root / "job_runs"

        self.env_patch = patch.dict(
            os.environ,
            {
                "TLS_BACKEND_DATABASE_URL": f"sqlite:///{database_path}",
                "TLS_BACKEND_QUEUE_BACKEND": "inline",
                "TLS_BACKEND_OBJECT_STORE_BACKEND": "local",
                "TLS_BACKEND_OBJECT_STORE_LOCAL_ROOT": str(object_root),
                "TLS_BACKEND_JOB_RUN_ROOT": str(job_root),
            },
            clear=False,
        )
        self.env_patch.start()
        clear_backend_settings_cache()
        clear_db_caches()
        init_database()

        self._write_dashboard_fixture()
        base_settings = get_backend_settings()
        self.settings = replace(
            base_settings,
            project_root=self.root,
            model_bundle_root=self.root / "artifacts" / "ml_workflow",
            default_model_bundle_dir=self.root / "artifacts" / "ml_workflow" / "latest",
            job_run_root=job_root,
            object_store_local_root=object_root,
        )

    def tearDown(self) -> None:
        clear_backend_settings_cache()
        clear_db_caches()
        self.env_patch.stop()
        self.temp_dir.cleanup()

    def _write_json(self, path: Path, payload: dict[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _write_dashboard_fixture(self) -> None:
        artifacts_root = self.root / "artifacts"
        canonical_root = artifacts_root / "canonical"
        ml_root = artifacts_root / "ml_workflow" / "latest"
        multi_root = artifacts_root / "multi_tier" / "latest"
        runs_root = artifacts_root / "runs" / "sample_run"

        canonical_root.mkdir(parents=True, exist_ok=True)
        ml_root.mkdir(parents=True, exist_ok=True)
        multi_root.mkdir(parents=True, exist_ok=True)
        runs_root.mkdir(parents=True, exist_ok=True)

        canonical_rows = [
            {
                "record_id": "flow-a",
                "sample_id": "flow-a",
                "label": "benign",
                "label_id": 0,
                "attack_family": "benign",
                "attack_category": "none",
                "traffic_role": "user_activity",
                "capture_id": "benign_filtered_primary",
                "protocol_family": "tls",
                "window_id": "benign_filtered_primary:w000000",
                "flow_start_ms": 1000,
                "flow_end_ms": 1200,
                "window_start_ms": 1000,
                "window_end_ms": 60999,
                "source_dataset": "lab_benign",
                "source_name": "benign_lab_nfstream",
                "feature_view": "nfstream",
                "source_row_index": 0,
                "quality_status": "unknown",
                "quality_failed": None,
                "quality_report_path": None,
                "provenance_path": None,
                "input_csv": "benign.csv",
                "is_encrypted": True,
                "collection_origin": "thesis_workspace",
                "environment": "lab",
                "src_ip": "10.0.0.2",
                "dst_ip": "142.250.0.1",
                "src_port": 51000,
                "dst_port": 443,
                "requested_server_name": "mail.google.com",
                "application_name": "TLS",
                "bidirectional_packets": 100,
                "bidirectional_duration_ms": 200,
            },
            {
                "record_id": "flow-b",
                "sample_id": "flow-b",
                "label": "malicious",
                "label_id": 1,
                "attack_family": "botnet",
                "attack_category": "c2_exfil",
                "traffic_role": "adversarial_activity",
                "capture_id": "malicious_ready_primary",
                "protocol_family": "tls",
                "window_id": "malicious_ready_primary:w000000",
                "flow_start_ms": 2000,
                "flow_end_ms": 2500,
                "window_start_ms": 2000,
                "window_end_ms": 61999,
                "source_dataset": "ctu_botnet_tls_filtered",
                "source_name": "malicious_ctu_nfstream",
                "feature_view": "nfstream",
                "source_row_index": 1,
                "quality_status": "fail",
                "quality_failed": True,
                "quality_report_path": str(runs_root / "sample_quality_report.json"),
                "provenance_path": "malicious_provenance.json",
                "input_csv": "malicious.csv",
                "is_encrypted": True,
                "collection_origin": "ctu_botnet",
                "environment": "public_dataset",
                "src_ip": "10.0.0.9",
                "dst_ip": "45.12.1.9",
                "src_port": 51234,
                "dst_port": 443,
                "requested_server_name": "bad.example",
                "application_name": "TLS",
                "bidirectional_packets": 240,
                "bidirectional_duration_ms": 510,
            },
            {
                "record_id": "flow-c",
                "sample_id": "flow-c",
                "label": "malicious",
                "label_id": 1,
                "attack_family": "botnet",
                "attack_category": "c2_exfil",
                "traffic_role": "adversarial_activity",
                "capture_id": "malicious_ready_primary",
                "protocol_family": "quic",
                "window_id": "malicious_ready_primary:w000001",
                "flow_start_ms": 62000,
                "flow_end_ms": 62500,
                "window_start_ms": 62000,
                "window_end_ms": 121999,
                "source_dataset": "ctu_botnet_tls_filtered",
                "source_name": "malicious_ctu_nfstream",
                "feature_view": "nfstream",
                "source_row_index": 2,
                "quality_status": "fail",
                "quality_failed": True,
                "quality_report_path": str(runs_root / "sample_quality_report.json"),
                "provenance_path": "malicious_provenance.json",
                "input_csv": "malicious.csv",
                "is_encrypted": True,
                "collection_origin": "ctu_botnet",
                "environment": "public_dataset",
                "src_ip": "10.0.0.9",
                "dst_ip": "52.10.10.10",
                "src_port": 52000,
                "dst_port": 443,
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
                "columns": 33,
                "quality_status_counts": {"fail": 2, "unknown": 1},
                "source_counts": {"malicious_ctu_nfstream": 2, "benign_lab_nfstream": 1},
                "capture_counts": {"malicious_ready_primary": 2, "benign_filtered_primary": 1},
            },
        )

        self._write_json(
            ml_root / "feature_manifest.json",
            {"training_feature_columns": ["bidirectional_packets", "bidirectional_duration_ms"]},
        )
        self._write_json(
            ml_root / "workflow_summary.json",
            {"rows": 3, "columns": 2, "warnings": ["quality-failed source present"]},
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
                    "cv_specificity_mean": float("nan"),
                },
                {
                    "model": "gradient_boosting",
                    "threshold_metric": "f1",
                    "selected_threshold": 0.10,
                    "test_optimized_f1": 0.97,
                    "test_optimized_roc_auc": 0.99,
                    "test_optimized_precision": 0.96,
                    "test_optimized_recall": 0.98,
                    "cv_specificity_mean": float("nan"),
                },
            ]
        ).to_csv(ml_root / "model_comparison.csv", index=False)
        for model_name in ("gaussian_nb", "random_forest", "gradient_boosting"):
            model_dir = ml_root / model_name
            model_dir.mkdir(parents=True, exist_ok=True)
            (model_dir / "model.joblib").write_bytes(b"placeholder")
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
                "tier1_threshold": 0.50,
                "tier1_pass": False,
                "tier1_model_name": "gaussian_nb",
                "random_forest_probability": None,
                "random_forest_threshold": 0.51,
                "random_forest_pass": False,
                "gradient_boosting_probability": None,
                "gradient_boosting_threshold": 0.10,
                "gradient_boosting_pass": False,
                "tier2_consensus_score": None,
                "tier2_pass_count": 0,
                "tier2_consensus_threshold": 0.50,
                "tier2_consensus_pass": False,
                "tier2_pass": False,
                "alert_level": "none",
            },
            {
                **canonical_rows[1],
                "tier1_probability": 0.97,
                "tier1_threshold": 0.50,
                "tier1_pass": True,
                "tier1_model_name": "gaussian_nb",
                "random_forest_probability": 0.99,
                "random_forest_threshold": 0.51,
                "random_forest_pass": True,
                "gradient_boosting_probability": 0.95,
                "gradient_boosting_threshold": 0.10,
                "gradient_boosting_pass": True,
                "tier2_consensus_score": 0.97,
                "tier2_pass_count": 2,
                "tier2_consensus_threshold": 0.50,
                "tier2_consensus_pass": True,
                "tier2_pass": True,
                "alert_level": "high",
            },
            {
                **canonical_rows[2],
                "tier1_probability": 0.83,
                "tier1_threshold": 0.50,
                "tier1_pass": True,
                "tier1_model_name": "gaussian_nb",
                "random_forest_probability": 0.77,
                "random_forest_threshold": 0.51,
                "random_forest_pass": True,
                "gradient_boosting_probability": 0.55,
                "gradient_boosting_threshold": 0.10,
                "gradient_boosting_pass": True,
                "tier2_consensus_score": 0.66,
                "tier2_pass_count": 2,
                "tier2_consensus_threshold": 0.50,
                "tier2_consensus_pass": True,
                "tier2_pass": True,
                "alert_level": "medium",
            },
        ]
        pd.DataFrame(tiered_rows).to_csv(multi_root / "tiered_flow_scores.csv", index=False)
        pd.DataFrame(tiered_rows[1:]).to_csv(multi_root / "suspicious_flows.csv", index=False)
        pd.DataFrame(tiered_rows[1:]).to_csv(multi_root / "tier1_candidates.csv", index=False)
        pd.DataFrame(
            [
                {"cluster_id": "cluster-1", "suspicious_flow_count": 2, "endpoint_count": 3, "max_consensus_score": 0.97},
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
            runs_root / "sample_quality_report.json",
            {
                "dataset_name": "malicious_ready_primary",
                "failed": True,
                "outcomes": [{"gate": "zeek_protocol_evidence", "status": "fail"}],
            },
        )

    def test_dashboard_summary_builds_json_safe_payload(self) -> None:
        payload = build_dashboard_summary(settings=self.settings)
        self.assertEqual(payload["overview"]["total_flows"], 3)
        self.assertEqual(payload["overview"]["tls_flows"], 2)
        self.assertEqual(payload["overview"]["quic_flows"], 1)
        self.assertEqual(payload["top_alerts"][0]["capture_id"], "malicious_ready_primary")
        self.assertIsNone(payload["model_quality"]["models"][0]["cv_specificity_mean"])
        self.assertEqual(payload["graph_overview"]["cluster_count"], 1)
        self.assertEqual(payload["ingestion_health"]["capture_counts"]["malicious_ready_primary"], 2)

    def test_bundle_resolution_prefers_latest_directory(self) -> None:
        settings_without_default = replace(self.settings, default_model_bundle_dir=None)
        self.assertEqual(
            resolve_model_bundle_dir(settings=settings_without_default),
            (self.root / "artifacts" / "ml_workflow" / "latest").resolve(),
        )

    def test_flow_explorer_filters_suspicious_and_search(self) -> None:
        suspicious_only = query_flow_explorer(
            settings=self.settings,
            only_suspicious=True,
        )
        self.assertEqual(suspicious_only["total"], 2)
        searched = query_flow_explorer(
            settings=self.settings,
            search="evil.example",
        )
        self.assertEqual(searched["total"], 1)
        self.assertEqual(searched["items"][0]["protocol_family"], "quic")

    def test_graph_view_limits_nodes_and_returns_cluster_summary(self) -> None:
        payload = build_graph_view(
            settings=self.settings,
            cluster_id="cluster-1",
            max_nodes=2,
        )
        self.assertEqual(payload["cluster_id"], "cluster-1")
        self.assertEqual(payload["cluster_summary"]["endpoint_count"], 3)
        self.assertEqual(payload["returned_node_count"], 2)
        self.assertTrue(payload["available_clusters"])

    def test_reporting_snapshot_helpers_share_the_same_fixture(self) -> None:
        summary = build_dashboard_summary(settings=self.settings)
        flows = query_flow_explorer(settings=self.settings, only_suspicious=True)
        graph = build_graph_view(settings=self.settings, cluster_id="cluster-1", max_nodes=2)

        self.assertEqual(summary["overview"]["suspicious_flows"], 2)
        self.assertEqual(flows["total"], 2)
        self.assertEqual(graph["cluster_id"], "cluster-1")
