from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from tls_dataset.backend.config import clear_backend_settings_cache
from tls_dataset.backend.db import clear_db_caches, init_database, session_scope
from tls_dataset.backend.models import JobStatus, ProcessingJob
from tls_dataset.backend.services import IncomingPcap, create_batch_from_pcaps
from tls_dataset.backend.worker import process_scoring_job


class BackendPlatformTests(TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        database_path = root / "backend.sqlite3"
        object_root = root / "object_store"
        job_root = root / "job_runs"
        model_root = root / "models"
        bundle = model_root / "run_test_bundle"
        bundle.mkdir(parents=True, exist_ok=True)
        (bundle / "feature_manifest.json").write_text(
            '{"training_feature_columns": ["feature_a", "feature_b"]}',
            encoding="utf-8",
        )
        (bundle / "workflow_summary.json").write_text('{"rows": 10, "columns": 4}', encoding="utf-8")
        for model_name in ("gaussian_nb", "random_forest", "gradient_boosting"):
            model_dir = bundle / model_name
            model_dir.mkdir(parents=True, exist_ok=True)
            (model_dir / "model.joblib").write_bytes(b"placeholder")

        self.env_patch = patch.dict(
            os.environ,
            {
                "TLS_BACKEND_DATABASE_URL": f"sqlite:///{database_path}",
                "TLS_BACKEND_QUEUE_BACKEND": "inline",
                "TLS_BACKEND_OBJECT_STORE_BACKEND": "local",
                "TLS_BACKEND_OBJECT_STORE_LOCAL_ROOT": str(object_root),
                "TLS_BACKEND_MODEL_BUNDLE_ROOT": str(model_root),
                "TLS_BACKEND_DEFAULT_MODEL_BUNDLE_DIR": str(bundle),
                "TLS_BACKEND_JOB_RUN_ROOT": str(job_root),
            },
            clear=False,
        )
        self.env_patch.start()
        clear_backend_settings_cache()
        clear_db_caches()
        init_database()
        from tls_dataset.backend.app import create_app

        self.app = create_app()
        self.route_map = {
            route.path: route.endpoint
            for route in self.app.routes
            if hasattr(route, "path") and hasattr(route, "endpoint")
        }

    def tearDown(self) -> None:
        clear_backend_settings_cache()
        clear_db_caches()
        self.env_patch.stop()
        self.temp_dir.cleanup()

    def test_health_endpoint_reports_platform_services(self) -> None:
        payload = self.route_map["/api/v1/health"]().model_dump()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["queue"]["backend"], "inline")
        self.assertEqual(payload["model_bundles"]["count"], 1)

    def test_single_job_submission_persists_metadata_and_artifact(self) -> None:
        upload_path = Path(self.temp_dir.name) / "sample_capture.pcap"
        upload_path.write_bytes(b"dummy-pcap-bytes")
        with session_scope() as session:
            batch = create_batch_from_pcaps(
                session,
                [
                    IncomingPcap(
                        local_path=upload_path,
                        filename=upload_path.name,
                        dataset_name="sample_capture",
                        content_type="application/vnd.tcpdump.pcap",
                    )
                ],
                batch_name="sample_batch",
                model_bundle_dir=None,
            )
            payload = {
                "job_count": len(batch.jobs),
                "jobs": [
                    {
                        "status": batch.jobs[0].status,
                        "dataset_name": batch.jobs[0].dataset_name,
                        "artifact_type": batch.jobs[0].artifacts[0].artifact_type,
                    }
                ],
            }
        self.assertEqual(payload["job_count"], 1)
        job = payload["jobs"][0]
        self.assertEqual(job["status"], "queued")
        self.assertEqual(job["dataset_name"], "sample_capture")
        self.assertEqual(job["artifact_type"], "input_pcap")

    def test_worker_updates_job_state_when_scoring_runner_succeeds(self) -> None:
        upload_path = Path(self.temp_dir.name) / "worker_capture.pcap"
        upload_path.write_bytes(b"dummy-pcap-bytes")
        with session_scope() as session:
            batch = create_batch_from_pcaps(
                session,
                [
                    IncomingPcap(
                        local_path=upload_path,
                        filename=upload_path.name,
                        dataset_name="worker_sample",
                        content_type="application/vnd.tcpdump.pcap",
                    )
                ],
                batch_name="worker_batch",
                model_bundle_dir=None,
            )
            job_id = batch.jobs[0].id

        fake_run_dir = Path(os.environ["TLS_BACKEND_JOB_RUN_ROOT"]) / job_id / "run"
        fake_output_dir = fake_run_dir / "scoring"

        def _fake_runner(**_: object):
            fake_output_dir.mkdir(parents=True, exist_ok=True)
            (fake_output_dir / "workflow_summary.json").write_text(
                '{"tier1_candidate_rows": 12, "tier2_suspicious_rows": 5, "cluster_count": 2}',
                encoding="utf-8",
            )
            (fake_run_dir / "platform_summary.json").write_text("{}", encoding="utf-8")
            return type(
                "FakeScoringRun",
                (),
                {
                    "summary": {
                        "inference_summary": {
                            "tier1_candidate_rows": 12,
                            "tier2_suspicious_rows": 5,
                            "cluster_count": 2,
                        }
                    }
                },
            )()

        with patch("tls_dataset.backend.worker.run_pcap_scoring_job", side_effect=_fake_runner):
            process_scoring_job(job_id)

        with session_scope() as session:
            job = session.get(ProcessingJob, job_id)
            assert job is not None
            self.assertEqual(job.status, JobStatus.SUCCEEDED.value)
            self.assertEqual(job.suspicious_flow_count, 5)
            self.assertEqual(job.candidate_flow_count, 12)
            self.assertEqual(job.cluster_count, 2)
