"""Worker process for queued PCAP scoring jobs."""

from __future__ import annotations

import argparse
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from redis import Redis
from rq import Connection, Worker

from tls_dataset.backend.config import get_backend_settings
from tls_dataset.backend.db import init_database, session_scope
from tls_dataset.backend.models import JobArtifact, JobStatus, ProcessingJob
from tls_dataset.backend.scoring import run_pcap_scoring_job
from tls_dataset.backend.services import get_storage, upload_output_artifacts


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _input_artifact(job: ProcessingJob) -> JobArtifact:
    for artifact in job.artifacts:
        if artifact.kind == "input" and artifact.artifact_type == "input_pcap":
            return artifact
    raise RuntimeError(f"Job {job.id} is missing an input_pcap artifact")


def process_scoring_job(job_id: str) -> None:
    settings = get_backend_settings()
    storage = get_storage(settings)
    init_database()

    with session_scope() as session:
        job = session.get(ProcessingJob, job_id)
        if job is None:
            raise RuntimeError(f"Job not found: {job_id}")
        job.status = JobStatus.RUNNING.value
        job.started_at = utc_now()
        job.error_message = None

    workspace_root = (settings.job_run_root / job_id).expanduser().resolve()
    input_dir = workspace_root / "input"
    run_dir = workspace_root / "run"
    input_dir.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)

    try:
        with session_scope() as session:
            job = session.get(ProcessingJob, job_id)
            if job is None:
                raise RuntimeError(f"Job not found during processing: {job_id}")
            input_artifact = _input_artifact(job)
            local_input = storage.download_file(
                bucket=input_artifact.bucket,
                object_key=input_artifact.object_key,
                destination_path=input_dir / input_artifact.filename,
            )
            scoring_result = run_pcap_scoring_job(
                input_pcap=local_input,
                workspace_dir=run_dir,
                dataset_name=job.dataset_name,
                model_bundle_dir=job.model_bundle_dir,
                allow_quality_failures=settings.scoring_allow_quality_failures,
                display_filter=settings.pcap_display_filter,
            )
            upload_output_artifacts(session, job=job, output_root=run_dir, settings=settings)
            inference_summary = scoring_result.summary.get("inference_summary", {})
            job.summary_payload = scoring_result.summary
            job.suspicious_flow_count = int(inference_summary.get("tier2_suspicious_rows", 0))
            job.candidate_flow_count = int(inference_summary.get("tier1_candidate_rows", 0))
            job.cluster_count = int(inference_summary.get("cluster_count", 0))
            job.status = JobStatus.SUCCEEDED.value
            job.completed_at = utc_now()
            job.error_message = None
    except Exception as exc:
        with session_scope() as session:
            job = session.get(ProcessingJob, job_id)
            if job is not None:
                job.status = JobStatus.FAILED.value
                job.completed_at = utc_now()
                job.error_message = str(exc)
        raise


def run_worker(*, burst: bool = False) -> None:
    settings = get_backend_settings()
    if settings.queue_backend != "rq":
        raise RuntimeError("RQ worker mode requires TLS_BACKEND_QUEUE_BACKEND=rq")
    init_database()
    connection = Redis.from_url(settings.redis_url)
    with Connection(connection):
        worker = Worker([settings.queue_name])
        worker.work(burst=burst)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the backend scoring worker")
    parser.add_argument("--burst", action="store_true", help="Process queued jobs and then exit")
    parser.add_argument("--job-id", default=None, help="Process a single job directly without entering worker loop")
    args = parser.parse_args(argv)

    if args.job_id:
        process_scoring_job(args.job_id)
        return 0
    run_worker(burst=args.burst)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
