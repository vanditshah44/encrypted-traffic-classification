"""Backend services for job intake, persistence, and serialization."""

from __future__ import annotations

import mimetypes
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tls_dataset.backend.config import BackendSettings, get_backend_settings
from tls_dataset.backend.models import ArtifactKind, JobArtifact, JobBatch, JobStatus, ProcessingJob
from tls_dataset.backend.queue import QueueBackend, build_queue_backend
from tls_dataset.backend.registry import ModelBundle, discover_model_bundles, resolve_model_bundle_dir
from tls_dataset.backend.storage import ObjectStorage, StoredObject, build_object_storage


DATASET_SAFE = re.compile(r"[^a-zA-Z0-9_-]+")


@dataclass(frozen=True)
class IncomingPcap:
    local_path: Path
    filename: str
    dataset_name: str
    content_type: str | None = None


def normalize_dataset_name(value: str) -> str:
    cleaned = DATASET_SAFE.sub("_", value.strip())
    cleaned = cleaned.strip("_")
    return cleaned[:120] or "pcap_job"


def guess_content_type(filename: str, override: str | None) -> str:
    return override or mimetypes.guess_type(filename)[0] or "application/octet-stream"


def get_storage(settings: BackendSettings | None = None) -> ObjectStorage:
    resolved = settings or get_backend_settings()
    storage = build_object_storage(resolved)
    storage.ensure_bucket(resolved.object_store_bucket)
    return storage


def get_queue(settings: BackendSettings | None = None) -> QueueBackend:
    return build_queue_backend(settings or get_backend_settings())


def create_batch_from_pcaps(
    session: Session,
    uploads: list[IncomingPcap],
    *,
    batch_name: str | None,
    model_bundle_dir: str | Path | None,
    settings: BackendSettings | None = None,
) -> JobBatch:
    resolved_settings = settings or get_backend_settings()
    if not uploads:
        raise ValueError("At least one PCAP must be provided")

    storage = get_storage(resolved_settings)
    queue = get_queue(resolved_settings)
    resolved_model_bundle_dir = resolve_model_bundle_dir(model_bundle_dir, settings=resolved_settings)
    batch = JobBatch(
        batch_name=batch_name or f"pcap_batch_{len(uploads)}",
        request_payload={
            "job_count": len(uploads),
            "model_bundle_dir": str(resolved_model_bundle_dir),
        },
    )
    session.add(batch)
    session.flush()

    jobs: list[ProcessingJob] = []
    for upload in uploads:
        dataset_name = normalize_dataset_name(upload.dataset_name)
        job = ProcessingJob(
            batch_id=batch.id,
            job_type="pcap_score",
            status=JobStatus.QUEUED.value,
            dataset_name=dataset_name,
            queue_name=resolved_settings.queue_name,
            queue_backend=resolved_settings.queue_backend,
            model_bundle_dir=str(resolved_model_bundle_dir),
            request_payload={
                "filename": upload.filename,
                "content_type": guess_content_type(upload.filename, upload.content_type),
            },
        )
        session.add(job)
        session.flush()

        object_key = f"jobs/{job.id}/inputs/{Path(upload.filename).name}"
        stored = storage.put_file(
            upload.local_path,
            bucket=resolved_settings.object_store_bucket,
            object_key=object_key,
            content_type=guess_content_type(upload.filename, upload.content_type),
        )
        artifact = build_artifact_record(
            job_id=job.id,
            kind=ArtifactKind.INPUT.value,
            artifact_type="input_pcap",
            logical_path=f"inputs/{Path(upload.filename).name}",
            stored=stored,
            metadata_payload={"dataset_name": dataset_name},
        )
        session.add(artifact)
        jobs.append(job)

    session.commit()

    for job in jobs:
        ticket = queue.enqueue_scoring_job(job.id)
        job.queue_backend = ticket.backend
        job.queue_name = ticket.queue_name
        job.external_job_id = ticket.external_job_id

    session.commit()
    session.refresh(batch)
    return batch


def build_artifact_record(
    *,
    job_id: str,
    kind: str,
    artifact_type: str,
    logical_path: str,
    stored: StoredObject,
    metadata_payload: dict[str, Any] | None = None,
) -> JobArtifact:
    return JobArtifact(
        job_id=job_id,
        kind=kind,
        artifact_type=artifact_type,
        logical_path=logical_path,
        storage_backend=stored.backend,
        bucket=stored.bucket,
        object_key=stored.object_key,
        object_uri=stored.object_uri,
        filename=stored.filename,
        content_type=stored.content_type,
        size_bytes=stored.size_bytes,
        sha256=stored.sha256,
        metadata_payload=metadata_payload,
    )


def upload_output_artifacts(
    session: Session,
    *,
    job: ProcessingJob,
    output_root: str | Path,
    settings: BackendSettings | None = None,
) -> list[JobArtifact]:
    resolved_settings = settings or get_backend_settings()
    storage = get_storage(resolved_settings)
    root = Path(output_root).expanduser().resolve()
    if not root.exists():
        return []

    uploaded: list[JobArtifact] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        logical_path = path.relative_to(root).as_posix()
        object_key = f"jobs/{job.id}/outputs/{logical_path}"
        stored = storage.put_file(
            path,
            bucket=resolved_settings.object_store_bucket,
            object_key=object_key,
        )
        artifact = build_artifact_record(
            job_id=job.id,
            kind=ArtifactKind.OUTPUT.value,
            artifact_type=classify_output_artifact(logical_path),
            logical_path=f"outputs/{logical_path}",
            stored=stored,
            metadata_payload={"relative_path": logical_path},
        )
        session.add(artifact)
        uploaded.append(artifact)
    session.flush()
    return uploaded


def classify_output_artifact(logical_path: str) -> str:
    lower = logical_path.lower()
    if lower.endswith("_quality_report.json"):
        return "quality_report"
    if lower.endswith("workflow_summary.json"):
        return "workflow_summary"
    if lower.endswith("platform_summary.json"):
        return "platform_summary"
    if lower.endswith("graph_bundle.json"):
        return "graph_bundle"
    if lower.endswith("suspicious_flows.csv"):
        return "suspicious_flows_csv"
    if lower.endswith("tiered_flow_scores.csv"):
        return "tiered_scores_csv"
    if lower.endswith(".png"):
        return "plot"
    if lower.endswith(".csv"):
        return "csv"
    if lower.endswith(".json"):
        return "json"
    if lower.endswith(".pcap") or lower.endswith(".pcapng"):
        return "pcap"
    return "artifact"


def serialize_artifact(artifact: JobArtifact, *, settings: BackendSettings | None = None) -> dict[str, Any]:
    resolved_settings = settings or get_backend_settings()
    storage = get_storage(resolved_settings)
    return {
        "id": artifact.id,
        "job_id": artifact.job_id,
        "kind": artifact.kind,
        "artifact_type": artifact.artifact_type,
        "logical_path": artifact.logical_path,
        "storage_backend": artifact.storage_backend,
        "bucket": artifact.bucket,
        "object_key": artifact.object_key,
        "object_uri": artifact.object_uri,
        "download_reference": storage.build_reference(
            bucket=artifact.bucket,
            object_key=artifact.object_key,
            filename=artifact.filename,
        ),
        "filename": artifact.filename,
        "content_type": artifact.content_type,
        "size_bytes": artifact.size_bytes,
        "sha256": artifact.sha256,
        "metadata": artifact.metadata_payload or {},
        "created_at": artifact.created_at.isoformat(),
    }


def serialize_job(job: ProcessingJob, *, settings: BackendSettings | None = None) -> dict[str, Any]:
    return {
        "id": job.id,
        "batch_id": job.batch_id,
        "job_type": job.job_type,
        "status": job.status,
        "dataset_name": job.dataset_name,
        "queue_name": job.queue_name,
        "queue_backend": job.queue_backend,
        "external_job_id": job.external_job_id,
        "model_bundle_dir": job.model_bundle_dir,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "error_message": job.error_message,
        "request": job.request_payload or {},
        "summary": job.summary_payload or {},
        "suspicious_flow_count": job.suspicious_flow_count,
        "candidate_flow_count": job.candidate_flow_count,
        "cluster_count": job.cluster_count,
        "artifacts": [serialize_artifact(artifact, settings=settings) for artifact in job.artifacts],
    }


def serialize_batch(batch: JobBatch, *, settings: BackendSettings | None = None) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    for job in batch.jobs:
        status_counts[job.status] = status_counts.get(job.status, 0) + 1
    return {
        "id": batch.id,
        "batch_name": batch.batch_name,
        "created_at": batch.created_at.isoformat(),
        "request": batch.request_payload or {},
        "job_count": len(batch.jobs),
        "status_counts": status_counts,
        "jobs": [serialize_job(job, settings=settings) for job in batch.jobs],
    }


def list_jobs(session: Session, *, limit: int = 50) -> list[ProcessingJob]:
    statement = select(ProcessingJob).order_by(ProcessingJob.created_at.desc()).limit(limit)
    return list(session.scalars(statement))


def get_job(session: Session, job_id: str) -> ProcessingJob | None:
    return session.get(ProcessingJob, job_id)


def get_batch(session: Session, batch_id: str) -> JobBatch | None:
    return session.get(JobBatch, batch_id)


def count_jobs(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(ProcessingJob)) or 0)


def count_batches(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(JobBatch)) or 0)


def list_model_bundle_payloads(settings: BackendSettings | None = None) -> list[dict[str, Any]]:
    resolved_settings = settings or get_backend_settings()
    bundles = discover_model_bundles(resolved_settings.model_bundle_root)
    return [serialize_model_bundle(bundle, settings=resolved_settings) for bundle in bundles]


def serialize_model_bundle(bundle: ModelBundle, *, settings: BackendSettings | None = None) -> dict[str, Any]:
    resolved_settings = settings or get_backend_settings()
    return {
        "name": bundle.name,
        "path": str(bundle.path),
        "model_names": list(bundle.model_names),
        "rows": bundle.rows,
        "columns": bundle.columns,
        "is_default": resolved_settings.default_model_bundle_dir == bundle.path,
        "workflow_summary_path": str(bundle.workflow_summary_path) if bundle.workflow_summary_path else None,
    }


def stage_uploaded_file(
    *,
    source_path: str | Path,
    working_dir: str | Path,
    filename: str | None = None,
) -> Path:
    source = Path(source_path).expanduser().resolve()
    target_dir = Path(working_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / (filename or source.name)
    shutil.copy2(source, target)
    return target
