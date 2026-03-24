"""ORM models for backend metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from tls_dataset.backend.db import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ArtifactKind(str, Enum):
    INPUT = "input"
    OUTPUT = "output"


class JobBatch(Base):
    __tablename__ = "job_batches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    batch_name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    request_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    jobs: Mapped[list["ProcessingJob"]] = relationship(
        back_populates="batch",
        cascade="all, delete-orphan",
        order_by="ProcessingJob.created_at",
    )


class ProcessingJob(Base):
    __tablename__ = "processing_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    batch_id: Mapped[str | None] = mapped_column(ForeignKey("job_batches.id"), nullable=True, index=True)
    job_type: Mapped[str] = mapped_column(String(64), default="pcap_score", index=True)
    status: Mapped[str] = mapped_column(String(32), default=JobStatus.QUEUED.value, index=True)
    dataset_name: Mapped[str] = mapped_column(String(255), index=True)
    queue_name: Mapped[str] = mapped_column(String(128))
    queue_backend: Mapped[str] = mapped_column(String(64))
    external_job_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    model_bundle_dir: Mapped[str] = mapped_column(String(2048))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    summary_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    suspicious_flow_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    candidate_flow_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cluster_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    batch: Mapped[JobBatch | None] = relationship(back_populates="jobs")
    artifacts: Mapped[list["JobArtifact"]] = relationship(
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="JobArtifact.created_at",
    )


class JobArtifact(Base):
    __tablename__ = "job_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    job_id: Mapped[str] = mapped_column(ForeignKey("processing_jobs.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default=ArtifactKind.OUTPUT.value)
    artifact_type: Mapped[str] = mapped_column(String(128), index=True)
    logical_path: Mapped[str] = mapped_column(String(1024))
    storage_backend: Mapped[str] = mapped_column(String(64))
    bucket: Mapped[str] = mapped_column(String(255))
    object_key: Mapped[str] = mapped_column(String(2048))
    object_uri: Mapped[str] = mapped_column(String(4096))
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    metadata_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    job: Mapped[ProcessingJob] = relationship(back_populates="artifacts")
