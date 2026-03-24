"""Pydantic API schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    environment: str
    database: dict[str, Any]
    queue: dict[str, Any]
    object_storage: dict[str, Any]
    model_bundles: dict[str, Any]


class ArtifactResponse(BaseModel):
    id: str
    job_id: str
    kind: str
    artifact_type: str
    logical_path: str
    storage_backend: str
    bucket: str
    object_key: str
    object_uri: str
    download_reference: str
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class JobResponse(BaseModel):
    id: str
    batch_id: str | None = None
    job_type: str
    status: str
    dataset_name: str
    queue_name: str
    queue_backend: str
    external_job_id: str | None = None
    model_bundle_dir: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    error_message: str | None = None
    request: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    suspicious_flow_count: int | None = None
    candidate_flow_count: int | None = None
    cluster_count: int | None = None
    artifacts: list[ArtifactResponse] = Field(default_factory=list)


class BatchResponse(BaseModel):
    id: str
    batch_name: str
    created_at: str
    request: dict[str, Any] = Field(default_factory=dict)
    job_count: int
    status_counts: dict[str, int] = Field(default_factory=dict)
    jobs: list[JobResponse] = Field(default_factory=list)


class JobListResponse(BaseModel):
    items: list[JobResponse]


class ModelBundleResponse(BaseModel):
    name: str
    path: str
    model_names: list[str]
    rows: int | None = None
    columns: int | None = None
    is_default: bool
    workflow_summary_path: str | None = None


class ModelBundleListResponse(BaseModel):
    items: list[ModelBundleResponse]


class PathJobRequest(BaseModel):
    source_path: str
    dataset_name: str | None = None
    model_bundle_dir: str | None = None
    batch_name: str | None = None
