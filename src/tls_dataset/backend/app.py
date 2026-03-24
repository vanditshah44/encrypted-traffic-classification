"""FastAPI application for the scoring platform."""

from __future__ import annotations

from contextlib import asynccontextmanager
import shutil
import tempfile
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from sqlalchemy import text
from sqlalchemy.orm import Session

from tls_dataset.backend.config import get_backend_settings
from tls_dataset.backend.db import get_db_session, init_database, get_engine
from tls_dataset.backend.queue import build_queue_backend
from tls_dataset.backend.registry import discover_model_bundles
from tls_dataset.backend.schemas import (
    BatchResponse,
    HealthResponse,
    JobListResponse,
    JobResponse,
    ModelBundleListResponse,
    PathJobRequest,
)
from tls_dataset.backend.services import (
    IncomingPcap,
    count_batches,
    count_jobs,
    create_batch_from_pcaps,
    get_batch,
    get_job,
    get_storage,
    list_jobs,
    list_model_bundle_payloads,
    serialize_batch,
    serialize_job,
    stage_uploaded_file,
)


def create_app() -> FastAPI:
    settings = get_backend_settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        init_database()
        get_storage(settings)
        yield

    app = FastAPI(title=settings.api_title, version="0.1.0", lifespan=lifespan)

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, object]:
        return {
            "service": settings.api_title,
            "status": "ok",
            "api_base": "/api/v1",
            "docs_url": "/docs",
        }

    @app.get("/api/v1/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        database_health = {"ok": False}
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
        database_health["ok"] = True

        queue = build_queue_backend(settings)
        storage = get_storage(settings)
        bundles = discover_model_bundles(settings.model_bundle_root)
        return HealthResponse(
            status="ok",
            environment=settings.environment,
            database=database_health,
            queue=queue.healthcheck(),
            object_storage=storage.healthcheck(),
            model_bundles={
                "count": len(bundles),
                "root": str(settings.model_bundle_root),
            },
        )

    @app.get("/api/v1/model-bundles", response_model=ModelBundleListResponse)
    def model_bundles() -> ModelBundleListResponse:
        return ModelBundleListResponse(items=list_model_bundle_payloads(settings))

    @app.get("/api/v1/jobs", response_model=JobListResponse)
    def jobs(
        limit: int = 50,
        session: Session = Depends(get_db_session),
    ) -> JobListResponse:
        return JobListResponse(items=[serialize_job(job, settings=settings) for job in list_jobs(session, limit=limit)])

    @app.get("/api/v1/jobs/{job_id}", response_model=JobResponse)
    def job_detail(job_id: str, session: Session = Depends(get_db_session)) -> JobResponse:
        job = get_job(session, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        return JobResponse.model_validate(serialize_job(job, settings=settings))

    @app.get("/api/v1/batches/{batch_id}", response_model=BatchResponse)
    def batch_detail(batch_id: str, session: Session = Depends(get_db_session)) -> BatchResponse:
        batch = get_batch(session, batch_id)
        if batch is None:
            raise HTTPException(status_code=404, detail=f"Batch not found: {batch_id}")
        return BatchResponse.model_validate(serialize_batch(batch, settings=settings))

    @app.post("/api/v1/jobs/pcap-score", response_model=BatchResponse, status_code=201)
    async def create_single_job(
        file: UploadFile = File(...),
        dataset_name: str | None = Form(default=None),
        model_bundle_dir: str | None = Form(default=None),
        batch_name: str | None = Form(default=None),
        session: Session = Depends(get_db_session),
    ) -> BatchResponse:
        temp_dir = Path(tempfile.mkdtemp(prefix="tls_dataset_upload_"))
        try:
            target = temp_dir / file.filename
            with target.open("wb") as handle:
                shutil.copyfileobj(file.file, handle)
            incoming = IncomingPcap(
                local_path=target,
                filename=file.filename,
                dataset_name=dataset_name or Path(file.filename).stem,
                content_type=file.content_type,
            )
            batch = create_batch_from_pcaps(
                session,
                [incoming],
                batch_name=batch_name or f"single_{incoming.dataset_name}",
                model_bundle_dir=model_bundle_dir,
                settings=settings,
            )
            return BatchResponse.model_validate(serialize_batch(batch, settings=settings))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    @app.post("/api/v1/batches/pcap-score", response_model=BatchResponse, status_code=201)
    async def create_batch_jobs(
        files: list[UploadFile] = File(...),
        batch_name: str | None = Form(default=None),
        model_bundle_dir: str | None = Form(default=None),
        session: Session = Depends(get_db_session),
    ) -> BatchResponse:
        temp_dir = Path(tempfile.mkdtemp(prefix="tls_dataset_batch_upload_"))
        uploads: list[IncomingPcap] = []
        try:
            for file in files:
                target = temp_dir / file.filename
                with target.open("wb") as handle:
                    shutil.copyfileobj(file.file, handle)
                uploads.append(
                    IncomingPcap(
                        local_path=target,
                        filename=file.filename,
                        dataset_name=Path(file.filename).stem,
                        content_type=file.content_type,
                    )
                )
            batch = create_batch_from_pcaps(
                session,
                uploads,
                batch_name=batch_name or f"batch_{len(uploads)}",
                model_bundle_dir=model_bundle_dir,
                settings=settings,
            )
            return BatchResponse.model_validate(serialize_batch(batch, settings=settings))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    @app.post("/api/v1/jobs/pcap-score/from-path", response_model=BatchResponse, status_code=201)
    def create_job_from_path(
        request: PathJobRequest,
        session: Session = Depends(get_db_session),
    ) -> BatchResponse:
        temp_dir = Path(tempfile.mkdtemp(prefix="tls_dataset_path_stage_"))
        try:
            staged = stage_uploaded_file(source_path=request.source_path, working_dir=temp_dir)
            incoming = IncomingPcap(
                local_path=staged,
                filename=staged.name,
                dataset_name=request.dataset_name or staged.stem,
                content_type=None,
            )
            batch = create_batch_from_pcaps(
                session,
                [incoming],
                batch_name=request.batch_name or f"path_{incoming.dataset_name}",
                model_bundle_dir=request.model_bundle_dir,
                settings=settings,
            )
            return BatchResponse.model_validate(serialize_batch(batch, settings=settings))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    @app.get("/api/v1/platform/summary")
    def platform_summary(session: Session = Depends(get_db_session)) -> dict[str, object]:
        return {
            "job_count": count_jobs(session),
            "batch_count": count_batches(session),
            "model_bundle_count": len(discover_model_bundles(settings.model_bundle_root)),
            "job_run_root": str(settings.job_run_root),
            "object_store_bucket": settings.object_store_bucket,
        }

    return app


app = create_app()
