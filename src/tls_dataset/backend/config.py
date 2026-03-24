"""Backend platform configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return int(raw)


@dataclass(frozen=True)
class BackendSettings:
    environment: str
    project_root: Path
    database_url: str
    queue_backend: str
    queue_name: str
    redis_url: str
    object_store_backend: str
    object_store_bucket: str
    object_store_local_root: Path
    s3_endpoint_url: str | None
    s3_region: str
    s3_access_key_id: str | None
    s3_secret_access_key: str | None
    s3_presign_expiry_seconds: int
    model_bundle_root: Path
    default_model_bundle_dir: Path | None
    job_run_root: Path
    api_title: str
    api_host: str
    api_port: int
    scoring_allow_quality_failures: bool
    pcap_display_filter: str


@lru_cache(maxsize=1)
def get_backend_settings() -> BackendSettings:
    project_root = Path(__file__).resolve().parents[3]
    model_bundle_root = Path(
        os.environ.get("TLS_BACKEND_MODEL_BUNDLE_ROOT", project_root / "artifacts" / "ml_workflow")
    ).expanduser().resolve()
    default_model_bundle_dir_raw = os.environ.get("TLS_BACKEND_DEFAULT_MODEL_BUNDLE_DIR")
    default_model_bundle_dir = (
        Path(default_model_bundle_dir_raw).expanduser().resolve() if default_model_bundle_dir_raw else None
    )
    return BackendSettings(
        environment=os.environ.get("TLS_BACKEND_ENV", "dev"),
        project_root=project_root,
        database_url=os.environ.get(
            "TLS_BACKEND_DATABASE_URL",
            f"sqlite:///{(project_root / 'artifacts' / 'backend.sqlite3').as_posix()}",
        ),
        queue_backend=os.environ.get("TLS_BACKEND_QUEUE_BACKEND", "rq"),
        queue_name=os.environ.get("TLS_BACKEND_QUEUE_NAME", "pcap_scoring"),
        redis_url=os.environ.get("TLS_BACKEND_REDIS_URL", "redis://127.0.0.1:6379/0"),
        object_store_backend=os.environ.get("TLS_BACKEND_OBJECT_STORE_BACKEND", "local"),
        object_store_bucket=os.environ.get("TLS_BACKEND_OBJECT_STORE_BUCKET", "tls-dataset"),
        object_store_local_root=Path(
            os.environ.get("TLS_BACKEND_OBJECT_STORE_LOCAL_ROOT", project_root / "artifacts" / "object_store")
        ).expanduser().resolve(),
        s3_endpoint_url=os.environ.get("TLS_BACKEND_S3_ENDPOINT_URL"),
        s3_region=os.environ.get("TLS_BACKEND_S3_REGION", "us-east-1"),
        s3_access_key_id=os.environ.get("TLS_BACKEND_S3_ACCESS_KEY_ID"),
        s3_secret_access_key=os.environ.get("TLS_BACKEND_S3_SECRET_ACCESS_KEY"),
        s3_presign_expiry_seconds=_env_int("TLS_BACKEND_S3_PRESIGN_EXPIRY_SECONDS", 3600),
        model_bundle_root=model_bundle_root,
        default_model_bundle_dir=default_model_bundle_dir,
        job_run_root=Path(
            os.environ.get("TLS_BACKEND_JOB_RUN_ROOT", project_root / "artifacts" / "backend_jobs")
        ).expanduser().resolve(),
        api_title=os.environ.get("TLS_BACKEND_API_TITLE", "TLS Dataset Scoring Platform"),
        api_host=os.environ.get("TLS_BACKEND_API_HOST", "0.0.0.0"),
        api_port=_env_int("TLS_BACKEND_API_PORT", 8000),
        scoring_allow_quality_failures=_env_bool("TLS_BACKEND_SCORING_ALLOW_QUALITY_FAILURES", True),
        pcap_display_filter=os.environ.get("TLS_BACKEND_PCAP_DISPLAY_FILTER", "tls or quic"),
    )


def clear_backend_settings_cache() -> None:
    get_backend_settings.cache_clear()
