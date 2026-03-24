"""Object storage adapters for inputs and produced artifacts."""

from __future__ import annotations

import hashlib
import mimetypes
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import boto3
from botocore.client import BaseClient

from tls_dataset.backend.config import BackendSettings, get_backend_settings


@dataclass(frozen=True)
class StoredObject:
    backend: str
    bucket: str
    object_key: str
    object_uri: str
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


class ObjectStorage(Protocol):
    def ensure_bucket(self, bucket: str) -> None: ...
    def put_file(self, source_path: str | Path, *, bucket: str, object_key: str, content_type: str | None = None) -> StoredObject: ...
    def download_file(self, *, bucket: str, object_key: str, destination_path: str | Path) -> Path: ...
    def build_reference(self, *, bucket: str, object_key: str, filename: str | None = None) -> str: ...
    def healthcheck(self) -> dict[str, object]: ...


def compute_file_digest(path: str | Path) -> tuple[str, int]:
    target = Path(path).expanduser().resolve()
    digest = hashlib.sha256()
    size_bytes = 0
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size_bytes += len(chunk)
    return digest.hexdigest(), size_bytes


class LocalObjectStorage:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()

    def ensure_bucket(self, bucket: str) -> None:
        (self.root / bucket).mkdir(parents=True, exist_ok=True)

    def put_file(
        self,
        source_path: str | Path,
        *,
        bucket: str,
        object_key: str,
        content_type: str | None = None,
    ) -> StoredObject:
        source = Path(source_path).expanduser().resolve()
        destination = (self.root / bucket / object_key).resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        sha256, size_bytes = compute_file_digest(destination)
        resolved_content_type = content_type or mimetypes.guess_type(destination.name)[0] or "application/octet-stream"
        return StoredObject(
            backend="local",
            bucket=bucket,
            object_key=object_key,
            object_uri=str(destination),
            filename=destination.name,
            content_type=resolved_content_type,
            size_bytes=size_bytes,
            sha256=sha256,
        )

    def download_file(self, *, bucket: str, object_key: str, destination_path: str | Path) -> Path:
        source = (self.root / bucket / object_key).expanduser().resolve()
        destination = Path(destination_path).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return destination

    def build_reference(self, *, bucket: str, object_key: str, filename: str | None = None) -> str:
        return str((self.root / bucket / object_key).resolve())

    def healthcheck(self) -> dict[str, object]:
        self.root.mkdir(parents=True, exist_ok=True)
        return {
            "backend": "local",
            "root": str(self.root),
            "writable": self.root.exists(),
        }


class S3ObjectStorage:
    def __init__(self, client: BaseClient, *, presign_expiry_seconds: int) -> None:
        self.client = client
        self.presign_expiry_seconds = presign_expiry_seconds

    def ensure_bucket(self, bucket: str) -> None:
        try:
            self.client.head_bucket(Bucket=bucket)
        except Exception:
            self.client.create_bucket(Bucket=bucket)

    def put_file(
        self,
        source_path: str | Path,
        *,
        bucket: str,
        object_key: str,
        content_type: str | None = None,
    ) -> StoredObject:
        source = Path(source_path).expanduser().resolve()
        sha256, size_bytes = compute_file_digest(source)
        resolved_content_type = content_type or mimetypes.guess_type(source.name)[0] or "application/octet-stream"
        self.client.upload_file(
            str(source),
            bucket,
            object_key,
            ExtraArgs={"ContentType": resolved_content_type},
        )
        return StoredObject(
            backend="s3",
            bucket=bucket,
            object_key=object_key,
            object_uri=f"s3://{bucket}/{object_key}",
            filename=source.name,
            content_type=resolved_content_type,
            size_bytes=size_bytes,
            sha256=sha256,
        )

    def download_file(self, *, bucket: str, object_key: str, destination_path: str | Path) -> Path:
        destination = Path(destination_path).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.client.download_file(bucket, object_key, str(destination))
        return destination

    def build_reference(self, *, bucket: str, object_key: str, filename: str | None = None) -> str:
        return str(
            self.client.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket, "Key": object_key},
                ExpiresIn=self.presign_expiry_seconds,
            )
        )

    def healthcheck(self) -> dict[str, object]:
        return {
            "backend": "s3",
            "endpoint": getattr(self.client.meta, "endpoint_url", None),
        }


def build_object_storage(settings: BackendSettings | None = None) -> ObjectStorage:
    resolved = settings or get_backend_settings()
    if resolved.object_store_backend == "s3":
        client = boto3.client(
            "s3",
            endpoint_url=resolved.s3_endpoint_url,
            region_name=resolved.s3_region,
            aws_access_key_id=resolved.s3_access_key_id,
            aws_secret_access_key=resolved.s3_secret_access_key,
        )
        return S3ObjectStorage(client, presign_expiry_seconds=resolved.s3_presign_expiry_seconds)
    return LocalObjectStorage(resolved.object_store_local_root)
