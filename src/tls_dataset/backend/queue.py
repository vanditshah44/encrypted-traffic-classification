"""Queue adapters for asynchronous scoring jobs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from redis import Redis
from rq import Queue

from tls_dataset.backend.config import BackendSettings, get_backend_settings


@dataclass(frozen=True)
class QueueTicket:
    backend: str
    queue_name: str
    external_job_id: str


class QueueBackend(Protocol):
    def enqueue_scoring_job(self, job_id: str) -> QueueTicket: ...
    def healthcheck(self) -> dict[str, object]: ...


class InlineQueueBackend:
    def __init__(self, queue_name: str) -> None:
        self.queue_name = queue_name

    def enqueue_scoring_job(self, job_id: str) -> QueueTicket:
        return QueueTicket(
            backend="inline",
            queue_name=self.queue_name,
            external_job_id=job_id,
        )

    def healthcheck(self) -> dict[str, object]:
        return {
            "backend": "inline",
            "queue_name": self.queue_name,
        }


class RQQueueBackend:
    def __init__(self, redis_url: str, queue_name: str) -> None:
        self.redis_url = redis_url
        self.queue_name = queue_name
        self.connection = Redis.from_url(redis_url)
        self.queue = Queue(name=queue_name, connection=self.connection)

    def enqueue_scoring_job(self, job_id: str) -> QueueTicket:
        job = self.queue.enqueue(
            "tls_dataset.backend.worker.process_scoring_job",
            job_id,
            job_timeout="4h",
            result_ttl=86400,
        )
        return QueueTicket(
            backend="rq",
            queue_name=self.queue_name,
            external_job_id=job.id,
        )

    def healthcheck(self) -> dict[str, object]:
        return {
            "backend": "rq",
            "queue_name": self.queue_name,
            "redis_ping": bool(self.connection.ping()),
        }


def build_queue_backend(settings: BackendSettings | None = None) -> QueueBackend:
    resolved = settings or get_backend_settings()
    if resolved.queue_backend == "inline":
        return InlineQueueBackend(queue_name=resolved.queue_name)
    return RQQueueBackend(redis_url=resolved.redis_url, queue_name=resolved.queue_name)
