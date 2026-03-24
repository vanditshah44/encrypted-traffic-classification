# Docker Support

This directory is reserved for container helper assets such as entrypoint scripts, compose overrides, and deployment-specific templates.

The initial scaffold keeps the primary container definitions at the repository root:

- `Dockerfile`
- `docker-compose.yaml`

The Compose stack now targets the backend scoring platform and includes:

- `api` for FastAPI
- `worker` for queued PCAP scoring
- `postgres` for metadata
- `redis` for RQ
- `minio` for object storage
