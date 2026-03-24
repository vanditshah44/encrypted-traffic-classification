# ADR 0001: Feature Extraction Stack

## Status

Accepted

## Context

The thesis text references CICFlowMeter in the feature-engineering methodology, while the actual repository code and generated artifacts are already centered around Zeek and NFStream:

- `zeektocsv.py` converts Zeek outputs to CSV
- `combineCSV.py` merges NFStream data with Zeek connection and protocol logs
- `freeze_benign.py` and the downstream CSV artifacts are derived from that Zeek + NFStream flow

If the repository keeps both stories alive without a formal decision, the project will drift in three ways:

1. the written methodology will not match the executable pipeline
2. future implementation work will duplicate effort across incompatible extractors
3. reproducibility and production hardening will become much harder than necessary

## Decision

The official production extraction stack is:

- `Zeek` as the authoritative source for TLS 1.3 and QUIC protocol-aware metadata
- `NFStream` as the authoritative source for bidirectional statistical flow features

`CICFlowMeter` is not part of the forward production path for this repository. It is retained only as historical context unless an explicit academic requirement later forces compatibility work for legacy materials.

## Rationale

- Zeek already matches the protocol-focused direction of the project, especially for TLS and QUIC evidence.
- NFStream already matches the current scripts and generated feature tables.
- A single stack keeps the future pipeline reproducible and easier to operationalize.
- Avoiding CICFlowMeter removes an extra Java-based dependency track and an additional merge surface.

## Consequences

Positive:

- one canonical extractor stack for future implementation
- simpler pipeline orchestration and testing
- cleaner production packaging and deployment story
- better alignment with the current repository’s strongest assets

Trade-offs:

- the thesis text will remain slightly out of sync until we add an explicit implementation note in project documentation
- any claims requiring strict CICFlowMeter parity will need to be handled as a separate academic compatibility task, not as the default production direction

## Follow-up

- encode this decision in repository configs and package metadata
- refactor the legacy scripts into a Zeek + NFStream pipeline under `src/`
- keep a clear boundary between production implementation and thesis-only references
