# ATI — v0.2 Testing Target

PR 28 detailed plans must add deterministic coverage for the global-Evidence and distributed-ingestion invariants defined in `GLOBAL_EVIDENCE_ARCHITECTURE.md`. Required closure includes stable Evidence identity, per-Evidence observation versioning, unchanged-state no-op, material-change diff, exact Investigation admission, exact Entity/Relationship provenance, duplicate/replay idempotency, failure during DB transaction, crash after DB commit before consumer-position commit, redelivery, and producer/consumer restart behavior.

`TESTING.md` remains the delivered test architecture and must be reconciled by each implementation PR as those seams land.
