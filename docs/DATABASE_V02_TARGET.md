# ATI — v0.2 Persistence Target

The approved v0.2 persistence direction is defined by `GLOBAL_EVIDENCE_ARCHITECTURE.md` and the database impact section of `V02_DOCUMENTATION_TRANSITION.md`.

`DATABASE.md` intentionally remains the delivered-v0.1 persistence contract until PR 28B changes the schema/stored functions/repositories. PR 28B must reconcile that document against the actual migration that lands, including global Evidence identity, immutable EvidenceObservation history, EvidenceObservationEntity, exact InvestigationEvidence admission, RelationshipObservation provenance, Evidence removal from generic domain history, concurrency-safe per-Evidence version allocation, and replay-idempotent bounded consumer transactions.
