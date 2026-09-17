# ATI — v0.2 Datasource Target

PR 27's delivered acquisition/serialization/semantic-format separation remains authoritative. PR 28 extends the post-conversion boundary as specified by `GLOBAL_EVIDENCE_ARCHITECTURE.md`: semantic conversion produces global Evidence state for an explicit versioned EvidenceMessage, publication is through an application `EvidencePublisher`, and PostgreSQL persistence occurs behind an `EvidenceConsumer` in bounded idempotent batches.

`DATASOURCE_ARCHITECTURE.md` remains the delivered PR 27 contract until implementation lands. Converter selection continues to depend only on `semantic_format`; broker/log transport must not leak into semantic parsing or conversion.
