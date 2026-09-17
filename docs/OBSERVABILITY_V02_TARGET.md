# ATI — v0.2 Observability Target

Distributed Evidence ingestion adds producer publication and consumer processing boundaries that will require correlation and operational visibility, while preserving datasource execution provenance. `datasource_execution_id` may correlate EvidenceMessage provenance but does not define Evidence identity or semantic observation versioning. Exact tracing/metrics changes belong to the implementation slices and must preserve provider-neutral observability.

`OBSERVABILITY.md` remains current delivered behavior until those changes land.
