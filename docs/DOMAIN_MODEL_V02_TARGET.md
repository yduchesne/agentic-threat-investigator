# ATI — v0.2 Domain Model Target

The approved global Evidence domain model is defined in `GLOBAL_EVIDENCE_ARCHITECTURE.md`. `DOMAIN_MODEL.md` remains the delivered v0.1 domain contract until PR 28A/28B migrate the Python and persistence models.

The v0.2 target centers all provenance-sensitive associations on immutable `EvidenceObservation`: observation-to-Entity via `EvidenceObservationEntity`, observation-to-Relationship via `RelationshipObservation`, and Investigation-to-observation via `InvestigationEvidence`. Stable `Evidence` is global source identity and does not own Investigation or single-subject state.
