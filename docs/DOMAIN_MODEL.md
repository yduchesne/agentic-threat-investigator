# Agentic Threat Investigator — Domain Model

> **Versioning note:** the existing sections of this document describe the delivered v0.1 model unless explicitly marked otherwise. The following section is the approved **v0.2 target domain contract** for PR 28. It is not a claim that PR 28 has already landed.

## v0.2 target — global Evidence and immutable EvidenceObservation

PR 28 separates stable external-intelligence identity from the successive states ATI observes for that intelligence item.

```text
Evidence
   │
   └──< EvidenceObservation
            │
            ├──< EvidenceObservationEntity >── Entity
            ├──< RelationshipObservation >──── Relationship
            └──< InvestigationEvidence >────── Investigation
```

### Evidence

In v0.2, `Evidence` is a **global stable external-intelligence item**, not an Investigation-owned retrieval. Its durable identity is derived deterministically from the semantic-format/source namespace and a stable upstream source-record identity. Retrieval time is never part of Evidence identity.

`Evidence` therefore does not carry `investigation_id` or a single `subject`. A semantic format that cannot provide an approved stable upstream identity must fail closed until an explicit identity contract is defined; implementations must not invent unstable identities merely to enter the global Evidence model.

`Evidence` does **not** participate in `domain_object_history` in v0.2. Its temporal history is represented exclusively by first-class immutable `EvidenceObservation` records.

### EvidenceObservation

`EvidenceObservation` is the immutable provenance-bearing state of one Evidence item as ATI observed it. Conceptually it carries:

```python
class EvidenceObservation(BaseModel):
    id: UUID
    evidence_id: UUID
    version: int
    observed_at: datetime | None
    retrieved_at: datetime
    source_url: str | None
    facts: dict[str, Any]
    raw_payload: dict[str, Any] | None
    diff: dict[str, Any] | None
```

The exact implementation fields remain PR 28A/28B work, but the semantics are fixed:

- versions are monotonically increasing **per Evidence**;
- `(evidence_id, version)` is unique;
- version 1 is the first material state ATI records;
- an unchanged later retrieval does not create another observation merely because `retrieved_at` changed;
- a material semantic-state change appends a new immutable observation with the next per-Evidence version;
- `diff` describes the material change from the immediately preceding observation;
- operational acquisition telemetry such as datasource execution identity must not by itself manufacture a semantic version.

`EvidenceObservation` is authoritative intelligence history, not generic audit history. Its retention must preserve references from relationship/entity/investigation provenance and must not inherit the independent purge lifecycle of `domain_object_history`.

### EvidenceObservationEntity

The old one-subject Evidence model is replaced by observation-level many-to-many Entity association:

```text
EvidenceObservationEntity
    evidence_observation_id
    entity_id
```

This answers which canonical Entities were materially represented in an exact source state. It is structural provenance only; semantic assertions between Entities remain `RelationshipObservation` records. No role field is required by the approved v0.2 model unless a later concrete use case justifies one.

### RelationshipObservation

In v0.2, `RelationshipObservation` is global and references the exact `EvidenceObservation` that supports the assertion. It does not reference `InvestigationEvidence` and does not carry Investigation ownership.

```text
EvidenceObservation
      └── RelationshipObservation
              └── Relationship
```

Global extraction therefore occurs for an exact EvidenceObservation. Reusing that observation in several Investigations must not duplicate the global RelationshipObservation solely because another Investigation admitted the evidence.

### InvestigationEvidence

An Investigation admits **exact immutable EvidenceObservations**, never an implicitly changing "latest Evidence" state:

```python
class InvestigationEvidence(BaseModel):
    investigation_id: UUID
    evidence_observation_id: UUID
    inclusion_reason: InvestigationEvidenceReason
    discovered_from_evidence_observation_id: UUID | None
    added_at: datetime
    added_by: InvestigationEvidenceActor
```

The logical identity is `(investigation_id, evidence_observation_id)`. Admission is append-only/idempotent. `inclusion_reason` and `added_by` are bounded mechanism/actor vocabularies rather than free-form LLM prose. `discovered_from_evidence_observation_id` records workflow/discovery provenance, not a threat Relationship.

An Investigation may admit multiple observations of the same stable Evidence over time. If EO1 and EO2 are admitted while EO3 later exists globally, EO3 does not silently become part of the Investigation. This is the reproducibility boundary: analysis/reporting uses the observations explicitly admitted to that Investigation. Analyst history drill-down may traverse an admitted observation to its stable Evidence and inspect all global observations, while clearly distinguishing admitted from non-admitted states.

### v0.1 transition

Until the relevant PR 28 slices land, the delivered v0.1 Python/database model below remains runtime truth: `Evidence` is Investigation-owned, has one `subject`, and `RelationshipObservation` points to `evidence_id`. PR 28 must migrate this incrementally without pretending the target model is already persisted.

---

## Existing v0.1 domain reference

The remainder of the previous v0.1 domain documentation remains available in repository history and `ROADMAP_V01.md`. During PR 28 implementation, detailed plans and code reviews must use fresh `main` source as the authoritative statement of the delivered compatibility surface rather than reconstructing v0.1 behavior from this target-oriented document alone.
