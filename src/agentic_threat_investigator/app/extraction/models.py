# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable deterministic extraction output and the extraction error contract.

Extraction converts one normalized, persisted :class:`Evidence` observation
into canonical discovered entity identities and evidence-backed relationship
assertions without any I/O, persistence, provider calls, or database access.

The output models are deliberately small, frozen, and independent of the
persisted ``Relationship`` contract: persistence (PR 18C) allocates database
entity/relationship identifiers, so extraction never fabricates UUIDs. Every
assertion carries the supporting persisted ``Evidence`` ID directly.
"""

from collections.abc import Iterable
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.relationships import RelationshipType


class ExtractedEntity(BaseModel):
    """A canonical discovered entity identity produced by extraction.

    ``value`` is always the output of the shared domain canonicalizer for
    ``type``. ``display_name`` is optional presentation metadata (for
    example a ThreatFox printable malware name) and never participates in
    identity.
    """

    model_config = ConfigDict(frozen=True)

    type: EntityType
    value: str
    display_name: str | None = None


class EntityIdentity(BaseModel):
    """A canonical entity identity participating in a relationship assertion.

    Assertion endpoints reference entities by canonical identity rather than
    database ID because discovery and persistence are separate concerns.
    """

    model_config = ConfigDict(frozen=True)

    type: EntityType
    value: str


class RelationshipAssertion(BaseModel):
    """A source-semantic relationship assertion backed by one persisted Evidence.

    Assertions are candidate semantic edges justified by the documented
    semantics of the source that produced the evidence; they are not yet
    persisted relationships and carry no database identifiers.
    """

    model_config = ConfigDict(frozen=True)

    source: EntityIdentity
    type: RelationshipType
    target: EntityIdentity
    evidence_id: UUID


class ExtractionResult(BaseModel):
    """Deterministic, deduplicated extraction output for one Evidence.

    Entities and relationships are already collapsed by canonical identity
    and preserve first-seen source order; extraction is all-or-nothing per
    Evidence, so a result is either complete or replaced by a typed error.
    """

    model_config = ConfigDict(frozen=True)

    entities: tuple[ExtractedEntity, ...] = ()
    relationships: tuple[RelationshipAssertion, ...] = ()


class ExtractionErrorReason(str, Enum):
    """Bounded, log-safe reason categories for extraction failures."""

    MISSING_EVIDENCE_ID = "missing_evidence_id"
    UNSUPPORTED_EVIDENCE_TYPE = "unsupported_evidence_type"
    MALFORMED_FACTS = "malformed_facts"


class EvidenceExtractionError(Exception):
    """Raised when normalized Evidence cannot be extracted deterministically.

    Context is deliberately restricted to safe values: the source identifier,
    a bounded reason category, and the Evidence ID when known. Messages are
    static strings authored by ATI and never include raw payloads,
    credentials, or uncontrolled third-party response bodies. Extraction is
    all-or-nothing per Evidence: callers must treat this error as discarding
    the whole result rather than a partial one.
    """

    def __init__(
        self,
        source: str,
        reason: ExtractionErrorReason,
        message: str,
        *,
        evidence_id: UUID | None = None,
    ) -> None:
        """Record the safe failure context and the static message."""
        super().__init__(message)
        self.source = source
        self.reason = reason
        self.evidence_id = evidence_id


def validate_extractor_input(
    evidence: Evidence,
    *,
    source: str,
    evidence_type: EvidenceType,
    subject_types: tuple[EntityType, ...] = (),
) -> UUID:
    """Validate the per-extractor Evidence contract and return the Evidence ID.

    Every non-empty extractor requires a persisted Evidence (a database-assigned
    ID) because every relationship assertion must carry that provenance, a
    source/type combination matching the documented contract, and — when the
    contract restricts them — a subject entity type the source actually
    produces. Violations are contract failures, never silent repairs.
    """

    if evidence.source != source or evidence.type is not evidence_type:
        raise unsupported_evidence_type(
            evidence.source,
            "evidence source/type does not match the extractor contract",
            evidence_id=evidence.id,
        )
    if evidence.id is None:
        raise EvidenceExtractionError(
            source,
            ExtractionErrorReason.MISSING_EVIDENCE_ID,
            "extraction requires a persisted Evidence identifier",
        )
    if subject_types and evidence.subject.type not in subject_types:
        raise EvidenceExtractionError(
            source,
            ExtractionErrorReason.MALFORMED_FACTS,
            "evidence subject type is inconsistent with the source contract",
            evidence_id=evidence.id,
        )
    return evidence.id


def unsupported_evidence_type(
    source: str, message: str, *, evidence_id: UUID | None = None
) -> EvidenceExtractionError:
    """Build an unsupported-evidence-type contract failure error."""
    return EvidenceExtractionError(
        source,
        ExtractionErrorReason.UNSUPPORTED_EVIDENCE_TYPE,
        message,
        evidence_id=evidence_id,
    )


def malformed_facts(
    source: str, message: str, *, evidence_id: UUID | None = None
) -> EvidenceExtractionError:
    """Build a malformed-facts contract failure error."""
    return EvidenceExtractionError(
        source,
        ExtractionErrorReason.MALFORMED_FACTS,
        message,
        evidence_id=evidence_id,
    )


def deduplicate_entities(
    entities: Iterable[ExtractedEntity],
) -> tuple[ExtractedEntity, ...]:
    """Collapse duplicate entity identities deterministically.

    The key is ``(type, canonical value)``. First-seen source order is
    preserved; the first occurrence fixes an identity's position and the
    first non-null ``display_name`` wins. No other attributes are merged.
    """
    positions: dict[tuple[EntityType, str], int] = {}
    ordered: list[ExtractedEntity] = []
    for entity in entities:
        key = (entity.type, entity.value)
        existing = positions.get(key)
        if existing is None:
            positions[key] = len(ordered)
            ordered.append(entity)
            continue
        first = ordered[existing]
        if first.display_name is None and entity.display_name is not None:
            ordered[existing] = first.model_copy(
                update={"display_name": entity.display_name}
            )
    return tuple(ordered)


def assertion_order_key(
    assertion: RelationshipAssertion,
) -> tuple[EntityType, str, RelationshipType, EntityType, str]:
    """Return the deterministic ordering key of one relationship assertion."""
    return (
        assertion.source.type,
        assertion.source.value,
        assertion.type,
        assertion.target.type,
        assertion.target.value,
    )


def deduplicate_assertions(
    assertions: Iterable[RelationshipAssertion],
) -> tuple[RelationshipAssertion, ...]:
    """Collapse duplicate relationship assertions deterministically.

    The key is ``(source type, source value, relationship type, target
    type, target value, evidence id)``. First-seen source order is
    preserved; duplicate semantic output within one Evidence is emitted once.
    """
    seen: set[tuple[EntityType, str, RelationshipType, EntityType, str, UUID]] = set()
    ordered: list[RelationshipAssertion] = []
    for assertion in assertions:
        key = (*assertion_order_key(assertion), assertion.evidence_id)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(assertion)
    return tuple(ordered)
