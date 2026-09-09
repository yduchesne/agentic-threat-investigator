# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic ThreatFox IOC-to-malware extraction.

Implements the documented ThreatFox extraction matrix on normalized
``THREAT_INTELLIGENCE`` evidence facts. For every ``facts.matches[]`` entry,
the Evidence subject IOC is asserted ``ASSOCIATED_WITH`` the canonical
``MALWARE`` entity derived from the machine malware identifier:

    Evidence subject IOC ASSOCIATED_WITH MALWARE(matches[].malware)

The machine identifier is the identity; ``malware_printable`` is display
metadata only and never determines identity. Confidence levels, threat
types, tags, references, and timestamps are ignored for graph semantics.
Repeated same-malware matches within one Evidence deduplicate to one entity
and one assertion while first-seen source order is preserved.
"""

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from agentic_threat_investigator.app.extraction.models import (
    EntityIdentity,
    EvidenceExtractionError,
    ExtractedEntity,
    ExtractionResult,
    RelationshipAssertion,
    deduplicate_assertions,
    deduplicate_entities,
    malformed_facts,
    validate_extractor_input,
)
from agentic_threat_investigator.domain.entities import EntityType, canonicalize
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.relationships import RelationshipType

_PRINTABLE_MAX_LENGTH = 256
"""Bounded printable-name length promised by the normalized fact contract."""


def extract_threatfox(evidence: Evidence) -> ExtractionResult:
    """Extract the documented ThreatFox identities and assertions from one Evidence."""
    evidence_id = validate_extractor_input(
        evidence,
        source=SourceId.THREATFOX.value,
        evidence_type=EvidenceType.THREAT_INTELLIGENCE,
        subject_types=(EntityType.DOMAIN, EntityType.IP_ADDRESS),
    )
    subject = _subject_identity(evidence, evidence_id)
    matches = evidence.facts.get("matches")
    if not isinstance(matches, (list, tuple)) or not matches:
        raise _malformed(evidence_id, "ThreatFox evidence must carry validated matches")

    entities: list[ExtractedEntity] = []
    relationships: list[RelationshipAssertion] = []
    for match in matches:
        _extract_match(match, subject, evidence_id, entities, relationships)
    return ExtractionResult(
        entities=deduplicate_entities(entities),
        relationships=deduplicate_assertions(relationships),
    )


def _malformed(evidence_id: UUID, message: str) -> EvidenceExtractionError:
    """Build the ThreatFox extraction error with the bounded safe context."""
    return malformed_facts(SourceId.THREATFOX.value, message, evidence_id=evidence_id)


def _subject_identity(evidence: Evidence, evidence_id: UUID) -> EntityIdentity:
    """Return the canonical identity of the queried IOC subject.

    Normalized subjects promise canonical values, so a subject that
    canonicalizes differently is a contract failure, not a silent repair.
    """
    try:
        canonical = canonicalize(evidence.subject.type, evidence.subject.value)
    except ValueError as exc:
        raise _malformed(evidence_id, "ThreatFox subject is malformed") from exc
    if canonical != evidence.subject.value:
        raise _malformed(evidence_id, "ThreatFox subject is not in canonical form")
    return EntityIdentity(type=evidence.subject.type, value=canonical)


def _extract_match(
    match: Any,
    subject: EntityIdentity,
    evidence_id: UUID,
    entities: list[ExtractedEntity],
    relationships: list[RelationshipAssertion],
) -> None:
    """Process one normalized match record in source order."""
    if not isinstance(match, Mapping):
        raise _malformed(evidence_id, "ThreatFox match must be an object")
    malware = match.get("malware")
    if not isinstance(malware, str):
        raise _malformed(
            evidence_id, "ThreatFox match carries an invalid malware identifier"
        )
    try:
        canonical_malware = canonicalize(EntityType.MALWARE, malware)
    except ValueError as exc:
        raise _malformed(
            evidence_id, "ThreatFox match carries a malformed malware identifier"
        ) from exc
    display_name = _validated_printable_name(
        match.get("malware_printable"), evidence_id
    )

    malware_entity = ExtractedEntity(
        type=EntityType.MALWARE,
        value=canonical_malware,
        display_name=display_name,
    )
    entities.append(malware_entity)
    relationships.append(
        RelationshipAssertion(
            source=subject,
            type=RelationshipType.ASSOCIATED_WITH,
            target=EntityIdentity(type=EntityType.MALWARE, value=canonical_malware),
            evidence_id=evidence_id,
        )
    )


def _validated_printable_name(value: Any, evidence_id: UUID) -> str | None:
    """Return the validated optional printable name; it never determines identity."""
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > _PRINTABLE_MAX_LENGTH
    ):
        raise _malformed(
            evidence_id, "ThreatFox match carries an invalid printable name"
        )
    return value
