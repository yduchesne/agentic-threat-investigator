# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic URLhaus entity extraction.

Implements the documented URLhaus extraction matrix on normalized
``THREAT_INTELLIGENCE`` evidence facts. For each ``facts.matches[]`` entry:

- ``matches[].url`` canonicalizes to and discovers a canonical URL entity;
- direct URL records carry a non-null ``matches[].host`` that is classified
  as an IP address first or, failing that, strictly validated as a DOMAIN,
  and discovered;
- host-response nested records carry ``host=null``; the record-level host is
  never synthesized from the ``queried_host`` envelope fact.

No URL-to-host relationship is emitted: no existing ``RelationshipType``
semantic is repurposed for URL composition. Payload hashes, filenames, file
types, sizes, signatures, tags, statuses, threat labels, and timestamps
remain fact-only; no MALWARE entity is ever inferred from URLhaus data.
"""

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from agentic_threat_investigator.app.extraction.models import (
    EntityIdentity,
    EvidenceExtractionError,
    ExtractedEntity,
    ExtractionResult,
    deduplicate_entities,
    malformed_facts,
    validate_extractor_input,
)
from agentic_threat_investigator.domain.entities import (
    EntityType,
    canonicalize,
    canonicalize_ip_address,
    canonicalize_url,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId


def extract_urlhaus(evidence: Evidence) -> ExtractionResult:
    """Extract the documented URLhaus identities from one Evidence."""
    evidence_id = validate_extractor_input(
        evidence,
        source=SourceId.URLHAUS.value,
        evidence_type=EvidenceType.THREAT_INTELLIGENCE,
        subject_types=(EntityType.URL, EntityType.DOMAIN, EntityType.IP_ADDRESS),
    )
    _validate_subject(evidence, evidence_id)
    matches = evidence.facts.get("matches")
    if not isinstance(matches, (list, tuple)) or not matches:
        raise _malformed(evidence_id, "URLhaus evidence must carry validated matches")

    entities: list[ExtractedEntity] = []
    for match in matches:
        _extract_match(match, evidence_id, entities)
    return ExtractionResult(entities=deduplicate_entities(entities))


def _malformed(evidence_id: UUID, message: str) -> EvidenceExtractionError:
    """Build the URLhaus extraction error with the bounded safe context."""
    return malformed_facts(SourceId.URLHAUS.value, message, evidence_id=evidence_id)


def _validate_subject(evidence: Evidence, evidence_id: UUID) -> None:
    """Require the canonical Evidence subject promised by the provider."""
    try:
        canonical = canonicalize(evidence.subject.type, evidence.subject.value)
    except ValueError as exc:
        raise _malformed(evidence_id, "URLhaus subject is malformed") from exc
    if canonical != evidence.subject.value:
        raise _malformed(evidence_id, "URLhaus subject is not in canonical form")


def _extract_match(
    match: Any,
    evidence_id: UUID,
    entities: list[ExtractedEntity],
) -> None:
    """Process one normalized match record in source order."""
    if not isinstance(match, Mapping):
        raise _malformed(evidence_id, "URLhaus match must be an object")
    url = match.get("url")
    host = match.get("host")
    if not isinstance(url, str):
        raise _malformed(evidence_id, "URLhaus match carries an invalid url member")
    if host is not None and not isinstance(host, str):
        raise _malformed(evidence_id, "URLhaus match carries an invalid host member")

    canonical_url = _canonical_url(url, evidence_id)
    entities.append(ExtractedEntity(type=EntityType.URL, value=canonical_url))
    if host is not None:
        identity = _classified_host(host, evidence_id)
        entities.append(ExtractedEntity(type=identity.type, value=identity.value))


def _canonical_url(value: str, evidence_id: UUID) -> str:
    """Return the canonical URL identity of an already-canonical URL fact."""
    try:
        canonical = canonicalize_url(value)
    except ValueError as exc:
        raise _malformed(evidence_id, "URLhaus URL fact is malformed") from exc
    if canonical != value:
        raise _malformed(evidence_id, "URLhaus URL fact is not in canonical form")
    return canonical


def _classified_host(value: str, evidence_id: UUID) -> EntityIdentity:
    """Classify a record host as an IP address first, then a strict DNS name.

    Normalized host facts promise canonical DOMAIN/IP identities, so a value
    that canonicalizes differently is a contract failure, not a silent repair.
    """
    try:
        canonical = canonicalize_ip_address(value)
    except ValueError:
        pass
    else:
        if canonical != value:
            raise _malformed(evidence_id, "URLhaus host fact is not in canonical form")
        return EntityIdentity(type=EntityType.IP_ADDRESS, value=canonical)
    try:
        canonical = validate_dns_name(value)
    except (ValueError, UnicodeError) as exc:
        raise _malformed(evidence_id, "URLhaus host fact is malformed") from exc
    if canonical != value:
        raise _malformed(evidence_id, "URLhaus host fact is not in canonical form")
    return EntityIdentity(type=EntityType.DOMAIN, value=canonical)
