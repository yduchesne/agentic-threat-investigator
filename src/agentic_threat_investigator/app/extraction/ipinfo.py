# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Conservative IPinfo Lite extraction.

Implements the documented IPinfo Lite extraction matrix. The source
envelope is validated first: the Evidence subject must be a canonical IP
address, before any ASN-presence decision. When the normalized ``facts.asn``
member is present, it is canonicalized and discovered as a canonical
``ASN`` entity. When the member is absent, extraction yields an empty
result. No relationship is emitted and no ORGANIZATION entity is ever
derived from ``as_name``/``as_domain``: the announced-by semantic is not
authorized for IPinfo evidence in v0.1. Country/continent members remain
contextual facts.
"""

from uuid import UUID

from agentic_threat_investigator.app.extraction.models import (
    EvidenceExtractionError,
    ExtractedEntity,
    ExtractionResult,
    malformed_facts,
    validate_extractor_input,
)
from agentic_threat_investigator.domain.entities import (
    EntityType,
    canonicalize_asn,
    canonicalize_ip_address,
)
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId


def extract_ipinfo(evidence: Evidence) -> ExtractionResult:
    """Extract the documented IPinfo Lite output from one Evidence."""
    evidence_id = validate_extractor_input(
        evidence,
        source=SourceId.IPINFO_LITE.value,
        evidence_type=EvidenceType.NETWORK,
        subject_types=(EntityType.IP_ADDRESS,),
    )
    _validate_canonical_subject(evidence, evidence_id)
    asn = evidence.facts.get("asn")
    if asn is None:
        return ExtractionResult()
    if not isinstance(asn, str):
        raise _malformed(evidence_id, "IPinfo ASN fact is malformed")
    try:
        canonical = canonicalize_asn(asn)
    except ValueError as exc:
        raise _malformed(evidence_id, "IPinfo ASN fact is malformed") from exc
    if canonical != asn:
        raise _malformed(evidence_id, "IPinfo ASN fact is not in canonical form")
    return ExtractionResult(
        entities=(ExtractedEntity(type=EntityType.ASN, value=canonical),)
    )


def _validate_canonical_subject(evidence: Evidence, evidence_id: UUID) -> None:
    """Require a canonical IP subject before any ASN-presence decision."""
    try:
        canonical = canonicalize_ip_address(evidence.subject.value)
    except ValueError as exc:
        raise _malformed(evidence_id, "IPinfo subject address is malformed") from exc
    if canonical != evidence.subject.value:
        raise _malformed(evidence_id, "IPinfo subject address is not in canonical form")


def _malformed(evidence_id: UUID, message: str) -> EvidenceExtractionError:
    """Build the IPinfo extraction error with the bounded safe context."""
    return malformed_facts(SourceId.IPINFO_LITE.value, message, evidence_id=evidence_id)
