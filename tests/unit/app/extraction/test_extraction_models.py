# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for immutable extraction output and the error contract."""

from uuid import UUID

import pydantic
import pytest

from agentic_threat_investigator.app.extraction.models import (
    EntityIdentity,
    EvidenceExtractionError,
    ExtractedEntity,
    ExtractionErrorReason,
    ExtractionResult,
    RelationshipAssertion,
    deduplicate_assertions,
    deduplicate_entities,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import RelationshipType

EVIDENCE_ID = UUID("33333333-3333-4333-8333-333333333333")


def _assertion(suffix: str) -> RelationshipAssertion:
    """Build one assertion with a distinct target value."""
    return RelationshipAssertion(
        source=EntityIdentity(type=EntityType.DOMAIN, value="example.test"),
        type=RelationshipType.RESOLVES_TO,
        target=EntityIdentity(type=EntityType.IP_ADDRESS, value=suffix),
        evidence_id=EVIDENCE_ID,
    )


def test_extracted_entity_is_frozen() -> None:
    """Extracted entities reject mutation."""
    entity = ExtractedEntity(type=EntityType.DOMAIN, value="example.test")

    with pytest.raises(pydantic.ValidationError):
        entity.value = "other.test"


def test_entity_identity_is_frozen() -> None:
    """Entity identities reject mutation."""
    identity = EntityIdentity(type=EntityType.DOMAIN, value="example.test")

    with pytest.raises(pydantic.ValidationError):
        identity.value = "other.test"


def test_relationship_assertion_is_frozen() -> None:
    """Assertions reject mutation."""
    assertion = _assertion("203.0.113.42")

    with pytest.raises(pydantic.ValidationError):
        assertion.evidence_id = None  # type: ignore[assignment]


def test_extraction_result_is_frozen_and_defaults_to_empty() -> None:
    """Results are immutable and default to no output."""
    result = ExtractionResult()

    assert not result.entities
    assert not result.relationships
    with pytest.raises(pydantic.ValidationError):
        result.entities = ()


def test_deduplicate_entities_collapses_identity_preserving_first_order() -> None:
    """Duplicate canonical identities collapse to the first occurrence."""
    first = ExtractedEntity(type=EntityType.DOMAIN, value="example.test")
    duplicate = ExtractedEntity(type=EntityType.DOMAIN, value="example.test")
    other = ExtractedEntity(type=EntityType.IP_ADDRESS, value="203.0.113.42")

    result = deduplicate_entities([first, duplicate, other, first])

    assert result == (first, other)


def test_deduplicate_entities_first_non_null_display_name_wins() -> None:
    """The first non-null display name is retained without merging anything else."""
    anonymous = ExtractedEntity(type=EntityType.MALWARE, value="win.asyncrat")
    named = ExtractedEntity(
        type=EntityType.MALWARE, value="win.asyncrat", display_name="AsyncRAT"
    )
    renamed = ExtractedEntity(
        type=EntityType.MALWARE, value="win.asyncrat", display_name="Other"
    )

    result = deduplicate_entities([anonymous, named, renamed])

    assert result == (named,)


def test_deduplicate_assertions_collapses_semantic_duplicates() -> None:
    """Identical assertions within one Evidence collapse to one."""
    first = _assertion("203.0.113.42")
    duplicate = _assertion("203.0.113.42")
    other = _assertion("203.0.113.43")

    result = deduplicate_assertions([first, duplicate, other, duplicate])

    assert result == (first, other)


def test_deduplicate_assertions_keeps_distinct_evidence_provenance() -> None:
    """The same semantic edge for a different Evidence stays distinct."""
    first = _assertion("203.0.113.42")
    other_evidence = first.model_copy(
        update={"evidence_id": UUID("44444444-4444-4444-8444-444444444444")}
    )

    result = deduplicate_assertions([first, other_evidence])

    assert result == (first, other_evidence)


def test_extraction_error_carries_only_safe_context() -> None:
    """The error exposes source, reason, Evidence ID, and a static message."""
    error = EvidenceExtractionError(
        "urn:ati:source:threatfox",
        ExtractionErrorReason.MALFORMED_FACTS,
        "malformed match facts",
        evidence_id=EVIDENCE_ID,
    )

    assert error.source == "urn:ati:source:threatfox"
    assert error.reason is ExtractionErrorReason.MALFORMED_FACTS
    assert str(error) == "malformed match facts"
    assert error.evidence_id == EVIDENCE_ID


def test_extraction_error_evidence_id_is_optional() -> None:
    """The Evidence ID may be unknown when the contract fails before it."""
    error = EvidenceExtractionError(
        "urn:ati:source:rdap",
        ExtractionErrorReason.MISSING_EVIDENCE_ID,
        "extraction requires a persisted Evidence identifier",
    )

    assert error.evidence_id is None
    assert error.reason is ExtractionErrorReason.MISSING_EVIDENCE_ID
