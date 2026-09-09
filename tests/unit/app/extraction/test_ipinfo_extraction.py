# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for conservative IPinfo Lite extraction."""

# The evidence-builder helpers in extraction test modules intentionally
# share the normalized Evidence construction shape (see the established
# provider fixture family); the duplication is test-only and accepted.
# pylint: disable=duplicate-code

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.extraction import (
    EvidenceExtractionError,
    ExtractionErrorReason,
    extract_ipinfo,
)
from agentic_threat_investigator.app.extraction.models import ExtractionResult
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.relationships import RelationshipType

SOURCE = SourceId.IPINFO_LITE.value


def ipinfo_evidence(
    facts: Mapping[str, Any], evidence_id: UUID | None = None
) -> Evidence:
    """Build one normalized IPinfo Lite NETWORK evidence observation."""
    return Evidence(
        id=evidence_id if evidence_id is not None else uuid4(),
        investigation_id=uuid4(),
        type=EvidenceType.NETWORK,
        subject=EntityRef(type=EntityType.IP_ADDRESS, value="203.0.113.42"),
        source=SOURCE,
        retrieved_at=datetime(2026, 1, 15, tzinfo=UTC),
        facts=dict(facts),
        raw_payload=None,
    )


def test_present_asn_is_discovered() -> None:
    """A present canonical ASN fact discovers the ASN entity."""
    result = extract_ipinfo(ipinfo_evidence({"ip": "203.0.113.42", "asn": "AS64496"}))

    assert len(result.entities) == 1
    assert result.entities[0].type is EntityType.ASN
    assert result.entities[0].value == "AS64496"


def test_absent_asn_yields_empty() -> None:
    """Source ASN absence is a documented source fact and yields an empty result."""
    result = extract_ipinfo(
        ipinfo_evidence({"ip": "203.0.113.42", "country_code": "US"})
    )

    assert result == ExtractionResult()


def test_no_relationship_or_organization_is_produced() -> None:
    """No ANNOUNCED_BY is emitted and as_name never becomes an ORGANIZATION."""
    result = extract_ipinfo(
        ipinfo_evidence(
            {
                "ip": "203.0.113.42",
                "asn": "AS64496",
                "as_name": "Some Network Operator",
                "as_domain": "operator.test",
            }
        )
    )

    assert not result.relationships
    assert all(entity.type is not EntityType.ORGANIZATION for entity in result.entities)
    assert all(
        edge.type is not RelationshipType.ANNOUNCED_BY for edge in result.relationships
    )


def test_malformed_asn_fails() -> None:
    """A non-string or non-canonical ASN fact is a contract failure."""
    for facts in ({"asn": 64496}, {"asn": "not-an-asn"}, {"asn": "as64496"}):
        with pytest.raises(EvidenceExtractionError) as excinfo:
            extract_ipinfo(ipinfo_evidence(facts))
        assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_missing_persisted_evidence_id_fails() -> None:
    """IPinfo extraction requires a persisted Evidence ID."""
    evidence = ipinfo_evidence({"ip": "203.0.113.42", "asn": "AS64496"})
    unpersisted = evidence.model_copy(update={"id": None})

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_ipinfo(unpersisted)

    assert excinfo.value.reason is ExtractionErrorReason.MISSING_EVIDENCE_ID
