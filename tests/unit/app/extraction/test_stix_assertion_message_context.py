# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33D durable message reconstruction tests (M33D-M01..M13).

Pins the consumer-side message-context seam over PR 33D source-assertion
Evidence: a Relationship assertion derives its transient invocation Entity
from the durable **source endpoint**; a Sighting assertion derives it from
``sighting_of``; contradictory shared shapes (assertion plus ``cti_entity``
or nonempty ``iocs``), unknown kinds, missing/mismatched relationship or
sighting bodies, and tampered endpoint canonicality all fail closed with
:class:`MalformedMessageExtractionError` without echoing source content;
and the legacy IOC and CTI-SDO invocation paths remain unchanged.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.datasource_semantics import (
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_conversion import (
    EvidenceConversionContext,
)
from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    converted_evidence_from_message,
    evidence_message_from_converted,
)
from agentic_threat_investigator.app.extraction.message_context import (
    MalformedMessageExtractionError,
    extraction_view_from_message,
)
from agentic_threat_investigator.domain.datasource import DatasourceId
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.stix21_evidence import (
    Stix21ToEvidenceConverter,
)
from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
    parse_stix21_object,
)
from tests.support import stix21_fixtures as fixtures

pytestmark = pytest.mark.unit

_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_SOURCE_REFERENCE = "https://taxii.example.test/collections/1/objects/"

_CONVERTER = Stix21ToEvidenceConverter()


def _semantic_context(source_id: SourceId = SourceId.CISA_KEV) -> SemanticSourceContext:
    """Build one deterministic STIX semantic provenance context."""
    return SemanticSourceContext(
        datasource_id=DatasourceId("stix-future"),
        source_id=source_id,
        semantic_format=SemanticFormatId.STIX_21,
        retrieved_at=_FIXED_TS,
        source_reference=_SOURCE_REFERENCE,
    )


def _convert_and_message(
    decoded: dict[str, Any],
    *,
    source_id: SourceId = SourceId.CISA_KEV,
    sequence: int = 0,
) -> tuple[EvidenceMessage, ConvertedEvidence]:
    """Convert one object and build its V1 message through production code."""
    context = EvidenceConversionContext(semantic_source=_semantic_context(source_id))
    converted = _CONVERTER.convert(parse_stix21_object(decoded), context)[0]
    message = evidence_message_from_converted(
        converted,
        datasource_execution_id=uuid4(),
        semantic_source=context.semantic_source,
        sequence=sequence,
    )
    return message, converted


def _tampered_message(
    facts: dict[str, Any],
    *,
    source_record_id: str,
    source_id: SourceId = SourceId.CISA_KEV,
) -> tuple[EvidenceMessage, ConvertedEvidence]:
    """Build a V1 message carrying the given (tampered) durable facts.

    The deterministic global Evidence identity is recomputed from the exact
    source-record identity exactly as the real converter would; only the
    material facts are authored by the test.
    """
    evidence_id = evidence_id_for_source_record(
        SemanticFormatId.STIX_21, source_id, source_record_id
    )
    evidence = Evidence(
        id=evidence_id,
        type=EvidenceType.THREAT_INTELLIGENCE,
        source=source_id.value,
        source_record_id=source_record_id,
    )
    converted = ConvertedEvidence(
        evidence=evidence,
        observation=EvidenceObservationCandidate(
            evidence_id=evidence_id,
            source_url=_SOURCE_REFERENCE,
            observed_at=None,
            retrieved_at=_FIXED_TS,
            facts=facts,
            raw_payload=None,
        ),
    )
    message = evidence_message_from_converted(
        converted,
        datasource_execution_id=uuid4(),
        semantic_source=_semantic_context(source_id),
        sequence=0,
    )
    return message, converted


def _endpoint(entity_type: str, value: str) -> dict[str, str]:
    """Return one normalized endpoint fact."""
    return {"type": entity_type, "value": value}


def _relationship_facts(**overrides: Any) -> dict[str, Any]:
    """Return durable Relationship assertion facts with test overrides."""
    facts: dict[str, Any] = {
        "stix": {"id": fixtures.RELATIONSHIP_ID, "type": "relationship"},
        "indicator": None,
        "iocs": [],
        "cti_entity": None,
        "source_assertion": {
            "kind": "relationship",
            "relationship": {
                "type": "uses",
                "ati_type": "urn:ati:relationship:threat:uses",
                "source": _endpoint("threat_actor", fixtures.THREAT_ACTOR_ID),
                "target": _endpoint("tool", fixtures.TOOL_ID),
                "start_time": None,
                "stop_time": None,
            },
            "sighting": None,
        },
    }
    facts.update(overrides)
    return facts


def _sighting_facts(**overrides: Any) -> dict[str, Any]:
    """Return durable Sighting assertion facts with test overrides."""
    facts: dict[str, Any] = {
        "stix": {"id": fixtures.SIGHTING_ID, "type": "sighting"},
        "indicator": None,
        "iocs": [],
        "cti_entity": None,
        "source_assertion": {
            "kind": "sighting",
            "relationship": None,
            "sighting": {
                "sighting_of": _endpoint("threat_actor", fixtures.THREAT_ACTOR_ID),
                "first_seen": None,
                "last_seen": None,
                "count": None,
                "summary": None,
                "where_sighted_refs": [],
                "observed_data_refs": [],
            },
        },
    }
    facts.update(overrides)
    return facts


def _invocation(message: EvidenceMessage) -> Entity:
    """Derive the invocation Entity through the real production seam."""
    converted = converted_evidence_from_message(message)
    return extraction_view_from_message(message, converted).invocation_entity


class TestAssertionInvocation:
    """M33D-M01..M02: safe transient invocation identities."""

    def test_m33d_m01_relationship_invocation_is_source_endpoint(self) -> None:
        """M33D-M01: a Relationship derives its invocation from the source endpoint."""
        message, _ = _convert_and_message(
            fixtures.stix_relationship(
                relationship_type="uses",
                source_ref=fixtures.THREAT_ACTOR_ID,
                target_ref=fixtures.TOOL_ID,
            )
        )
        invocation = _invocation(message)
        assert invocation.type is EntityType.THREAT_ACTOR
        assert invocation.value == fixtures.THREAT_ACTOR_ID

    def test_m33d_m02_sighting_invocation_is_sighting_of(self) -> None:
        """M33D-M02: a Sighting derives its invocation from sighting_of."""
        message, _ = _convert_and_message(
            fixtures.stix_sighting(sighting_of_ref=fixtures.CAMPAIGN_ID)
        )
        invocation = _invocation(message)
        assert invocation.type is EntityType.CAMPAIGN
        assert invocation.value == fixtures.CAMPAIGN_ID


class TestMalformedAssertions:
    """M33D-M03..M11: mutually exclusive durable shapes fail closed."""

    def test_m33d_m03_relationship_with_cti_entity_malformed(self) -> None:
        """M33D-M03: an assertion plus cti_entity is malformed."""
        facts = _relationship_facts(
            cti_entity={
                "type": "threat_actor",
                "value": fixtures.THREAT_ACTOR_ID,
                "display_name": "x",
            }
        )
        message, _ = _tampered_message(facts, source_record_id=fixtures.RELATIONSHIP_ID)
        with pytest.raises(MalformedMessageExtractionError):
            _invocation(message)

    def test_m33d_m04_relationship_with_nonempty_iocs_malformed(self) -> None:
        """M33D-M04: an assertion plus nonempty iocs is malformed."""
        facts = _relationship_facts(iocs=[{"type": "domain", "value": "example.test"}])
        message, _ = _tampered_message(facts, source_record_id=fixtures.RELATIONSHIP_ID)
        with pytest.raises(MalformedMessageExtractionError):
            _invocation(message)

    def test_m33d_m05_sighting_with_cti_entity_malformed(self) -> None:
        """M33D-M05: a Sighting assertion plus cti_entity is malformed."""
        facts = _sighting_facts(
            cti_entity={
                "type": "campaign",
                "value": fixtures.CAMPAIGN_ID,
                "display_name": "x",
            }
        )
        message, _ = _tampered_message(facts, source_record_id=fixtures.SIGHTING_ID)
        with pytest.raises(MalformedMessageExtractionError):
            _invocation(message)

    def test_m33d_m06_unknown_assertion_kind_malformed(self) -> None:
        """M33D-M06: an unknown assertion kind is malformed."""
        facts = _relationship_facts()
        facts["source_assertion"] = {
            "kind": "mystery",
            "relationship": None,
            "sighting": None,
        }
        message, _ = _tampered_message(facts, source_record_id=fixtures.RELATIONSHIP_ID)
        with pytest.raises(MalformedMessageExtractionError):
            _invocation(message)

    def test_m33d_m07_relationship_body_missing_malformed(self) -> None:
        """M33D-M07: a relationship kind with no body is malformed."""
        facts = _relationship_facts()
        facts["source_assertion"]["relationship"] = None
        message, _ = _tampered_message(facts, source_record_id=fixtures.RELATIONSHIP_ID)
        with pytest.raises(MalformedMessageExtractionError):
            _invocation(message)

    def test_m33d_m08_sighting_body_missing_malformed(self) -> None:
        """M33D-M08: a sighting kind with no body is malformed."""
        facts = _sighting_facts()
        facts["source_assertion"]["sighting"] = None
        message, _ = _tampered_message(facts, source_record_id=fixtures.SIGHTING_ID)
        with pytest.raises(MalformedMessageExtractionError):
            _invocation(message)

    def test_m33d_m09_mismatched_bodies_malformed(self) -> None:
        """M33D-M09: a relationship kind carrying a sighting body is malformed."""
        facts = _relationship_facts()
        facts["source_assertion"]["sighting"] = {
            "sighting_of": _endpoint("threat_actor", fixtures.THREAT_ACTOR_ID),
            "first_seen": None,
            "last_seen": None,
            "count": None,
            "summary": None,
            "where_sighted_refs": [],
            "observed_data_refs": [],
        }
        message, _ = _tampered_message(facts, source_record_id=fixtures.RELATIONSHIP_ID)
        with pytest.raises(MalformedMessageExtractionError):
            _invocation(message)

    def test_m33d_m10_tampered_endpoint_canonicality_malformed(self) -> None:
        """M33D-M10: a non-canonical durable endpoint fact is malformed."""
        facts = _relationship_facts()
        facts["source_assertion"]["relationship"]["source"]["value"] = (
            fixtures.THREAT_ACTOR_ID.upper()
        )
        message, _ = _tampered_message(facts, source_record_id=fixtures.RELATIONSHIP_ID)
        with pytest.raises(MalformedMessageExtractionError):
            _invocation(message)

    def test_m33d_m11_errors_never_echo_source_content(self) -> None:
        """M33D-M11: malformed-message errors never echo durable fact content."""
        secret = "secret-entity-value"
        facts = _relationship_facts()
        facts["source_assertion"]["relationship"]["source"]["type"] = "mystery_type"
        facts["source_assertion"]["relationship"]["source"]["value"] = secret
        message, _ = _tampered_message(facts, source_record_id=fixtures.RELATIONSHIP_ID)
        with pytest.raises(MalformedMessageExtractionError) as error:
            _invocation(message)
        assert secret not in str(error.value)
        assert fixtures.RELATIONSHIP_ID not in str(error.value)

    def test_m33d_m11b_unknown_endpoint_wire_type_malformed(self) -> None:
        """M33D-M11b: an unknown endpoint wire type fails closed."""
        facts = _relationship_facts()
        facts["source_assertion"]["relationship"]["source"]["type"] = "malware"
        message, _ = _tampered_message(facts, source_record_id=fixtures.RELATIONSHIP_ID)
        with pytest.raises(MalformedMessageExtractionError):
            _invocation(message)


class TestLegacyPathsUnchanged:
    """M33D-M12..M13: the pre-33D STIX reconstruction paths are unchanged."""

    def test_m33d_m12_old_ioc_path_unchanged(self) -> None:
        """M33D-M12: the first-IOC invocation path is unchanged."""
        message, _ = _convert_and_message(
            fixtures.stix_indicator(
                pattern=(
                    "[domain-name:value = 'a.test' OR ipv4-addr:value = '203.0.113.42']"
                )
            )
        )
        invocation = _invocation(message)
        assert invocation.type is EntityType.DOMAIN
        assert invocation.value == "a.test"

    def test_m33d_m13_old_cti_sdo_path_unchanged(self) -> None:
        """M33D-M13: the cti_entity invocation path is unchanged."""
        message, _ = _convert_and_message(fixtures.stix_threat_actor())
        invocation = _invocation(message)
        assert invocation.type is EntityType.THREAT_ACTOR
        assert invocation.value == fixtures.THREAT_ACTOR_ID

    def test_m13b_message_fact_key_never_conditionally_absent(self) -> None:
        """M33D-M13b: even tampered IOC/CTI messages carry the assertion key."""
        message, _ = _convert_and_message(fixtures.stix_threat_actor())
        assert "source_assertion" in message.facts
