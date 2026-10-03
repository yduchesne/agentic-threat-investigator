# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 32D MISP durable-message extraction tests (M32D-X01..X18).

Covers the consumer-side reconstruction of MISP extraction solely from the
durable normalized ``facts.iocs`` contract: canonical DOMAIN/IP_ADDRESS
invocation Entities, the ``domain|ip`` two-Entity observation association
with zero invented relationships, strict fail-closed malformed handling,
the exact ``(semantic format, source)`` dispatch pairs, and the unchanged
ThreatFox regression path. All message fixtures go through the public
PR 28C builder so identity recomputation is exercised by the same
production code the consumer uses.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from agentic_threat_investigator.app.evidence_message import (
    EvidenceMessage,
    converted_evidence_from_message,
    evidence_message_id,
    evidence_observation_candidate_id,
)
from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.extraction.message_context import (
    MalformedMessageExtractionError,
    UnsupportedMessageExtractionError,
    extraction_view_from_message,
)
from agentic_threat_investigator.app.extraction.models import (
    EvidenceExtractionView,
    ExtractionErrorReason,
)
from agentic_threat_investigator.domain.datasource import DatasourceId
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.relationships import RelationshipType
from tests.support.evidence_batch_fixtures import (
    build_misp_ioc_fact,
    misp_message,
    threatfox_message,
)

pytestmark = pytest.mark.unit

_RECORD = "21e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b02"
_DOMAIN = "malicious-domain.test"
_IPV4 = "203.0.113.42"
_IPV6 = "2001:db8::42"
_RETRIEVED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)
_EXECUTION_ID = UUID("44444444-5555-6666-7777-888888888888")


def _view_for(message: EvidenceMessage) -> EvidenceExtractionView:
    """Build the extraction view of one message through production code."""
    converted = converted_evidence_from_message(message)
    return extraction_view_from_message(message, converted)


def _misp(
    *,
    iocs: tuple[dict[str, str], ...],
    facts: dict[str, object] | None = None,
) -> EvidenceMessage:
    """Build one MISP message with the given durable iocs."""
    message, _ = misp_message(
        source_record_id=_RECORD,
        iocs=iocs,
        facts=facts,
    )
    return message


class TestMispInvocationReconstruction:
    """M32D-X01..X05: canonical invocation Entities from durable iocs."""

    def test_x01_domain_invocation(self) -> None:
        """X01: ``domain`` IOC yields the canonical DOMAIN invocation."""
        message = _misp(iocs=(build_misp_ioc_fact(type="domain", value=_DOMAIN),))
        view = _view_for(message)
        assert view.invocation_entity.type is EntityType.DOMAIN
        assert view.invocation_entity.value == _DOMAIN

    def test_x02_hostname_produced_facts_are_domain(self) -> None:
        """X02: a MISP hostname Attribute produces a durable ``domain`` IOC."""
        message = _misp(iocs=(build_misp_ioc_fact(type="domain", value=_DOMAIN),))
        view = _view_for(message)
        assert view.invocation_entity.type is EntityType.DOMAIN

    def test_x03_ipv4_invocation(self) -> None:
        """X03: an IPv4 ``ip_address`` IOC yields the canonical IP invocation."""
        message = _misp(iocs=(build_misp_ioc_fact(type="ip_address", value=_IPV4),))
        view = _view_for(message)
        assert view.invocation_entity.type is EntityType.IP_ADDRESS
        assert view.invocation_entity.value == _IPV4

    def test_x04_ipv6_invocation(self) -> None:
        """X04: an IPv6 ``ip_address`` IOC yields the canonical IP invocation."""
        message = _misp(iocs=(build_misp_ioc_fact(type="ip_address", value=_IPV6),))
        view = _view_for(message)
        assert view.invocation_entity.type is EntityType.IP_ADDRESS
        assert view.invocation_entity.value == _IPV6

    def test_x05_domain_plus_ip_two_entities_no_relationship(self) -> None:
        """X05: domain+IP preserves both entities and never a relationship."""
        message = _misp(
            iocs=(
                build_misp_ioc_fact(type="domain", value=_DOMAIN),
                build_misp_ioc_fact(type="ip_address", value=_IPV4),
            )
        )
        view = _view_for(message)
        assert view.invocation_entity.type is EntityType.DOMAIN
        assert view.invocation_entity.value == _DOMAIN
        extraction = extract(view)
        assert extraction.relationships == ()
        identities = {(entity.type, entity.value) for entity in extraction.entities}
        assert identities == {(EntityType.IP_ADDRESS, _IPV4)}


class TestMispMalformedFacts:
    """M32D-X06..X15: fail-closed malformed durable facts."""

    def test_x06_missing_iocs_fails_closed(self) -> None:
        """X06: missing ``iocs`` is a typed malformed failure."""
        message = _misp(iocs=(), facts={})
        with pytest.raises(MalformedMessageExtractionError) as excinfo:
            _view_for(message)
        assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_x07_empty_iocs_fails_closed(self) -> None:
        """X07: an empty ``iocs`` array is a typed malformed failure."""
        message = _misp(iocs=(), facts={"iocs": []})
        with pytest.raises(MalformedMessageExtractionError):
            _view_for(message)

    def test_x08_non_array_iocs_fails_closed(self) -> None:
        """X08: a non-array ``iocs`` value is a typed malformed failure."""
        message = _misp(iocs=(), facts={"iocs": "domain"})
        with pytest.raises(MalformedMessageExtractionError):
            _view_for(message)

    def test_x09_non_object_ioc_fails_closed(self) -> None:
        """X09: a non-object IOC entry is a typed malformed failure."""
        message = _misp(iocs=(), facts={"iocs": ["malicious-domain.test"]})
        with pytest.raises(MalformedMessageExtractionError):
            _view_for(message)

    def test_x10_unknown_ioc_type_fails_closed(self) -> None:
        """X10: an unknown IOC type fails closed, never guesses a graph."""
        message = _misp(iocs=(build_misp_ioc_fact(type="sha256", value="a" * 64),))
        with pytest.raises(MalformedMessageExtractionError):
            _view_for(message)

    def test_x11_malformed_domain_fails_closed(self) -> None:
        """X11: a malformed domain value fails closed."""
        message = _misp(
            iocs=(build_misp_ioc_fact(type="domain", value="not a domain"),)
        )
        with pytest.raises(MalformedMessageExtractionError):
            _view_for(message)

    def test_x12_noncanonical_domain_fails_closed(self) -> None:
        """X12: a non-canonical domain fails closed, never silently repairs."""
        message = _misp(
            iocs=(build_misp_ioc_fact(type="domain", value="Example.TEST."),)
        )
        with pytest.raises(MalformedMessageExtractionError):
            _view_for(message)

    def test_x13_malformed_ip_fails_closed(self) -> None:
        """X13: a malformed IP value fails closed."""
        message = _misp(
            iocs=(build_misp_ioc_fact(type="ip_address", value="203.0.113.999"),)
        )
        with pytest.raises(MalformedMessageExtractionError):
            _view_for(message)

    def test_x14_noncanonical_ip_fails_closed(self) -> None:
        """X14: a non-canonical IP value fails closed."""
        message = _misp(
            iocs=(
                build_misp_ioc_fact(
                    type="ip_address",
                    value="2001:0db8:0000:0000:0000:0000:0000:0042",
                ),
            )
        )
        with pytest.raises(MalformedMessageExtractionError):
            _view_for(message)

    def test_x15_duplicate_identity_fails_closed(self) -> None:
        """X15: repeated IOC identities fail closed (no deterministic dedupe)."""
        message = _misp(
            iocs=(
                build_misp_ioc_fact(type="domain", value=_DOMAIN),
                build_misp_ioc_fact(type="domain", value=_DOMAIN),
            )
        )
        with pytest.raises(MalformedMessageExtractionError):
            _view_for(message)


class TestMispDispatchPairs:
    """M32D-X16..X18: exact (semantic format, source) dispatch pairs."""

    def test_x16_misp_format_wrong_source_fails_closed(self) -> None:
        """X16: MISP format with a non-MISP source never dispatches."""
        message = _mismatched_message(
            semantic_format=SemanticFormatId.MISP,
            source_id=SourceId.THREATFOX,
        )
        with pytest.raises(UnsupportedMessageExtractionError):
            _view_for(message)

    def test_x17_misp_source_wrong_format_fails_closed(self) -> None:
        """X17: MISP source with a non-MISP format never dispatches."""
        message = _mismatched_message(
            semantic_format=SemanticFormatId.THREATFOX,
            source_id=SourceId.MISP,
        )
        with pytest.raises(UnsupportedMessageExtractionError):
            _view_for(message)

    def test_x18_threatfox_regression_unchanged(self) -> None:
        """X18: the ThreatFox reconstruction/extraction path is unchanged."""
        message, _ = threatfox_message(
            ioc=_DOMAIN,
            ioc_type="domain",
            source_record_id="rec-tf",
        )
        view = _view_for(message)
        assert view.invocation_entity.type is EntityType.DOMAIN
        extraction = extract(view)
        assert len(extraction.entities) == 1
        assert extraction.entities[0].type is EntityType.MALWARE
        assert len(extraction.relationships) == 1
        assert extraction.relationships[0].type is RelationshipType.ASSOCIATED_WITH


def _mismatched_message(
    *,
    semantic_format: SemanticFormatId,
    source_id: SourceId,
) -> EvidenceMessage:
    """Build one EvidenceMessage whose pair is deliberately mismatched.

    The message is structurally valid V1 wire content (all three identities
    recomputed for its own format/source/source-record triple); only the
    ``(semantic_format, source)`` pair is not an approved extraction pair.
    """
    evidence_id = evidence_id_for_source_record(semantic_format, source_id, _RECORD)
    message_id = evidence_message_id(
        evidence_id=evidence_id,
        datasource_execution_id=_EXECUTION_ID,
        sequence=0,
    )
    return EvidenceMessage(
        schema_version=1,
        message_id=message_id,
        observation_candidate_id=evidence_observation_candidate_id(message_id),
        datasource_execution_id=_EXECUTION_ID,
        datasource_id=DatasourceId("mismatched"),
        source_id=source_id,
        semantic_format=semantic_format,
        sequence=0,
        evidence_id=evidence_id,
        evidence_type=EvidenceType.THREAT_INTELLIGENCE,
        source_record_id=_RECORD,
        retrieved_at=_RETRIEVED_AT,
        source_url="https://misp.example.test/events/restSearch",
        facts={"iocs": [{"type": "domain", "value": "example.test"}]},
        raw_payload=None,
    )
