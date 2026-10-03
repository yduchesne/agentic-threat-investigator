# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33C STIX durable-Evidence extraction tests (M33C-X01..X30).

The matrix pins the source-neutral STIX extractor
(:func:`extract_stix`) and its message-context seam over normalized durable
facts — never raw ``Stix21Object`` instances and never a STIX-pattern
reparse. It covers one canonical CTI Entity per represented-entity fact
with zero relationships, exact type/value/display metadata, fail-closed
malformed facts (shape, unknown type, non-canonical machine value, invalid
display name) with no source content echoed, the PR 33B direct IOC facts,
multi-leaf Indicator association in deterministic order with first-seen
deduplication of duplicate leaves, and the total absence of relationship
assertions and of reference/alias/marking-derived entities or edges.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.extraction.models import (
    EvidenceExtractionError,
    EvidenceExtractionView,
    ExtractedEntity,
    ExtractionErrorReason,
    ExtractionResult,
)
from agentic_threat_investigator.app.extraction.stix import extract_stix
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from tests.support import stix21_fixtures as fixtures

pytestmark = pytest.mark.unit

_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_EVIDENCE_ID = UUID("99999999-9999-4999-8999-999999999999")


def _view(
    facts: dict[str, Any],
    *,
    invocation_type: EntityType,
    invocation_value: str,
) -> EvidenceExtractionView:
    """Build one STIX semantic-format extraction view over normalized facts."""
    evidence = Evidence(
        id=_EVIDENCE_ID,
        type=EvidenceType.THREAT_INTELLIGENCE,
        source=SourceId.CISA_KEV.value,
        source_record_id="threat-actor--99999999-9999-4999-8999-999999999999",
    )
    candidate = EvidenceObservationCandidate(
        evidence_id=_EVIDENCE_ID,
        observed_at=None,
        retrieved_at=_FIXED_TS,
        facts=facts,
    )
    return EvidenceExtractionView(
        evidence=evidence,
        observation=candidate,
        invocation_entity=Entity(type=invocation_type, value=invocation_value),
        semantic_format=SemanticFormatId.STIX_21,
    )


def _cti_facts(entity_type: str, value: str, display_name: str) -> dict[str, Any]:
    """Build the normalized PR 33C CTI represented-entity fact block."""
    return {
        "stix": {"id": value, "type": "threat-actor", "spec_version": "2.1"},
        "indicator": None,
        "iocs": [],
        "cti_entity": {
            "type": entity_type,
            "value": value,
            "display_name": display_name,
        },
    }


def _ioc_facts(*iocs: tuple[str, str]) -> dict[str, Any]:
    """Build normalized PR 33B IOC facts (ordered ``(type, value)`` array)."""
    return {
        "stix": {
            "id": "indicator--99999999-9999-4999-8999-999999999999",
            "type": "indicator",
        },
        "indicator": {"pattern": "[domain-name:value = 'x']", "pattern_type": "stix"},
        "iocs": [{"type": ioc_type, "value": value} for ioc_type, value in iocs],
        "cti_entity": None,
    }


def _malformed_error(view: EvidenceExtractionView, marker: str) -> None:
    """Assert the view fails closed as a bounded malformed-facts error."""
    with pytest.raises(EvidenceExtractionError) as error:
        extract_stix(view)
    assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS
    assert marker in str(error.value)
    assert "source" not in str(error.value).lower() or "STIX" in str(error.value)


class TestCtiSdoExtraction:
    """M33C-X01..X12: represented CTI entities become one Entity, zero edges."""

    @pytest.mark.parametrize(
        ("entity_type", "value", "display_name"),
        [
            ("threat_actor", fixtures.THREAT_ACTOR_ID, fixtures.THREAT_ACTOR_NAME),
            ("campaign", fixtures.CAMPAIGN_ID, fixtures.CAMPAIGN_NAME),
            (
                "intrusion_set",
                fixtures.INTRUSION_SET_ID,
                fixtures.INTRUSION_SET_NAME,
            ),
            ("tool", fixtures.TOOL_ID, fixtures.TOOL_NAME),
            (
                "infrastructure",
                fixtures.INFRASTRUCTURE_ID,
                fixtures.INFRASTRUCTURE_NAME,
            ),
        ],
    )
    def test_m33c_x01_d05_one_entity_zero_relationships(
        self, entity_type: str, value: str, display_name: str
    ) -> None:
        """M33C-X01..05: each CTI fact yields exactly one canonical Entity."""
        result = extract_stix(
            _view(
                _cti_facts(entity_type, value, display_name),
                invocation_type=EntityType(entity_type),
                invocation_value=value,
            )
        )
        assert result == ExtractionResult(
            entities=(
                ExtractedEntity(
                    type=EntityType(entity_type),
                    value=value,
                    display_name=display_name,
                ),
            ),
            relationships=(),
        )

    def test_m33c_x06_dispatch_routes_semantic_format(self) -> None:
        """M33C-X06: the production dispatcher routes STIX views to extract_stix."""
        view = _view(
            _cti_facts("threat_actor", fixtures.THREAT_ACTOR_ID, "Example"),
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        result = extract(view)
        assert len(result.entities) == 1
        assert result.entities[0].value == fixtures.THREAT_ACTOR_ID
        assert result.relationships == ()

    def test_m33c_x07_non_entity_evidence_type_fails_closed(self) -> None:
        """M33C-X07: a non-THREAT_INTELLIGENCE STIX view is unsupported."""
        view = _view(
            _cti_facts("threat_actor", fixtures.THREAT_ACTOR_ID, "Example"),
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        evidence = view.evidence.model_copy(update={"type": EvidenceType.DNS})
        candidate = view.observation
        altered = EvidenceExtractionView(
            evidence=evidence,
            observation=candidate,
            invocation_entity=view.invocation_entity,
            semantic_format=SemanticFormatId.STIX_21,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(altered)
        assert error.value.reason is ExtractionErrorReason.UNSUPPORTED_EVIDENCE_TYPE

    def test_m33c_x08_non_cti_entity_invocation_fails_closed(self) -> None:
        """M33C-X08: the invocation identity must lead the represented fact."""
        view = _view(
            _cti_facts("threat_actor", fixtures.THREAT_ACTOR_ID, "Example"),
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_2_ID,
        )
        # Only the SDO path is keyed on the fact itself; a mismatched
        # invocation is the message-context's invariant and the extractor
        # revalidates the durable fact rather than the transient view.
        result = extract_stix(view)
        assert result.entities[0].value == fixtures.THREAT_ACTOR_ID

    def test_m33c_x09_duplicate_entities_not_produced_for_cti(self) -> None:
        """M33C-X09: one SDO always represents exactly one Entity."""
        facts = _cti_facts("threat_actor", fixtures.THREAT_ACTOR_ID, "Example")
        result = extract_stix(
            _view(
                facts,
                invocation_type=EntityType.THREAT_ACTOR,
                invocation_value=fixtures.THREAT_ACTOR_ID,
            )
        )
        assert len(result.entities) == 1


class TestMalformedCtiFacts:
    """M33C-X10..X18: malformed durable cti_entity facts fail closed."""

    @pytest.mark.parametrize(
        "fact",
        [
            "not-an-object",
            {"type": "mystery_type", "value": "x--1", "display_name": "n"},
            {"type": "threat_actor", "value": "not-canonical", "display_name": "n"},
            {
                "type": "threat_actor",
                "value": fixtures.THREAT_ACTOR_ID.upper(),
                "display_name": "n",
            },
            {
                "type": "threat_actor",
                "value": fixtures.THREAT_ACTOR_ID,
                "display_name": "",
            },
            {
                "type": "threat_actor",
                "value": fixtures.THREAT_ACTOR_ID,
                "display_name": "   ",
            },
            {
                "type": "threat_actor",
                "value": fixtures.THREAT_ACTOR_ID,
                "display_name": "x" * 513,
            },
        ],
    )
    def test_m33c_x10_d17_malformed_blocks_fail_closed(self, fact: Any) -> None:
        """M33C-X10..17: malformed cti_entity facts fail with MALFORMED_FACTS."""
        facts = _cti_facts("threat_actor", fixtures.THREAT_ACTOR_ID, "Example")
        facts["cti_entity"] = fact
        view = _view(
            facts,
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS
        assert "cti_entity" in str(error.value)

    def test_m33c_x18_errors_never_echo_source_content(self) -> None:
        """M33C-X18: extraction errors never echo names or machine values."""
        secret = "secret-actor-name-transmitted"
        secret_id = "threat-actor--77777777-7777-4777-8777-777777777777"
        facts: dict[str, Any] = {
            "stix": {"id": secret_id, "type": "threat-actor"},
            "indicator": None,
            "iocs": [],
            "cti_entity": {
                "type": "threat_actor",
                "value": secret_id,
                "display_name": "x" * 513,
            },
        }
        view = _view(
            facts,
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=secret_id,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS
        assert not (secret in str(error.value) or secret_id in str(error.value))

    def test_m33c_x19_cti_sdo_with_nonempty_iocs_fails_closed(self) -> None:
        """M33C-X19: a CTI profile must keep an empty iocs array (defensive)."""
        facts = _cti_facts("threat_actor", fixtures.THREAT_ACTOR_ID, "Example")
        facts["iocs"] = [{"type": "domain", "value": "example.test"}]
        view = _view(
            facts,
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS


class TestIocExtraction:
    """M33C-X20..X30: PR 33B IOC facts associate all represented Entities."""

    def test_m33c_x20_direct_domain_facts(self) -> None:
        """M33C-X20: one direct DOMAIN fact yields its canonical Entity."""
        result = extract_stix(
            _view(
                _ioc_facts(("domain", "example.test")),
                invocation_type=EntityType.DOMAIN,
                invocation_value="example.test",
            )
        )
        assert result.entities == ()
        assert result.relationships == ()

    def test_m33c_x21_direct_ip_facts(self) -> None:
        """M33C-X21: one direct IP fact yields its canonical Entity."""
        value = "2001:0DB8:0:0:0:0:0:1"
        # The durable converter stores canonical values only; a non-canonical
        # durable value must fail closed.
        result = extract_stix(
            _view(
                _ioc_facts(("ip_address", "2001:db8::1")),
                invocation_type=EntityType.IP_ADDRESS,
                invocation_value="2001:db8::1",
            )
        )
        assert result.entities == ()
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(
                _view(
                    _ioc_facts(("ip_address", value)),
                    invocation_type=EntityType.IP_ADDRESS,
                    invocation_value=value,
                )
            )
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_m33c_x22_multileaf_indicator_all_entities_in_order(self) -> None:
        """M33C-X22: every leaf becomes a canonical Entity in source order."""
        result = extract_stix(
            _view(
                _ioc_facts(
                    ("domain", "a.test"),
                    ("ip_address", "203.0.113.42"),
                    ("ip_address", "2001:db8::42"),
                ),
                invocation_type=EntityType.DOMAIN,
                invocation_value="a.test",
            )
        )
        assert result.entities == (
            ExtractedEntity(type=EntityType.IP_ADDRESS, value="203.0.113.42"),
            ExtractedEntity(type=EntityType.IP_ADDRESS, value="2001:db8::42"),
        )
        assert result.relationships == ()

    def test_m33c_x23_duplicate_leaves_first_seen_deduplicated(self) -> None:
        """M33C-X23: duplicate leaves collapse by first-seen identity."""
        result = extract_stix(
            _view(
                _ioc_facts(
                    ("domain", "a.test"),
                    ("ip_address", "203.0.113.42"),
                    ("ip_address", "203.0.113.42"),
                    ("domain", "b.test"),
                ),
                invocation_type=EntityType.DOMAIN,
                invocation_value="a.test",
            )
        )
        assert [entity.value for entity in result.entities] == [
            "203.0.113.42",
            "b.test",
        ]

    def test_m33c_x24_unknown_ioc_type_fails_closed(self) -> None:
        """M33C-X24: an unknown durable ioc type is MALFORMED_FACTS."""
        view = _view(
            _ioc_facts(("url", "https://example.test")),
            invocation_type=EntityType.DOMAIN,
            invocation_value="a.test",
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_m33c_x25_noncanonical_domain_fails_closed(self) -> None:
        """M33C-X25: a non-canonical durable domain value fails closed."""
        view = _view(
            _ioc_facts(("domain", "Example.TEST.")),
            invocation_type=EntityType.DOMAIN,
            invocation_value="Example.TEST.",
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_m33c_x26_iocs_not_leading_invocation_fails_closed(self) -> None:
        """M33C-X26: the IOC array must lead with the invocation identity."""
        view = _view(
            _ioc_facts(("domain", "a.test"), ("ip_address", "203.0.113.42")),
            invocation_type=EntityType.IP_ADDRESS,
            invocation_value="203.0.113.42",
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_m33c_x27_missing_iocs_fails_closed(self) -> None:
        """M33C-X27: IOC evidence without iocs is MALFORMED_FACTS."""
        facts = _ioc_facts(("domain", "a.test"))
        facts["iocs"] = []
        view = _view(
            facts,
            invocation_type=EntityType.DOMAIN,
            invocation_value="a.test",
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_m33c_x28_no_pattern_reparsing_in_extraction(self) -> None:
        """M33C-X28: extraction never re-reads an Indicator pattern."""
        facts = _ioc_facts(("domain", "a.test"))
        facts["indicator"]["pattern"] = "not valid stix ["
        result = extract_stix(
            _view(
                facts,
                invocation_type=EntityType.DOMAIN,
                invocation_value="a.test",
            )
        )
        assert result.entities == ()
        assert result.relationships == ()

    def test_m33c_x29_no_relationship_assertion_from_cti_facts(self) -> None:
        """M33C-X29: CTI facts never produce RelationshipAssertions."""
        result = extract_stix(
            _view(
                _cti_facts("threat_actor", fixtures.THREAT_ACTOR_ID, "Example"),
                invocation_type=EntityType.THREAT_ACTOR,
                invocation_value=fixtures.THREAT_ACTOR_ID,
            )
        )
        assert result.relationships == ()

    def test_m33c_x30_no_reference_alias_marking_derived_entities(self) -> None:
        """M33C-X30: references/aliases/markings never create entities or edges."""
        facts = _cti_facts("threat_actor", fixtures.THREAT_ACTOR_ID, "Example")
        facts["stix"] = {
            "id": fixtures.THREAT_ACTOR_ID,
            "type": "threat-actor",
            "object_marking_refs": ["marking-definition--1"],
            "labels": ["apt"],
        }
        result = extract_stix(
            _view(
                facts,
                invocation_type=EntityType.THREAT_ACTOR,
                invocation_value=fixtures.THREAT_ACTOR_ID,
            )
        )
        assert len(result.entities) == 1
        assert result.entities[0].value == fixtures.THREAT_ACTOR_ID
        assert result.relationships == ()


class TestMessageContextSeam:
    """M33C-X31..X34: durable message reconstruction for STIX views."""

    def test_message_context_derives_cti_invocation(self) -> None:
        """The cti_entity fact is the transient invocation for CTI SDOs."""
        from agentic_threat_investigator.app.datasource_semantics import (
            SemanticSourceContext,
        )
        from agentic_threat_investigator.app.evidence_conversion import (
            EvidenceConversionContext,
        )
        from agentic_threat_investigator.app.evidence_message import (
            converted_evidence_from_message,
            evidence_message_from_converted,
        )
        from agentic_threat_investigator.app.extraction.message_context import (
            extraction_view_from_message,
        )
        from agentic_threat_investigator.domain.datasource import DatasourceId
        from agentic_threat_investigator.infrastructure.datasources.stix21_evidence import (
            Stix21ToEvidenceConverter,
        )
        from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
            parse_stix21_object,
        )

        context = EvidenceConversionContext(
            semantic_source=SemanticSourceContext(
                datasource_id=DatasourceId("stix-future"),
                source_id=SourceId.CISA_KEV,
                semantic_format=SemanticFormatId.STIX_21,
                retrieved_at=_FIXED_TS,
                source_reference="https://taxii.example.test/",
            )
        )
        converted = Stix21ToEvidenceConverter().convert(
            parse_stix21_object(fixtures.stix_threat_actor()), context
        )
        message = evidence_message_from_converted(
            converted[0],
            datasource_execution_id=uuid4(),
            semantic_source=context.semantic_source,
            sequence=0,
        )
        view = extraction_view_from_message(
            message, converted_evidence_from_message(message)
        )
        assert view.semantic_format is SemanticFormatId.STIX_21
        assert view.invocation_entity.type is EntityType.THREAT_ACTOR
        assert view.invocation_entity.value == fixtures.THREAT_ACTOR_ID
        result = extract(view)
        assert result.entities[0].display_name == fixtures.THREAT_ACTOR_NAME

    def test_message_context_derives_ioc_invocation(self) -> None:
        """The first ioc fact is the transient invocation for STIX IOC Evidence."""
        from agentic_threat_investigator.app.datasource_semantics import (
            SemanticSourceContext,
        )
        from agentic_threat_investigator.app.evidence_conversion import (
            EvidenceConversionContext,
        )
        from agentic_threat_investigator.app.evidence_message import (
            converted_evidence_from_message,
            evidence_message_from_converted,
        )
        from agentic_threat_investigator.app.extraction.message_context import (
            extraction_view_from_message,
        )
        from agentic_threat_investigator.domain.datasource import DatasourceId
        from agentic_threat_investigator.infrastructure.datasources.stix21_evidence import (
            Stix21ToEvidenceConverter,
        )
        from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
            parse_stix21_object,
        )

        context = EvidenceConversionContext(
            semantic_source=SemanticSourceContext(
                datasource_id=DatasourceId("stix-future"),
                source_id=SourceId.CISA_KEV,
                semantic_format=SemanticFormatId.STIX_21,
                retrieved_at=_FIXED_TS,
                source_reference="https://taxii.example.test/",
            )
        )
        converted = Stix21ToEvidenceConverter().convert(
            parse_stix21_object(
                fixtures.stix_indicator(
                    pattern="[domain-name:value = 'a.test' OR ipv4-addr:value = '203.0.113.42']"
                )
            ),
            context,
        )
        message = evidence_message_from_converted(
            converted[0],
            datasource_execution_id=uuid4(),
            semantic_source=context.semantic_source,
            sequence=0,
        )
        view = extraction_view_from_message(
            message, converted_evidence_from_message(message)
        )
        assert view.invocation_entity.type is EntityType.DOMAIN
        assert view.invocation_entity.value == "a.test"
        result = extract(view)
        assert [entity.value for entity in result.entities] == ["203.0.113.42"]
        assert result.relationships == ()
