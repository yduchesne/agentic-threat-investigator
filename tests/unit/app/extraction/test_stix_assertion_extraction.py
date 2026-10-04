# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33D STIX durable-assertion extraction tests (M33D-X01..X16).

Pins :func:`extract_stix` over normalized source-assertion facts: a
Relationship assertion yields exactly the two canonical endpoint Entities
(first-seen source order) and exactly one approved RelationshipAssertion in
source-asserted direction; a Sighting assertion yields exactly the sighted
CTI Entity and zero assertions. Durable facts are revalidated defensively —
self-edges, tampered STIX/ATI mapping pairs, inconsistent endpoint types,
and malformed assertion bodies fail closed with ``MALFORMED_FACTS`` without
echoing fact content — and the legacy IOC/CTI-SDO extraction paths remain
unchanged.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.extraction.models import (
    EntityIdentity,
    EvidenceExtractionError,
    EvidenceExtractionView,
    ExtractedEntity,
    ExtractionErrorReason,
    ExtractionResult,
    RelationshipAssertion,
)
from agentic_threat_investigator.app.extraction.stix import (
    extract_stix,
    validate_stix_cti_entity_fact,
    validate_stix_ioc_fact,
)
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
from agentic_threat_investigator.domain.relationships import RelationshipType
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
        source_record_id="relationship--99999999-9999-4999-8999-999999999999",
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


def _endpoint(entity_type: str, value: str) -> dict[str, str]:
    """Return one normalized endpoint fact."""
    return {"type": entity_type, "value": value}


def _relationship_facts(
    *,
    stix_type: str = "uses",
    ati_urn: str = "urn:ati:relationship:threat:uses",
    source_type: str = "threat_actor",
    source_value: str = fixtures.THREAT_ACTOR_ID,
    target_type: str = "tool",
    target_value: str = fixtures.TOOL_ID,
    start_time: str | None = None,
    stop_time: str | None = None,
) -> dict[str, Any]:
    """Build the durable normalized Relationship assertion facts."""
    return {
        "stix": {"id": fixtures.RELATIONSHIP_ID, "type": "relationship"},
        "indicator": None,
        "iocs": [],
        "cti_entity": None,
        "source_assertion": {
            "kind": "relationship",
            "relationship": {
                "type": stix_type,
                "ati_type": ati_urn,
                "source": _endpoint(source_type, source_value),
                "target": _endpoint(target_type, target_value),
                "start_time": start_time,
                "stop_time": stop_time,
            },
            "sighting": None,
        },
    }


def _sighting_facts(
    *,
    sighting_of_type: str = "threat_actor",
    sighting_of_value: str = fixtures.THREAT_ACTOR_ID,
    first_seen: str | None = None,
    last_seen: str | None = None,
    count: int | None = None,
    summary: bool | None = None,
    where_sighted_refs: tuple[str, ...] = (),
    observed_data_refs: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build the durable normalized Sighting assertion facts."""
    return {
        "stix": {"id": fixtures.SIGHTING_ID, "type": "sighting"},
        "indicator": None,
        "iocs": [],
        "cti_entity": None,
        "source_assertion": {
            "kind": "sighting",
            "relationship": None,
            "sighting": {
                "sighting_of": _endpoint(sighting_of_type, sighting_of_value),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "count": count,
                "summary": summary,
                "where_sighted_refs": list(where_sighted_refs),
                "observed_data_refs": list(observed_data_refs),
            },
        },
    }


def _relationship_result(
    *,
    source_type: EntityType,
    source_value: str,
    target_type: EntityType,
    target_value: str,
    relationship_type: RelationshipType,
) -> ExtractionResult:
    """Return the expected extraction output of one admitted Relationship."""
    return ExtractionResult(
        entities=(
            ExtractedEntity(type=source_type, value=source_value),
            ExtractedEntity(type=target_type, value=target_value),
        ),
        relationships=(
            RelationshipAssertion(
                source=EntityIdentity(type=source_type, value=source_value),
                type=relationship_type,
                target=EntityIdentity(type=target_type, value=target_value),
            ),
        ),
    )


class TestRelationshipExtraction:
    """M33D-X01..X10: Relationship assertion extraction."""

    def test_m33d_x01_threat_actor_uses_tool(self) -> None:
        """M33D-X01: threat actor uses tool -> 2 Entities + 1 USES assertion."""
        result = extract_stix(
            _view(
                _relationship_facts(),
                invocation_type=EntityType.THREAT_ACTOR,
                invocation_value=fixtures.THREAT_ACTOR_ID,
            )
        )
        assert result == _relationship_result(
            source_type=EntityType.THREAT_ACTOR,
            source_value=fixtures.THREAT_ACTOR_ID,
            target_type=EntityType.TOOL,
            target_value=fixtures.TOOL_ID,
            relationship_type=RelationshipType.USES,
        )

    def test_m33d_x02_campaign_targets_infrastructure(self) -> None:
        """M33D-X02: campaign targets infrastructure -> TARGETS assertion."""
        result = extract_stix(
            _view(
                _relationship_facts(
                    stix_type="targets",
                    ati_urn=RelationshipType.TARGETS.value,
                    source_type="campaign",
                    source_value=fixtures.CAMPAIGN_ID,
                    target_type="infrastructure",
                    target_value=fixtures.INFRASTRUCTURE_ID,
                ),
                invocation_type=EntityType.CAMPAIGN,
                invocation_value=fixtures.CAMPAIGN_ID,
            )
        )
        assert result == _relationship_result(
            source_type=EntityType.CAMPAIGN,
            source_value=fixtures.CAMPAIGN_ID,
            target_type=EntityType.INFRASTRUCTURE,
            target_value=fixtures.INFRASTRUCTURE_ID,
            relationship_type=RelationshipType.TARGETS,
        )

    def test_m33d_x03_campaign_attributed_to_threat_actor(self) -> None:
        """M33D-X03: campaign attributed-to threat actor -> ATTRIBUTED_TO."""
        result = extract_stix(
            _view(
                _relationship_facts(
                    stix_type="attributed-to",
                    ati_urn=RelationshipType.ATTRIBUTED_TO.value,
                    source_type="campaign",
                    source_value=fixtures.CAMPAIGN_ID,
                    target_type="threat_actor",
                    target_value=fixtures.THREAT_ACTOR_2_ID,
                ),
                invocation_type=EntityType.CAMPAIGN,
                invocation_value=fixtures.CAMPAIGN_ID,
            )
        )
        assert result == _relationship_result(
            source_type=EntityType.CAMPAIGN,
            source_value=fixtures.CAMPAIGN_ID,
            target_type=EntityType.THREAT_ACTOR,
            target_value=fixtures.THREAT_ACTOR_2_ID,
            relationship_type=RelationshipType.ATTRIBUTED_TO,
        )

    def test_m33d_x04_intrusion_set_controls_infrastructure(self) -> None:
        """M33D-X04: intrusion set controls infrastructure -> CONTROLS."""
        result = extract_stix(
            _view(
                _relationship_facts(
                    stix_type="controls",
                    ati_urn=RelationshipType.CONTROLS.value,
                    source_type="intrusion_set",
                    source_value=fixtures.INTRUSION_SET_ID,
                    target_type="infrastructure",
                    target_value=fixtures.INFRASTRUCTURE_ID,
                ),
                invocation_type=EntityType.INTRUSION_SET,
                invocation_value=fixtures.INTRUSION_SET_ID,
            )
        )
        assert result == _relationship_result(
            source_type=EntityType.INTRUSION_SET,
            source_value=fixtures.INTRUSION_SET_ID,
            target_type=EntityType.INFRASTRUCTURE,
            target_value=fixtures.INFRASTRUCTURE_ID,
            relationship_type=RelationshipType.CONTROLS,
        )

    def test_m33d_x05_endpoint_order_source_then_target(self) -> None:
        """M33D-X05: Entities are first-seen ordered source then target."""
        result = extract_stix(
            _view(
                _relationship_facts(),
                invocation_type=EntityType.THREAT_ACTOR,
                invocation_value=fixtures.THREAT_ACTOR_ID,
            )
        )
        assert [entity.value for entity in result.entities] == [
            fixtures.THREAT_ACTOR_ID,
            fixtures.TOOL_ID,
        ]

    def test_m33d_x06_assertion_direction_source_to_target(self) -> None:
        """M33D-X06: the assertion direction matches source_ref -> target_ref."""
        result = extract_stix(
            _view(
                _relationship_facts(),
                invocation_type=EntityType.THREAT_ACTOR,
                invocation_value=fixtures.THREAT_ACTOR_ID,
            )
        )
        (assertion,) = result.relationships
        assert assertion.source.value == fixtures.THREAT_ACTOR_ID
        assert assertion.target.value == fixtures.TOOL_ID
        assert assertion.source is not assertion.target

    def test_m33d_x07_no_reciprocal_edge(self) -> None:
        """M33D-X07: exactly one assertion, never a reciprocal edge."""
        result = extract_stix(
            _view(
                _relationship_facts(),
                invocation_type=EntityType.THREAT_ACTOR,
                invocation_value=fixtures.THREAT_ACTOR_ID,
            )
        )
        assert len(result.relationships) == 1

    def test_m33d_x08_same_endpoint_self_edge_malformed(self) -> None:
        """M33D-X08: a self-edge Relationship assertion is malformed."""
        view = _view(
            _relationship_facts(
                source_value=fixtures.THREAT_ACTOR_ID,
                target_type="threat_actor",
                target_value=fixtures.THREAT_ACTOR_ID,
            ),
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS
        assert "self-edge" in str(error.value)

    def test_m33d_x09_tampered_stix_ati_mapping_malformed(self) -> None:
        """M33D-X09: a tampered STIX/ATI mapping pair fails closed."""
        view = _view(
            _relationship_facts(
                stix_type="uses",
                ati_urn=RelationshipType.TARGETS.value,
            ),
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS
        assert "inconsistent" in str(error.value)

    def test_m33d_x09b_unknown_stix_type_malformed(self) -> None:
        """M33D-X09b: an unadmitted STIX relationship string fails closed."""
        view = _view(
            _relationship_facts(
                stix_type="indicates",
                ati_urn=RelationshipType.USES.value,
            ),
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_m33d_x10_tampered_endpoint_type_pair_malformed(self) -> None:
        """M33D-X10: endpoint types inconsistent with the profile fail closed."""
        view = _view(
            _relationship_facts(
                stix_type="uses",
                target_type="threat_actor",
                target_value=fixtures.THREAT_ACTOR_2_ID,
            ),
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS
        assert "endpoint types" in str(error.value)


class TestSightingExtraction:
    """M33D-X11..X13: Sighting assertion extraction."""

    def test_m33d_x11_sighting_one_entity_zero_assertions(self) -> None:
        """M33D-X11: a Sighting yields exactly the sighted Entity, zero edges."""
        result = extract_stix(
            _view(
                _sighting_facts(),
                invocation_type=EntityType.THREAT_ACTOR,
                invocation_value=fixtures.THREAT_ACTOR_ID,
            )
        )
        assert result == ExtractionResult(
            entities=(
                ExtractedEntity(
                    type=EntityType.THREAT_ACTOR, value=fixtures.THREAT_ACTOR_ID
                ),
            ),
            relationships=(),
        )

    def test_m33d_x12_where_sighted_refs_no_entity_or_edge(self) -> None:
        """M33D-X12: where_sighted_refs facts create no Entity or edge."""
        refs = ("identity--11111111-1111-1111-1111-111111111111",)
        result = extract_stix(
            _view(
                _sighting_facts(where_sighted_refs=refs),
                invocation_type=EntityType.THREAT_ACTOR,
                invocation_value=fixtures.THREAT_ACTOR_ID,
            )
        )
        assert len(result.entities) == 1
        assert result.entities[0].value == fixtures.THREAT_ACTOR_ID
        assert result.relationships == ()

    def test_m33d_x13_observed_data_refs_no_entity_or_edge(self) -> None:
        """M33D-X13: observed_data_refs facts create no Entity or edge."""
        refs = ("observed-data--11111111-1111-1111-1111-111111111111",)
        result = extract_stix(
            _view(
                _sighting_facts(observed_data_refs=refs),
                invocation_type=EntityType.THREAT_ACTOR,
                invocation_value=fixtures.THREAT_ACTOR_ID,
            )
        )
        assert len(result.entities) == 1
        assert result.entities[0].value == fixtures.THREAT_ACTOR_ID
        assert result.relationships == ()

    def test_m33d_x13b_invalid_sighting_facts_fail_closed(self) -> None:
        """M33D-X13b: malformed sighting facts (bad endpoint) fail closed."""
        view = _view(
            _sighting_facts(
                sighting_of_type="malware",
                sighting_of_value=fixtures.MALWARE_ID,
            ),
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS
        assert "sighting" in str(error.value)


class TestAssertionShapeGuards:
    """Additional durable-shape guards (plan §4.4)."""

    def test_assertion_with_cti_entity_fails_closed(self) -> None:
        """An assertion combined with cti_entity is malformed."""
        facts = _relationship_facts()
        facts["cti_entity"] = {
            "type": "threat_actor",
            "value": fixtures.THREAT_ACTOR_ID,
            "display_name": "x",
        }
        view = _view(
            facts,
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_assertion_with_nonempty_iocs_fails_closed(self) -> None:
        """An assertion combined with nonempty iocs is malformed."""
        facts = _relationship_facts()
        facts["iocs"] = [{"type": "domain", "value": "example.test"}]
        view = _view(
            facts,
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_unknown_assertion_kind_fails_closed(self) -> None:
        """An unknown assertion kind is malformed."""
        facts = _relationship_facts()
        facts["source_assertion"] = {
            "kind": "mystery",
            "relationship": None,
            "sighting": None,
        }
        view = _view(
            facts,
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_relationship_with_sighting_body_fails_closed(self) -> None:
        """A relationship kind carrying a sighting body is malformed."""
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
        view = _view(
            facts,
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_missing_relationship_body_fails_closed(self) -> None:
        """A relationship kind without a body is malformed."""
        facts = _relationship_facts()
        facts["source_assertion"]["relationship"] = None
        view = _view(
            facts,
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    def test_errors_never_echo_assertion_content(self) -> None:
        """Extraction errors never echo machine values or relationship content."""
        secret = "secret-machine-id-leaked"
        facts = _relationship_facts(
            ati_urn=RelationshipType.TARGETS.value,
            source_value=fixtures.THREAT_ACTOR_ID,
            target_value=secret,
        )
        view = _view(
            facts,
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        with pytest.raises(EvidenceExtractionError) as error:
            extract_stix(view)
        assert error.value.reason is ExtractionErrorReason.MALFORMED_FACTS
        assert secret not in str(error.value)
        assert fixtures.THREAT_ACTOR_ID not in str(error.value)


class TestLegacyPathsUnchanged:
    """M33D-X14..X16: IOC and CTI-SDO extraction remain unchanged."""

    def test_m33d_x14_ioc_extraction_unchanged(self) -> None:
        """M33D-X14: the PR 33B IOC extraction path is unchanged."""
        facts: dict[str, Any] = {
            "stix": {"id": fixtures.INDICATOR_ID, "type": "indicator"},
            "indicator": {
                "pattern": "[domain-name:value = 'a.test']",
                "pattern_type": "stix",
            },
            "iocs": [{"type": "domain", "value": "a.test"}],
            "cti_entity": None,
            "source_assertion": None,
        }
        result = extract_stix(
            _view(facts, invocation_type=EntityType.DOMAIN, invocation_value="a.test")
        )
        assert result.entities == ()
        assert result.relationships == ()

    def test_m33d_x15_cti_sdo_extraction_unchanged(self) -> None:
        """M33D-X15: the PR 33C CTI-SDO extraction path is unchanged."""
        facts: dict[str, Any] = {
            "stix": {"id": fixtures.THREAT_ACTOR_ID, "type": "threat-actor"},
            "indicator": None,
            "iocs": [],
            "cti_entity": {
                "type": "threat_actor",
                "value": fixtures.THREAT_ACTOR_ID,
                "display_name": fixtures.THREAT_ACTOR_NAME,
            },
            "source_assertion": None,
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

    def test_m33d_x16_extraction_performs_no_io(self) -> None:
        """M33D-X16: the extraction module has no I/O, persistence, or clock code."""
        import agentic_threat_investigator.app.extraction.stix as stix_module

        source = inspect.getsource(stix_module)
        for banned in (
            "import aiohttp",
            "import httpx",
            "import requests",
            "import sqlalchemy",
            "from sqlalchemy",
            "import aiokafka",
            "import psycopg",
            "import socket",
            "async def",
            "await ",
            "import random",
            "datetime.now",
            "import time",
        ):
            assert banned not in source
        # The extractor itself remains the pure synchronous entry point.
        assert extract_stix.__name__ == "extract_stix"

    def test_dispatcher_routes_assertion_through_real_seam(self) -> None:
        """The real dispatcher routes assertion views to extract_stix."""
        view = _view(
            _relationship_facts(),
            invocation_type=EntityType.THREAT_ACTOR,
            invocation_value=fixtures.THREAT_ACTOR_ID,
        )
        result = extract(view)
        assert len(result.entities) == 2
        assert len(result.relationships) == 1
        (assertion,) = result.relationships
        assert assertion.type is RelationshipType.USES

    def test_validators_still_used_by_legacy_paths(self) -> None:
        """M33D-X15b: the legacy fact validators remain importable/stable."""
        assert validate_stix_cti_entity_fact(
            {
                "type": "tool",
                "value": fixtures.TOOL_ID,
                "display_name": fixtures.TOOL_NAME,
            }
        ) == (EntityType.TOOL, fixtures.TOOL_ID, fixtures.TOOL_NAME)
        assert validate_stix_ioc_fact({"type": "domain", "value": "example.test"}) == (
            EntityType.DOMAIN,
            "example.test",
        )
