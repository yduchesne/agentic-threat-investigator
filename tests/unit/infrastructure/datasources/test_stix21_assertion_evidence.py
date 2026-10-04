# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33D STIX Relationship/Sighting Evidence conversion tests (M33D-R01..R36, M33D-S01..S25).

Pins the pure :class:`Stix21ToEvidenceConverter` source-assertion profile:
the exact approved §5.3 Relationship matrix (one supported Evidence per
admitted pair, exact pinned normalized assertion facts, deterministic
Evidence identity from the exact STIX Relationship ID + source namespace,
``observed_at=None``, context retrieval provenance, normalized
``start_time``/``stop_time`` facts with ordering enforcement), the
malformed-versus-unsupported distinction (§5.4), the bounded Sighting
profile (one supported Evidence per CTI ``sighting_of_ref``, normalized
``first_seen``/``last_seen``/``count``/``summary`` and bounded ordered
reference lists, `last_seen >= first_seen`), zero-Evidence behavior for
every valid-but-unsupported Relationship/Sighting shape, the no-echo error
rule, and the stable top-level ``source_assertion`` fact key.

Matrix IDs follow the PR 33D plan: M33D-R for Relationships, M33D-S for
Sightings. The conversion-side profile table is compared with the
extraction-side table (``app.extraction.stix.STIX_RELATIONSHIP_PROFILE``)
and the conversion-side reference-list bound is compared with the durable
revalidation bound so the two layers cannot drift.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from agentic_threat_investigator.app.datasource_semantics import (
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_conversion import (
    ConversionError,
    EvidenceConversionContext,
)
from agentic_threat_investigator.app.extraction.source_assertion import (
    STIX_ASSERTION_REFERENCE_LIST_MAX,
)
from agentic_threat_investigator.app.extraction.stix import (
    STIX_RELATIONSHIP_PROFILE as EXTRACTION_PROFILE,
)
from agentic_threat_investigator.domain.datasource import DatasourceId
from agentic_threat_investigator.domain.evidence import (
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.infrastructure.datasources import stix21_evidence
from agentic_threat_investigator.infrastructure.datasources.stix21_evidence import (
    STIX_RELATIONSHIP_PROFILE,
    Stix21ToEvidenceConverter,
)
from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
    parse_stix21_object,
)
from tests.support import stix21_fixtures as fixtures

pytestmark = pytest.mark.unit

pytestmark = pytest.mark.unit

_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_SOURCE_REFERENCE = "https://taxii.example.test/collections/1/objects/"
_OTHER_RELATIONSHIP_ID = "relationship--88888888-8888-4888-8888-888888888888"
_OTHER_TOOL_ID = "tool--99999999-9999-4999-8999-999999999999"
_RELATIONSHIP_START = "2026-01-05T00:00:00Z"
_RELATIONSHIP_STOP = "2026-02-05T00:00:00Z"
_SIGHTING_FIRST = "2026-01-10T00:00:00Z"
_SIGHTING_LAST = "2026-01-20T00:00:00Z"


def _context(
    *,
    source_id: SourceId = SourceId.CISA_KEV,
    retrieved_at: datetime = _FIXED_TS,
    source_reference: str | None = _SOURCE_REFERENCE,
) -> EvidenceConversionContext:
    """Build one deterministic STIX conversion context."""
    return EvidenceConversionContext(
        semantic_source=SemanticSourceContext(
            datasource_id=DatasourceId("stix-future"),
            source_id=source_id,
            semantic_format=SemanticFormatId.STIX_21,
            retrieved_at=retrieved_at,
            source_reference=source_reference,
        )
    )


def _convert_single(
    decoded: dict[str, Any],
    context: EvidenceConversionContext | None = None,
) -> Any:
    """Convert one parsed STIX object through the real converter."""
    return Stix21ToEvidenceConverter().convert(
        parse_stix21_object(decoded), context or _context()
    )


def _thaw_facts(candidate: Any) -> dict[str, Any]:
    """Thaw one candidate's deeply immutable facts for plain comparison."""
    facts = thaw_json(candidate.facts)
    assert isinstance(facts, dict)
    return facts


def _expected_evidence_id(
    stix_id: str, source_id: SourceId = SourceId.CISA_KEV
) -> UUID:
    """Return the exact deterministic Evidence ID of one STIX object ID."""
    return evidence_id_for_source_record(SemanticFormatId.STIX_21, source_id, stix_id)


def _endpoint(entity_type: str, value: str) -> dict[str, str]:
    """Return one pinned normalized endpoint fact."""
    return {"type": entity_type, "value": value}


def _uses_fixture(
    *,
    source_ref: str = fixtures.THREAT_ACTOR_ID,
    target_ref: str = fixtures.TOOL_ID,
    **overrides: Any,
) -> dict[str, Any]:
    """Build a synthetic admitted ``uses`` Relationship fixture."""
    return fixtures.stix_relationship(
        relationship_type="uses",
        source_ref=source_ref,
        target_ref=target_ref,
        **overrides,
    )


# ---------------------------------------------------------------------------
# M33D-R01..R13: the exact approved Relationship matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source_type", "source_ref", "target_type", "target_ref", "ati_type"),
    [
        ("threat_actor", fixtures.THREAT_ACTOR_ID, "tool", fixtures.TOOL_ID, "uses"),
        (
            "threat_actor",
            fixtures.THREAT_ACTOR_ID,
            "infrastructure",
            fixtures.INFRASTRUCTURE_ID,
            "uses",
        ),
        ("campaign", fixtures.CAMPAIGN_ID, "tool", fixtures.TOOL_ID, "uses"),
        (
            "campaign",
            fixtures.CAMPAIGN_ID,
            "infrastructure",
            fixtures.INFRASTRUCTURE_ID,
            "uses",
        ),
        ("intrusion_set", fixtures.INTRUSION_SET_ID, "tool", fixtures.TOOL_ID, "uses"),
        (
            "intrusion_set",
            fixtures.INTRUSION_SET_ID,
            "infrastructure",
            fixtures.INFRASTRUCTURE_ID,
            "uses",
        ),
        (
            "threat_actor",
            fixtures.THREAT_ACTOR_ID,
            "infrastructure",
            fixtures.INFRASTRUCTURE_ID,
            "targets",
        ),
        (
            "campaign",
            fixtures.CAMPAIGN_ID,
            "infrastructure",
            fixtures.INFRASTRUCTURE_ID,
            "targets",
        ),
        (
            "intrusion_set",
            fixtures.INTRUSION_SET_ID,
            "infrastructure",
            fixtures.INFRASTRUCTURE_ID,
            "targets",
        ),
        (
            "campaign",
            fixtures.CAMPAIGN_ID,
            "threat_actor",
            fixtures.THREAT_ACTOR_ID,
            "attributed-to",
        ),
        (
            "intrusion_set",
            fixtures.INTRUSION_SET_ID,
            "threat_actor",
            fixtures.THREAT_ACTOR_ID,
            "attributed-to",
        ),
        (
            "threat_actor",
            fixtures.THREAT_ACTOR_ID,
            "infrastructure",
            fixtures.INFRASTRUCTURE_ID,
            "controls",
        ),
        (
            "intrusion_set",
            fixtures.INTRUSION_SET_ID,
            "infrastructure",
            fixtures.INFRASTRUCTURE_ID,
            "controls",
        ),
    ],
)
def test_m33d_r01_d13_admitted_pairs_one_evidence(
    source_type: str,
    source_ref: str,
    target_type: str,
    target_ref: str,
    ati_type: str,
) -> None:
    """M33D-R01..13: each admitted pair converts to exactly one Evidence."""
    converted = _convert_single(
        fixtures.stix_relationship(
            relationship_type=ati_type,
            source_ref=source_ref,
            target_ref=target_ref,
        )
    )
    assert len(converted) == 1
    (single,) = converted
    assert single.evidence.type is EvidenceType.THREAT_INTELLIGENCE
    assertion = _thaw_facts(single.observation)["source_assertion"]
    assert assertion["kind"] == "relationship"
    body = assertion["relationship"]
    assert body["type"] == ati_type
    assert body["source"] == _endpoint(source_type, source_ref)
    assert body["target"] == _endpoint(target_type, target_ref)
    assert assertion["sighting"] is None


class TestRelationshipConversion:
    """M33D-R14..R36: shape, identity, provenance, malformed contracts."""

    def test_m33d_r14_exact_normalized_assertion_shape(self) -> None:
        """M33D-R14: the normalized relationship fact shape is pinned exactly."""
        (converted,) = _convert_single(
            fixtures.stix_relationship(
                relationship_type="uses",
                source_ref=fixtures.THREAT_ACTOR_ID,
                target_ref=fixtures.TOOL_ID,
                start_time=_RELATIONSHIP_START,
                stop_time=_RELATIONSHIP_STOP,
            )
        )
        facts = _thaw_facts(converted.observation)
        assert list(facts.keys()) == [
            "stix",
            "indicator",
            "iocs",
            "cti_entity",
            "source_assertion",
        ]
        assert facts["iocs"] == []
        assert facts["cti_entity"] is None
        assert facts["source_assertion"] == {
            "kind": "relationship",
            "relationship": {
                "type": "uses",
                "ati_type": "urn:ati:relationship:threat:uses",
                "source": _endpoint("threat_actor", fixtures.THREAT_ACTOR_ID),
                "target": _endpoint("tool", fixtures.TOOL_ID),
                "start_time": _RELATIONSHIP_START,
                "stop_time": _RELATIONSHIP_STOP,
            },
            "sighting": None,
        }

    def test_m33d_r15_evidence_identity_exact_stix_id_and_namespace(self) -> None:
        """M33D-R15: Evidence identity pins the exact relationship ID + namespace."""
        (converted,) = _convert_single(
            fixtures.stix_relationship(
                relationship_type="uses",
                source_ref=fixtures.THREAT_ACTOR_ID,
                target_ref=fixtures.TOOL_ID,
            )
        )
        assert converted.evidence.source_record_id == fixtures.RELATIONSHIP_ID
        assert converted.evidence.id == _expected_evidence_id(fixtures.RELATIONSHIP_ID)

    def test_m33d_r16_observed_at_is_none(self) -> None:
        """M33D-R16: observed_at stays None; start/stop stay facts."""
        (converted,) = _convert_single(
            fixtures.stix_relationship(
                relationship_type="uses",
                source_ref=fixtures.THREAT_ACTOR_ID,
                target_ref=fixtures.TOOL_ID,
                start_time=_RELATIONSHIP_START,
                stop_time=_RELATIONSHIP_STOP,
            )
        )
        assert converted.observation.observed_at is None

    def test_m33d_r17_retrieved_at_and_source_reference_from_context(self) -> None:
        """M33D-R17: retrieved_at/source_reference come from the context."""
        later = datetime(2026, 7, 1, 9, 0, 0, tzinfo=UTC)
        (converted,) = _convert_single(
            fixtures.stix_relationship(
                relationship_type="uses",
                source_ref=fixtures.THREAT_ACTOR_ID,
                target_ref=fixtures.TOOL_ID,
            ),
            _context(retrieved_at=later),
        )
        assert converted.observation.retrieved_at == later
        assert converted.observation.source_url == _SOURCE_REFERENCE
        assert converted.observation.raw_payload is None

    def test_m33d_r18_start_time_only_preserved_utc(self) -> None:
        """M33D-R18: a lone start_time normalizes to UTC Z."""
        (converted,) = _convert_single(
            fixtures.stix_relationship(
                relationship_type="uses",
                source_ref=fixtures.THREAT_ACTOR_ID,
                target_ref=fixtures.TOOL_ID,
                start_time="2026-01-05T02:30:00+02:00",
            )
        )
        body = _thaw_facts(converted.observation)["source_assertion"]["relationship"]
        assert body["start_time"] == "2026-01-05T00:30:00Z"
        assert body["stop_time"] is None

    def test_m33d_r19_stop_time_only_preserved_utc(self) -> None:
        """M33D-R19: a lone stop_time normalizes to UTC Z."""
        (converted,) = _convert_single(
            fixtures.stix_relationship(
                relationship_type="uses",
                source_ref=fixtures.THREAT_ACTOR_ID,
                target_ref=fixtures.TOOL_ID,
                stop_time="2026-02-05T00:00:00.500000Z",
            )
        )
        body = _thaw_facts(converted.observation)["source_assertion"]["relationship"]
        assert body["start_time"] is None
        assert body["stop_time"] == "2026-02-05T00:00:00Z"

    def test_m33d_r20_valid_start_stop_order_accepted(self) -> None:
        """M33D-R20: stop_time >= start_time is accepted."""
        (converted,) = _convert_single(
            fixtures.stix_relationship(
                relationship_type="targets",
                source_ref=fixtures.CAMPAIGN_ID,
                target_ref=fixtures.INFRASTRUCTURE_ID,
                start_time=_RELATIONSHIP_START,
                stop_time=_RELATIONSHIP_START,
            )
        )
        body = _thaw_facts(converted.observation)["source_assertion"]["relationship"]
        assert body["start_time"] == body["stop_time"] == _RELATIONSHIP_START

    def test_m33d_r21_stop_before_start_conversion_error(self) -> None:
        """M33D-R21: stop before start is a bounded ConversionError."""
        with pytest.raises(ConversionError, match="out of order"):
            _convert_single(
                fixtures.stix_relationship(
                    relationship_type="uses",
                    source_ref=fixtures.THREAT_ACTOR_ID,
                    target_ref=fixtures.TOOL_ID,
                    start_time=_RELATIONSHIP_STOP,
                    stop_time=_RELATIONSHIP_START,
                )
            )

    def test_m33d_r22_same_edge_distinct_relationship_ids_distinct_evidence(
        self,
    ) -> None:
        """M33D-R22: the same semantic edge under different IDs is distinct Evidence."""
        (first,) = _convert_single(_uses_fixture())
        (second,) = _convert_single(_uses_fixture(id=_OTHER_RELATIONSHIP_ID))
        assert first.evidence.id != second.evidence.id
        assert first.evidence.id == _expected_evidence_id(fixtures.RELATIONSHIP_ID)
        assert second.evidence.id == _expected_evidence_id(_OTHER_RELATIONSHIP_ID)

    def test_m33d_r23_same_pair_different_source_namespaces(self) -> None:
        """M33D-R23: the source namespace is part of the Evidence identity."""
        (a,) = _convert_single(_uses_fixture())
        (b,) = _convert_single(_uses_fixture(), _context(source_id=SourceId.MISP))
        assert a.evidence.id != b.evidence.id
        assert b.evidence.id == _expected_evidence_id(
            fixtures.RELATIONSHIP_ID, SourceId.MISP
        )

    @pytest.mark.parametrize(
        "source_ref",
        [
            "threat-actor--not-a-uuid",
            "threat-actor--11111111-1111-1111-1111-11111111111x",
            "threat-actor--11111111-1111-1111-1111-11111111111111",
            " threat-actor--11111111-1111-1111-1111-111111111111",
        ],
    )
    def test_m33d_r24_wrong_endpoint_uuid_in_admitted_profile_fails(
        self, source_ref: str
    ) -> None:
        """M33D-R24: an admitted-prefix endpoint with a bad UUID is ConversionError."""
        with pytest.raises(ConversionError):
            _convert_single(_uses_fixture(source_ref=source_ref))

    def test_m33d_r25_source_content_never_echoed(self) -> None:
        """M33D-R25: bounded errors never echo relationship/endpoint content."""
        secret = "secret-actor-identity-threat"
        # The prefix is admitted, so the malformed UUID fails closed; the
        # bounded error must never echo the source-controlled suffix.
        with pytest.raises(ConversionError) as error:
            _convert_single(
                fixtures.stix_relationship(
                    relationship_type="uses",
                    source_ref=f"threat-actor--{secret}",
                    target_ref=fixtures.TOOL_ID,
                )
            )
        assert secret not in str(error.value)
        assert fixtures.RELATIONSHIP_ID not in str(error.value)
        with pytest.raises(ConversionError) as error:
            _convert_single(
                fixtures.stix_relationship(
                    relationship_type="uses",
                    source_ref=f" {fixtures.THREAT_ACTOR_ID}",
                    target_ref=fixtures.TOOL_ID,
                )
            )
        assert fixtures.THREAT_ACTOR_ID not in str(error.value)

    def test_m33d_r26_indicates_zero_evidence(self) -> None:
        """M33D-R26: a valid ``indicates`` Relationship yields zero Evidence."""
        assert _convert_single(fixtures.stix_relationship()) == ()

    def test_m33d_r27_related_to_zero_evidence(self) -> None:
        """M33D-R27: a valid ``related-to`` Relationship yields zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_relationship(
                    relationship_type="related-to",
                    source_ref=fixtures.THREAT_ACTOR_ID,
                    target_ref=fixtures.TOOL_ID,
                )
            )
            == ()
        )

    def test_m33d_r28_uses_with_malware_target_zero(self) -> None:
        """M33D-R28: an admitted string with a malware endpoint yields zero."""
        assert (
            _convert_single(
                fixtures.stix_relationship(
                    relationship_type="uses",
                    source_ref=fixtures.THREAT_ACTOR_ID,
                    target_ref=fixtures.MALWARE_ID,
                )
            )
            == ()
        )

    def test_m33d_r29_uses_with_domain_target_zero(self) -> None:
        """M33D-R29: an admitted string with a domain endpoint yields zero."""
        assert (
            _convert_single(
                fixtures.stix_relationship(
                    relationship_type="uses",
                    source_ref=fixtures.THREAT_ACTOR_ID,
                    target_ref=fixtures.DOMAIN_ID,
                )
            )
            == ()
        )

    def test_m33d_r30_uses_tool_to_campaign_zero(self) -> None:
        """M33D-R30: a tool-to-campaign ``uses`` is outside the profile."""
        assert (
            _convert_single(
                fixtures.stix_relationship(
                    relationship_type="uses",
                    source_ref=fixtures.TOOL_ID,
                    target_ref=fixtures.CAMPAIGN_ID,
                )
            )
            == ()
        )

    def test_m33d_r31_targets_threat_actor_target_zero(self) -> None:
        """M33D-R31: ``targets`` toward a threat actor is outside the profile."""
        assert (
            _convert_single(
                fixtures.stix_relationship(
                    relationship_type="targets",
                    source_ref=fixtures.THREAT_ACTOR_ID,
                    target_ref=fixtures.THREAT_ACTOR_2_ID,
                )
            )
            == ()
        )

    def test_m33d_r32_attack_pattern_endpoint_zero(self) -> None:
        """M33D-R32: an attack-pattern endpoint yields zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_relationship(
                    relationship_type="uses",
                    source_ref=fixtures.THREAT_ACTOR_ID,
                    target_ref=fixtures.ATTACK_PATTERN_ID,
                )
            )
            == ()
        )

    def test_m33d_r33_vulnerability_endpoint_zero(self) -> None:
        """M33D-R33: a vulnerability endpoint yields zero Evidence."""
        vulnerability_id = "vulnerability--99999999-9999-4999-8999-999999999999"
        assert (
            _convert_single(
                fixtures.stix_relationship(
                    relationship_type="uses",
                    source_ref=fixtures.THREAT_ACTOR_ID,
                    target_ref=vulnerability_id,
                )
            )
            == ()
        )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"relationship_type": None},
            {"relationship_type": ""},
            {"relationship_type": "   "},
            {"relationship_type": 42},
        ],
    )
    def test_m33d_r34_empty_invalid_relationship_type_fails(self, kwargs: Any) -> None:
        """M33D-R34: blank/non-string relationship_type is a bounded failure."""
        with pytest.raises(ConversionError):
            _convert_single(fixtures.stix_relationship(**kwargs))

    def test_m33d_r35_unsupported_custom_relationship_zero(self) -> None:
        """M33D-R35: a valid custom relationship string yields zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_relationship(
                    relationship_type="x-ati-custom",
                    source_ref=fixtures.THREAT_ACTOR_ID,
                    target_ref=fixtures.TOOL_ID,
                )
            )
            == ()
        )

    def test_m33d_r36_converter_has_no_graph_or_persistence_imports(self) -> None:
        """M33D-R36: the converter stays free of persistence/graph imports."""
        source = inspect.getsource(stix21_evidence)
        for banned in (
            "from agentic_threat_investigator.domain.relationships",
            "from agentic_threat_investigator.app.extraction",
            "from agentic_threat_investigator.app.persistence",
            "from agentic_threat_investigator.app.evidence_consumer",
            "from agentic_threat_investigator.app.evidence_batch_persistence",
            "RelationshipAssertion",
            "ExtractedEntity",
        ):
            assert banned not in source

    def test_m33d_r37_conversion_profile_matches_extraction_profile(self) -> None:
        """M33D-R37: the conversion and extraction profile tables stay identical.

        The extractor revalidates durable facts against the same §5.3
        profile; this cross-layer pin prevents the two STIX modules from
        drifting while keeping the STIX-to-ATI mapping out of the generic
        domain (the converter emits the exact ATI RelationshipType wire URN
        and the extraction side carries the domain enum).
        """
        assert set(STIX_RELATIONSHIP_PROFILE) == set(EXTRACTION_PROFILE)
        for stix_type, (
            atti_urn,
            source_types,
            target_types,
        ) in STIX_RELATIONSHIP_PROFILE.items():
            extraction_ati_type, extraction_source, extraction_target = (
                EXTRACTION_PROFILE[stix_type]
            )
            assert atti_urn == extraction_ati_type.value
            assert {t.value for t in source_types} == {
                t.value for t in extraction_source
            }
            assert {t.value for t in target_types} == {
                t.value for t in extraction_target
            }

    def test_m33d_r38_reference_list_bound_matches_durable_seam(self) -> None:
        """M33D-R38: the conversion-side reference-list bound equals the seam bound."""
        assert (
            stix21_evidence._STIX_REFERENCE_LIST_BOUND
            == STIX_ASSERTION_REFERENCE_LIST_MAX
        )


class TestSightingConversion:
    """M33D-S01..S25: the bounded STIX Sighting Evidence profile."""

    @pytest.mark.parametrize(
        ("sighting_of_ref", "expected_type"),
        [
            (fixtures.THREAT_ACTOR_ID, "threat_actor"),
            (fixtures.CAMPAIGN_ID, "campaign"),
            (fixtures.INTRUSION_SET_ID, "intrusion_set"),
            (fixtures.TOOL_ID, "tool"),
            (fixtures.INFRASTRUCTURE_ID, "infrastructure"),
        ],
    )
    def test_m33d_s01_d05_sighting_of_each_cti_type_one_evidence(
        self, sighting_of_ref: str, expected_type: str
    ) -> None:
        """M33D-S01..05: a Sighting of each CTI type converts to one Evidence."""
        converted = _convert_single(
            fixtures.stix_sighting(sighting_of_ref=sighting_of_ref)
        )
        assert len(converted) == 1
        (single,) = converted
        sighting = _thaw_facts(single.observation)["source_assertion"]["sighting"]
        assert sighting["sighting_of"] == _endpoint(expected_type, sighting_of_ref)

    def test_m33d_s06_exact_normalized_assertion_shape(self) -> None:
        """M33D-S06: the normalized Sighting fact shape is pinned exactly."""
        where = [
            "identity--11111111-1111-1111-1111-111111111111",
            "location--22222222-2222-2222-2222-222222222222",
        ]
        observed = ["observed-data--33333333-3333-3333-3333-333333333333"]
        (converted,) = _convert_single(
            fixtures.stix_sighting(
                sighting_of_ref=fixtures.THREAT_ACTOR_ID,
                first_seen=_SIGHTING_FIRST,
                last_seen=_SIGHTING_LAST,
                count=4,
                summary=True,
                where_sighted_refs=where,
                observed_data_refs=observed,
            )
        )
        facts = _thaw_facts(converted.observation)
        assert facts["source_assertion"] == {
            "kind": "sighting",
            "relationship": None,
            "sighting": {
                "sighting_of": _endpoint("threat_actor", fixtures.THREAT_ACTOR_ID),
                "first_seen": _SIGHTING_FIRST,
                "last_seen": _SIGHTING_LAST,
                "count": 4,
                "summary": True,
                "where_sighted_refs": where,
                "observed_data_refs": observed,
            },
        }

    def test_m33d_s07_first_seen_only_normalized(self) -> None:
        """M33D-S07: a lone first_seen normalizes to UTC Z."""
        (converted,) = _convert_single(
            fixtures.stix_sighting(
                sighting_of_ref=fixtures.TOOL_ID, first_seen=_SIGHTING_FIRST
            )
        )
        sighting = _thaw_facts(converted.observation)["source_assertion"]["sighting"]
        assert sighting["first_seen"] == _SIGHTING_FIRST
        assert sighting["last_seen"] is None

    def test_m33d_s08_last_seen_only_normalized(self) -> None:
        """M33D-S08: a lone last_seen normalizes to UTC Z."""
        (converted,) = _convert_single(
            fixtures.stix_sighting(
                sighting_of_ref=fixtures.TOOL_ID,
                last_seen="2026-01-20T01:00:00+01:00",
            )
        )
        sighting = _thaw_facts(converted.observation)["source_assertion"]["sighting"]
        assert sighting["first_seen"] is None
        assert sighting["last_seen"] == "2026-01-20T00:00:00Z"

    def test_m33d_s09_first_seen_before_last_seen_accepted(self) -> None:
        """M33D-S09: first_seen <= last_seen is accepted."""
        (converted,) = _convert_single(
            fixtures.stix_sighting(
                sighting_of_ref=fixtures.TOOL_ID,
                first_seen=_SIGHTING_FIRST,
                last_seen=_SIGHTING_FIRST,
            )
        )
        sighting = _thaw_facts(converted.observation)["source_assertion"]["sighting"]
        assert sighting["first_seen"] == sighting["last_seen"] == _SIGHTING_FIRST

    def test_m33d_s10_last_seen_before_first_seen_fails(self) -> None:
        """M33D-S10: last_seen < first_seen is a bounded ConversionError."""
        with pytest.raises(ConversionError, match="out of order"):
            _convert_single(
                fixtures.stix_sighting(
                    sighting_of_ref=fixtures.TOOL_ID,
                    first_seen=_SIGHTING_LAST,
                    last_seen=_SIGHTING_FIRST,
                )
            )

    def test_m33d_s11_positive_count_preserved(self) -> None:
        """M33D-S11: a positive count is preserved verbatim."""
        (converted,) = _convert_single(
            fixtures.stix_sighting(sighting_of_ref=fixtures.TOOL_ID, count=7)
        )
        sighting = _thaw_facts(converted.observation)["source_assertion"]["sighting"]
        assert sighting["count"] == 7

    @pytest.mark.parametrize("count", [0, -1, -100])
    def test_m33d_s12_count_zero_or_negative_fails(self, count: int) -> None:
        """M33D-S12: a non-positive count fails closed."""
        with pytest.raises(ConversionError, match="positive"):
            _convert_single(
                fixtures.stix_sighting(sighting_of_ref=fixtures.TOOL_ID, count=count)
            )

    @pytest.mark.parametrize("count", ["3", 3.5, True])
    def test_m33d_s13_count_non_int_or_bool_fails(self, count: Any) -> None:
        """M33D-S13: a non-integer (incl. bool) count fails closed."""
        with pytest.raises(ConversionError):
            _convert_single(
                fixtures.stix_sighting(sighting_of_ref=fixtures.TOOL_ID, count=count)
            )

    @pytest.mark.parametrize("summary", [True, False])
    def test_m33d_s14_summary_true_false_preserved(self, summary: bool) -> None:
        """M33D-S14: a boolean summary is preserved."""
        (converted,) = _convert_single(
            fixtures.stix_sighting(sighting_of_ref=fixtures.TOOL_ID, summary=summary)
        )
        sighting = _thaw_facts(converted.observation)["source_assertion"]["sighting"]
        assert sighting["summary"] is summary

    def test_m33d_s15_summary_wrong_type_fails(self) -> None:
        """M33D-S15: a non-boolean summary fails closed."""
        with pytest.raises(ConversionError, match="boolean"):
            _convert_single(
                fixtures.stix_sighting(sighting_of_ref=fixtures.TOOL_ID, summary="yes")
            )

    def test_m33d_s16_where_sighted_refs_ordered(self) -> None:
        """M33D-S16: where_sighted_refs preserve exact source order."""
        refs = ["identity--1", "identity--2", "identity--3"]
        (converted,) = _convert_single(
            fixtures.stix_sighting(
                sighting_of_ref=fixtures.TOOL_ID,
                where_sighted_refs=list(reversed(refs)),
            )
        )
        sighting = _thaw_facts(converted.observation)["source_assertion"]["sighting"]
        assert sighting["where_sighted_refs"] == list(reversed(refs))

    def test_m33d_s17_observed_data_refs_ordered(self) -> None:
        """M33D-S17: observed_data_refs preserve exact source order."""
        refs = ["observed-data--1", "observed-data--2"]
        (converted,) = _convert_single(
            fixtures.stix_sighting(
                sighting_of_ref=fixtures.TOOL_ID, observed_data_refs=refs
            )
        )
        sighting = _thaw_facts(converted.observation)["source_assertion"]["sighting"]
        assert sighting["observed_data_refs"] == refs

    def test_m33d_s18_list_at_exact_bound_accepted(self) -> None:
        """M33D-S18: a reference list at the exact bound is accepted."""
        refs = [
            f"identity--{index:08d}-0000-4000-8000-000000000000"
            for index in range(STIX_ASSERTION_REFERENCE_LIST_MAX)
        ]
        (converted,) = _convert_single(
            fixtures.stix_sighting(
                sighting_of_ref=fixtures.TOOL_ID, where_sighted_refs=refs
            )
        )
        sighting = _thaw_facts(converted.observation)["source_assertion"]["sighting"]
        assert len(sighting["where_sighted_refs"]) == STIX_ASSERTION_REFERENCE_LIST_MAX

    def test_m33d_s19_list_over_bound_fails(self) -> None:
        """M33D-S19: a reference list over the bound fails closed."""
        refs = ["identity--1"] * (STIX_ASSERTION_REFERENCE_LIST_MAX + 1)
        with pytest.raises(ConversionError, match="maximum"):
            _convert_single(
                fixtures.stix_sighting(
                    sighting_of_ref=fixtures.TOOL_ID, where_sighted_refs=refs
                )
            )

    @pytest.mark.parametrize(
        "refs",
        [
            ["identity--1", ""],
            ["identity--1", "   "],
            ["identity--1", " padded-identity"],
            ["identity--1", 42],
        ],
    )
    def test_m33d_s20_malformed_list_member_fails(self, refs: list[Any]) -> None:
        """M33D-S20: a malformed reference-list member fails closed."""
        with pytest.raises(ConversionError):
            _convert_single(
                fixtures.stix_sighting(
                    sighting_of_ref=fixtures.TOOL_ID, where_sighted_refs=refs
                )
            )

    @pytest.mark.parametrize(
        "sighting_of_ref",
        [
            fixtures.MALWARE_ID,
            fixtures.INDICATOR_ID,
            fixtures.DOMAIN_ID,
            fixtures.IPV4_ID,
            fixtures.IPV6_ID,
            fixtures.ATTACK_PATTERN_ID,
        ],
    )
    def test_m33d_s21_d23_non_cti_sighting_zero(self, sighting_of_ref: str) -> None:
        """M33D-S21..23: malware/indicator/domain/IP/attack-pattern sightings are zero."""
        assert (
            _convert_single(fixtures.stix_sighting(sighting_of_ref=sighting_of_ref))
            == ()
        )

    def test_m33d_s21_malware_sighting_zero(self) -> None:
        """M33D-S21: a Sighting of malware yields zero Evidence."""
        assert _convert_single(fixtures.stix_sighting()) == ()

    def test_m33d_s24_observed_at_is_none(self) -> None:
        """M33D-S24: observed_at stays None; first/last stay facts."""
        (converted,) = _convert_single(
            fixtures.stix_sighting(
                sighting_of_ref=fixtures.TOOL_ID,
                first_seen=_SIGHTING_FIRST,
                last_seen=_SIGHTING_LAST,
            )
        )
        assert converted.observation.observed_at is None

    def test_m33d_s25_no_relationship_semantic_synthesized(self) -> None:
        """M33D-S25: the facts carry no synthetic relationship edge semantics."""
        (converted,) = _convert_single(
            fixtures.stix_sighting(
                sighting_of_ref=fixtures.TOOL_ID,
                where_sighted_refs=["identity--11111111-1111-1111-1111-111111111111"],
                observed_data_refs=[
                    "observed-data--11111111-1111-1111-1111-111111111111"
                ],
            )
        )
        facts = _thaw_facts(converted.observation)
        flat = str(facts)
        for banned in (
            "sighted_at",
            "observed_by",
            "seen_by",
            "located_at",
            "associated_with",
        ):
            assert banned not in flat
        assertion = facts["source_assertion"]
        assert assertion["kind"] == "sighting"
        assert assertion["relationship"] is None
