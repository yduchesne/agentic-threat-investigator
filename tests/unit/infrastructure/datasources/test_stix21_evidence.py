# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33B STIX 2.1 IOC Evidence conversion tests.

Matrix IDs M33B-01..78 pin the pure :class:`Stix21ToEvidenceConverter`
contract: exact semantic-format registration, fail-closed type/format
guards with **no** fixed ``SourceId`` guard, deterministic global Evidence
identity from the exact STIX ``id`` + semantic format + ATI source
namespace (``created``/``modified``/retrieval time never participate), the
direct ``domain-name``/``ipv4-addr``/``ipv6-addr`` SCO profile through the
existing DNS/IP canonicalizers with enforced IP family, zero-Evidence
behavior for valid unsupported objects and valid-but-unsupported Indicator
patterns, the standards-parser-backed Indicator equality whitelist
(left-to-right ordered leaves, duplicates preserved, malformed-vs-
unsupported distinction, whole-pattern whitelisting), the exact normalized
STIX/Indicator/IOC fact shapes (``observed_at=None``, ``raw_payload=None``,
markings preserved-not-enforced), no verdict/risk/relationship synthesis,
and deterministic ordering through the real generic conversion seam.

Matrix IDs M33B-V01..V06 are the parser-to-converter vertical slices: a
synthetic decoded STIX object through the **real** ``parse_stix21_object()``
(PR 33A), the **real** whitelist-adapter parser, the **real** registry, and
the **real** ``convert_semantic_source_objects()``. Everything is
synthetic, static, and offline — no database, network, TAXII, MITRE, or
OASIS service is involved.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.datasource_semantics import (
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_conversion import (
    ConversionError,
    EvidenceConversionContext,
    UnknownSemanticFormatError,
    convert_semantic_source_objects,
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
from agentic_threat_investigator.domain.immutable_json import FrozenDict, thaw_json
from agentic_threat_investigator.infrastructure.datasources import (
    stix21_evidence,
    stix21_pattern,
    stix21_semantics,
)
from agentic_threat_investigator.infrastructure.datasources.stix21_evidence import (
    Stix21ToEvidenceConverter,
    build_stix21_conversion_registry,
    build_stix_common_facts,
    build_stix_indicator_facts,
    build_stix_normalized_facts,
    extract_stix_ioc_facts,
)
from agentic_threat_investigator.infrastructure.datasources.stix21_semantics import (
    Stix21Object,
    parse_stix21_object,
)
from tests.support import stix21_fixtures as fixtures

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[4]
_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_SOURCE_REFERENCE = "https://taxii.example.test/collections/1/objects/"
_MARKING_REF = "marking-definition--1c9b3a0a-7f1b-4b1e-8f2b-2b2b2b2b2b2b"


def _semantic_context(
    *,
    source_id: SourceId = SourceId.CISA_KEV,
    semantic_format: SemanticFormatId = SemanticFormatId.STIX_21,
    retrieved_at: datetime = _FIXED_TS,
    source_reference: str | None = _SOURCE_REFERENCE,
) -> SemanticSourceContext:
    """Build one deterministic STIX semantic provenance context."""
    return SemanticSourceContext(
        datasource_id=DatasourceId("stix-future"),
        source_id=source_id,
        semantic_format=semantic_format,
        retrieved_at=retrieved_at,
        source_reference=source_reference,
    )


def _conversion_context(
    *,
    source_id: SourceId = SourceId.CISA_KEV,
    semantic_format: SemanticFormatId = SemanticFormatId.STIX_21,
    retrieved_at: datetime = _FIXED_TS,
) -> EvidenceConversionContext:
    """Build one deterministic global conversion context."""
    return EvidenceConversionContext(
        semantic_source=_semantic_context(
            source_id=source_id,
            semantic_format=semantic_format,
            retrieved_at=retrieved_at,
        )
    )


def _object(decoded: dict[str, Any]) -> Stix21Object:
    """Parse one decoded synthetic STIX object through the real PR 33A seam."""
    return parse_stix21_object(decoded)


def _convert_single(
    decoded: dict[str, Any],
    context: EvidenceConversionContext | None = None,
) -> Any:
    """Convert one parsed STIX object through the real converter."""
    return Stix21ToEvidenceConverter().convert(
        _object(decoded), context or _conversion_context()
    )


def _expected_evidence_id(
    stix_id: str, source_id: SourceId = SourceId.CISA_KEV
) -> UUID:
    """Return the exact deterministic Evidence ID of one STIX object ID."""
    return evidence_id_for_source_record(SemanticFormatId.STIX_21, source_id, stix_id)


def _expected_common_facts(
    object_id: str, object_type: str, **overrides: Any
) -> dict[str, Any]:
    """Return the pinned normalized common STIX fact object."""
    facts: dict[str, Any] = {
        "id": object_id,
        "type": object_type,
        "spec_version": "2.1",
        "created": None,
        "modified": None,
        "revoked": None,
        "labels": [],
        "confidence": None,
        "lang": None,
        "external_references": [],
        "object_marking_refs": [],
        "granular_markings": [],
        "defanged": None,
    }
    facts.update(overrides)
    return facts


def _expected_indicator_facts(**overrides: Any) -> dict[str, Any]:
    """Return the pinned normalized Indicator fact block for the fixture."""
    facts: dict[str, Any] = {
        "pattern": fixtures.SINGLE_DOMAIN_PATTERN,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2026-01-03T00:00:00Z",
        "valid_until": None,
        "indicator_types": ["malicious-activity"],
    }
    facts.update(overrides)
    return facts


def _expected_facts(
    *,
    object_id: str,
    object_type: str,
    indicator: dict[str, Any] | None,
    iocs: list[dict[str, str]],
    common: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the pinned normalized fact object (PR 33D includes source_assertion)."""
    return {
        "stix": _expected_common_facts(object_id, object_type, **(common or {})),
        "indicator": indicator,
        "iocs": iocs,
        "cti_entity": None,
        "source_assertion": None,
    }


def _thaw_facts(candidate: Any) -> dict[str, Any]:
    """Thaw one candidate's deeply immutable facts for plain comparison."""
    facts = thaw_json(candidate.facts)
    assert isinstance(facts, dict)
    return facts


class TestRegistrationContract:
    """M33B-01..04: format identity, guards, and no SourceId guard."""

    def test_m33b_01_converter_format_exactly_stix21(self) -> None:
        """M33B-01: the converter owns exactly the STIX 2.1 semantic format."""
        assert Stix21ToEvidenceConverter().semantic_format is SemanticFormatId.STIX_21

    def test_m33b_02_wrong_source_object_type_fails_closed(self) -> None:
        """M33B-02: a non-Stix21Object source is a bounded ConversionError."""
        wrong_source: object = {"type": "domain-name", "id": "x"}
        with pytest.raises(ConversionError, match="STIX 2.1 object"):
            Stix21ToEvidenceConverter().convert(
                wrong_source,  # type: ignore[arg-type]
                _conversion_context(),
            )

    def test_m33b_03_wrong_semantic_format_fails_closed(self) -> None:
        """M33B-03: a non-STIX semantic-format context is a ConversionError."""
        decoded = fixtures.stix_domain_name()
        with pytest.raises(ConversionError, match="semantic-format"):
            Stix21ToEvidenceConverter().convert(
                _object(decoded),
                _conversion_context(semantic_format=SemanticFormatId.MISP),
            )

    def test_m33b_04_non_mitre_source_accepted(self) -> None:
        """M33B-04: STIX under a non-MITRE source identity is accepted.

        STIX is a shared open semantic model; future TAXII sources may carry
        it under any ATI source namespace. There is deliberately no fixed
        ``SourceId`` guard in the STIX converter.
        """
        (converted,) = _convert_single(
            fixtures.stix_domain_name(),
            _conversion_context(source_id=SourceId.CISA_KEV),
        )
        assert converted.evidence.source == SourceId.CISA_KEV.value

    def test_repeat_conversion_structurally_equal(self) -> None:
        """Identical conversion is repeatably structural-equal."""
        converter = Stix21ToEvidenceConverter()
        decoded = fixtures.stix_domain_name()
        context = _conversion_context()
        assert converter.convert(_object(decoded), context) == converter.convert(
            _object(decoded), context
        )


class TestIdentityProvenance:
    """M33B-05..10: stable global Evidence identity and provenance."""

    def test_m33b_05_repeated_conversion_same_evidence_uuid(self) -> None:
        """M33B-05: converting the same object twice yields the same UUID."""
        (first,) = _convert_single(fixtures.stix_domain_name())
        (second,) = _convert_single(fixtures.stix_domain_name())
        assert first.evidence.id == second.evidence.id

    def test_m33b_06_later_modified_same_evidence_uuid(self) -> None:
        """M33B-06: a later ``modified`` never changes the Evidence identity."""
        (first,) = _convert_single(fixtures.stix_indicator())
        (second,) = _convert_single(
            fixtures.stix_indicator(modified="2026-02-01T00:00:00Z")
        )
        assert (
            first.evidence.id
            == second.evidence.id
            == _expected_evidence_id(fixtures.INDICATOR_ID)
        )
        assert (
            _thaw_facts(first.observation)["stix"]["modified"]
            != _thaw_facts(second.observation)["stix"]["modified"]
        )

    def test_m33b_07_different_source_namespace_different_uuid(self) -> None:
        """M33B-07: the source namespace is part of the Evidence identity."""
        (a,) = _convert_single(
            fixtures.stix_domain_name(),
            _conversion_context(source_id=SourceId.CISA_KEV),
        )
        (b,) = _convert_single(
            fixtures.stix_domain_name(), _conversion_context(source_id=SourceId.MISP)
        )
        assert a.evidence.id != b.evidence.id
        assert a.evidence.id == _expected_evidence_id(
            fixtures.DOMAIN_ID, SourceId.CISA_KEV
        )
        assert b.evidence.id == _expected_evidence_id(fixtures.DOMAIN_ID, SourceId.MISP)

    def test_m33b_08_source_record_id_is_exact_stix_id(self) -> None:
        """M33B-08: source_record_id is the exact STIX ``id``, verbatim."""
        for decoded in (
            fixtures.stix_domain_name(),
            fixtures.stix_indicator(),
        ):
            (converted,) = _convert_single(decoded)
            assert converted.evidence.source_record_id == decoded["id"]
            assert converted.evidence.id == _expected_evidence_id(decoded["id"])

    def test_m33b_09_retrieval_time_only_change_same_identity(self) -> None:
        """M33B-09: retrieval-time-only change never changes Evidence identity."""
        (a,) = _convert_single(fixtures.stix_domain_name())
        later = datetime(2026, 7, 1, 9, 0, 0, tzinfo=UTC)
        (b,) = _convert_single(
            fixtures.stix_domain_name(), _conversion_context(retrieved_at=later)
        )
        assert a.evidence.id == b.evidence.id
        assert b.observation.retrieved_at == later

    def test_m33b_10_no_investigation_or_subject_identity(self) -> None:
        """M33B-10: output carries no Investigation or subject identity."""
        (converted,) = _convert_single(fixtures.stix_indicator())
        assert not hasattr(converted.evidence, "investigation_id")
        assert not hasattr(converted.evidence, "subject")
        assert not hasattr(converted.observation, "investigation_id")
        assert not hasattr(converted.observation, "subject")


class TestDirectScos:
    """M33B-11..20: direct SCO profile through existing canonicalizers."""

    def test_m33b_11_domain_one_canonical_domain_ioc(self) -> None:
        """M33B-11: domain-name maps to one canonical DOMAIN IOC fact."""
        (converted,) = _convert_single(fixtures.stix_domain_name())
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [{"type": "domain", "value": fixtures.DOMAIN_VALUE}]
        assert facts["stix"]["type"] == "domain-name"

    def test_m33b_12_mixed_case_root_dot_domain_canonicalized(self) -> None:
        """M33B-12: mixed-case/root-dot domains canonicalize via the helper."""
        (converted,) = _convert_single(
            fixtures.stix_domain_name(value=fixtures.MIXED_CASE_DOMAIN_VALUE)
        )
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [{"type": "domain", "value": "example.test"}]

    def test_m33b_13_idna_domain_canonicalized(self) -> None:
        """M33B-13: IDNA domains canonicalize to their punycode form."""
        (converted,) = _convert_single(
            fixtures.stix_domain_name(value=fixtures.UNICODE_DOMAIN_VALUE)
        )
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [{"type": "domain", "value": "xn--bcher-kva.example"}]

    def test_m33b_14_malformed_domain_is_conversion_error(self) -> None:
        """M33B-14: a supported SCO with a malformed domain fails closed."""
        with pytest.raises(ConversionError, match="DNS"):
            _convert_single(fixtures.stix_domain_name(value="bad domain.test"))

    def test_m33b_15_ipv4_canonicalized(self) -> None:
        """M33B-15: ipv4-addr maps to one canonical IP_ADDRESS IOC."""
        (converted,) = _convert_single(fixtures.stix_ipv4_addr())
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [{"type": "ip_address", "value": fixtures.IPV4_VALUE}]

    def test_m33b_16_malformed_ipv4_is_conversion_error(self) -> None:
        """M33B-16: a malformed IPv4 value is a bounded ConversionError."""
        with pytest.raises(ConversionError, match="IP"):
            _convert_single(fixtures.stix_ipv4_addr(value="999.1.1.1"))

    def test_m33b_17_ipv4_object_with_ipv6_fails_closed(self) -> None:
        """M33B-17: an ipv4-addr containing IPv6 is a ConversionError."""
        with pytest.raises(ConversionError, match="family"):
            _convert_single(fixtures.stix_ipv4_addr(value=fixtures.IPV6_VALUE))

    def test_m33b_18_ipv6_compressed_canonical_form(self) -> None:
        """M33B-18: an expanded IPv6 canonicalizes to its compressed form."""
        (converted,) = _convert_single(
            fixtures.stix_ipv6_addr(value=fixtures.EXPANDED_IPV6_VALUE)
        )
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [{"type": "ip_address", "value": fixtures.IPV6_VALUE}]

    def test_m33b_19_malformed_ipv6_is_conversion_error(self) -> None:
        """M33B-19: a malformed IPv6 value is a bounded ConversionError."""
        with pytest.raises(ConversionError, match="IP"):
            _convert_single(fixtures.stix_ipv6_addr(value="2001:db8:::1"))

    def test_m33b_20_ipv6_object_with_ipv4_fails_closed(self) -> None:
        """M33B-20: an ipv6-addr containing IPv4 is a ConversionError."""
        with pytest.raises(ConversionError, match="family"):
            _convert_single(fixtures.stix_ipv6_addr(value="192.0.2.1"))

    def test_scos_share_one_evidence_profile(self) -> None:
        """All three SCOs produce one THREAT_INTELLIGENCE Evidence each."""
        for decoded in (
            fixtures.stix_domain_name(),
            fixtures.stix_ipv4_addr(),
            fixtures.stix_ipv6_addr(),
        ):
            (converted,) = _convert_single(decoded)
            assert converted.evidence.type is EvidenceType.THREAT_INTELLIGENCE
            assert converted.observation.raw_payload is None
            assert converted.observation.observed_at is None


class TestUnsupportedObjects:
    """M33B-21..25: valid unsupported STIX objects yield zero Evidence."""

    @pytest.mark.parametrize(
        "decoded",
        [
            fixtures.stix_malware(),
            fixtures.stix_relationship(),
            fixtures.stix_sighting(),
            fixtures.stix_attack_pattern(),
            fixtures.stix_custom(),
        ],
    )
    def test_m33b_21_25_unsupported_objects_zero(self, decoded: dict[str, Any]) -> None:
        """M33B-21..25: valid unsupported object types produce zero Evidence."""
        assert _convert_single(decoded) == ()

    def test_m33b_21_malware_zero(self) -> None:
        """M33B-21: a valid malware object produces zero Evidence."""
        assert _convert_single(fixtures.stix_malware()) == ()

    def test_m33b_22_relationship_zero(self) -> None:
        """M33B-22: a valid relationship produces zero Evidence."""
        assert _convert_single(fixtures.stix_relationship()) == ()

    def test_m33b_23_sighting_zero(self) -> None:
        """M33B-23: a valid sighting produces zero Evidence."""
        assert _convert_single(fixtures.stix_sighting()) == ()

    def test_m33b_24_attack_pattern_zero(self) -> None:
        """M33B-24: a valid attack-pattern produces zero Evidence."""
        assert _convert_single(fixtures.stix_attack_pattern()) == ()

    def test_m33b_25_custom_type_zero(self) -> None:
        """M33B-25: a valid custom object type produces zero Evidence."""
        assert _convert_single(fixtures.stix_custom()) == ()


class TestIndicatorProfile:
    """M33B-26..48: Indicator equality-only whitelist conversion."""

    def test_m33b_26_single_domain_equality(self) -> None:
        """M33B-26: one domain equality maps to one canonical IOC fact."""
        (converted,) = _convert_single(fixtures.stix_indicator())
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [{"type": "domain", "value": fixtures.DOMAIN_VALUE}]

    def test_m33b_27_single_ipv4_equality(self) -> None:
        """M33B-27: one IPv4 equality maps to one canonical IOC fact."""
        (converted,) = _convert_single(
            fixtures.stix_indicator(pattern=fixtures.SINGLE_IPV4_PATTERN)
        )
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [{"type": "ip_address", "value": fixtures.IPV4_VALUE}]

    def test_m33b_28_single_ipv6_equality(self) -> None:
        """M33B-28: one IPv6 equality maps to one canonical IOC fact."""
        (converted,) = _convert_single(
            fixtures.stix_indicator(pattern=fixtures.SINGLE_IPV6_PATTERN)
        )
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [{"type": "ip_address", "value": fixtures.IPV6_VALUE}]

    def test_m33b_29_approved_or_preserves_left_to_right(self) -> None:
        """M33B-29: approved OR preserves deterministic left-to-right order."""
        pattern = "[ipv4-addr:value = '203.0.113.42'] OR [domain-name:value = 'a.test']"
        (converted,) = _convert_single(fixtures.stix_indicator(pattern=pattern))
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [
            {"type": "ip_address", "value": "203.0.113.42"},
            {"type": "domain", "value": "a.test"},
        ]

    def test_m33b_30_approved_and_preserves_order(self) -> None:
        """M33B-30: approved AND preserves deterministic left-to-right order."""
        pattern = "[domain-name:value = 'a.test' AND ipv4-addr:value = '203.0.113.42']"
        (converted,) = _convert_single(fixtures.stix_indicator(pattern=pattern))
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [
            {"type": "domain", "value": "a.test"},
            {"type": "ip_address", "value": "203.0.113.42"},
        ]

    def test_m33b_31_nested_approved_parentheses_deterministic(self) -> None:
        """M33B-31: nested approved parentheses are deterministic."""
        pattern = (
            "[domain-name:value = 'a.test' AND "
            "(ipv4-addr:value = '203.0.113.42' OR ipv6-addr:value = '2001:db8::42')]"
        )
        (converted,) = _convert_single(fixtures.stix_indicator(pattern=pattern))
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [
            {"type": "domain", "value": "a.test"},
            {"type": "ip_address", "value": "203.0.113.42"},
            {"type": "ip_address", "value": "2001:db8::42"},
        ]

    def test_m33b_32_duplicate_leaves_preserved(self) -> None:
        """M33B-32: exact duplicate leaves are preserved, never deduplicated."""
        pattern = (
            "[ipv4-addr:value = '203.0.113.42' OR ipv4-addr:value = '203.0.113.42']"
        )
        (converted,) = _convert_single(fixtures.stix_indicator(pattern=pattern))
        facts = _thaw_facts(converted.observation)
        assert facts["iocs"] == [
            {"type": "ip_address", "value": "203.0.113.42"},
            {"type": "ip_address", "value": "203.0.113.42"},
        ]

    def test_m33b_33_malformed_pattern_is_conversion_error(self) -> None:
        """M33B-33: a syntactically malformed pattern is a ConversionError."""
        with pytest.raises(ConversionError, match="Patterning"):
            _convert_single(fixtures.stix_indicator(pattern="domain-name:value = 'x'"))

    def test_m33b_34_matches_valid_unsupported(self) -> None:
        """M33B-34: a valid MATCHES pattern produces zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_indicator(pattern="[domain-name:value MATCHES '^evil']")
            )
            == ()
        )

    def test_m33b_35_like_valid_unsupported(self) -> None:
        """M33B-35: a valid LIKE pattern produces zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_indicator(pattern="[domain-name:value LIKE 'a%']")
            )
            == ()
        )

    def test_m33b_36_subset_superset_valid_unsupported(self) -> None:
        """M33B-36: ISSUBSET/ISSUPERSET patterns produce zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_indicator(
                    pattern="[ipv4-addr:value ISSUBSET '203.0.113.0/24']"
                )
            )
            == ()
        )
        assert (
            _convert_single(
                fixtures.stix_indicator(
                    pattern="[ipv4-addr:value ISSUPERSET '10.0.0.0/8']"
                )
            )
            == ()
        )

    def test_m33b_37_inequality_valid_unsupported(self) -> None:
        """M33B-37: inequality/range patterns produce zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_indicator(pattern="[domain-name:value > 'aaa']")
            )
            == ()
        )
        assert (
            _convert_single(
                fixtures.stix_indicator(pattern="[domain-name:value != 'a.test']")
            )
            == ()
        )

    def test_m33b_38_file_hash_valid_unsupported(self) -> None:
        """M33B-38: a file hash comparison produces zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_indicator(pattern="[file:hashes.'SHA-256' = 'abc123']")
            )
            == ()
        )

    def test_m33b_39_url_comparison_valid_unsupported(self) -> None:
        """M33B-39: a URL comparison produces zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_indicator(pattern="[url:value = 'https://example.test']")
            )
            == ()
        )

    def test_m33b_40_mixed_supported_unsupported_whole_pattern(self) -> None:
        """M33B-40: mixed supported/unsupported patterns convert to zero.

        No supported leaf is ever partially extracted from an unsupported
        whole pattern.
        """
        assert (
            _convert_single(
                fixtures.stix_indicator(
                    pattern="[domain-name:value = 'a.test' AND file:name = 'x.exe']"
                )
            )
            == ()
        )

    def test_m33b_41_followedby_temporal_valid_unsupported(self) -> None:
        """M33B-41: FOLLOWEDBY/temporal chains produce zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_indicator(
                    pattern="[domain-name:value = 'a.test'] FOLLOWEDBY "
                    "[ipv4-addr:value = '203.0.113.42']"
                )
            )
            == ()
        )

    def test_m33b_42_qualifiers_valid_unsupported(self) -> None:
        """M33B-42: WITHIN/START-STOP/REPEATS qualifiers produce zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_indicator(
                    pattern="[domain-name:value = 'a.test'] WITHIN 5 SECONDS"
                )
            )
            == ()
        )
        assert (
            _convert_single(
                fixtures.stix_indicator(
                    pattern="[domain-name:value = 'a.test'] REPEATS 3 TIMES"
                )
            )
            == ()
        )

    def test_m33b_43_indexed_wildcard_extension_path_unsupported(self) -> None:
        """M33B-43: indexed/wildcard/extension paths produce zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_indicator(pattern="[ipv4-addr:value[0] = 'x']")
            )
            == ()
        )
        assert (
            _convert_single(
                fixtures.stix_indicator(pattern="[ipv4-addr:value[*] = 'x']")
            )
            == ()
        )
        assert (
            _convert_single(
                fixtures.stix_indicator(pattern="[x-org:custom_property = 'x']")
            )
            == ()
        )

    def test_m33b_44_non_string_literal_unsupported(self) -> None:
        """M33B-44: a non-string comparison literal produces zero Evidence."""
        assert (
            _convert_single(fixtures.stix_indicator(pattern="[domain-name:value = 42]"))
            == ()
        )

    def test_m33b_45_wrong_pattern_type_valid_unsupported(self) -> None:
        """M33B-45: a non-STIX pattern_type produces zero Evidence."""
        assert (
            _convert_single(
                fixtures.stix_indicator(
                    pattern='rule evil { strings: $a = "x" condition: $a }',
                    pattern_type="yara",
                )
            )
            == ()
        )

    def test_m33b_46_missing_or_non_string_pattern_fails_closed(self) -> None:
        """M33B-46: stix-typed Indicators need a nonblank string pattern."""
        with pytest.raises(ConversionError, match="pattern"):
            _convert_single(
                fixtures.stix_indicator(pattern=None)  # type: ignore[arg-type]
            )
        with pytest.raises(ConversionError, match="pattern"):
            _convert_single(fixtures.stix_indicator(pattern=123))  # type: ignore[arg-type]
        with pytest.raises(ConversionError, match="pattern"):
            _convert_single(fixtures.stix_indicator(pattern="   "))

    def test_m33b_47_admitted_path_malformed_ioc_value_fails_closed(self) -> None:
        """M33B-47: a malformed value in an admitted comparison is an error."""
        with pytest.raises(ConversionError, match="DNS"):
            _convert_single(
                fixtures.stix_indicator(
                    pattern="[domain-name:value = 'bad value.test']"
                )
            )
        with pytest.raises(ConversionError, match="family"):
            _convert_single(
                fixtures.stix_indicator(pattern="[ipv4-addr:value = '2001:db8::1']")
            )

    def test_m33b_48_original_pattern_preserved_exactly(self) -> None:
        """M33B-48: the original pattern string is preserved verbatim."""
        pattern = "[domain-name:value='a.test'  AND   ipv4-addr:value='203.0.113.42']"
        (converted,) = _convert_single(fixtures.stix_indicator(pattern=pattern))
        facts = _thaw_facts(converted.observation)
        assert facts["indicator"]["pattern"] == pattern

    def test_m33b_72_multileaf_indicator_one_evidence(self) -> None:
        """M33B-72: a multi-leaf Indicator is still exactly one Evidence."""
        pattern = (
            "[domain-name:value = 'a.test' AND ipv4-addr:value = '203.0.113.42' "
            "AND ipv6-addr:value = '2001:db8::42']"
        )
        converted = _convert_single(fixtures.stix_indicator(pattern=pattern))
        assert len(converted) == 1
        (single,) = converted
        facts = _thaw_facts(single.observation)
        assert len(facts["iocs"]) == 3


class TestFactsProvenance:
    """M33B-49..66: exact normalized facts and provenance contract."""

    def test_m33b_49_exact_common_fact_key_set(self) -> None:
        """M33B-49: the common STIX fact key set is exact and ordered."""
        (converted,) = _convert_single(fixtures.stix_indicator())
        facts = _thaw_facts(converted.observation)
        assert list(facts.keys()) == [
            "stix",
            "indicator",
            "iocs",
            "cti_entity",
            "source_assertion",
        ]
        assert facts["source_assertion"] is None
        assert list(facts["stix"].keys()) == [
            "id",
            "type",
            "spec_version",
            "created",
            "modified",
            "revoked",
            "labels",
            "confidence",
            "lang",
            "external_references",
            "object_marking_refs",
            "granular_markings",
            "defanged",
        ]

    def test_m33b_50_exact_indicator_fact_key_set(self) -> None:
        """M33B-50: the Indicator fact key set is exact and ordered."""
        (converted,) = _convert_single(fixtures.stix_indicator())
        facts = _thaw_facts(converted.observation)
        assert list(facts["indicator"].keys()) == [
            "pattern",
            "pattern_type",
            "pattern_version",
            "valid_from",
            "valid_until",
            "indicator_types",
        ]

    def test_m33b_51_id_type_spec_version_preserved(self) -> None:
        """M33B-51: STIX id/type/spec_version are preserved as source facts."""
        (converted,) = _convert_single(
            fixtures.stix_indicator(
                id="indicator--9f000000-0000-4000-8000-000000000009"
            )
        )
        facts = _thaw_facts(converted.observation)
        assert facts["stix"]["id"] == "indicator--9f000000-0000-4000-8000-000000000009"
        assert facts["stix"]["type"] == "indicator"
        assert facts["stix"]["spec_version"] == "2.1"

    def test_m33b_52_created_modified_normalized(self) -> None:
        """M33B-52: created/modified normalize to canonical UTC Z form."""
        (converted,) = _convert_single(
            fixtures.stix_indicator(
                created="2026-01-01T00:00:00.123456+01:00",
                modified="2026-01-02T00:00:00+00:00",
            )
        )
        facts = _thaw_facts(converted.observation)
        assert facts["stix"]["created"] == "2025-12-31T23:00:00Z"
        assert facts["stix"]["modified"] == "2026-01-02T00:00:00Z"

    def test_m33b_53_valid_from_until_normalized(self) -> None:
        """M33B-53: valid_from/valid_until normalize to canonical UTC Z form."""
        (converted,) = _convert_single(
            fixtures.stix_indicator(
                valid_from="2026-01-03T00:00:00+00:00",
                valid_until="2026-04-01T00:00:00Z",
            )
        )
        facts = _thaw_facts(converted.observation)
        assert facts["indicator"]["valid_from"] == "2026-01-03T00:00:00Z"
        assert facts["indicator"]["valid_until"] == "2026-04-01T00:00:00Z"

    def test_m33b_54_marking_refs_preserved_not_dereferenced(self) -> None:
        """M33B-54: object_marking_refs are preserved, never dereferenced."""
        (converted,) = _convert_single(fixtures.stix_indicator())
        facts = _thaw_facts(converted.observation)
        assert facts["stix"]["object_marking_refs"] == [_MARKING_REF]
        assert "tlp" not in str(facts["stix"]["object_marking_refs"]).lower()

    def test_m33b_55_granular_markings_preserved_not_enforced(self) -> None:
        """M33B-55: granular_markings are preserved, never enforced."""
        granular = [
            {
                "marking_ref": "marking-definition--5e57c739-391a-4eb3-b6be-7d15caoshobo",
                "selectors": ["labels.0"],
            }
        ]
        (converted,) = _convert_single(
            fixtures.stix_indicator(granular_markings=granular)
        )
        facts = _thaw_facts(converted.observation)
        assert facts["stix"]["granular_markings"] == granular

    def test_m33b_56_confidence_preserved_as_source_fact_only(self) -> None:
        """M33B-56: confidence stays a source fact; no ATI confidence exists."""
        (converted,) = _convert_single(fixtures.stix_indicator(confidence=75))
        facts = _thaw_facts(converted.observation)
        assert facts["stix"]["confidence"] == 75
        assert "confidence" not in facts["iocs"][0]
        assert set(facts["iocs"][0].keys()) == {"type", "value"}

    def test_m33b_57_labels_indicator_types_order_preserved(self) -> None:
        """M33B-57: labels/indicator_types keep their source order."""
        labels = ["osint", "apt", "osint"]
        indicator_types = ["malicious-activity", "anomalous-activity"]
        (converted,) = _convert_single(
            fixtures.stix_indicator(
                labels=labels,
                indicator_types=indicator_types,
            )
        )
        facts = _thaw_facts(converted.observation)
        assert facts["stix"]["labels"] == labels
        assert facts["indicator"]["indicator_types"] == indicator_types

    def test_m33b_58_external_references_preserved(self) -> None:
        """M33B-58: external_references are preserved without interpretation."""
        references = [
            {
                "source_name": "synthetic-doc",
                "url": "https://docs.example.test/note",
                "external_id": "X-0001",
            }
        ]
        (converted,) = _convert_single(
            fixtures.stix_indicator(external_references=references)
        )
        facts = _thaw_facts(converted.observation)
        assert facts["stix"]["external_references"] == references

    def test_m33b_59_defanged_behavior_pinned(self) -> None:
        """M33B-59: SCO defanged is a preserved optional boolean fact."""
        (plain,) = _convert_single(fixtures.stix_domain_name())
        assert _thaw_facts(plain.observation)["stix"]["defanged"] is None
        (marked,) = _convert_single(
            fixtures.stix_domain_name(value="defanged.example.test", defanged=True)
        )
        assert _thaw_facts(marked.observation)["stix"]["defanged"] is True
        (clean,) = _convert_single(fixtures.stix_domain_name(defanged=False))
        assert _thaw_facts(clean.observation)["stix"]["defanged"] is False

    def test_m33b_60_observed_at_is_none(self) -> None:
        """M33B-60: observed_at is None; STIX timestamps never conflate."""
        for decoded in (
            fixtures.stix_domain_name(),
            fixtures.stix_indicator(),
        ):
            (converted,) = _convert_single(decoded)
            assert converted.observation.observed_at is None

    def test_m33b_61_retrieved_at_exact_context_time(self) -> None:
        """M33B-61: retrieved_at is the exact context retrieval time."""
        (converted,) = _convert_single(fixtures.stix_indicator())
        assert converted.observation.retrieved_at == _FIXED_TS
        assert converted.observation.retrieved_at.utcoffset() == timedelta(0)

    def test_m33b_62_source_url_exact_context_reference(self) -> None:
        """M33B-62: source_url is the exact credential-free context reference."""
        (converted,) = _convert_single(fixtures.stix_indicator())
        assert converted.observation.source_url == _SOURCE_REFERENCE

    def test_m33b_63_raw_payload_is_none(self) -> None:
        """M33B-63: the candidate never carries a raw payload."""
        (converted,) = _convert_single(fixtures.stix_indicator())
        assert converted.observation.raw_payload is None

    def test_m33b_64_output_and_facts_immutable(self) -> None:
        """M33B-64: Evidence and observation candidates are deeply immutable."""
        (converted,) = _convert_single(fixtures.stix_indicator())
        with pytest.raises(ValidationError):
            converted.evidence.source_record_id = "mutated"
        assert isinstance(converted.observation.facts, FrozenDict)
        with pytest.raises(TypeError):
            converted.observation.facts["stix"] = "mutated"
        with pytest.raises(TypeError):
            converted.observation.facts["iocs"][0]["value"] = "mutated"

    def test_m33b_65_no_verdict_risk_relationship_synthesis(self) -> None:
        """M33B-65: no verdict/risk/attribution/relationship semantics exist."""
        (converted,) = _convert_single(fixtures.stix_indicator())
        facts = _thaw_facts(converted.observation)
        assert set(facts.keys()) == {
            "stix",
            "indicator",
            "iocs",
            "cti_entity",
            "source_assertion",
        }
        assert facts["source_assertion"] is None
        assert all(set(ioc.keys()) == {"type", "value"} for ioc in facts["iocs"])
        flattened = str(facts).lower()
        for banned in (
            "verdict",
            "malicious_score",
            "risk",
            "attribution",
            "relationship",
            "pivot",
            "probability",
            "sighting",
        ):
            assert banned not in flattened

    def test_m33b_66_errors_never_echo_source_content(self) -> None:
        """M33B-66: bounded errors never echo IOC/pattern/source content."""
        secret_domain = "very-secret-domain.test"
        with pytest.raises(ConversionError) as error:
            _convert_single(fixtures.stix_domain_name(value=f"bad {secret_domain}"))
        assert secret_domain not in str(error.value)
        secret_pattern = "[secret pattern : value = 'x']"
        with pytest.raises(ConversionError) as error:
            _convert_single(fixtures.stix_indicator(pattern=secret_pattern))
        assert "secret" not in str(error.value)
        assert _SOURCE_REFERENCE not in str(error.value)


class TestRegistryGenericSeamIsolation:
    """M33B-67..78: registry, generic seam, and module isolation."""

    def test_m33b_67_registry_lookup_by_semantic_format(self) -> None:
        """M33B-67: registry lookup selects the STIX converter by format only."""
        registry = build_stix21_conversion_registry()
        converter = registry.get(SemanticFormatId.STIX_21)
        assert isinstance(converter, Stix21ToEvidenceConverter)
        with pytest.raises(UnknownSemanticFormatError):
            registry.get(SemanticFormatId.MISP)
        with pytest.raises(UnknownSemanticFormatError):
            registry.get(SemanticFormatId.THREATFOX)

    def test_m33b_68_registry_factory_independent_deterministic(self) -> None:
        """M33B-68: factory calls are independent and structural-equal."""
        first = build_stix21_conversion_registry()
        second = build_stix21_conversion_registry()
        assert first.get(SemanticFormatId.STIX_21).semantic_format is (
            SemanticFormatId.STIX_21
        )
        assert second.get(SemanticFormatId.STIX_21).semantic_format is (
            SemanticFormatId.STIX_21
        )
        (a,) = convert_semantic_source_objects(
            (_object(fixtures.stix_domain_name()),),
            _conversion_context(),
            first,
        )
        (b,) = convert_semantic_source_objects(
            (_object(fixtures.stix_domain_name()),),
            _conversion_context(),
            second,
        )
        assert a == b

    def test_m33b_69_supported_order_preserved_through_generic_seam(self) -> None:
        """M33B-69: supported objects keep source order across unsupported ones."""
        remote = convert_semantic_source_objects(
            (
                _object(fixtures.stix_domain_name()),
                _object(fixtures.stix_malware()),
                _object(fixtures.stix_indicator()),
                _object(fixtures.stix_relationship()),
                _object(fixtures.stix_ipv4_addr()),
            ),
            _conversion_context(),
            build_stix21_conversion_registry(),
        )
        assert [r.evidence.source_record_id for r in remote] == [
            fixtures.DOMAIN_ID,
            fixtures.INDICATOR_ID,
            fixtures.IPV4_ID,
        ]

    def test_m33b_70_all_unsupported_empty_success(self) -> None:
        """M33B-70: all-unsupported input converts to empty success, no error."""
        remote = convert_semantic_source_objects(
            (
                _object(fixtures.stix_malware()),
                _object(fixtures.stix_relationship()),
                _object(fixtures.stix_sighting()),
            ),
            _conversion_context(),
            build_stix21_conversion_registry(),
        )
        assert remote == ()

    def test_m33b_71_malformed_after_valid_raises_no_partial(self) -> None:
        """M33B-71: a malformed supported object aborts without partial output."""
        with pytest.raises(ConversionError):
            convert_semantic_source_objects(
                (
                    _object(fixtures.stix_domain_name()),
                    _object(fixtures.stix_indicator(pattern="not a pattern [")),
                ),
                _conversion_context(),
                build_stix21_conversion_registry(),
            )

    def test_m33b_73_converter_module_no_io_imports(self) -> None:
        """M33B-73: the converter module has no HTTP/DB/broker/orchestration imports."""
        source = inspect.getsource(stix21_evidence)
        for banned in (
            "import httpx",
            "from httpx",
            "import requests",
            "import sqlalchemy",
            "from sqlalchemy",
            "import psycopg",
            "import aiokafka",
            "from aiokafka",
            "import fastapi",
            "from fastapi",
            "import langchain",
            "import langgraph",
            "import aiohttp",
            "import socket",
            "import urllib",
            "import asyncio",
            "async def",
            "await ",
            "import random",
            "import time",
            "import secrets",
            "import os",
        ):
            assert banned not in source

    def test_m33b_74_semantic_module_evidence_independent(self) -> None:
        """M33B-74: stix21_semantics stays Evidence- and conversion-independent."""
        # No bound module attribute is an Evidence/conversion dependency and
        # no declared name carries Evidence/converter integration.
        banned_modules = {
            "agentic_threat_investigator.domain.evidence",
            "agentic_threat_investigator.app.evidence_conversion",
            "agentic_threat_investigator.infrastructure.datasources.stix21_evidence",
            "agentic_threat_investigator.infrastructure.datasources.stix21_pattern",
        }
        bound_modules = {
            str(value.__name__)
            for value in vars(stix21_semantics).values()
            if inspect.ismodule(value)
        }
        assert not (bound_modules & banned_modules)
        assert not any(
            "evidence" in name.lower() or "convert" in name.lower()
            for name in vars(stix21_semantics)
        )

    def test_m33b_75_no_regex_grammar_implementation(self) -> None:
        """M33B-75: no regex/string-splitting pattern grammar exists."""
        source = inspect.getsource(stix21_pattern)
        assert "import re" not in source
        assert ".split(" not in source
        assert "stix2patterns" in source

    def test_m33b_76_pattern_adapter_no_network_clock_random(self) -> None:
        """M33B-76: the pattern adapter has no network/clock/random behavior."""
        source = inspect.getsource(stix21_pattern)
        for banned in (
            "import httpx",
            "import requests",
            "import socket",
            "import urllib",
            "import aiohttp",
            "import time",
            "import random",
            "import secrets",
            "import os",
            "datetime",
            "async def",
            "await ",
        ):
            assert banned not in source

    def test_m33b_77_lockfile_contains_approved_bounded_dependency(self) -> None:
        """M33B-77: the bounded parser dependency is present in pyproject+lock."""
        pyproject = (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        lockfile = (_REPO_ROOT / "uv.lock").read_text(encoding="utf-8")
        assert "stix2-patterns>=2.1.2,<3" in pyproject
        assert 'name = "stix2-patterns"' in lockfile
        assert 'name = "antlr4-python3-runtime"' in lockfile

    def test_m33b_78_mitre_batch_isolation_unaffected(self) -> None:
        """M33B-78: MITRE batch normalization stays independent of the converter."""
        evidence_source = inspect.getsource(stix21_evidence)
        assert "mitre_attack" not in evidence_source
        mitre_source = (
            _REPO_ROOT
            / "src/agentic_threat_investigator/infrastructure/sources/mitre_attack.py"
        )
        mitre_text = mitre_source.read_text(encoding="utf-8")
        assert "stix21_evidence" not in mitre_text
        assert "ToEvidenceConverter" not in mitre_text


class TestFactBuilders:
    """Direct pinning of the small pure fact-builder helpers."""

    def test_common_builder_explicit_optional_none(self) -> None:
        """Absent optional scalars render as explicit None."""
        facts = build_stix_common_facts(
            _object(fixtures.stix_domain_name()).source_value()
        )
        assert facts["created"] is None
        assert facts["confidence"] is None
        assert facts["spec_version"] == "2.1"

    def test_list_fields_default_to_empty(self) -> None:
        """Absent modeled list fields render as []."""
        facts = build_stix_common_facts(
            _object(fixtures.stix_domain_name()).source_value()
        )
        assert facts["labels"] == []
        assert facts["external_references"] == []
        assert facts["object_marking_refs"] == []
        assert facts["granular_markings"] == []

    def test_indicator_builder_preserves_original_pattern(self) -> None:
        """The Indicator builder preserves the original pattern exactly."""
        pattern = "[domain-name:value = 'a.test']"
        facts = build_stix_indicator_facts(
            _object(fixtures.stix_indicator(pattern=pattern)).source_value()
        )
        assert facts["pattern"] == pattern

    def test_normalized_builder_composes_blocks(self) -> None:
        """The normalized builder composes stix/indicator-or-None/iocs."""
        source = _object(fixtures.stix_indicator())
        facts = build_stix_normalized_facts(
            source,
            ({"type": "domain", "value": "example.test"},),
        )
        assert facts["indicator"]["pattern"] == fixtures.SINGLE_DOMAIN_PATTERN
        assert facts["iocs"] == [{"type": "domain", "value": "example.test"}]
        sco = _object(fixtures.stix_domain_name())
        sco_facts = build_stix_normalized_facts(
            sco,
            ({"type": "domain", "value": "example.test"},),
        )
        assert sco_facts["indicator"] is None

    def test_extract_ioc_facts_dispatch(self) -> None:
        """extract_stix_ioc_facts dispatches exactly by supported type."""
        assert extract_stix_ioc_facts(_object(fixtures.stix_domain_name())) == (
            {"type": "domain", "value": fixtures.DOMAIN_VALUE},
        )
        assert extract_stix_ioc_facts(_object(fixtures.stix_malware())) == ()
        pattern = "[domain-name:value = 'a.test' AND ipv4-addr:value = '203.0.113.42']"
        assert extract_stix_ioc_facts(
            _object(fixtures.stix_indicator(pattern=pattern))
        ) == (
            {"type": "domain", "value": "a.test"},
            {"type": "ip_address", "value": "203.0.113.42"},
        )


class TestVerticalSlices:
    """M33B-V01..V06: real PR 33A + pattern parser + generic seam slices."""

    def test_m33b_v01_direct_scos_through_real_seams(self) -> None:
        """M33B-V01: three direct SCOs convert in order through real seams."""
        converted = convert_semantic_source_objects(
            (
                _object(fixtures.stix_domain_name()),
                _object(fixtures.stix_ipv4_addr()),
                _object(fixtures.stix_ipv6_addr()),
            ),
            _conversion_context(),
            build_stix21_conversion_registry(),
        )
        assert len(converted) == 3
        assert [r.evidence.source_record_id for r in converted] == [
            fixtures.DOMAIN_ID,
            fixtures.IPV4_ID,
            fixtures.IPV6_ID,
        ]
        assert [r.evidence.id for r in converted] == [
            _expected_evidence_id(fixtures.DOMAIN_ID),
            _expected_evidence_id(fixtures.IPV4_ID),
            _expected_evidence_id(fixtures.IPV6_ID),
        ]
        assert [_thaw_facts(r.observation)["iocs"] for r in converted] == [
            [{"type": "domain", "value": fixtures.DOMAIN_VALUE}],
            [{"type": "ip_address", "value": fixtures.IPV4_VALUE}],
            [{"type": "ip_address", "value": fixtures.IPV6_VALUE}],
        ]
        for result in converted:
            assert result.observation.retrieved_at == _FIXED_TS
            assert result.observation.source_url == _SOURCE_REFERENCE
            assert result.observation.observed_at is None
            assert result.observation.raw_payload is None

    def test_m33b_v02_supported_indicator_through_real_seams(self) -> None:
        """M33B-V02: one supported Indicator stays one Evidence via real seams."""
        pattern = (
            "[domain-name:value = 'a.test' AND "
            "(ipv4-addr:value = '203.0.113.42' OR ipv6-addr:value = '2001:db8::42')]"
        )
        converted = convert_semantic_source_objects(
            (_object(fixtures.stix_indicator(pattern=pattern)),),
            _conversion_context(),
            build_stix21_conversion_registry(),
        )
        assert len(converted) == 1
        (single,) = converted
        facts = _thaw_facts(single.observation)
        assert facts["indicator"]["pattern"] == pattern
        assert facts["iocs"] == [
            {"type": "domain", "value": "a.test"},
            {"type": "ip_address", "value": "203.0.113.42"},
            {"type": "ip_address", "value": "2001:db8::42"},
        ]
        # No verdict/relationship semantics anywhere in the slice.
        assert set(facts.keys()) == {
            "stix",
            "indicator",
            "iocs",
            "cti_entity",
            "source_assertion",
        }
        assert facts["cti_entity"] is None
        assert facts["source_assertion"] is None

    def test_m33b_v03_mixed_objects_supported_order(self) -> None:
        """M33B-V03: mixed objects yield exactly three outputs in source order."""
        converted = convert_semantic_source_objects(
            (
                _object(fixtures.stix_domain_name()),
                _object(fixtures.stix_malware()),
                _object(fixtures.stix_indicator()),
                _object(fixtures.stix_relationship()),
                _object(fixtures.stix_ipv4_addr()),
            ),
            _conversion_context(),
            build_stix21_conversion_registry(),
        )
        assert [r.evidence.source_record_id for r in converted] == [
            fixtures.DOMAIN_ID,
            fixtures.INDICATOR_ID,
            fixtures.IPV4_ID,
        ]

    def test_m33b_v04_valid_unsupported_indicator_zero(self) -> None:
        """M33B-V04: a valid unsupported Indicator converts to zero, no error."""
        converted = convert_semantic_source_objects(
            (_object(fixtures.stix_indicator(pattern="[file:name = 'x.exe']")),),
            _conversion_context(),
            build_stix21_conversion_registry(),
        )
        assert converted == ()

    def test_m33b_v05_malformed_indicator_bounded_error(self) -> None:
        """M33B-V05: a malformed Indicator raises, with no partial result."""
        with pytest.raises(ConversionError, match="Patterning"):
            convert_semantic_source_objects(
                (_object(fixtures.stix_indicator(pattern="domain-name:value = 'x'")),),
                _conversion_context(),
                build_stix21_conversion_registry(),
            )

    def test_m33b_v06_version_continuity(self) -> None:
        """M33B-V06: same ID/namespace, changed facts keep the same identity."""
        first = convert_semantic_source_objects(
            (_object(fixtures.stix_indicator()),),
            _conversion_context(),
            build_stix21_conversion_registry(),
        )[0]
        second = convert_semantic_source_objects(
            (
                _object(
                    fixtures.stix_indicator(
                        modified="2026-03-01T00:00:00Z",
                        valid_until="2026-09-01T00:00:00Z",
                        labels=["updated"],
                    )
                ),
            ),
            _conversion_context(),
            build_stix21_conversion_registry(),
        )[0]
        assert first.evidence.id == second.evidence.id
        assert first.evidence.source_record_id == second.evidence.source_record_id
        assert first.evidence.source == second.evidence.source
        assert _thaw_facts(first.observation) != _thaw_facts(second.observation)


class TestCtiSdoEvidence:
    """M33C-S01..S22: the five PR 33C CTI SDO Evidence profile."""

    @pytest.mark.parametrize(
        ("decoded", "expected_type", "expected_id"),
        [
            (
                fixtures.stix_threat_actor(),
                "threat_actor",
                fixtures.THREAT_ACTOR_ID,
            ),
            (fixtures.stix_campaign(), "campaign", fixtures.CAMPAIGN_ID),
            (
                fixtures.stix_intrusion_set(),
                "intrusion_set",
                fixtures.INTRUSION_SET_ID,
            ),
            (fixtures.stix_tool(), "tool", fixtures.TOOL_ID),
            (
                fixtures.stix_infrastructure(),
                "infrastructure",
                fixtures.INFRASTRUCTURE_ID,
            ),
        ],
    )
    def test_m33c_s01_d05_exactly_one_evidence(
        self, decoded: dict[str, Any], expected_type: str, expected_id: str
    ) -> None:
        """M33C-S01..05: each supported CTI SDO converts to exactly one Evidence."""
        converted = _convert_single(decoded)
        assert len(converted) == 1
        (single,) = converted
        assert single.evidence.type is EvidenceType.THREAT_INTELLIGENCE
        assert single.evidence.source_record_id == expected_id
        assert single.evidence.id == _expected_evidence_id(expected_id)
        facts = _thaw_facts(single.observation)
        assert facts["cti_entity"]["type"] == expected_type
        assert facts["cti_entity"]["value"] == expected_id
        assert facts["iocs"] == []
        assert facts["indicator"] is None
        assert single.observation.observed_at is None
        assert single.observation.raw_payload is None

    def test_m33c_s06_exact_cti_entity_block_shape(self) -> None:
        """M33C-S06: cti_entity carries exactly type/value/display_name."""
        (converted,) = _convert_single(fixtures.stix_threat_actor())
        facts = _thaw_facts(converted.observation)
        assert set(facts["cti_entity"].keys()) == {
            "type",
            "value",
            "display_name",
        }
        assert facts["cti_entity"] == {
            "type": "threat_actor",
            "value": fixtures.THREAT_ACTOR_ID,
            "display_name": fixtures.THREAT_ACTOR_NAME,
        }

    def test_m33c_s07_name_preserved_exactly_as_display_metadata(self) -> None:
        """M33C-S07: the source name spelling/case is preserved verbatim."""
        name = "  MidNight Blizzard!"
        (converted,) = _convert_single(fixtures.stix_threat_actor(name=name))
        facts = _thaw_facts(converted.observation)
        assert facts["cti_entity"]["display_name"] == name
        assert facts["cti_entity"]["value"] == fixtures.THREAT_ACTOR_ID

    def test_m33c_s08_same_name_different_ids_distinct(self) -> None:
        """M33C-S08: same name + different STIX IDs remain distinct identities."""
        (a,) = _convert_single(fixtures.stix_threat_actor())
        (b,) = _convert_single(
            fixtures.stix_threat_actor(
                id=fixtures.THREAT_ACTOR_2_ID, name=fixtures.THREAT_ACTOR_NAME
            )
        )
        facts_a = _thaw_facts(a.observation)
        facts_b = _thaw_facts(b.observation)
        assert facts_a["cti_entity"]["value"] == fixtures.THREAT_ACTOR_ID
        assert facts_b["cti_entity"]["value"] == fixtures.THREAT_ACTOR_2_ID
        assert (
            facts_a["cti_entity"]["display_name"]
            == facts_b["cti_entity"]["display_name"]
        )
        assert a.evidence.id != b.evidence.id

    @pytest.mark.parametrize(
        "decoded",
        [
            fixtures.stix_threat_actor(id=fixtures.CAMPAIGN_ID),
            fixtures.stix_campaign(id=fixtures.TOOL_ID),
            fixtures.stix_intrusion_set(id=fixtures.INFRASTRUCTURE_ID),
            fixtures.stix_tool(id=fixtures.THREAT_ACTOR_ID),
            fixtures.stix_infrastructure(id=fixtures.CAMPAIGN_ID),
        ],
    )
    def test_m33c_s09_d13_wrong_type_prefix_fails_closed(
        self, decoded: dict[str, Any]
    ) -> None:
        """M33C-S09..13: a mismatched id prefix is a bounded ConversionError."""
        with pytest.raises(ConversionError, match="id"):
            _convert_single(decoded)

    def test_m33c_s14_malformed_id_fails_closed(self) -> None:
        """M33C-S14: a malformed machine ID is a bounded ConversionError."""
        with pytest.raises(ConversionError):
            _convert_single(fixtures.stix_threat_actor(id="threat-actor--not-a-uuid"))
        with pytest.raises(ConversionError):
            _convert_single(
                fixtures.stix_threat_actor(
                    id="threat-actor--11111111-1111-1111-1111-11111111111x"
                )
            )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"name": None},
            {"name": 42},
            {"name": ""},
            {"name": "   "},
            {"name": "x" * 513},
        ],
    )
    def test_m33c_s15_d19_invalid_name_fails_closed(
        self, kwargs: dict[str, Any]
    ) -> None:
        """M33C-S15..19: missing/non-string/blank/over-bound names fail."""
        with pytest.raises(ConversionError, match="name"):
            _convert_single(fixtures.stix_tool(**kwargs))

    def test_m33c_s20_errors_never_echo_source_content(self) -> None:
        """M33C-S20: bounded errors never echo names, ids, or source content."""
        secret_name = "Ultra-Secret-Actor-Name"
        with pytest.raises(ConversionError) as error:
            _convert_single(fixtures.stix_threat_actor(name=secret_name, id="bad"))
        assert secret_name not in str(error.value)
        assert "threat-actor" not in str(error.value)
        with pytest.raises(ConversionError) as error:
            _convert_single(fixtures.stix_threat_actor(name="x" * 513))
        assert "x" * 10 not in str(error.value)

    def test_m33c_s21_common_stix_metadata_preserved(self) -> None:
        """M33C-S21: approved common STIX metadata is preserved as in 33B."""
        (converted,) = _convert_single(
            fixtures.stix_campaign(
                created="2026-01-01T00:00:00+01:00",
                modified="2026-01-02T00:00:00Z",
                labels=["espionage"],
                confidence=60,
                object_marking_refs=[_MARKING_REF],
            )
        )
        facts = _thaw_facts(converted.observation)
        assert facts["stix"]["created"] == "2025-12-31T23:00:00Z"
        assert facts["stix"]["modified"] == "2026-01-02T00:00:00Z"
        assert facts["stix"]["labels"] == ["espionage"]
        assert facts["stix"]["confidence"] == 60
        assert facts["stix"]["object_marking_refs"] == [_MARKING_REF]

    def test_m33c_s22_no_reference_fields_become_entities(self) -> None:
        """M33C-S22: references/aliases stay source facts, never entities."""
        (converted,) = _convert_single(fixtures.stix_threat_actor())
        facts = _thaw_facts(converted.observation)
        flattened = str(facts).lower()
        # The threat-actor fixture carries aliases; they never surface.
        assert "synthetic-alias" not in flattened
        assert set(facts["cti_entity"].keys()) == {
            "type",
            "value",
            "display_name",
        }


class TestCtiSdoIsolation:
    """M33C-S23..S35: CTI support never disturbs unsupported/IOC behavior."""

    def test_m33c_s23_ioc_evidence_keeps_cti_entity_null(self) -> None:
        """M33C-S23: PR33B IOC/Indicator Evidence keeps cti_entity=None."""
        for decoded in (
            fixtures.stix_domain_name(),
            fixtures.stix_indicator(),
        ):
            (converted,) = _convert_single(decoded)
            assert _thaw_facts(converted.observation)["cti_entity"] is None

    def test_m33c_s24_cti_fields_absent_from_ioc_facts(self) -> None:
        """M33C-S24: CTI SDO blocks never leak into IOC-only facts."""
        (converted,) = _convert_single(fixtures.stix_indicator())
        facts = _thaw_facts(converted.observation)
        assert list(facts.keys()) == [
            "stix",
            "indicator",
            "iocs",
            "cti_entity",
            "source_assertion",
        ]
        assert facts["cti_entity"] is None
        assert facts["source_assertion"] is None
        assert facts["iocs"] == [{"type": "domain", "value": fixtures.DOMAIN_VALUE}]

    @pytest.mark.parametrize(
        "decoded",
        [
            fixtures.stix_malware(),
            fixtures.stix_relationship(),
            fixtures.stix_sighting(),
            fixtures.stix_attack_pattern(),
            fixtures.stix_custom(),
        ],
    )
    def test_m33c_s25_d29_other_objects_still_zero(
        self, decoded: dict[str, Any]
    ) -> None:
        """M33C-S25..29: relationship/sighting/attack-pattern/malware/custom stay zero."""
        assert _convert_single(decoded) == ()

    def test_m33c_s30_generic_vulnerability_object_unsupported(self) -> None:
        """M33C-S30: a valid STIX vulnerability object produces zero Evidence."""
        decoded = {
            "type": "vulnerability",
            "id": "vulnerability--99999999-9999-9999-9999-999999999999",
            "spec_version": "2.1",
            "name": "CVE-2024-0001 Synthetic",
        }
        assert _convert_single(decoded) == ()

    def test_m33c_s31_unsupported_indicator_still_zero(self) -> None:
        """M33C-S31: valid-but-unsupported Indicator patterns stay zero."""
        assert (
            _convert_single(fixtures.stix_indicator(pattern="[file:name = 'x.exe']"))
            == ()
        )

    def test_m33c_s32_mixed_supported_and_unsupported_objects(self) -> None:
        """M33C-S32: CTI objects convert alongside zero-result objects in order."""
        converted = convert_semantic_source_objects(
            (
                _object(fixtures.stix_malware()),
                _object(fixtures.stix_threat_actor()),
                _object(fixtures.stix_relationship()),
                _object(fixtures.stix_tool()),
                _object(fixtures.stix_custom()),
            ),
            _conversion_context(),
            build_stix21_conversion_registry(),
        )
        assert [r.evidence.source_record_id for r in converted] == [
            fixtures.THREAT_ACTOR_ID,
            fixtures.TOOL_ID,
        ]

    def test_m33c_s33_version_continuity_for_cti_object(self) -> None:
        """M33C-S33: later versions keep the same Evidence identity."""
        (first,) = _convert_single(fixtures.stix_threat_actor())
        (second,) = _convert_single(
            fixtures.stix_threat_actor(
                modified="2026-03-01T00:00:00Z", name="Renamed Actor"
            )
        )
        assert first.evidence.id == second.evidence.id
        assert (
            _thaw_facts(first.observation)["cti_entity"]["display_name"]
            != _thaw_facts(second.observation)["cti_entity"]["display_name"]
        )

    def test_m33c_s34_registry_remains_single_stix_converter(self) -> None:
        """M33C-S34: the registry stays keyed only by the STIX 2.1 format."""
        registry = build_stix21_conversion_registry()
        assert isinstance(
            registry.get(SemanticFormatId.STIX_21), Stix21ToEvidenceConverter
        )
        with pytest.raises(UnknownSemanticFormatError):
            registry.get(SemanticFormatId.MISP)

    def test_m33c_s35_converter_has_no_persistence_or_graph_imports(self) -> None:
        """M33C-S35: the converter stays free of persistence/graph semantics."""
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

    def test_m33c_v01_all_five_sdos_through_real_seams(self) -> None:
        """M33C-V01: all five SDOs convert through the real registry seam."""
        converted = convert_semantic_source_objects(
            (
                _object(fixtures.stix_threat_actor()),
                _object(fixtures.stix_campaign()),
                _object(fixtures.stix_intrusion_set()),
                _object(fixtures.stix_tool()),
                _object(fixtures.stix_infrastructure()),
            ),
            _conversion_context(),
            build_stix21_conversion_registry(),
        )
        assert len(converted) == 5
        assert [r.evidence.source_record_id for r in converted] == [
            fixtures.THREAT_ACTOR_ID,
            fixtures.CAMPAIGN_ID,
            fixtures.INTRUSION_SET_ID,
            fixtures.TOOL_ID,
            fixtures.INFRASTRUCTURE_ID,
        ]
        for result, expected_type in zip(
            converted,
            ("threat_actor", "campaign", "intrusion_set", "tool", "infrastructure"),
            strict=True,
        ):
            facts = _thaw_facts(result.observation)
            assert facts["cti_entity"]["type"] == expected_type
            assert facts["iocs"] == []
