# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 32B native MISP-to-Evidence converter tests.

Matrix IDs M32B-01..57 pin the pure ``MispToEvidenceConverter`` contract:
exact semantic-format registration, fail-closed type/format/SourceId
guards, deterministic global Evidence identity from the Attribute UUID,
the exact normalized Event/Attribute/IOC fact shape, the five-type IOC
profile (``domain``/``hostname``/``ip-src``/``ip-dst``/``domain|ip``),
existing ATI DOMAIN/IP canonicalization, one-Evidence/two-IOC-facts
compound semantics, zero-Evidence behavior for valid unsupported
Attributes and every ``MispObjectRecord``, source-fact preservation
(``deleted``/``to_ids``/distribution/sharing/tags/published), no verdict/
risk/relationship synthesis, no local numeric IDs/raw/binary content, and
deterministic ordering through the real generic conversion seam. Matrix
IDs M32B-V01..V05 are the parser-to-converter vertical slices: a synthetic
ATI MISP Event through the **real** ``parse_misp_event``, then the **real**
registry and ``convert_semantic_source_objects``. Everything is synthetic,
static, and offline — no database, network, or persistence is involved.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

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
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.evidence import (
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.domain.immutable_json import FrozenDict, thaw_json
from agentic_threat_investigator.infrastructure.datasources.misp_evidence import (
    SUPPORTED_MISP_IOC_TYPES,
    MispToEvidenceConverter,
    build_misp_conversion_registry,
    build_misp_normalized_facts,
    extract_misp_ioc_facts,
    format_misp_fact_timestamp,
)
from agentic_threat_investigator.infrastructure.datasources.misp_semantics import (
    MispAttribute,
    MispAttributeRecord,
    MispEventContext,
    MispObject,
    MispObjectRecord,
    parse_misp_event,
)
from tests.support import misp_fixtures as fixtures

pytestmark = pytest.mark.unit

_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_SOURCE_REFERENCE = "https://misp.example.test/"

_MISP_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("misp-live"),
    source_id=SourceId.MISP,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.MISP,
)


def _semantic_context(
    *,
    source_id: SourceId = SourceId.MISP,
    semantic_format: SemanticFormatId = SemanticFormatId.MISP,
    retrieved_at: datetime = _FIXED_TS,
) -> SemanticSourceContext:
    """Build one deterministic MISP semantic provenance context."""
    return SemanticSourceContext(
        datasource_id=DatasourceId("misp-live"),
        source_id=source_id,
        semantic_format=semantic_format,
        retrieved_at=retrieved_at,
        source_reference=_SOURCE_REFERENCE,
    )


def _conversion_context(
    *,
    source_id: SourceId = SourceId.MISP,
    semantic_format: SemanticFormatId = SemanticFormatId.MISP,
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


def _event_context(event_fields: dict[str, Any] | None = None) -> MispEventContext:
    """Build one validated MISP Event context from the synthetic fixture."""
    decoded = event_fields if event_fields is not None else fixtures.misp_event()
    return MispEventContext.model_validate(decoded["Event"])


def _attribute_record(
    *,
    attribute: dict[str, Any] | None = None,
    event_fields: dict[str, Any] | None = None,
) -> MispAttributeRecord:
    """Build one validated Event-level MISP Attribute record."""
    attribute_fields = attribute if attribute is not None else fixtures.misp_attribute()
    return MispAttributeRecord(
        event=_event_context(event_fields),
        attribute=MispAttribute.model_validate(attribute_fields["Attribute"]),
    )


def _object_record(*, object_: dict[str, Any] | None = None) -> MispObjectRecord:
    """Build one validated Event-level MISP Object record."""
    object_fields = object_ if object_ is not None else fixtures.misp_object()
    return MispObjectRecord(
        event=_event_context(),
        object=MispObject.model_validate(object_fields["Object"]),
    )


def _expected_evidence_id(attribute_uuid: str) -> UUID:
    """Return the exact deterministic Evidence ID of one Attribute UUID."""
    return evidence_id_for_source_record(
        SemanticFormatId.MISP, SourceId.MISP, attribute_uuid
    )


def _expected_event_facts(**overrides: Any) -> dict[str, Any]:
    """Return the default normalized Event fact object (fixture defaults)."""
    facts: dict[str, Any] = {
        "uuid": fixtures.EVENT_UUID,
        "info": "Synthetic MISP event for ATI documentation testing",
        "timestamp": "2023-11-14T22:13:20Z",
        "published": True,
        "publish_timestamp": None,
        "extends_uuid": None,
        "distribution": 0,
        "sharing_group_id": 0,
        "tags": [],
    }
    facts.update(overrides)
    return facts


def _expected_attribute_facts(**overrides: Any) -> dict[str, Any]:
    """Return the default normalized Attribute fact object (fixture defaults)."""
    facts: dict[str, Any] = {
        "uuid": fixtures.ATTRIBUTE_UUID,
        "type": "domain",
        "category": "Network activity",
        "value": fixtures.DOMAIN_VALUE,
        "timestamp": "2023-11-14T22:15:00Z",
        "to_ids": True,
        "deleted": False,
        "distribution": 1,
        "sharing_group_id": 0,
        "comment": "",
        "object_relation": None,
        "tags": [],
    }
    facts.update(overrides)
    return facts


def _expected_facts(
    attribute: dict[str, Any] | None = None,
    event: dict[str, Any] | None = None,
    iocs: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Return the pinned normalized fact object for the fixture defaults."""
    return {
        "event": _expected_event_facts(**(event or {})),
        "attribute": _expected_attribute_facts(**(attribute or {})),
        "iocs": (
            [{"type": "domain", "value": fixtures.DOMAIN_VALUE}]
            if iocs is None
            else iocs
        ),
    }


def _iter_keys(value: Any) -> Iterator[Any]:
    """Yield every nested mapping key in a thawed JSON value."""
    if isinstance(value, dict):
        yield from value
        for nested in value.values():
            yield from _iter_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _iter_keys(nested)


class TestRegistrationContract:
    """M32B-01..06: format identity, registry, fail-closed guards."""

    def test_m32b_01_converter_format_exactly_misp(self) -> None:
        """M32B-01: the converter owns exactly the MISP semantic format."""
        assert MispToEvidenceConverter().semantic_format is SemanticFormatId.MISP

    def test_m32b_02_registry_lookup_returns_misp_converter(self) -> None:
        """M32B-02: registry lookup selects the MISP converter by format only."""
        registry = build_misp_conversion_registry()
        converter = registry.get(SemanticFormatId.MISP)
        assert isinstance(converter, MispToEvidenceConverter)
        assert converter.semantic_format is SemanticFormatId.MISP
        with pytest.raises(UnknownSemanticFormatError):
            registry.get(SemanticFormatId.THREATFOX)
        with pytest.raises(UnknownSemanticFormatError):
            registry.get(SemanticFormatId.STIX_21)

    def test_m32b_03_wrong_semantic_format_fails_closed(self) -> None:
        """M32B-03: a non-MISP semantic-format context is a ConversionError."""
        record = _attribute_record()
        with pytest.raises(ConversionError, match="semantic-format"):
            MispToEvidenceConverter().convert(
                record,
                _conversion_context(semantic_format=SemanticFormatId.THREATFOX),
            )

    def test_m32b_04_wrong_source_object_type_fails_closed(self) -> None:
        """M32B-04: a non-MISP source object is a typed ConversionError."""
        wrong_source: object = {"Event": {}}
        with pytest.raises(ConversionError, match="MISP semantic record"):
            MispToEvidenceConverter().convert(
                wrong_source,  # type: ignore[arg-type]
                _conversion_context(),
            )

    def test_m32b_05_wrong_source_id_fails_closed(self) -> None:
        """M32B-05: provenance guard rejects a non-MISP SourceId context."""
        record = _attribute_record()
        with pytest.raises(ConversionError, match="source identity"):
            MispToEvidenceConverter().convert(
                record, _conversion_context(source_id=SourceId.THREATFOX)
            )

    def test_m32b_06_repeat_conversion_structurally_equal(self) -> None:
        """M32B-06: identical conversion is repeatably structural-equal."""
        converter = MispToEvidenceConverter()
        record = _attribute_record()
        context = _conversion_context()
        assert converter.convert(record, context) == converter.convert(record, context)

    def test_m32b_56_registry_selection_is_semantic_format_only(self) -> None:
        """M32B-56: generic selection keys only on the semantic format.

        A MISP SourceId context carrying the THREATFOX semantic format fails
        on format lookup through the real registry — never on SourceId,
        provider, protocol, or object shape.
        """
        registry = build_misp_conversion_registry()
        record = _attribute_record()
        with pytest.raises(UnknownSemanticFormatError):
            convert_semantic_source_objects(
                (record,),
                _conversion_context(semantic_format=SemanticFormatId.THREATFOX),
                registry,
            )


class TestIdentityProvenance:
    """M32B-07..16: stable global Evidence identity and provenance."""

    def test_m32b_07_source_record_id_is_attribute_uuid(self) -> None:
        """M32B-07: source_record_id is the exact Attribute UUID string."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        assert converted.evidence.source_record_id == fixtures.ATTRIBUTE_UUID

    def test_m32b_08_evidence_id_exact_helper_result(self) -> None:
        """M32B-08: Evidence ID is exactly the deterministic helper result."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        assert converted.evidence.id == _expected_evidence_id(fixtures.ATTRIBUTE_UUID)
        assert converted.evidence.id.version == 5
        assert converted.evidence.source == SourceId.MISP.value
        assert converted.evidence.type is EvidenceType.THREAT_INTELLIGENCE
        assert converted.observation.evidence_id == converted.evidence.id

    def test_m32b_09_same_uuid_changed_value_same_evidence_id(self) -> None:
        """M32B-09: value content never participates in Evidence identity."""
        first = _attribute_record()
        second = _attribute_record(
            attribute=fixtures.misp_attribute(value=fixtures.SECONDARY_DOMAIN_VALUE)
        )
        (a,) = MispToEvidenceConverter().convert(first, _conversion_context())
        (b,) = MispToEvidenceConverter().convert(second, _conversion_context())
        assert (
            a.evidence.id
            == b.evidence.id
            == _expected_evidence_id(fixtures.ATTRIBUTE_UUID)
        )
        assert a.observation.facts != b.observation.facts

    def test_m32b_10_different_uuid_same_value_different_id(self) -> None:
        """M32B-10: a different Attribute UUID yields a different Evidence ID."""
        other_uuid = "99fac2a0-7e54-4a0a-ac7d-4f9cc2ff3b99"
        (a,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        (b,) = MispToEvidenceConverter().convert(
            _attribute_record(attribute=fixtures.misp_attribute(uuid=other_uuid)),
            _conversion_context(),
        )
        assert a.evidence.id != b.evidence.id
        assert b.evidence.source_record_id == other_uuid

    def test_m32b_11_event_uuid_changes_evidence_id_unchanged(self) -> None:
        """M32B-11: Event UUID is enclosing provenance, not Evidence identity."""
        (a,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        different_event = fixtures.misp_event(
            uuid="12c8c2a0-5e54-4a0a-8b5c-2f9cc2ff3b12"
        )
        (b,) = MispToEvidenceConverter().convert(
            _attribute_record(event_fields=different_event), _conversion_context()
        )
        assert a.evidence.id == b.evidence.id

    def test_m32b_12_retrieval_time_changes_evidence_id_unchanged(self) -> None:
        """M32B-12: retrieval time is acquisition provenance only."""
        (a,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        (b,) = MispToEvidenceConverter().convert(
            _attribute_record(),
            _conversion_context(retrieved_at=datetime(2026, 7, 1, 9, 0, 0, tzinfo=UTC)),
        )
        assert a.evidence.id == b.evidence.id
        assert b.observation.retrieved_at == datetime(2026, 7, 1, 9, 0, 0, tzinfo=UTC)

    def test_m32b_13_source_reference_copied_exactly(self) -> None:
        """M32B-13: candidate source_url is the exact credential-free reference."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        assert converted.observation.source_url == _SOURCE_REFERENCE

    def test_m32b_14_retrieved_at_is_context_value(self) -> None:
        """M32B-14: candidate retrieved_at is the exact context retrieval time."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        assert converted.observation.retrieved_at == _FIXED_TS
        assert converted.observation.retrieved_at.utcoffset() == timedelta(0)

    def test_m32b_15_observed_at_is_attribute_timestamp(self) -> None:
        """M32B-15: observed_at is the exact Attribute source timestamp."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        assert converted.observation.observed_at == datetime(
            2023, 11, 14, 22, 15, 0, tzinfo=UTC
        )

    def test_m32b_15b_observed_at_not_event_or_retrieval_time(self) -> None:
        """M32B-15b: Event/publish/retrieval times never substitute observed_at."""
        event = fixtures.misp_event(
            published=True,
            publish_timestamp="1700000500",
            attributes=(),
        )
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(event_fields=event), _conversion_context()
        )
        assert converted.observation.observed_at == datetime(
            2023, 11, 14, 22, 15, 0, tzinfo=UTC
        )
        assert converted.observation.observed_at != datetime(
            2023, 11, 14, 22, 13, 20, tzinfo=UTC
        )

    def test_m32b_16_raw_payload_is_none(self) -> None:
        """M32B-16: the candidate never carries a raw payload."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        assert converted.observation.raw_payload is None

    def test_no_investigation_or_subject_binding(self) -> None:
        """PR 28A: conversion is global and Investigation-independent."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        assert not hasattr(converted.evidence, "investigation_id")
        assert not hasattr(converted.evidence, "subject")
        assert not hasattr(converted.observation, "investigation_id")
        assert not hasattr(converted.observation, "subject")


class TestIocProfile:
    """M32B-17..24: the five-type IOC profile through existing canonicalizers."""

    def test_supported_profile_is_exactly_five_types(self) -> None:
        """Only the approved five MISP types produce Evidence."""
        assert (
            frozenset({"domain", "hostname", "ip-src", "ip-dst", "domain|ip"})
            == SUPPORTED_MISP_IOC_TYPES
        )

    def test_m32b_17_domain_one_canonical_domain_ioc(self) -> None:
        """M32B-17: domain maps to one canonical DOMAIN IOC fact."""
        facts = extract_misp_ioc_facts(_attribute_record().attribute)
        assert facts == ({"type": "domain", "value": fixtures.DOMAIN_VALUE},)

    def test_m32b_18_hostname_one_canonical_domain_ioc(self) -> None:
        """M32B-18: hostname maps to one canonical DOMAIN IOC fact."""
        facts = extract_misp_ioc_facts(
            _attribute_record(
                attribute=fixtures.misp_attribute(type_="hostname")
            ).attribute
        )
        assert facts == ({"type": "domain", "value": fixtures.DOMAIN_VALUE},)

    def test_m32b_19_ip_src_ipv4_one_canonical_ip_ioc(self) -> None:
        """M32B-19: ip-src IPv4 maps to one canonical IP_ADDRESS IOC fact."""
        facts = extract_misp_ioc_facts(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    type_="ip-src",
                    value=fixtures.IPV4_VALUE,
                    category="Network activity",
                )
            ).attribute
        )
        assert facts == ({"type": "ip_address", "value": fixtures.IPV4_VALUE},)

    def test_m32b_20_ip_dst_ipv4_one_canonical_ip_ioc(self) -> None:
        """M32B-20: ip-dst IPv4 maps to one canonical IP_ADDRESS IOC fact."""
        facts = extract_misp_ioc_facts(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    type_="ip-dst",
                    value=fixtures.IPV4_VALUE,
                    category="Network activity",
                )
            ).attribute
        )
        assert facts == ({"type": "ip_address", "value": fixtures.IPV4_VALUE},)

    def test_m32b_21_ip_src_ipv6_canonical_compressed(self) -> None:
        """M32B-21: ip-src IPv6 normalizes to the canonical compressed form."""
        facts = extract_misp_ioc_facts(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    type_="ip-src", value=fixtures.EXPANDED_IPV6_VALUE
                )
            ).attribute
        )
        assert facts == ({"type": "ip_address", "value": fixtures.IPV6_VALUE},)

    def test_m32b_22_ip_dst_ipv6_canonical_compressed(self) -> None:
        """M32B-22: ip-dst IPv6 normalizes to the canonical compressed form."""
        facts = extract_misp_ioc_facts(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    type_="ip-dst", value=fixtures.IPV6_VALUE
                )
            ).attribute
        )
        assert facts == ({"type": "ip_address", "value": fixtures.IPV6_VALUE},)

    def test_m32b_23_domain_normalization_strict_helper(self) -> None:
        """M32B-23: DOMAIN uses the existing strict DNS helper.

        Mixed case and a terminal root dot canonicalize; IDNA applies to
        non-ASCII labels; malformed names fail closed as ConversionError.
        """
        facts = extract_misp_ioc_facts(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    type_="domain", value=fixtures.MIXED_CASE_DOMAIN_VALUE
                )
            ).attribute
        )
        assert facts == ({"type": "domain", "value": "example.test"},)
        unicode_facts = extract_misp_ioc_facts(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    type_="domain", value=fixtures.UNICODE_DOMAIN_VALUE
                )
            ).attribute
        )
        assert unicode_facts == ({"type": "domain", "value": "xn--bcher-kva.example"},)
        with pytest.raises(ConversionError, match="DNS"):
            extract_misp_ioc_facts(
                _attribute_record(
                    attribute=fixtures.misp_attribute(
                        type_="domain", value="bad domain.test"
                    )
                ).attribute
            )

    def test_m32b_24_ip_normalization_existing_helper(self) -> None:
        """M32B-24: IP uses the existing canonical IP helper for IPv4/IPv6."""
        ipv4_facts = extract_misp_ioc_facts(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    type_="ip-src", value=" 203.0.113.42 "
                )
            ).attribute
        )
        assert ipv4_facts == ({"type": "ip_address", "value": "203.0.113.42"},)
        ipv6_facts = extract_misp_ioc_facts(
            _attribute_record(
                attribute=fixtures.misp_attribute(type_="ip-dst", value="::1")
            ).attribute
        )
        assert ipv6_facts == ({"type": "ip_address", "value": "::1"},)


class TestCompound:
    """M32B-25..32: exact two-component domain|ip semantics, one Evidence."""

    def test_m32b_25_domain_pipe_ipv4(self) -> None:
        """M32B-25: domain|ip is one Evidence with DOMAIN then IP facts."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    type_="domain|ip",
                    value=fixtures.COMPOUND_DOMAIN_IP_VALUE,
                )
            ),
            _conversion_context(),
        )
        assert converted.observation.facts["iocs"] == (
            {"type": "domain", "value": "example.test"},
            {"type": "ip_address", "value": fixtures.IPV4_VALUE},
        )

    def test_m32b_26_domain_pipe_ipv6(self) -> None:
        """M32B-26: domain|ip IPv6 canonicalizes both components."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    type_="domain|ip",
                    value=fixtures.COMPOUND_DOMAIN_IPV6_VALUE,
                )
            ),
            _conversion_context(),
        )
        assert converted.observation.facts["iocs"] == (
            {"type": "domain", "value": "example.test"},
            {"type": "ip_address", "value": fixtures.IPV6_VALUE},
        )

    def test_m32b_27_missing_domain_fails_closed(self) -> None:
        """M32B-27: a missing domain component is a bounded ConversionError."""
        with pytest.raises(ConversionError, match="two nonempty components"):
            extract_misp_ioc_facts(
                _attribute_record(
                    attribute=fixtures.misp_attribute(
                        type_="domain|ip", value=f"|{fixtures.IPV4_VALUE}"
                    )
                ).attribute
            )

    def test_m32b_28_missing_ip_fails_closed(self) -> None:
        """M32B-28: a missing IP component is a bounded ConversionError."""
        with pytest.raises(ConversionError, match="two nonempty components"):
            extract_misp_ioc_facts(
                _attribute_record(
                    attribute=fixtures.misp_attribute(
                        type_="domain|ip", value=f"{fixtures.DOMAIN_VALUE}|"
                    )
                ).attribute
            )

    def test_m32b_29_extra_component_fails_closed(self) -> None:
        """M32B-29: an extra component is a bounded ConversionError."""
        with pytest.raises(ConversionError, match="two nonempty components"):
            extract_misp_ioc_facts(
                _attribute_record(
                    attribute=fixtures.misp_attribute(
                        type_="domain|ip",
                        value=f"{fixtures.DOMAIN_VALUE}|{fixtures.IPV4_VALUE}|x",
                    )
                ).attribute
            )

    def test_m32b_30_invalid_domain_fails_closed(self) -> None:
        """M32B-30: an invalid DOMAIN component is a bounded ConversionError."""
        with pytest.raises(ConversionError, match="DNS"):
            extract_misp_ioc_facts(
                _attribute_record(
                    attribute=fixtures.misp_attribute(
                        type_="domain|ip",
                        value=f"bad_domain.test|{fixtures.IPV4_VALUE}",
                    )
                ).attribute
            )

    def test_m32b_31_invalid_ip_fails_closed(self) -> None:
        """M32B-31: an invalid IP component is a bounded ConversionError."""
        with pytest.raises(ConversionError, match="inverted|IP|address"):
            extract_misp_ioc_facts(
                _attribute_record(
                    attribute=fixtures.misp_attribute(
                        type_="domain|ip",
                        value=f"{fixtures.DOMAIN_VALUE}|999.1.1.1",
                    )
                ).attribute
            )

    def test_m32b_32_identity_is_bare_attribute_uuid_no_suffix(self) -> None:
        """M32B-32: compound identity is the bare Attribute UUID, no suffix."""
        record = _attribute_record(
            attribute=fixtures.misp_attribute(
                type_="domain|ip", value=fixtures.COMPOUND_DOMAIN_IP_VALUE
            )
        )
        (converted,) = MispToEvidenceConverter().convert(record, _conversion_context())
        assert converted.evidence.source_record_id == str(record.attribute.uuid)
        assert converted.evidence.id == _expected_evidence_id(
            str(record.attribute.uuid)
        )

    def test_m32b_57_compound_through_generic_flattening(self) -> None:
        """M32B-57: generic flattening keeps one Evidence with two IOC facts."""
        registry = build_misp_conversion_registry()
        record = _attribute_record(
            attribute=fixtures.misp_attribute(
                type_="domain|ip", value=fixtures.COMPOUND_DOMAIN_IP_VALUE
            )
        )
        (converted,) = convert_semantic_source_objects(
            (record,), _conversion_context(), registry
        )
        assert converted.evidence.source_record_id == str(record.attribute.uuid)
        assert len(converted.observation.facts["iocs"]) == 2


class TestUnsupportedAndStatePreservation:
    """M32B-33..45: zero-Evidence behavior and source-fact preservation."""

    @pytest.mark.parametrize(
        "type_",
        [
            "sha256",
            "url",
            "filename",
            "email-src",
            "port",
            "asn",
            "mutex",
            "x-custom-unknown",
        ],
    )
    def test_m32b_33_34_35_unsupported_types_zero_evidence(self, type_: str) -> None:
        """M32B-33/34/35: valid unsupported types deterministically yield zero."""
        converter = MispToEvidenceConverter()
        record = _attribute_record(
            attribute=fixtures.misp_attribute(type_=type_, value="synthetic-value")
        )
        assert converter.convert(record, _conversion_context()) == ()

    def test_m32b_36_object_record_zero_evidence(self) -> None:
        """M32B-36: a valid MispObjectRecord yields zero Evidence."""
        assert (
            MispToEvidenceConverter().convert(_object_record(), _conversion_context())
            == ()
        )

    def test_m32b_37_object_with_supported_nested_attribute_still_zero(
        self,
    ) -> None:
        """M32B-37: Objects are never flattened, even with nested domain/IP."""
        object_ = fixtures.misp_object(
            attributes=(
                fixtures.misp_object_attribute(
                    uuid="43fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b04",
                    type_="domain",
                    value=fixtures.DOMAIN_VALUE,
                ),
                fixtures.misp_object_attribute(
                    uuid="44fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b44",
                    type_="ip-dst",
                    value=fixtures.IPV4_VALUE,
                    object_relation="ip",
                ),
            )
        )
        assert (
            MispToEvidenceConverter().convert(
                _object_record(object_=object_), _conversion_context()
            )
            == ()
        )

    def test_m32b_38_to_ids_false_converts_and_preserves(self) -> None:
        """M32B-38: to_ids=false is a source fact, not a verdict/barrier."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(attribute=fixtures.misp_attribute(to_ids=False)),
            _conversion_context(),
        )
        assert thaw_json(converted.observation.facts)["attribute"]["to_ids"] is False

    def test_m32b_39_deleted_true_converts_and_preserves(self) -> None:
        """M32B-39: deleted supported Attributes still convert material state."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(attribute=fixtures.misp_attribute(deleted=True)),
            _conversion_context(),
        )
        facts = thaw_json(converted.observation.facts)
        assert facts["attribute"]["deleted"] is True

    def test_m32b_40_attribute_distribution_five_preserved(self) -> None:
        """M32B-40: Attribute distribution 5 is preserved, never resolved."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(attribute=fixtures.misp_attribute(distribution="5")),
            _conversion_context(),
        )
        facts = thaw_json(converted.observation.facts)
        assert facts["attribute"]["distribution"] == 5
        assert facts["attribute"]["sharing_group_id"] == 0

    def test_m32b_41_distribution_four_sharing_group_exact(self) -> None:
        """M32B-41: distribution 4 + sharing group are preserved exactly."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    distribution="4", sharing_group_id="77"
                )
            ),
            _conversion_context(),
        )
        facts = thaw_json(converted.observation.facts)
        assert facts["attribute"]["distribution"] == 4
        assert facts["attribute"]["sharing_group_id"] == 77

    def test_m32b_42_event_distribution_preserved(self) -> None:
        """M32B-42: Event distribution is preserved untouched."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(event_fields=fixtures.misp_event(distribution="2")),
            _conversion_context(),
        )
        facts = thaw_json(converted.observation.facts)
        assert facts["event"]["distribution"] == 2

    def test_m32b_43_event_and_attribute_tags_ordered(self) -> None:
        """M32B-43: Event/Attribute tags preserve first-occurrence order."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(
                event_fields=fixtures.misp_event(
                    tags=(
                        fixtures.misp_tag(name="tlp:white"),
                        fixtures.misp_tag(name='misp:galaxy-malware="EvilCorp"'),
                    )
                ),
                attribute=fixtures.misp_attribute(
                    tags=(
                        fixtures.misp_tag(name="tlp:green"),
                        fixtures.misp_tag(name='osint:source="feed-a"'),
                    )
                ),
            ),
            _conversion_context(),
        )
        facts = thaw_json(converted.observation.facts)
        assert facts["event"]["tags"] == [
            "tlp:white",
            'misp:galaxy-malware="EvilCorp"',
        ]
        assert facts["attribute"]["tags"] == [
            "tlp:green",
            'osint:source="feed-a"',
        ]

    def test_m32b_44_comment_and_object_relation_preserved(self) -> None:
        """M32B-44: comment/object_relation are preserved, not interpreted."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    comment="source note",
                    object_relation="related-domain",
                )
            ),
            _conversion_context(),
        )
        facts = thaw_json(converted.observation.facts)
        assert facts["attribute"]["comment"] == "source note"
        assert facts["attribute"]["object_relation"] == "related-domain"

    def test_m32b_45_published_metadata_preserved(self) -> None:
        """M32B-45: published/publish_timestamp/extends_uuid are preserved."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(
                event_fields=fixtures.misp_event(
                    published=False,
                    publish_timestamp="1700000500",
                    extends_uuid="65fd2d2c-8f47-4a90-a48f-b8cdd0e3f234",
                )
            ),
            _conversion_context(),
        )
        facts = thaw_json(converted.observation.facts)
        assert facts["event"]["published"] is False
        assert facts["event"]["publish_timestamp"] == "2023-11-14T22:21:40Z"
        assert facts["event"]["extends_uuid"] == "65fd2d2c-8f47-4a90-a48f-b8cdd0e3f234"


class TestFactShapeDeterminism:
    """M32B-46..52 + pinned schema: exact normalized fact contract."""

    def test_pinned_normalized_fact_schema(self) -> None:
        """The normalized fact keys are pinned exactly (Event/Attribute/IOCs)."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        assert thaw_json(converted.observation.facts) == _expected_facts()
        assert set(converted.observation.facts) == {"event", "attribute", "iocs"}
        assert set(converted.observation.facts["event"]) == {
            "uuid",
            "info",
            "timestamp",
            "published",
            "publish_timestamp",
            "extends_uuid",
            "distribution",
            "sharing_group_id",
            "tags",
        }
        assert set(converted.observation.facts["attribute"]) == {
            "uuid",
            "type",
            "category",
            "value",
            "timestamp",
            "to_ids",
            "deleted",
            "distribution",
            "sharing_group_id",
            "comment",
            "object_relation",
            "tags",
        }

    def test_m32b_46_timestamps_exact_utc_z_form(self) -> None:
        """M32B-46: every timestamp fact uses the exact UTC Z form."""
        assert (
            format_misp_fact_timestamp(datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC))
            == "2023-11-14T22:13:20Z"
        )
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        assert converted.observation.facts["event"]["timestamp"] == (
            "2023-11-14T22:13:20Z"
        )
        assert converted.observation.facts["attribute"]["timestamp"] == (
            "2023-11-14T22:15:00Z"
        )

    def test_m32b_47_uuid_facts_canonical_strings(self) -> None:
        """M32B-47: UUID facts are canonical strings, never UUID objects."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        facts = thaw_json(converted.observation.facts)
        assert facts["event"]["uuid"] == fixtures.EVENT_UUID
        assert facts["attribute"]["uuid"] == fixtures.ATTRIBUTE_UUID
        assert isinstance(facts["event"]["uuid"], str)

    def test_m32b_48_source_value_retained_separately_from_ioc(self) -> None:
        """M32B-48: original attribute value and canonical IOC coexist."""
        record = _attribute_record(
            attribute=fixtures.misp_attribute(
                type_="domain", value=fixtures.MIXED_CASE_DOMAIN_VALUE
            )
        )
        (converted,) = MispToEvidenceConverter().convert(record, _conversion_context())
        facts = thaw_json(converted.observation.facts)
        assert facts["attribute"]["value"] == fixtures.MIXED_CASE_DOMAIN_VALUE
        assert facts["iocs"] == [{"type": "domain", "value": "example.test"}]

    def test_m32b_49_output_immutable(self) -> None:
        """M32B-49: the emitted Evidence and facts reject all mutation."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        assert isinstance(converted.observation.facts, FrozenDict)
        with pytest.raises(TypeError):
            converted.observation.facts["event"] = {"changed": True}
        with pytest.raises(ValidationError):
            converted.evidence.id = uuid4()
        with pytest.raises(ValidationError):
            converted.observation.observed_at = datetime.now(tz=UTC)

    def test_m32b_50_no_verdict_synthesis(self) -> None:
        """M32B-50: no forbidden derived semantics are ever synthesized."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(
                attribute=fixtures.misp_attribute(
                    type_="domain|ip", value=fixtures.COMPOUND_DOMAIN_IP_VALUE
                )
            ),
            _conversion_context(),
        )
        serialized = str(converted.observation.facts)
        for fragment in (
            "verdict",
            "benign",
            "malicious",
            "risk",
            "confidence",
            "attribution",
            "relationship",
            "pivot",
            "discovery",
            "associated_with",
        ):
            assert fragment not in serialized

    def test_m32b_51_local_misp_numeric_ids_absent(self) -> None:
        """M32B-51: local MISP numeric IDs are never copied into facts."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        facts = thaw_json(converted.observation.facts)
        assert "id" not in set(_iter_keys(facts))
        assert "id" not in facts["event"]
        assert "id" not in facts["attribute"]

    def test_m32b_52_raw_binary_content_absent(self) -> None:
        """M32B-52: binary data/binary keys never reach the facts."""
        (converted,) = MispToEvidenceConverter().convert(
            _attribute_record(), _conversion_context()
        )
        facts = thaw_json(converted.observation.facts)
        assert "data" not in set(_iter_keys(facts))


class TestGenericSeamOrdering:
    """M32B-53..55: deterministic flattening through the real generic seam."""

    def test_m32b_53_supported_unsupported_supported_two_outputs(self) -> None:
        """M32B-53: mixed records emit in source order, unsupported skipped."""
        registry = build_misp_conversion_registry()
        context = _conversion_context()
        domain = _attribute_record(
            attribute=fixtures.misp_attribute(
                uuid="21e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b02", type_="domain"
            )
        )
        unsupported = _attribute_record(
            attribute=fixtures.misp_attribute(
                uuid="22e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b22",
                type_="sha256",
                value="ab" * 32,
            )
        )
        ip = _attribute_record(
            attribute=fixtures.misp_attribute(
                uuid="23e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b23",
                type_="ip-dst",
                value=fixtures.IPV4_VALUE,
            )
        )
        converted = convert_semantic_source_objects(
            (domain, unsupported, ip), context, registry
        )
        assert len(converted) == 2
        assert converted[0].evidence.source_record_id == str(domain.attribute.uuid)
        assert converted[1].evidence.source_record_id == str(ip.attribute.uuid)

    def test_m32b_54_all_unsupported_empty_success(self) -> None:
        """M32B-54: an all-unsupported pass is successful empty conversion."""
        registry = build_misp_conversion_registry()
        unsupported = _attribute_record(
            attribute=fixtures.misp_attribute(
                uuid="24e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b24", type_="url"
            )
        )
        assert (
            convert_semantic_source_objects(
                (unsupported,), _conversion_context(), registry
            )
            == ()
        )

    def test_m32b_55_one_malformed_record_fails_no_partial_api(self) -> None:
        """M32B-55: one malformed supported record fails, never partial output."""
        registry = build_misp_conversion_registry()
        valid = _attribute_record(
            attribute=fixtures.misp_attribute(
                uuid="25e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b25", type_="domain"
            )
        )
        malformed = _attribute_record(
            attribute=fixtures.misp_attribute(
                uuid="26e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b26",
                type_="domain",
                value="not a domain",
            )
        )
        with pytest.raises(ConversionError):
            convert_semantic_source_objects(
                (valid, malformed), _conversion_context(), registry
            )


class TestParserToConverterVerticalSlice:
    """M32B-V01..V05: real parse_misp_event -> real registry -> real converter."""

    def test_m32b_v01_event_domain_and_ipv4_two_evidence_source_order(
        self,
    ) -> None:
        """V01: an Event with domain + IPv4 Attributes emits two Evidence."""
        decoded = fixtures.misp_event(
            attributes=(
                fixtures.misp_attribute(
                    uuid="21e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b02", type_="domain"
                ),
                fixtures.misp_attribute(
                    uuid="23e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b23",
                    type_="ip-dst",
                    value=fixtures.IPV4_VALUE,
                ),
            )
        )
        result = parse_misp_event(decoded)
        assert result.error is None
        converted = convert_semantic_source_objects(
            result.records, _conversion_context(), build_misp_conversion_registry()
        )
        assert len(converted) == 2
        assert converted[0].evidence.source_record_id == (
            "21e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b02"
        )
        assert converted[1].evidence.source_record_id == (
            "23e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b23"
        )
        assert thaw_json(converted[0].observation.facts)["iocs"] == [
            {"type": "domain", "value": fixtures.DOMAIN_VALUE}
        ]
        assert thaw_json(converted[1].observation.facts)["iocs"] == [
            {"type": "ip_address", "value": fixtures.IPV4_VALUE}
        ]

    def test_m32b_v02_event_domain_pipe_ip(self) -> None:
        """V02: an Event with one domain|ip Attribute stays one Evidence."""
        decoded = fixtures.misp_event(
            attributes=(
                fixtures.misp_attribute(
                    type_="domain|ip", value=fixtures.COMPOUND_DOMAIN_IP_VALUE
                ),
            )
        )
        result = parse_misp_event(decoded)
        assert result.error is None
        converted = convert_semantic_source_objects(
            result.records, _conversion_context(), build_misp_conversion_registry()
        )
        assert len(converted) == 1
        assert thaw_json(converted[0].observation.facts)["iocs"] == [
            {"type": "domain", "value": "example.test"},
            {"type": "ip_address", "value": fixtures.IPV4_VALUE},
        ]

    def test_m32b_v03_supported_plus_unsupported_only_supported(self) -> None:
        """V03: unsupported valid types are skipped; supported types convert."""
        decoded = fixtures.misp_event(
            attributes=(
                fixtures.misp_attribute(
                    uuid="21e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b02", type_="domain"
                ),
                fixtures.misp_attribute(
                    uuid="22e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b22",
                    type_="sha256",
                    value="ab" * 32,
                ),
                fixtures.misp_attribute(
                    uuid="23e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b23",
                    type_="ip-src",
                    value=fixtures.IPV4_VALUE,
                ),
            )
        )
        result = parse_misp_event(decoded)
        assert result.error is None
        converted = convert_semantic_source_objects(
            result.records, _conversion_context(), build_misp_conversion_registry()
        )
        assert [item.evidence.source_record_id for item in converted] == [
            "21e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b02",
            "23e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b23",
        ]

    def test_m32b_v04_supported_deleted_attribute_emitted(self) -> None:
        """V04: a deleted supported Attribute still emits with deleted=true."""
        decoded = fixtures.misp_event(
            attributes=(fixtures.misp_attribute(type_="domain", deleted=True),)
        )
        result = parse_misp_event(decoded)
        assert result.error is None
        converted = convert_semantic_source_objects(
            result.records, _conversion_context(), build_misp_conversion_registry()
        )
        assert len(converted) == 1
        facts = thaw_json(converted[0].observation.facts)
        assert facts["attribute"]["deleted"] is True

    def test_m32b_v05_object_only_event_empty_success(self) -> None:
        """V05: an Object-only Event converts to successful empty output."""
        decoded = fixtures.misp_event(
            objects=(
                fixtures.misp_object(
                    attributes=(
                        fixtures.misp_object_attribute(
                            type_="domain", value=fixtures.DOMAIN_VALUE
                        ),
                    )
                ),
            )
        )
        result = parse_misp_event(decoded)
        assert result.error is None
        assert all(not isinstance(item, MispAttributeRecord) for item in result.records)
        converted = convert_semantic_source_objects(
            result.records, _conversion_context(), build_misp_conversion_registry()
        )
        assert converted == ()

    def test_builders_and_converter_agree(self) -> None:
        """The public fact builders and the converter emit identical facts."""
        record = _attribute_record()
        (converted,) = MispToEvidenceConverter().convert(record, _conversion_context())
        assert thaw_json(converted.observation.facts) == build_misp_normalized_facts(
            record
        )
