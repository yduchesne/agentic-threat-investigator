# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27A datasource vocabulary and definition contract tests.

Stable matrix IDs D27A-01..D27A-13 pin the typed datasource vocabulary:
durable semantic-format URNs, preserved ``SourceId`` values, the immutable
five-dimension ``DatasourceDefinition``, fail-closed typed validation, and
the independence of every classification dimension.
"""

import dataclasses

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.datasource import (
    REPRESENTATIVE_DATASOURCE_DEFINITIONS,
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
    validate_datasource_id,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)


def _definition(**overrides: object) -> DatasourceDefinition:
    """Build a valid definition with the default ThreatFox dimensions."""
    base: dict[str, object] = {
        "datasource_id": "threatfox-live",
        "source_id": SourceId.THREATFOX,
        "protocol": DatasourceProtocol.HTTPS,
        "serialization_format": SerializationFormat.JSON,
        "semantic_format": SemanticFormatId.THREATFOX,
    }
    base.update(overrides)
    return DatasourceDefinition(**base)  # type: ignore[arg-type]


def test_d27a_01_semantic_format_urns_are_exact() -> None:
    """D27A-01: STIX 2.1 and ThreatFox semantic URNs are exact durable values."""
    assert SemanticFormatId.STIX_21.value == (
        "urn:ati:datasource:semanticformat:stix21"
    )
    assert SemanticFormatId.THREATFOX.value == (
        "urn:ati:datasource:semanticformat:threatfox"
    )
    assert {member.value for member in SemanticFormatId} == {
        "urn:ati:datasource:semanticformat:stix21",
        "urn:ati:datasource:semanticformat:threatfox",
    }


def test_d27a_02_source_id_values_remain_exact() -> None:
    """D27A-02: every durable ``SourceId`` serialized value is unchanged."""
    assert {member: member.value for member in SourceId} == {
        SourceId.IPINFO_LITE: "urn:ati:source:ipinfo_lite",
        SourceId.RDAP: "urn:ati:source:rdap",
        SourceId.GOOGLE_PUBLIC_DNS: "urn:ati:source:google_public_dns",
        SourceId.DBIP_CITY_LITE: "urn:ati:source:dbip_city_lite",
        SourceId.ABUSEIPDB: "urn:ati:source:abuseipdb",
        SourceId.THREATFOX: "urn:ati:source:threatfox",
        SourceId.URLHAUS: "urn:ati:source:urlhaus",
        SourceId.MITRE_ATTACK: "urn:ati:source:mitre_attack",
        SourceId.CISA_KEV: "urn:ati:source:cisa_kev",
    }


def test_d27a_03_threatfox_definition_all_five_dimensions() -> None:
    """D27A-03: ThreatFox is HTTPS + JSON with proprietary ThreatFox semantics."""
    definition = DatasourceDefinition(
        datasource_id=DatasourceId("threatfox-live"),
        source_id=SourceId.THREATFOX,
        protocol=DatasourceProtocol.HTTPS,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.THREATFOX,
    )
    assert definition.datasource_id.value == "threatfox-live"
    assert definition.source_id is SourceId.THREATFOX
    assert definition.protocol is DatasourceProtocol.HTTPS
    assert definition.serialization_format is SerializationFormat.JSON
    assert definition.semantic_format is SemanticFormatId.THREATFOX


def test_d27a_04_mitre_stix_definition_all_five_dimensions() -> None:
    """D27A-04: MITRE ATT&CK is FILE + JSON with shared STIX 2.1 semantics."""
    definition = DatasourceDefinition(
        datasource_id=DatasourceId("mitre-attack-enterprise"),
        source_id=SourceId.MITRE_ATTACK,
        protocol=DatasourceProtocol.FILE,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.STIX_21,
    )
    assert definition.datasource_id.value == "mitre-attack-enterprise"
    assert definition.source_id is SourceId.MITRE_ATTACK
    assert definition.protocol is DatasourceProtocol.FILE
    assert definition.serialization_format is SerializationFormat.JSON
    assert definition.semantic_format is SemanticFormatId.STIX_21


def test_d27a_05_definition_is_immutable() -> None:
    """D27A-05: mutating any definition dimension is rejected."""
    definition = _definition()
    with pytest.raises(ValidationError):
        definition.source_id = SourceId.RDAP
    with pytest.raises(ValidationError):
        definition.protocol = DatasourceProtocol.FILE
    with pytest.raises(ValidationError):
        definition.datasource_id = DatasourceId("other")
    with pytest.raises(dataclasses.FrozenInstanceError):
        definition.datasource_id.value = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "   ",
        " padded ",
        "Upper",
        "snake_case",
        "has.dot",
        "a" * 65,
    ],
)
def test_d27a_06_invalid_datasource_ids_fail_closed(invalid: str) -> None:
    """D27A-06: blank, whitespace-only, padded, malformed, and over-bound IDs."""
    with pytest.raises((ValueError, ValidationError)):
        validate_datasource_id(invalid)
    with pytest.raises((ValueError, ValidationError)):
        DatasourceId(invalid)
    with pytest.raises(ValidationError):
        _definition(datasource_id=invalid)


@pytest.mark.parametrize("invalid", ["", "gopher", "TAXII", "file "])
def test_d27a_07_unknown_protocol_fails_closed(invalid: str) -> None:
    """D27A-07: only the typed acquisition protocol values are accepted."""
    with pytest.raises((ValueError, ValidationError)):
        DatasourceProtocol(invalid)
    with pytest.raises(ValidationError):
        _definition(protocol=invalid)


def test_d27a_07b_protocol_vocabulary_is_exact() -> None:
    """The typed protocol vocabulary contains exactly the current values."""
    assert {member.value for member in DatasourceProtocol} == {"https", "file"}


@pytest.mark.parametrize("invalid", ["", "xml", "csv", "jsonl"])
def test_d27a_08_unknown_serialization_fails_closed(invalid: str) -> None:
    """D27A-08: only the typed physical serialization values are accepted."""
    with pytest.raises((ValueError, ValidationError)):
        SerializationFormat(invalid)
    with pytest.raises(ValidationError):
        _definition(serialization_format=invalid)


def test_d27a_08b_serialization_vocabulary_is_exact() -> None:
    """The typed serialization vocabulary contains exactly the current values."""
    assert {member.value for member in SerializationFormat} == {"json"}


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "urn:ati:datasource:semanticformat:misp",
        "stix21",
        "urn:ati:source:threatfox",
    ],
)
def test_d27a_09_unknown_semantic_format_fails_closed(invalid: str) -> None:
    """D27A-09: only durable semantic-format URNs are accepted."""
    with pytest.raises((ValueError, ValidationError)):
        SemanticFormatId(invalid)
    with pytest.raises(ValidationError):
        _definition(semantic_format=invalid)


def test_d27a_11_same_provider_multiple_datasource_ids() -> None:
    """D27A-11: distinct datasource instances may share one ``SourceId``."""
    first = DatasourceDefinition(
        datasource_id=DatasourceId("threatfox-live"),
        source_id=SourceId.THREATFOX,
        protocol=DatasourceProtocol.HTTPS,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.THREATFOX,
    )
    second = DatasourceDefinition(
        datasource_id=DatasourceId("threatfox-replay"),
        source_id=SourceId.THREATFOX,
        protocol=DatasourceProtocol.HTTPS,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.THREATFOX,
    )
    assert first.datasource_id.value != second.datasource_id.value
    assert first.source_id is second.source_id


def test_d27a_12_no_dimension_selects_semantics() -> None:
    """D27A-12: construction retains exactly the supplied dimensions.

    MITRE source + HTTPS + JSON with ThreatFox semantics is legal: no
    provider/protocol/serialization mapping silently replaces the semantic
    format, and an unusual combination never fails because of an encoded
    compatibility matrix.
    """
    definition = DatasourceDefinition(
        datasource_id=DatasourceId("cross-over-a"),
        source_id=SourceId.MITRE_ATTACK,
        protocol=DatasourceProtocol.HTTPS,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.THREATFOX,
    )
    assert definition.source_id is SourceId.MITRE_ATTACK
    assert definition.protocol is DatasourceProtocol.HTTPS
    assert definition.serialization_format is SerializationFormat.JSON
    assert definition.semantic_format is SemanticFormatId.THREATFOX


def test_d27a_13_json_does_not_imply_semantics() -> None:
    """D27A-13: two JSON definitions may carry different semantic formats."""
    json_stix = DatasourceDefinition(
        datasource_id=DatasourceId("stix-json-a"),
        source_id=SourceId.MITRE_ATTACK,
        protocol=DatasourceProtocol.HTTPS,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.STIX_21,
    )
    json_threatfox = DatasourceDefinition(
        datasource_id=DatasourceId("threatfox-json-b"),
        source_id=SourceId.THREATFOX,
        protocol=DatasourceProtocol.HTTPS,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.THREATFOX,
    )
    assert json_stix.serialization_format is SerializationFormat.JSON
    assert json_threatfox.serialization_format is SerializationFormat.JSON
    assert json_stix.semantic_format is SemanticFormatId.STIX_21
    assert json_threatfox.semantic_format is SemanticFormatId.THREATFOX


def test_definition_requires_all_five_dimensions() -> None:
    """Every dimension is mandatory; no dimension is invented by inference."""
    with pytest.raises(ValidationError):
        DatasourceDefinition(  # type: ignore[call-arg]
            source_id=SourceId.THREATFOX,
            protocol=DatasourceProtocol.HTTPS,
            serialization_format=SerializationFormat.JSON,
        )
    with pytest.raises(ValidationError):
        _definition(source_id="urn:ati:source:unknown")
    with pytest.raises(ValidationError):
        _definition(extra_dimension="x")


def test_representative_definitions_are_the_documented_pair() -> None:
    """The repository-owned default pair is ThreatFox and MITRE ATT&CK."""
    assert len(REPRESENTATIVE_DATASOURCE_DEFINITIONS) == 2
    by_id = {d.datasource_id.value: d for d in REPRESENTATIVE_DATASOURCE_DEFINITIONS}
    assert by_id["threatfox-live"].source_id is SourceId.THREATFOX
    assert by_id["threatfox-live"].protocol is DatasourceProtocol.HTTPS
    assert by_id["threatfox-live"].semantic_format is SemanticFormatId.THREATFOX
    assert by_id["mitre-attack-enterprise"].source_id is SourceId.MITRE_ATTACK
    assert by_id["mitre-attack-enterprise"].protocol is DatasourceProtocol.FILE
    assert by_id["mitre-attack-enterprise"].semantic_format is (
        SemanticFormatId.STIX_21
    )
    assert all(
        d.serialization_format is SerializationFormat.JSON
        for d in REPRESENTATIVE_DATASOURCE_DEFINITIONS
    )
