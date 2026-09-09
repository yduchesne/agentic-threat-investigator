# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for conservative RDAP extraction."""

# The evidence-builder helpers in extraction test modules intentionally
# share the normalized Evidence construction shape (see the established
# provider fixture family); the duplication is test-only and accepted.
# pylint: disable=duplicate-code

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.extraction import (
    EvidenceExtractionError,
    ExtractionErrorReason,
    extract_rdap,
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

SOURCE = SourceId.RDAP.value


def rdap_evidence(
    facts: dict[str, object],
    *,
    subject_type: EntityType = EntityType.IP_ADDRESS,
    subject_value: str = "198.51.100.42",
    evidence_type: EvidenceType = EvidenceType.NETWORK,
    evidence_id: UUID | None = None,
) -> Evidence:
    """Build one normalized RDAP evidence observation with the given facts."""
    return Evidence(
        id=evidence_id if evidence_id is not None else uuid4(),
        investigation_id=uuid4(),
        type=evidence_type,
        subject=EntityRef(type=subject_type, value=subject_value),
        source=SOURCE,
        retrieved_at=datetime(2026, 1, 15, tzinfo=UTC),
        facts=facts,
        raw_payload=None,
    )


def network_facts(**overrides: object) -> dict[str, object]:
    """Build one normalized IP-network fact shape."""
    facts: dict[str, object] = {
        "object_class_name": "ip network",
        "start_address": "198.51.100.0",
        "end_address": "198.51.100.255",
        "ip_version": "v4",
        "cidr0_cidrs": [{"prefix": "198.51.100.0", "length": 24}],
        "handle": "NET-198-51-100-0-1",
        "entities": [
            {"handle": "ORG-1", "roles": ["registrant"], "display_name": "Some Org"}
        ],
    }
    facts.update(overrides)
    return facts


def test_ipv4_cidr0_discovers_prefix_and_belongsto() -> None:
    """An explicit CIDR0 prefix yields the BELONGS_TO assertion and the prefix entity."""
    result = extract_rdap(rdap_evidence(network_facts()))

    assert result.entities[0].type is EntityType.NETWORK_PREFIX
    assert result.entities[0].value == "198.51.100.0/24"
    edge = result.relationships[0]
    assert edge.source.type is EntityType.IP_ADDRESS
    assert edge.source.value == "198.51.100.42"
    assert edge.type is RelationshipType.BELONGS_TO
    assert edge.target.value == "198.51.100.0/24"
    assert edge.evidence_id is not None


def test_ipv6_cidr0_discovers_prefix_and_belongsto() -> None:
    """An IPv6 CIDR0 prefix canonicalizes and asserts containment."""
    result = extract_rdap(
        rdap_evidence(
            network_facts(
                start_address="2001:db8::",
                end_address="2001:db8:0:ffff:ffff:ffff:ffff:ffff",
                ip_version="v6",
                cidr0_cidrs=[{"prefix": "2001:db8::", "length": 32}],
            ),
            subject_value="2001:db8::1",
        )
    )

    assert result.entities[0].value == "2001:db8::/32"
    assert result.relationships[0].target.value == "2001:db8::/32"


def test_multiple_prefixes_all_assert() -> None:
    """Every explicit CIDR0 prefix produces its own assertion in order."""
    result = extract_rdap(
        rdap_evidence(
            network_facts(
                cidr0_cidrs=[
                    {"prefix": "198.51.100.0", "length": 24},
                    {"prefix": "198.51.100.128", "length": 25},
                ]
            ),
            subject_value="198.51.100.128",
        )
    )

    assert [entity.value for entity in result.entities] == [
        "198.51.100.0/24",
        "198.51.100.128/25",
    ]
    assert len(result.relationships) == 2


def test_duplicate_prefixes_deduplicate() -> None:
    """Repeated identical prefixes collapse to one entity and one assertion."""
    result = extract_rdap(
        rdap_evidence(
            network_facts(
                cidr0_cidrs=[
                    {"prefix": "198.51.100.0", "length": 24},
                    {"prefix": "198.51.100.0", "length": 24},
                ]
            )
        )
    )

    assert len(result.entities) == 1
    assert len(result.relationships) == 1


def test_noncontaining_prefix_fails() -> None:
    """A CIDR0 prefix that does not contain the subject is a contract failure."""
    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(
            rdap_evidence(
                network_facts(cidr0_cidrs=[{"prefix": "203.0.113.0", "length": 24}])
            )
        )

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_range_without_cidr0_yields_nothing() -> None:
    """No CIDR0 facts means no invented prefix: an empty result."""
    for facts in (
        network_facts(cidr0_cidrs=[]),
        {k: v for k, v in network_facts().items() if k != "cidr0_cidrs"},
    ):
        result = extract_rdap(rdap_evidence(facts))
        assert result == ExtractionResult()


def test_start_end_range_alone_never_invents_a_prefix() -> None:
    """Arbitrary start/end ranges are never synthesized into a prefix."""
    result = extract_rdap(rdap_evidence(network_facts(cidr0_cidrs=None)))

    assert result == ExtractionResult()


def test_rdap_entities_never_become_organization() -> None:
    """Handles, roles, and display names never produce ORGANIZATION entities."""
    result = extract_rdap(rdap_evidence(network_facts()))

    assert all(entity.type is not EntityType.ORGANIZATION for entity in result.entities)
    assert all(
        edge.type
        not in (
            RelationshipType.REGISTERED_TO,
            RelationshipType.OPERATED_BY,
            RelationshipType.ANNOUNCED_BY,
        )
        for edge in result.relationships
    )


def test_registration_evidence_returns_empty() -> None:
    """Domain and ASN RDAP evidence produce no extraction in PR 18B."""
    domain_result = extract_rdap(
        rdap_evidence(
            {
                "object_class_name": "domain",
                "ldh_name": "example.test",
                "nameservers": ["ns1.example.test"],
            },
            subject_type=EntityType.DOMAIN,
            subject_value="example.test",
            evidence_type=EvidenceType.REGISTRATION,
        )
    )
    asn_result = extract_rdap(
        rdap_evidence(
            {
                "object_class_name": "autnum",
                "start_autnum": 64496,
                "end_autnum": 64496,
            },
            subject_type=EntityType.ASN,
            subject_value="AS64496",
            evidence_type=EvidenceType.REGISTRATION,
        )
    )

    assert domain_result == ExtractionResult()
    assert asn_result == ExtractionResult()


def test_unsupported_rdap_evidence_type_fails() -> None:
    """An RDAP evidence type that RDAP never produces is a contract failure."""
    evidence = rdap_evidence(network_facts()).model_copy(
        update={"type": EvidenceType.DNS}
    )

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.UNSUPPORTED_EVIDENCE_TYPE


def test_network_evidence_without_ip_subject_fails() -> None:
    """RDAP network evidence always has an IP subject."""
    evidence = rdap_evidence(network_facts()).model_copy(
        update={"subject": EntityRef(type=EntityType.DOMAIN, value="example.test")}
    )

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_missing_persisted_evidence_id_fails() -> None:
    """RDAP network extraction requires a persisted Evidence ID."""
    evidence = rdap_evidence(network_facts())
    unpersisted = evidence.model_copy(update={"id": None})

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(unpersisted)

    assert excinfo.value.reason is ExtractionErrorReason.MISSING_EVIDENCE_ID


@pytest.mark.parametrize(
    "cidrs",
    [
        "not-a-list",
        [None],
        [{"length": 24}],
        [{"prefix": "198.51.100.0"}],
        [{"prefix": "198.51.100.0", "length": "24"}],
        [{"prefix": "198.51.100.0", "length": True}],
        [{"prefix": "198.51.100.0", "length": 33}],
        [{"prefix": "198.51.100.42", "length": 24}],
    ],
)
def test_malformed_cidr0_entries_fail(cidrs: list[object]) -> None:
    """Malformed or host-bit-set CIDR0 entries are contract failures."""
    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(rdap_evidence(network_facts(cidr0_cidrs=cidrs)))

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_unexpected_object_class_fails() -> None:
    """Network evidence without the ip-network object class is a contract failure."""
    evidence = rdap_evidence(network_facts(object_class_name="domain"))

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_wrong_source_is_a_contract_failure() -> None:
    """RDAP extraction rejects evidence from any other source contract."""
    evidence = rdap_evidence(network_facts()).model_copy(update={"source": "other"})

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.UNSUPPORTED_EVIDENCE_TYPE


def test_noncanonical_ip_subject_fails() -> None:
    """A subject address that cannot parse is a contract failure."""
    evidence = rdap_evidence(network_facts(), subject_value="198.51.100.042")

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_noncanonical_ipv6_subject_fails() -> None:
    """A valid but noncanonical IPv6 subject is a contract failure."""
    evidence = rdap_evidence(network_facts(), subject_value="2001:0db8::1")

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_noncanonical_subject_fails_without_cidr0() -> None:
    """The subject is validated even when no explicit prefixes exist."""
    cidrs_options: tuple[object, ...] = (None, [])
    for cidrs in cidrs_options:
        evidence = rdap_evidence(
            network_facts(cidr0_cidrs=cidrs), subject_value="2001:0db8::1"
        )

        with pytest.raises(EvidenceExtractionError) as excinfo:
            extract_rdap(evidence)

        assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_cidr0_family_must_match_subject_family() -> None:
    """A CIDR0 prefix of a different family than the subject fails explicitly."""
    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(
            rdap_evidence(
                network_facts(cidr0_cidrs=[{"prefix": "2001:db8::", "length": 32}]),
                subject_value="198.51.100.42",
            )
        )
    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(
            rdap_evidence(
                network_facts(cidr0_cidrs=[{"prefix": "198.51.100.0", "length": 24}]),
                subject_value="2001:db8::1",
            )
        )
    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


@pytest.mark.parametrize(
    "subject_type,subject_value,object_class",
    [
        (EntityType.IP_ADDRESS, "198.51.100.42", "domain"),
        (EntityType.IP_ADDRESS, "198.51.100.42", "autnum"),
        (EntityType.MALWARE, "win.asyncrat", "domain"),
        (EntityType.DOMAIN, "MALICIOUS-DOMAIN.TEST", "domain"),
        (EntityType.ASN, "as64496", "autnum"),
    ],
)
def test_invalid_registration_envelope_fails(
    subject_type: EntityType, subject_value: str, object_class: str
) -> None:
    """REGISTRATION validates its subject pairing and canonical subject value."""
    evidence = rdap_evidence(
        {"object_class_name": object_class},
        subject_type=subject_type,
        subject_value=subject_value,
        evidence_type=EvidenceType.REGISTRATION,
    )

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_registration_requires_persisted_evidence_id() -> None:
    """Both RDAP branches follow the same persisted-Evidence ID policy."""
    evidence = rdap_evidence(
        {
            "object_class_name": "domain",
            "ldh_name": "example.test",
        },
        subject_type=EntityType.DOMAIN,
        subject_value="example.test",
        evidence_type=EvidenceType.REGISTRATION,
    )
    unpersisted = evidence.model_copy(update={"id": None})

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_rdap(unpersisted)

    assert excinfo.value.reason is ExtractionErrorReason.MISSING_EVIDENCE_ID


def test_valid_registration_pairings_return_empty() -> None:
    """Valid DOMAIN/domain and ASN/autnum registrations yield empty results."""
    domain_result = extract_rdap(
        rdap_evidence(
            {"object_class_name": "domain", "ldh_name": "example.test"},
            subject_type=EntityType.DOMAIN,
            subject_value="example.test",
            evidence_type=EvidenceType.REGISTRATION,
        )
    )
    asn_result = extract_rdap(
        rdap_evidence(
            {"object_class_name": "autnum", "start_autnum": 64496},
            subject_type=EntityType.ASN,
            subject_value="AS64496",
            evidence_type=EvidenceType.REGISTRATION,
        )
    )

    assert domain_result == ExtractionResult()
    assert asn_result == ExtractionResult()
