# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for deterministic DNS extraction."""

# The evidence-builder helpers in extraction test modules intentionally
# share the normalized Evidence construction shape (see the established
# provider fixture family); the duplication is test-only and accepted.
# pylint: disable=duplicate-code

import pytest

from agentic_threat_investigator.app.extraction import (
    EvidenceExtractionError,
    ExtractionErrorReason,
    extract_dns,
)
from agentic_threat_investigator.app.extraction.models import ExtractionResult
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.relationships import RelationshipType
from tests.support.extraction_fixtures import (
    CANONICAL_ASYNCRAT_DOMAIN,
    CANONICAL_ASYNCRAT_IP,
    CANONICAL_DNS_EVIDENCE_ID,
    a_answer,
    dns_evidence,
)

SOURCE = SourceId.GOOGLE_PUBLIC_DNS.value


def test_a_record_resolves_and_discovers_address() -> None:
    """An A record asserts owner RESOLVES_TO address and discovers the address."""
    result = extract_dns(dns_evidence([a_answer()]))

    assert len(result.entities) == 1
    assert result.entities[0].type is EntityType.IP_ADDRESS
    assert result.entities[0].value == CANONICAL_ASYNCRAT_IP
    assert len(result.relationships) == 1
    edge = result.relationships[0]
    assert edge.source.type is EntityType.DOMAIN
    assert edge.source.value == CANONICAL_ASYNCRAT_DOMAIN
    assert edge.type is RelationshipType.RESOLVES_TO
    assert edge.target.type is EntityType.IP_ADDRESS
    assert edge.target.value == CANONICAL_ASYNCRAT_IP
    assert edge.evidence_id is not None


def test_canonical_scenario_evidence_id_is_carried_on_assertions() -> None:
    """Assertions carry the persisted canonical-scenario Evidence ID."""
    result = extract_dns(
        dns_evidence([a_answer()], evidence_id=CANONICAL_DNS_EVIDENCE_ID)
    )

    assert result.relationships[0].evidence_id == CANONICAL_DNS_EVIDENCE_ID


def test_aaaa_record_discovers_ipv6_address() -> None:
    """An AAAA record asserts RESOLVES_TO with the canonical IPv6 identity."""
    address = "2001:db8::1"
    result = extract_dns(
        dns_evidence(
            [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "AAAA",
                    "ttl": 300,
                    "value": address,
                }
            ],
            query_type="AAAA",
        )
    )

    assert result.entities[0].value == address
    assert result.relationships[0].target.value == address


def test_multiple_a_records_discover_each_address() -> None:
    """Multiple A records produce one assertion per address in source order."""
    result = extract_dns(
        dns_evidence(
            [
                a_answer(value="203.0.113.42"),
                a_answer(value="203.0.113.43"),
            ]
        )
    )

    assert [entity.value for entity in result.entities] == [
        "203.0.113.42",
        "203.0.113.43",
    ]
    assert [edge.target.value for edge in result.relationships] == [
        "203.0.113.42",
        "203.0.113.43",
    ]


def test_duplicate_a_records_deduplicate() -> None:
    """Repeated identical answers collapse to one entity and one assertion."""
    result = extract_dns(dns_evidence([a_answer(), a_answer()]))

    assert len(result.entities) == 1
    assert len(result.relationships) == 1


def test_cname_relation_discovers_target() -> None:
    """A CNAME record asserts owner CNAME_OF target and discovers the target."""
    result = extract_dns(
        dns_evidence(
            [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "CNAME",
                    "ttl": 300,
                    "value": "cdn.example.test",
                }
            ],
            query_type="CNAME",
        )
    )

    assert result.entities[0].type is EntityType.DOMAIN
    assert result.entities[0].value == "cdn.example.test"
    assert result.relationships[0].type is RelationshipType.CNAME_OF
    assert result.relationships[0].target.value == "cdn.example.test"


def test_cname_chain_asserts_each_link() -> None:
    """A CNAME chain asserts every link in source order."""
    result = extract_dns(
        dns_evidence(
            [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "CNAME",
                    "ttl": 300,
                    "value": "cdn.example.test",
                },
                {
                    "name": "cdn.example.test",
                    "record_type": "CNAME",
                    "ttl": 300,
                    "value": "edge.example.test",
                },
            ],
            query_type="CNAME",
        )
    )

    assert [
        (edge.source.value, edge.target.value) for edge in result.relationships
    ] == [
        (CANONICAL_ASYNCRAT_DOMAIN, "cdn.example.test"),
        ("cdn.example.test", "edge.example.test"),
    ]
    assert [entity.value for entity in result.entities] == [
        "cdn.example.test",
        "edge.example.test",
    ]


def test_a_after_cname_owner_uses_answer_owner_as_source() -> None:
    """A terminal A record behind a CNAME chain resolves from the chain target."""
    result = extract_dns(
        dns_evidence(
            [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "CNAME",
                    "ttl": 300,
                    "value": "cdn.example.test",
                },
                a_answer(name="cdn.example.test"),
            ],
            query_type="A",
        )
    )

    resolves = [
        edge
        for edge in result.relationships
        if edge.type is RelationshipType.RESOLVES_TO
    ]
    assert len(resolves) == 1
    assert resolves[0].source.value == "cdn.example.test"
    assert resolves[0].target.value == CANONICAL_ASYNCRAT_IP


def test_ns_relation_discovers_nameserver() -> None:
    """An NS record asserts owner USES_NAME_SERVER target and discovers the target."""
    result = extract_dns(
        dns_evidence(
            [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "NS",
                    "ttl": 3600,
                    "value": "ns1.example.test",
                }
            ],
            query_type="NS",
        )
    )

    assert result.relationships[0].type is RelationshipType.USES_NAME_SERVER
    assert result.relationships[0].target.value == "ns1.example.test"
    assert result.entities[0].value == "ns1.example.test"


def test_ordinary_mx_relation_discovers_exchange() -> None:
    """An ordinary MX record asserts USES_MAIL_SERVER and discovers the exchange."""
    result = extract_dns(
        dns_evidence(
            [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "MX",
                    "ttl": 3600,
                    "preference": 10,
                    "exchange": "mail.example.test",
                }
            ],
            query_type="MX",
        )
    )

    assert result.relationships[0].type is RelationshipType.USES_MAIL_SERVER
    assert result.relationships[0].target.value == "mail.example.test"
    assert result.entities[0].value == "mail.example.test"


def test_preference_zero_ordinary_mx_is_ordinary() -> None:
    """Preference zero with a real exchange is an ordinary MX record."""
    result = extract_dns(
        dns_evidence(
            [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "MX",
                    "ttl": 3600,
                    "preference": 0,
                    "exchange": "mail.example.test",
                }
            ],
            query_type="MX",
        )
    )

    assert len(result.relationships) == 1
    assert result.relationships[0].type is RelationshipType.USES_MAIL_SERVER


def test_null_mx_produces_nothing() -> None:
    """The null-MX sentinel (preference 0, root exchange) asserts nothing."""
    result = extract_dns(
        dns_evidence(
            [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "MX",
                    "ttl": 3600,
                    "preference": 0,
                    "exchange": ".",
                }
            ],
            query_type="MX",
        )
    )

    assert result == ExtractionResult()


def test_root_mx_exchange_with_nonzero_preference_is_malformed() -> None:
    """A root exchange with a nonzero preference cannot occur in facts."""
    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_dns(
            dns_evidence(
                [
                    {
                        "name": CANONICAL_ASYNCRAT_DOMAIN,
                        "record_type": "MX",
                        "ttl": 3600,
                        "preference": 10,
                        "exchange": ".",
                    }
                ],
                query_type="MX",
            )
        )

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_ptr_discovers_target_without_relationship() -> None:
    """PTR discovers the target domain only: no forward-resolution assertion."""
    result = extract_dns(
        dns_evidence(
            [
                {
                    "name": "42.113.0.203.in-addr.arpa",
                    "record_type": "PTR",
                    "ttl": 3600,
                    "value": CANONICAL_ASYNCRAT_DOMAIN,
                }
            ],
            subject_type=EntityType.IP_ADDRESS,
            subject_value=CANONICAL_ASYNCRAT_IP,
            query_type="PTR",
            query_name="42.113.0.203.in-addr.arpa",
        )
    )

    assert not result.relationships
    assert [entity.value for entity in result.entities] == [CANONICAL_ASYNCRAT_DOMAIN]


def test_root_ptr_value_is_not_discovered() -> None:
    """A root PTR value is a protocol sentinel and never an entity."""
    result = extract_dns(
        dns_evidence(
            [
                {
                    "name": "42.113.0.203.in-addr.arpa",
                    "record_type": "PTR",
                    "ttl": 3600,
                    "value": ".",
                }
            ],
            subject_type=EntityType.IP_ADDRESS,
            subject_value=CANONICAL_ASYNCRAT_IP,
            query_type="PTR",
            query_name="42.113.0.203.in-addr.arpa",
        )
    )

    assert result == ExtractionResult()


def test_root_cname_target_contributes_nothing() -> None:
    """A root CNAME target is a sentinel: no entity and no assertion."""
    result = extract_dns(
        dns_evidence(
            [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "CNAME",
                    "ttl": 300,
                    "value": ".",
                }
            ],
            query_type="CNAME",
        )
    )

    assert result == ExtractionResult()


def test_txt_and_soa_produce_nothing() -> None:
    """TXT and SOA answers never produce entities or assertions."""
    txt_result = extract_dns(
        dns_evidence(
            [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "TXT",
                    "ttl": 300,
                    "value": "v=spf1 -all",
                }
            ],
            query_type="TXT",
        )
    )
    soa_result = extract_dns(
        dns_evidence(
            [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "SOA",
                    "ttl": 3600,
                    "mname": "ns1.example.test",
                    "rname": "hostmaster.example.test",
                    "serial": 2026011501,
                    "refresh": 7200,
                    "retry": 3600,
                    "expire": 1209600,
                    "minimum": 3600,
                }
            ],
            query_type="SOA",
        )
    )

    assert txt_result == ExtractionResult()
    assert soa_result == ExtractionResult()


def test_missing_persisted_evidence_id_fails() -> None:
    """Unpersisted evidence cannot back assertions and fails explicitly."""
    evidence = dns_evidence([a_answer()])
    unpersisted = evidence.model_copy(update={"id": None})

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_dns(unpersisted)

    assert excinfo.value.reason is ExtractionErrorReason.MISSING_EVIDENCE_ID


def test_wrong_source_or_type_is_a_contract_failure() -> None:
    """DNS extraction rejects evidence from any other source/type contract."""
    wrong_source = dns_evidence([a_answer()]).model_copy(update={"source": "other"})
    wrong_type = dns_evidence([a_answer()]).model_copy(
        update={"type": EvidenceType.REPUTATION}
    )

    for evidence in (wrong_source, wrong_type):
        with pytest.raises(EvidenceExtractionError) as excinfo:
            extract_dns(evidence)
        assert excinfo.value.reason is ExtractionErrorReason.UNSUPPORTED_EVIDENCE_TYPE


@pytest.mark.parametrize(
    "facts",
    [
        {},
        {"query_name": "example.test", "query_type": "A", "status": 0},
        {
            "query_name": "example.test",
            "query_type": "BOGUS",
            "status": 0,
            "answers": [a_answer()],
        },
        {
            "query_name": "example.test",
            "query_type": "A",
            "status": 3,
            "answers": [a_answer()],
        },
        {
            "query_name": "example.test",
            "query_type": "A",
            "status": 0,
            "answers": [],
        },
        {
            "query_name": "example.test",
            "query_type": "A",
            "status": 0,
            "answers": "not-a-list",
        },
        {
            "query_name": "example.test",
            "query_type": "A",
            "status": 0,
            "answers": [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "BOGUS",
                    "ttl": 1,
                    "value": "x",
                }
            ],
        },
        {
            "query_name": "example.test",
            "query_type": "A",
            "status": 0,
            "answers": [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "A",
                    "ttl": -1,
                    "value": CANONICAL_ASYNCRAT_IP,
                }
            ],
        },
        {
            "query_name": "example.test",
            "query_type": "A",
            "status": 0,
            "answers": [
                {
                    "name": ".",
                    "record_type": "A",
                    "ttl": 300,
                    "value": CANONICAL_ASYNCRAT_IP,
                }
            ],
        },
        {
            "query_name": "example.test",
            "query_type": "A",
            "status": 0,
            "answers": [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN,
                    "record_type": "A",
                    "ttl": 300,
                    "value": "not-an-ip",
                }
            ],
        },
        {
            "query_name": "example.test",
            "query_type": "A",
            "status": 0,
            "answers": [
                {
                    "name": "Bad Domain.test",
                    "record_type": "A",
                    "ttl": 300,
                    "value": CANONICAL_ASYNCRAT_IP,
                }
            ],
        },
        {
            "query_name": "example.test",
            "query_type": "A",
            "status": 0,
            "answers": [
                {
                    "name": CANONICAL_ASYNCRAT_DOMAIN.upper(),
                    "record_type": "A",
                    "ttl": 300,
                    "value": CANONICAL_ASYNCRAT_IP,
                }
            ],
        },
    ],
)
def test_malformed_facts_fail_without_partial_results(
    facts: dict[object, object],
) -> None:
    """Every malformed normalized-fact shape raises and never yields output."""
    answers = facts.get("answers", [])
    assert isinstance(answers, (list, str))
    overrides = {str(k): v for k, v in facts.items() if k != "answers"}
    evidence = dns_evidence(
        answers if isinstance(answers, list) else [],
        facts_overrides=overrides,
    )

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_dns(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


@pytest.mark.parametrize(
    "answers",
    [
        ["not-an-object"],
        [{"record_type": "A", "ttl": 300, "value": CANONICAL_ASYNCRAT_IP}],
        [{"name": CANONICAL_ASYNCRAT_DOMAIN, "record_type": "A", "ttl": 300}],
        [
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "A",
                "ttl": 300,
                "value": 42,
            }
        ],
        [
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "A",
                "ttl": 300,
                "value": "2001:DB8::1",
            }
        ],
        [
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "MX",
                "ttl": 300,
                "preference": "10",
                "exchange": "mail.example.test",
            }
        ],
        [
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "MX",
                "ttl": 300,
                "preference": 10,
                "exchange": 42,
            }
        ],
    ],
)
def test_additional_malformed_answer_shapes_fail(answers: list[object]) -> None:
    """Non-object answers, invalid members, and non-canonical RDATA all fail."""
    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_dns(dns_evidence(answers))

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS
