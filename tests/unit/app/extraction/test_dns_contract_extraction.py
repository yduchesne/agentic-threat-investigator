# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""DNS extraction contract tests for the normalized query/answer envelope.

These tests pin the complete normalized Google Public DNS contract at the
extraction boundary: query envelope validation (name, type, status, flags,
subject pairing), answer attribution and CNAME-chain sequencing, and the
normalized shape of every supported answer record. Malformed or internally
inconsistent facts must raise ``EvidenceExtractionError`` and never yield
partial output.

# The evidence-builder helpers intentionally share the normalized Evidence
# construction shape with the other extraction test modules; the duplication
# is test-only and accepted.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.extraction import (
    EvidenceExtractionError,
    ExtractionErrorReason,
    extract_dns,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from tests.support.extraction_fixtures import (
    CANONICAL_ASYNCRAT_DOMAIN,
    CANONICAL_ASYNCRAT_IP,
    a_answer,
    dns_evidence,
)

SOURCE = SourceId.GOOGLE_PUBLIC_DNS.value


def raw_dns_evidence(
    facts: dict[str, object],
    *,
    subject_type: EntityType = EntityType.DOMAIN,
    subject_value: str = CANONICAL_ASYNCRAT_DOMAIN,
) -> Evidence:
    """Build one normalized DNS evidence observation from a raw fact mapping."""
    return Evidence(
        id=uuid4(),
        investigation_id=uuid4(),
        type=EvidenceType.DNS,
        subject=EntityRef(type=subject_type, value=subject_value),
        source=SOURCE,
        retrieved_at=datetime(2026, 1, 15, tzinfo=UTC),
        facts=facts,
        raw_payload=None,
    )


def assert_malformed(evidence: Evidence) -> None:
    """Assert the evidence raises a malformed-facts contract failure."""
    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_dns(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


@pytest.mark.parametrize(
    "query_name",
    [None, 42, ".", "example.com..", "bad_label.test", "EXAMPLE.TEST", " "],
)
def test_invalid_query_name_fails(query_name: object) -> None:
    """A missing, non-string, root, malformed, or noncanonical query name fails."""
    facts: dict[str, object] = {
        "query_type": "A",
        "status": 0,
        "flags": {},
        "answers": [a_answer()],
    }
    if query_name is not None:
        facts["query_name"] = query_name

    assert_malformed(raw_dns_evidence(facts))


@pytest.mark.parametrize(
    "query_type,answer",
    [
        ("A", a_answer()),
        ("AAAA", dict(a_answer(), record_type="AAAA", value="2001:db8::1")),
        (
            "CNAME",
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "CNAME",
                "ttl": 300,
                "value": "cdn.example.test",
            },
        ),
        (
            "MX",
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "MX",
                "ttl": 300,
                "preference": 10,
                "exchange": "mail.example.test",
            },
        ),
        (
            "NS",
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "NS",
                "ttl": 3600,
                "value": "ns1.example.test",
            },
        ),
        (
            "TXT",
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "TXT",
                "ttl": 300,
                "value": "v=spf1 -all",
            },
        ),
        (
            "SOA",
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "SOA",
                "ttl": 3600,
                "mname": "ns1.example.test",
                "rname": "hostmaster.example.test",
                "serial": 1,
                "refresh": 2,
                "retry": 3,
                "expire": 4,
                "minimum": 5,
            },
        ),
    ],
)
def test_forward_query_with_non_domain_subject_fails(
    query_type: str, answer: dict[str, object]
) -> None:
    """A forward query never has a non-DOMAIN evidence subject."""
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": query_type,
        "status": 0,
        "flags": {},
        "answers": [answer],
    }

    assert_malformed(
        raw_dns_evidence(
            facts,
            subject_type=EntityType.IP_ADDRESS,
            subject_value=CANONICAL_ASYNCRAT_IP,
        )
    )


def test_forward_query_name_not_matching_subject_fails() -> None:
    """A forward query name must equal the canonical DOMAIN subject."""
    facts: dict[str, object] = {
        "query_name": "other-domain.test",
        "query_type": "A",
        "status": 0,
        "flags": {},
        "answers": [a_answer(name="other-domain.test")],
    }

    assert_malformed(raw_dns_evidence(facts))


def test_forward_query_with_noncanonical_subject_fails() -> None:
    """A noncanonical DOMAIN subject never matches its own query name."""
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "A",
        "status": 0,
        "flags": {},
        "answers": [a_answer()],
    }

    assert_malformed(raw_dns_evidence(facts, subject_value="MALICIOUS-DOMAIN.TEST"))


def test_ptr_query_with_non_ip_subject_fails() -> None:
    """A PTR query never has a non-IP evidence subject."""
    facts: dict[str, object] = {
        "query_name": "42.113.0.203.in-addr.arpa",
        "query_type": "PTR",
        "status": 0,
        "flags": {},
        "answers": [
            {
                "name": "42.113.0.203.in-addr.arpa",
                "record_type": "PTR",
                "ttl": 3600,
                "value": CANONICAL_ASYNCRAT_DOMAIN,
            }
        ],
    }

    assert_malformed(raw_dns_evidence(facts))


@pytest.mark.parametrize(
    "query_name",
    ["43.113.0.203.in-addr.arpa", "42.113.0.203.in-addr.arpa.example.test"],
)
def test_ptr_query_name_not_reverse_pointer_fails(query_name: str) -> None:
    """A PTR query name must be the subject's exact reverse-pointer name."""
    facts: dict[str, object] = {
        "query_name": query_name,
        "query_type": "PTR",
        "status": 0,
        "flags": {},
        "answers": [
            {
                "name": query_name,
                "record_type": "PTR",
                "ttl": 3600,
                "value": CANONICAL_ASYNCRAT_DOMAIN,
            }
        ],
    }

    assert_malformed(
        raw_dns_evidence(
            facts,
            subject_type=EntityType.IP_ADDRESS,
            subject_value=CANONICAL_ASYNCRAT_IP,
        )
    )


def test_a_answer_with_ipv6_value_fails() -> None:
    """An A record must carry an IPv4 address."""
    assert_malformed(dns_evidence([a_answer(value="2001:db8::1")]))


def test_aaaa_answer_with_ipv4_value_fails() -> None:
    """An AAAA record must carry an IPv6 address."""
    assert_malformed(
        dns_evidence(
            [dict(a_answer(), record_type="AAAA", value=CANONICAL_ASYNCRAT_IP)],
            query_type="AAAA",
        )
    )


def test_answer_type_differing_from_query_type_fails() -> None:
    """An A query carrying an NS answer is an inconsistent answer set."""
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "A",
        "status": 0,
        "flags": {},
        "answers": [
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "NS",
                "ttl": 3600,
                "value": "ns1.example.test",
            }
        ],
    }

    assert_malformed(raw_dns_evidence(facts))


def test_answer_owner_outside_the_chain_fails() -> None:
    """An answer owner that does not follow the query/CNAME chain fails."""
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "A",
        "status": 0,
        "flags": {},
        "answers": [a_answer(name="unrelated.test")],
    }

    assert_malformed(raw_dns_evidence(facts))


def test_cname_after_terminal_answer_fails() -> None:
    """A CNAME record is never valid after a terminal answer."""
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "A",
        "status": 0,
        "flags": {},
        "answers": [a_answer(), dict(a_answer(), record_type="CNAME", value="x.test")],
    }

    assert_malformed(raw_dns_evidence(facts))


def test_cname_chain_cycle_fails() -> None:
    """A cycling or revisiting CNAME chain fails."""
    cycling: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "CNAME",
        "status": 0,
        "flags": {},
        "answers": [
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "CNAME",
                "ttl": 300,
                "value": "b.test",
            },
            {
                "name": "b.test",
                "record_type": "CNAME",
                "ttl": 300,
                "value": CANONICAL_ASYNCRAT_DOMAIN,
            },
        ],
    }
    self_referential: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "CNAME",
        "status": 0,
        "flags": {},
        "answers": [
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "CNAME",
                "ttl": 300,
                "value": CANONICAL_ASYNCRAT_DOMAIN,
            }
        ],
    }

    assert_malformed(raw_dns_evidence(cycling))
    assert_malformed(raw_dns_evidence(self_referential))


def test_txt_answer_without_value_fails() -> None:
    """A TXT answer requires its normalized string value even with no output."""
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "TXT",
        "status": 0,
        "flags": {},
        "answers": [
            {"name": CANONICAL_ASYNCRAT_DOMAIN, "record_type": "TXT", "ttl": 300}
        ],
    }

    assert_malformed(raw_dns_evidence(facts))


@pytest.mark.parametrize(
    "overrides",
    [
        {"mname": "ns1.example.test"},
        {"rname": "hostmaster.example.test"},
        {"serial": 1},
        {"refresh": 2},
        {"retry": 3},
        {"expire": 4},
        {"minimum": 5},
    ],
)
def test_soa_answer_missing_member_fails(overrides: dict[str, object]) -> None:
    """An SOA answer missing any normalized member fails."""
    complete: dict[str, object] = {
        "name": CANONICAL_ASYNCRAT_DOMAIN,
        "record_type": "SOA",
        "ttl": 3600,
        "mname": "ns1.example.test",
        "rname": "hostmaster.example.test",
        "serial": 1,
        "refresh": 2,
        "retry": 3,
        "expire": 4,
        "minimum": 5,
    }
    for key in overrides:
        complete.pop(key)
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "SOA",
        "status": 0,
        "flags": {},
        "answers": [complete],
    }

    assert_malformed(raw_dns_evidence(facts))


@pytest.mark.parametrize(
    "member,value",
    [
        ("serial", True),
        ("serial", -1),
        ("serial", 4294967296),
        ("minimum", False),
        ("expire", -5),
        ("retry", 4294967296),
    ],
)
def test_soa_invalid_integer_member_fails(member: str, value: object) -> None:
    """SOA integers reject booleans, negatives, and values above uint32."""
    complete: dict[str, object] = {
        "name": CANONICAL_ASYNCRAT_DOMAIN,
        "record_type": "SOA",
        "ttl": 3600,
        "mname": "ns1.example.test",
        "rname": "hostmaster.example.test",
        "serial": 1,
        "refresh": 2,
        "retry": 3,
        "expire": 4,
        "minimum": 5,
    }
    complete[member] = value
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "SOA",
        "status": 0,
        "flags": {},
        "answers": [complete],
    }

    assert_malformed(raw_dns_evidence(facts))


@pytest.mark.parametrize(
    "flags",
    [
        "not-a-mapping",
        {"bogus": True},
        {"rd": "yes"},
        {"ra": 1},
        {"tc": None},
    ],
)
def test_invalid_flags_fail(flags: object) -> None:
    """Flags must be a mapping of the documented names to strict booleans."""
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "A",
        "status": 0,
        "flags": flags,
        "answers": [a_answer()],
    }

    assert_malformed(raw_dns_evidence(facts))


def test_root_mx_with_second_mx_answer_fails() -> None:
    """A root (null) MX must be the only MX answer in the set."""
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "MX",
        "status": 0,
        "flags": {},
        "answers": [
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "MX",
                "ttl": 300,
                "preference": 0,
                "exchange": ".",
            },
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "MX",
                "ttl": 300,
                "preference": 10,
                "exchange": "mail.example.test",
            },
        ],
    }

    assert_malformed(raw_dns_evidence(facts))


def test_root_cname_cannot_be_followed_by_terminal_at_old_owner() -> None:
    """After a root CNAME, a terminal answer at the old owner is inconsistent.

    The authoritative provider chain validation advances the expected owner
    to every CNAME target, including the root sentinel, so this malformed
    sequence must fail instead of emitting a fabricated RESOLVES_TO edge.
    """
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "A",
        "status": 0,
        "flags": {},
        "answers": [
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "CNAME",
                "ttl": 300,
                "value": ".",
            },
            a_answer(name=CANONICAL_ASYNCRAT_DOMAIN),
        ],
    }

    assert_malformed(raw_dns_evidence(facts))


def test_root_cname_cannot_be_followed_by_cname_at_old_owner() -> None:
    """After a root CNAME, another CNAME at the old owner is inconsistent."""
    facts: dict[str, object] = {
        "query_name": CANONICAL_ASYNCRAT_DOMAIN,
        "query_type": "CNAME",
        "status": 0,
        "flags": {},
        "answers": [
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "CNAME",
                "ttl": 300,
                "value": ".",
            },
            {
                "name": CANONICAL_ASYNCRAT_DOMAIN,
                "record_type": "CNAME",
                "ttl": 300,
                "value": "other.test",
            },
        ],
    }

    assert_malformed(raw_dns_evidence(facts))
