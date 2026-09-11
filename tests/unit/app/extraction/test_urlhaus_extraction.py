# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for deterministic URLhaus entity extraction."""

# The evidence-builder helpers in extraction test modules intentionally
# share the normalized Evidence construction shape (see the established
# provider fixture family); the duplication is test-only and accepted.

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.extraction import (
    EvidenceExtractionError,
    ExtractionErrorReason,
    extract_urlhaus,
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
)

SOURCE = SourceId.URLHAUS.value
CANONICAL_SCENARIO_URL = f"http://{CANONICAL_ASYNCRAT_DOMAIN}/download/payload.bin"


def urlhaus_evidence(
    matches: list[dict[str, object]],
    *,
    subject_type: EntityType = EntityType.DOMAIN,
    subject_value: str = CANONICAL_ASYNCRAT_DOMAIN,
    evidence_id: UUID | None = None,
) -> Evidence:
    """Build one normalized URLhaus evidence observation with the given matches."""
    return Evidence(
        id=evidence_id if evidence_id is not None else uuid4(),
        investigation_id=uuid4(),
        type=EvidenceType.THREAT_INTELLIGENCE,
        subject=EntityRef(type=subject_type, value=subject_value),
        source=SOURCE,
        retrieved_at=datetime(2026, 1, 15, tzinfo=UTC),
        facts={"matches": matches},
        raw_payload=None,
    )


def direct_url_match(**overrides: object) -> dict[str, object]:
    """Build one normalized direct-URL match fact (URL lookup shape)."""
    match: dict[str, object] = {
        "urlhaus_id": "556677",
        "url": CANONICAL_SCENARIO_URL,
        "url_status": "online",
        "date_added": "2026-01-14T12:00:00Z",
        "last_online": None,
        "threat": "malware_download",
        "host": CANONICAL_ASYNCRAT_DOMAIN,
        "tags": ["elf"],
        "payloads": [
            {
                "first_seen": "2026-01-14",
                "filename": "payload.bin",
                "file_type": "elf",
                "response_size": 12345,
                "response_md5": "0" * 32,
                "response_sha256": "1" * 64,
                "signature": "AsyncRAT",
            }
        ],
    }
    match.update(overrides)
    return match


def host_record_match(**overrides: object) -> dict[str, object]:
    """Build one normalized host-response nested match fact (host=null)."""
    match: dict[str, object] = {
        "urlhaus_id": "556677",
        "url": CANONICAL_SCENARIO_URL,
        "url_status": "online",
        "date_added": "2026-01-14T12:00:00Z",
        "last_online": None,
        "threat": "malware_download",
        "host": None,
        "tags": ["elf"],
        "payloads": None,
    }
    match.update(overrides)
    return match


def test_direct_url_match_discovers_url_and_domain_host() -> None:
    """A direct URL record discovers both the URL and its DOMAIN host."""
    result = extract_urlhaus(urlhaus_evidence([direct_url_match()]))

    assert len(result.entities) == 2
    assert (result.entities[0].type, result.entities[0].value) == (
        EntityType.URL,
        CANONICAL_SCENARIO_URL,
    )
    assert (result.entities[1].type, result.entities[1].value) == (
        EntityType.DOMAIN,
        CANONICAL_ASYNCRAT_DOMAIN,
    )


def test_url_lookup_never_emits_relationships() -> None:
    """URLhaus extraction always yields zero relationships."""
    result = extract_urlhaus(urlhaus_evidence([direct_url_match()]))

    assert not result.relationships


def test_direct_url_match_with_ipv4_host() -> None:
    """A direct URL record with an IPv4 host discovers an IP_ADDRESS entity."""
    url = f"http://{CANONICAL_ASYNCRAT_IP}/a.bin"
    result = extract_urlhaus(
        urlhaus_evidence(
            [direct_url_match(url=url, host=CANONICAL_ASYNCRAT_IP)],
            subject_type=EntityType.IP_ADDRESS,
            subject_value=CANONICAL_ASYNCRAT_IP,
        )
    )

    hosts = [
        entity for entity in result.entities if entity.type is EntityType.IP_ADDRESS
    ]
    assert len(hosts) == 1
    assert hosts[0].value == CANONICAL_ASYNCRAT_IP


def test_host_lookup_record_with_null_host_discovers_url_only() -> None:
    """Host-response records carry host=null and never synthesize queried_host."""
    evidence = urlhaus_evidence([host_record_match()])
    assert evidence.facts["matches"][0]["host"] is None
    result = extract_urlhaus(evidence)

    assert [entity.type for entity in result.entities] == [EntityType.URL]


def test_duplicate_and_multiple_urls_deduplicate_in_order() -> None:
    """Duplicate URLs collapse; distinct URLs keep first-seen order."""
    first = direct_url_match(urlhaus_id="556677")
    second = direct_url_match(
        urlhaus_id="556678",
        url="http://other.example.test/b.bin",
        host="other.example.test",
    )
    result = extract_urlhaus(urlhaus_evidence([first, second, first]))

    urls = [entity.value for entity in result.entities if entity.type is EntityType.URL]
    assert urls == [CANONICAL_SCENARIO_URL, "http://other.example.test/b.bin"]


def test_hashes_signature_tags_and_status_are_ignored() -> None:
    """Payload hashes, signatures, tags, and statuses never become entities."""
    baseline = extract_urlhaus(urlhaus_evidence([direct_url_match()]))
    ignored = extract_urlhaus(
        urlhaus_evidence(
            [
                direct_url_match(
                    url_status="offline",
                    tags=["changed"],
                    payloads=[
                        {
                            "first_seen": "2026-01-01",
                            "filename": "other.bin",
                            "file_type": "exe",
                            "response_size": 1,
                            "response_md5": "2" * 32,
                            "response_sha256": "3" * 64,
                            "signature": "SomeOtherSignature",
                        }
                    ],
                )
            ]
        )
    )

    assert baseline == ignored


def test_no_malware_entity_is_ever_inferred() -> None:
    """URLhaus signatures and tags never produce MALWARE entities."""
    result = extract_urlhaus(urlhaus_evidence([direct_url_match()]))

    assert all(entity.type is not EntityType.MALWARE for entity in result.entities)


def test_malformed_url_fails() -> None:
    """A URL fact outside the identity contract is a contract failure."""
    for bad in (
        "ftp://example.test/a.bin",
        "http://example.test/a.bin#frag",
        "not a url",
    ):
        with pytest.raises(EvidenceExtractionError) as excinfo:
            extract_urlhaus(urlhaus_evidence([direct_url_match(url=bad)]))
        assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_malformed_host_fails() -> None:
    """A host fact outside the DOMAIN/IP identity contract is a contract failure.

    A dotted-decimal-looking value with an out-of-range octet is classified as
    a DNS name exactly like the provider does, so it is not a contract
    failure; blank and non-name spellings always are.
    """
    for bad in ("bad_host.test", "Bad Host", ""):
        with pytest.raises(EvidenceExtractionError) as excinfo:
            extract_urlhaus(urlhaus_evidence([direct_url_match(host=bad)]))
        assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_noncanonical_fact_values_fail() -> None:
    """Fact values that canonicalize differently are contract failures."""
    with pytest.raises(EvidenceExtractionError):
        extract_urlhaus(
            urlhaus_evidence([direct_url_match(url=CANONICAL_SCENARIO_URL.upper())])
        )
    with pytest.raises(EvidenceExtractionError):
        extract_urlhaus(
            urlhaus_evidence([direct_url_match(host=CANONICAL_ASYNCRAT_DOMAIN.upper())])
        )


def test_missing_matches_fail() -> None:
    """Missing or empty match collections are contract failures."""
    fact_shapes: tuple[dict[str, object], ...] = ({}, {"matches": []})
    for facts in fact_shapes:
        evidence = urlhaus_evidence([]).model_copy(update={"facts": facts})
        with pytest.raises(EvidenceExtractionError) as excinfo:
            extract_urlhaus(evidence)
        assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_missing_persisted_evidence_id_fails() -> None:
    """URLhaus entity discovery requires a persisted Evidence ID."""
    evidence = urlhaus_evidence([direct_url_match()])
    unpersisted = evidence.model_copy(update={"id": None})

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_urlhaus(unpersisted)

    assert excinfo.value.reason is ExtractionErrorReason.MISSING_EVIDENCE_ID


def test_mixed_record_shapes_never_emit_relationships() -> None:
    """Mixed direct and nested record shapes still yield zero relationships."""
    result = extract_urlhaus(
        urlhaus_evidence([direct_url_match(), host_record_match(urlhaus_id="556678")])
    )

    assert not result.relationships
    assert [entity.value for entity in result.entities] == [
        CANONICAL_SCENARIO_URL,
        CANONICAL_ASYNCRAT_DOMAIN,
    ]


def test_noncanonical_but_valid_subject_fails() -> None:
    """A subject that canonicalizes differently is a contract failure."""
    evidence = urlhaus_evidence(
        [direct_url_match()], subject_value="MALICIOUS-DOMAIN.TEST"
    )

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_urlhaus(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_malformed_url_subject_fails() -> None:
    """A URL subject outside the URL identity contract is a contract failure."""
    evidence = urlhaus_evidence(
        [direct_url_match()],
        subject_type=EntityType.URL,
        subject_value="not a url",
    )

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_urlhaus(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_non_object_match_fails() -> None:
    """A match entry that is not an object is a contract failure."""
    evidence = urlhaus_evidence([]).model_copy(
        update={"facts": {"matches": ("not-an-object",)}}
    )

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_urlhaus(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_non_string_url_or_host_members_fail() -> None:
    """Non-string url and host members are contract failures."""
    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_urlhaus(urlhaus_evidence([direct_url_match(url=42)]))
    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_urlhaus(urlhaus_evidence([direct_url_match(host=42)]))
    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_noncanonical_ip_host_form_fails() -> None:
    """An IP host fact that canonicalizes differently is a contract failure."""
    evidence = urlhaus_evidence([direct_url_match(host="2001:0db8:0:0:0:0:0:0001")])

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_urlhaus(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS
