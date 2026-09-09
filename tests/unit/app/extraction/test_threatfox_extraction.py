# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for deterministic ThreatFox extraction."""

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
    extract_threatfox,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.relationships import RelationshipType
from tests.support.extraction_fixtures import (
    CANONICAL_ASYNCRAT_IP,
    CANONICAL_ASYNCRAT_MALWARE,
    CANONICAL_ASYNCRAT_PRINTABLE,
    CANONICAL_THREATFOX_EVIDENCE_ID,
    canonical_threatfox_evidence,
)

SOURCE = SourceId.THREATFOX.value


def threatfox_evidence(
    matches: list[dict[str, object]],
    *,
    subject_type: EntityType = EntityType.IP_ADDRESS,
    subject_value: str = CANONICAL_ASYNCRAT_IP,
    evidence_id: UUID | None = None,
) -> Evidence:
    """Build one normalized ThreatFox evidence observation with the given matches."""
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


def asyncrat_match(**overrides: object) -> dict[str, object]:
    """Build one normalized AsyncRAT match fact."""
    match: dict[str, object] = {
        "threatfox_id": "864201",
        "ioc": CANONICAL_ASYNCRAT_IP,
        "ioc_type": "ip:port",
        "threat_type": "botnet_cc",
        "threat_type_description": "botnet command&control",
        "malware": CANONICAL_ASYNCRAT_MALWARE,
        "malware_printable": CANONICAL_ASYNCRAT_PRINTABLE,
        "confidence_level": 100,
        "first_seen": "2026-01-14T12:00:00Z",
        "last_seen": "2026-01-15T12:00:00Z",
        "reference": None,
        "tags": ["AsyncRAT"],
    }
    match.update(overrides)
    return match


def test_canonical_scenario_extracts_asyncrat() -> None:
    """The canonical ThreatFox evidence yields win.asyncrat (AsyncRAT)."""
    result = extract_threatfox(canonical_threatfox_evidence())

    assert len(result.entities) == 1
    entity = result.entities[0]
    assert entity.type is EntityType.MALWARE
    assert entity.value == CANONICAL_ASYNCRAT_MALWARE
    assert entity.display_name == CANONICAL_ASYNCRAT_PRINTABLE
    assert len(result.relationships) == 1
    edge = result.relationships[0]
    assert edge.source.type is EntityType.IP_ADDRESS
    assert edge.source.value == CANONICAL_ASYNCRAT_IP
    assert edge.type is RelationshipType.ASSOCIATED_WITH
    assert edge.target.type is EntityType.MALWARE
    assert edge.target.value == CANONICAL_ASYNCRAT_MALWARE
    assert edge.evidence_id == CANONICAL_THREATFOX_EVIDENCE_ID


def test_domain_subject_is_associated_with_malware() -> None:
    """A domain IOC subject is asserted ASSOCIATED_WITH the malware."""
    result = extract_threatfox(
        threatfox_evidence(
            [asyncrat_match()],
            subject_type=EntityType.DOMAIN,
            subject_value="malicious-domain.test",
        )
    )

    assert result.relationships[0].source.type is EntityType.DOMAIN
    assert result.relationships[0].source.value == "malicious-domain.test"


def test_repeated_same_malware_deduplicates() -> None:
    """Distinct source records naming the same malware deduplicate."""
    result = extract_threatfox(
        threatfox_evidence(
            [
                asyncrat_match(threatfox_id="864201"),
                asyncrat_match(threatfox_id="864202"),
            ]
        )
    )

    assert len(result.entities) == 1
    assert len(result.relationships) == 1


def test_multiple_malware_preserve_first_seen_order() -> None:
    """Multiple distinct malware identities stay in first-seen order."""
    result = extract_threatfox(
        threatfox_evidence(
            [
                asyncrat_match(threatfox_id="864201"),
                asyncrat_match(
                    threatfox_id="864202",
                    malware="win.syncrat",
                    malware_printable="SyncRAT",
                ),
            ]
        )
    )

    assert [entity.value for entity in result.entities] == [
        CANONICAL_ASYNCRAT_MALWARE,
        "win.syncrat",
    ]
    assert len(result.relationships) == 2


def test_null_printable_name_yields_no_display_name() -> None:
    """A documented null printable name yields an entity without display name."""
    result = extract_threatfox(
        threatfox_evidence([asyncrat_match(malware_printable=None)])
    )

    assert result.entities[0].display_name is None


def test_source_confidence_tags_and_threat_are_ignored() -> None:
    """Confidence, threat type, tags, reference, and timestamps never alter output."""
    fixed_id = UUID("44444444-4444-4444-8444-444444444444")
    baseline = extract_threatfox(
        threatfox_evidence([asyncrat_match()], evidence_id=fixed_id)
    )
    ignored = extract_threatfox(
        threatfox_evidence(
            [
                asyncrat_match(
                    confidence_level=13,
                    threat_type="payload_delivery",
                    tags=["Other", "Tags"],
                    reference="https://example.test/report",
                    first_seen="2020-01-01T00:00:00Z",
                    last_seen=None,
                )
            ],
            evidence_id=fixed_id,
        )
    )

    assert baseline == ignored


def test_malformed_malware_identifier_fails() -> None:
    """A malware value outside the machine-identity grammar is a contract failure."""
    for bad in ("AsyncRAT", "win asyncrat", "win/asyncrat", "", "WIN.ASYNCRAT"):
        with pytest.raises(EvidenceExtractionError) as excinfo:
            extract_threatfox(threatfox_evidence([asyncrat_match(malware=bad)]))
        assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_malformed_printable_name_fails() -> None:
    """A padded, blank, or overlong printable name is a contract failure."""
    for bad in (" AsyncRAT", "AsyncRAT ", "", " ", "x" * 257):
        with pytest.raises(EvidenceExtractionError) as excinfo:
            extract_threatfox(
                threatfox_evidence([asyncrat_match(malware_printable=bad)])
            )
        assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_missing_or_empty_matches_fail() -> None:
    """Missing or empty match collections are contract failures."""
    fact_shapes: tuple[dict[str, object], ...] = (
        {},
        {"matches": []},
        {"matches": "no"},
        {"matches": [None]},
        {"matches": [{"malware": 42}]},
    )
    for facts in fact_shapes:
        evidence = threatfox_evidence([]).model_copy(update={"facts": facts})
        with pytest.raises(EvidenceExtractionError) as excinfo:
            extract_threatfox(evidence)
        assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_missing_persisted_evidence_id_fails() -> None:
    """Unpersisted evidence cannot back assertions and fails explicitly."""
    evidence = threatfox_evidence([asyncrat_match()])
    unpersisted = evidence.model_copy(update={"id": None})

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_threatfox(unpersisted)

    assert excinfo.value.reason is ExtractionErrorReason.MISSING_EVIDENCE_ID


def test_noncanonical_subject_fails() -> None:
    """A subject that does not match its canonical form is a contract failure."""
    evidence = threatfox_evidence([asyncrat_match()], subject_value="203.0.113.042")

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_threatfox(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_unsupported_subject_type_fails() -> None:
    """ThreatFox evidence never has a subject outside the IOC domain/IP contract."""
    evidence = threatfox_evidence([asyncrat_match()]).model_copy(
        update={
            "subject": EntityRef(
                type=EntityType.MALWARE, value=CANONICAL_ASYNCRAT_MALWARE
            )
        }
    )

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_threatfox(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_noncanonical_but_valid_domain_subject_fails() -> None:
    """A domain subject that canonicalizes differently is a contract failure."""
    evidence = threatfox_evidence(
        [asyncrat_match()],
        subject_type=EntityType.DOMAIN,
        subject_value="MALICIOUS-DOMAIN.TEST",
    )

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_threatfox(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS


def test_non_mapping_match_fails() -> None:
    """A match entry that is not an object is a contract failure."""
    evidence = threatfox_evidence([]).model_copy(
        update={"facts": {"matches": ("not-an-object",)}}
    )

    with pytest.raises(EvidenceExtractionError) as excinfo:
        extract_threatfox(evidence)

    assert excinfo.value.reason is ExtractionErrorReason.MALFORMED_FACTS
