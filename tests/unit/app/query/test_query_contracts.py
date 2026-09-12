# SPDX-License-Identifier: AGPL-3.0-only
"""Query contract unit tests (PR 23A U11-U27)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.query.assessments import (
    AssessmentListQuery,
    assessment_sort_values,
    parse_assessment_cursor,
)
from agentic_threat_investigator.app.query.evidence import (
    EvidenceListQuery,
    evidence_sort_values,
    parse_evidence_cursor,
)
from agentic_threat_investigator.app.query.history import (
    DomainHistoryListQuery,
    HistoryOperation,
    domain_history_sort_values,
    parse_domain_history_cursor,
)
from agentic_threat_investigator.app.query.investigations import (
    InvestigationListQuery,
    investigation_sort_values,
    parse_investigation_cursor,
)
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    QueryKind,
)
from agentic_threat_investigator.app.query.relationships import (
    RelationshipListQuery,
    RelationshipObservationListQuery,
    parse_relationship_cursor,
    parse_relationship_observation_cursor,
    relationship_observation_sort_values,
)
from agentic_threat_investigator.app.query.research import (
    ResearchResultListQuery,
    parse_research_result_cursor,
    research_result_sort_values,
)
from agentic_threat_investigator.app.query.timeline import (
    TimelineListQuery,
    parse_timeline_cursor,
    timeline_sort_values,
)
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.investigation import InvestigationStatus
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.domain.relationships import RelationshipType


def _cursor_envelope(sort_values: tuple[str, ...], kind: QueryKind) -> CursorEnvelope:
    """Build a validated cursor envelope for parser tests."""
    return CursorEnvelope(
        query_kind=kind, filter_fingerprint="fp", sort_values=sort_values
    )


def test_u11_status_normalization_deterministic() -> None:
    """Status filter fingerprints are stable across equivalent enums."""
    query = InvestigationListQuery(status=InvestigationStatus.RUNNING, limit=10)
    assert (
        query.fingerprint()
        == InvestigationListQuery(
            status=InvestigationStatus("running"), limit=10
        ).fingerprint()
    )
    # A different status produces a different fingerprint.
    assert (
        query.fingerprint()
        != InvestigationListQuery(
            status=InvestigationStatus.COMPLETED, limit=10
        ).fingerprint()
    )


def test_u12_invalid_date_range_rejected() -> None:
    """A created-at range whose start exceeds its end is rejected."""
    with pytest.raises(ValidationError):
        InvestigationListQuery(
            created_from=datetime(2026, 1, 2, tzinfo=UTC),
            created_to=datetime(2026, 1, 1, tzinfo=UTC),
            limit=10,
        )


def test_u12_empty_half_open_range_accepted() -> None:
    """An equal start/end pair is a valid (empty) half-open range."""
    stamp = datetime(2026, 1, 1, tzinfo=UTC)
    query = InvestigationListQuery(created_from=stamp, created_to=stamp, limit=10)
    assert query.created_from == stamp


def test_u13_cursor_fields_match_order() -> None:
    """Investigation cursor sort values decode to the ordering identity."""
    stamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    investigation_id = uuid4()
    values = investigation_sort_values(stamp, investigation_id)
    assert parse_investigation_cursor(
        _cursor_envelope(values, QueryKind.INVESTIGATIONS)
    ) == (stamp, investigation_id)


def test_u13_naive_cursor_timestamp_rejected() -> None:
    """A cursor timestamp without timezone information is rejected."""
    with pytest.raises(ValueError):
        parse_investigation_cursor(
            _cursor_envelope(
                ("2026-01-01T00:00:00", str(uuid4())),
                QueryKind.INVESTIGATIONS,
            )
        )


def test_u14_evidence_source_filter_accepted() -> None:
    """A bounded source filter is accepted and fingerprinted."""
    query = EvidenceListQuery(
        investigation_id=uuid4(),
        source="urn:ati:source:google_public_dns",
        limit=10,
    )
    assert query.fingerprint()


def test_u14_blank_source_rejected() -> None:
    """A blank source filter is a contract failure."""
    with pytest.raises(ValidationError):
        EvidenceListQuery(investigation_id=uuid4(), source="  ", limit=10)


def test_u15_evidence_subject_filter_accepted() -> None:
    """The relational subject filter is accepted and fingerprinted."""
    entity_id = uuid4()
    query = EvidenceListQuery(
        investigation_id=uuid4(), subject_entity_id=entity_id, limit=10
    )
    assert (
        query.fingerprint()
        != EvidenceListQuery(investigation_id=uuid4(), limit=10).fingerprint()
    )


def test_u16_evidence_type_filter_accepted() -> None:
    """The bounded type filter is accepted and fingerprinted."""
    query = EvidenceListQuery(
        investigation_id=uuid4(), evidence_type=EvidenceType.DNS, limit=10
    )
    assert (
        query.fingerprint()
        != EvidenceListQuery(investigation_id=uuid4(), limit=10).fingerprint()
    )


def test_u17_evidence_retrieved_range_invalid_rejected() -> None:
    """A retrieved-at range whose start exceeds its end is rejected."""
    with pytest.raises(ValidationError):
        EvidenceListQuery(
            investigation_id=uuid4(),
            retrieved_from=datetime(2026, 2, 1, tzinfo=UTC),
            retrieved_to=datetime(2026, 1, 1, tzinfo=UTC),
            limit=10,
        )


def test_u17_naive_retrieved_timestamp_rejected() -> None:
    """A naive retrieved-time filter is rejected."""
    with pytest.raises(ValidationError):
        EvidenceListQuery(
            investigation_id=uuid4(), retrieved_from=datetime(2026, 1, 1), limit=10
        )


def test_u18_observation_without_scope_rejected() -> None:
    """Neither investigation nor relationship scope is rejected."""
    with pytest.raises(ValidationError):
        RelationshipObservationListQuery(limit=10)


def test_u19_observation_relationship_scope_accepted() -> None:
    """A relationship-scoped observation query is accepted."""
    query = RelationshipObservationListQuery(relationship_id=uuid4(), limit=10)
    assert query.fingerprint()


def test_u20_observation_investigation_scope_accepted() -> None:
    """An investigation-scoped observation query is accepted."""
    query = RelationshipObservationListQuery(investigation_id=uuid4(), limit=10)
    assert query.fingerprint()


def test_u21_observation_observed_range_accepted() -> None:
    """The observed-at half-open range is accepted and fingerprinted."""
    query = RelationshipObservationListQuery(
        relationship_id=uuid4(),
        observed_from=datetime(2026, 1, 1, tzinfo=UTC),
        observed_to=datetime(2026, 1, 2, tzinfo=UTC),
        limit=10,
    )
    assert (
        query.fingerprint()
        != RelationshipObservationListQuery(
            relationship_id=uuid4(), limit=10
        ).fingerprint()
    )


def test_u22_observation_retrieved_range_accepted() -> None:
    """The retrieved-at half-open range is accepted and fingerprinted."""
    query = RelationshipObservationListQuery(
        investigation_id=uuid4(),
        retrieved_from=datetime(2026, 1, 1, tzinfo=UTC),
        retrieved_to=datetime(2026, 1, 2, tzinfo=UTC),
        limit=10,
    )
    assert (
        query.fingerprint()
        != RelationshipObservationListQuery(
            investigation_id=uuid4(), limit=10
        ).fingerprint()
    )


def test_u23_nullable_observed_timestamp_never_cursor_key() -> None:
    """Observation cursors encode only retrieved_at and id — never observed_at."""
    stamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    observation_id = uuid4()
    values = relationship_observation_sort_values(stamp, observation_id)
    parsed = parse_relationship_observation_cursor(
        _cursor_envelope(values, QueryKind.RELATIONSHIP_OBSERVATIONS)
    )
    assert parsed == (stamp, observation_id)
    assert len(values) == 2


def test_u24_history_object_id_without_type_rejected() -> None:
    """An object_id filter without object_type is a contract failure."""
    with pytest.raises(ValidationError):
        DomainHistoryListQuery(object_id=uuid4(), limit=10)


def test_u25_history_object_type_and_id_accepted() -> None:
    """object_type + object_id browsing is accepted."""
    query = DomainHistoryListQuery(object_type="entity", object_id=uuid4(), limit=10)
    assert query.fingerprint()


def test_u26_history_investigation_scope_accepted() -> None:
    """Investigation-scoped history browsing is accepted."""
    query = DomainHistoryListQuery(investigation_id=uuid4(), limit=10)
    assert query.fingerprint()


def test_u26_history_operation_filter_accepted() -> None:
    """The bounded operation filter is accepted and canonicalized."""
    query = DomainHistoryListQuery(operation=HistoryOperation.DELETE, limit=10)
    assert query.fingerprint() != DomainHistoryListQuery(limit=10).fingerprint()


def test_u27_history_exact_version_requires_positive() -> None:
    """Exact version lookups reject non-positive versions and blank types."""
    from agentic_threat_investigator.app.query.history import (
        validate_object_version,
    )

    with pytest.raises(ValueError):
        validate_object_version("entity", 0)
    with pytest.raises(ValueError):
        validate_object_version("entity", -3)
    with pytest.raises(ValueError):
        validate_object_version("  ", 1)
    validate_object_version("entity", 1)
    values = domain_history_sort_values(datetime(2026, 1, 1, tzinfo=UTC), uuid4())
    parse_domain_history_cursor(_cursor_envelope(values, QueryKind.DOMAIN_HISTORY))


def test_relationship_cursor_identity() -> None:
    """Relationship cursors encode only the stable edge identity."""
    relationship_id = uuid4()
    parsed = parse_relationship_cursor(
        _cursor_envelope((str(relationship_id),), QueryKind.RELATIONSHIPS)
    )
    assert parsed == relationship_id


def test_relationship_query_fingerprint() -> None:
    """Relationship listing filters are fingerprinted."""
    query = RelationshipListQuery(
        investigation_id=uuid4(),
        source_entity_id=uuid4(),
        target_entity_id=uuid4(),
        relationship_type=RelationshipType.RESOLVES_TO,
        limit=10,
    )
    assert (
        query.fingerprint()
        != RelationshipListQuery(investigation_id=uuid4(), limit=10).fingerprint()
    )


def test_research_query_and_cursor() -> None:
    """ResearchResult filters are accepted and cursors round-trip."""
    stamp = datetime(2026, 1, 1, tzinfo=UTC)
    result_id = uuid4()
    query = ResearchResultListQuery(
        investigation_id=uuid4(), subject_entity_id=uuid4(), limit=10
    )
    assert query.fingerprint()
    values = research_result_sort_values(stamp, result_id)
    assert parse_research_result_cursor(
        _cursor_envelope(values, QueryKind.RESEARCH_RESULTS)
    ) == (stamp, result_id)


def test_assessment_query_and_cursor() -> None:
    """Assessment version cursors round-trip with positive versions."""
    assessment_id = uuid4()
    query = AssessmentListQuery(investigation_id=uuid4(), limit=10)
    assert query.fingerprint()
    values = assessment_sort_values(3, assessment_id)
    assert parse_assessment_cursor(_cursor_envelope(values, QueryKind.ASSESSMENTS)) == (
        3,
        assessment_id,
    )
    with pytest.raises(ValueError):
        parse_assessment_cursor(
            _cursor_envelope(("0", str(uuid4())), QueryKind.ASSESSMENTS)
        )


def test_timeline_query_and_cursor() -> None:
    """Timeline cursors encode occurred_at and the monotonic sequence."""
    stamp = datetime(2026, 1, 1, tzinfo=UTC)
    query = TimelineListQuery(
        investigation_id=uuid4(),
        event_type=InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
        limit=10,
    )
    assert query.fingerprint()
    values = timeline_sort_values(stamp, 7)
    assert parse_timeline_cursor(_cursor_envelope(values, QueryKind.TIMELINE)) == (
        stamp,
        7,
    )
    with pytest.raises(ValueError):
        parse_timeline_cursor(
            _cursor_envelope((stamp.isoformat(), "0"), QueryKind.TIMELINE)
        )


def test_evidence_sort_values_and_cursor_round_trip() -> None:
    """Evidence cursors round-trip through the typed parser."""
    stamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    evidence_id = uuid4()
    values = evidence_sort_values(stamp, evidence_id)
    assert parse_evidence_cursor(_cursor_envelope(values, QueryKind.EVIDENCE)) == (
        stamp,
        evidence_id,
    )
