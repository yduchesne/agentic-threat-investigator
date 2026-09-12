# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the investigation timeline domain model and app seam."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.investigation_timeline import (
    UnitOfWorkInvestigationTimelineSink,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)

_OCCURRED_AT = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)


def _event(**overrides: Any) -> InvestigationTimelineEvent:
    """Build one deterministic timeline event."""
    fields: dict[str, Any] = {
        "id": uuid4(),
        "investigation_id": uuid4(),
        "type": InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
        "occurred_at": _OCCURRED_AT,
        "provider": SourceId.GOOGLE_PUBLIC_DNS,
        "target_entity_id": uuid4(),
    }
    fields.update(overrides)
    return InvestigationTimelineEvent(**fields)


class TestInvestigationTimelineEvent:
    """Domain model invariants."""

    def test_timezone_naive_occurred_at_rejected(self) -> None:
        """Naive timestamps are rejected; aware timestamps are normalized."""
        with pytest.raises(ValidationError):
            _event(occurred_at=datetime(2026, 2, 3, 4, 5, 6))
        event = _event(occurred_at=datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC))
        assert event.occurred_at.utcoffset() is not None

    def test_error_code_grammar_and_length_are_bounded(self) -> None:
        """Error codes are lowercase snake-case, at most 64 characters."""
        failed = InvestigationTimelineEventType.PROVIDER_WORK_FAILED
        assert (
            _event(type=failed, error_code="provider_error").error_code
            == "provider_error"
        )
        assert _event(type=failed, error_code="a" * 64).error_code == "a" * 64
        for invalid in (
            "   ",
            " provider_error",
            "provider_error ",
            "ProviderError",
            "provider-error",
            "provider.error",
            "provider error",
            "_provider_error",
            "0provider",
            "a" * 65,
        ):
            with pytest.raises(ValidationError):
                _event(type=failed, error_code=invalid)

    def test_unexpected_fields_rejected(self) -> None:
        """Extra fields, such as a prose reason, are contract violations."""
        with pytest.raises(ValidationError):
            _event(reason="analyst reasoning text")

    def test_event_is_frozen(self) -> None:
        """Timeline events are immutable value objects."""
        event = _event()
        with pytest.raises(ValidationError):
            event.error_code = "changed"

    def test_event_type_values_are_stable(self) -> None:
        """Event type discriminators are stable serialized strings."""
        assert (
            InvestigationTimelineEventType.INVESTIGATION_STARTED.value
            == "investigation_started"
        )
        assert (
            InvestigationTimelineEventType.EVIDENCE_PERSISTED.value
            == "evidence_persisted"
        )

    @pytest.mark.parametrize(
        ("event_type", "overrides"),
        [
            (
                InvestigationTimelineEventType.INVESTIGATION_STARTED,
                {"provider": None, "target_entity_id": None},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
                {},
            ),
            (
                InvestigationTimelineEventType.EVIDENCE_PERSISTED,
                {"evidence_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
                {},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
                {"error_code": "timeout", "evidence_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
                {"error_code": "provider_error"},
            ),
            (
                InvestigationTimelineEventType.ENTITIES_DISCOVERED,
                {"entity_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.RESEARCH_REQUESTED,
                {"entity_ids": (uuid4(),), "provider": None, "target_entity_id": None},
            ),
        ],
    )
    def test_valid_event_shapes_accepted(
        self, event_type: InvestigationTimelineEventType, overrides: dict[str, Any]
    ) -> None:
        """Every documented event-type shape validates successfully."""
        _event(type=event_type, **overrides)

    @pytest.mark.parametrize(
        ("event_type", "overrides"),
        [
            (
                InvestigationTimelineEventType.INVESTIGATION_STARTED,
                {"provider": SourceId.GOOGLE_PUBLIC_DNS},
            ),
            (
                InvestigationTimelineEventType.INVESTIGATION_STARTED,
                {"target_entity_id": uuid4()},
            ),
            (
                InvestigationTimelineEventType.INVESTIGATION_STARTED,
                {"error_code": "provider_error"},
            ),
            (
                InvestigationTimelineEventType.INVESTIGATION_STARTED,
                {"evidence_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.INVESTIGATION_STARTED,
                {"entity_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.INVESTIGATION_STARTED,
                {"relationship_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
                {"provider": None},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
                {"target_entity_id": None},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
                {"error_code": "provider_error"},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
                {"evidence_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
                {"entity_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_STARTED,
                {"relationship_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.EVIDENCE_PERSISTED,
                {"evidence_ids": ()},
            ),
            (
                InvestigationTimelineEventType.EVIDENCE_PERSISTED,
                {"evidence_ids": (uuid4(), uuid4())},
            ),
            (
                InvestigationTimelineEventType.EVIDENCE_PERSISTED,
                {"error_code": "provider_error"},
            ),
            (
                InvestigationTimelineEventType.EVIDENCE_PERSISTED,
                {"provider": None},
            ),
            (
                InvestigationTimelineEventType.EVIDENCE_PERSISTED,
                {"target_entity_id": None},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
                {"provider": None},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED,
                {"target_entity_id": None},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
                {"error_code": None},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
                {"evidence_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
                {"entity_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
                {"relationship_ids": (uuid4(),)},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
                {"provider": None},
            ),
            (
                InvestigationTimelineEventType.PROVIDER_WORK_FAILED,
                {"target_entity_id": None},
            ),
            (
                InvestigationTimelineEventType.ENTITIES_DISCOVERED,
                {"entity_ids": ()},
            ),
            (
                InvestigationTimelineEventType.ENTITIES_DISCOVERED,
                {"error_code": "provider_error"},
            ),
            (
                InvestigationTimelineEventType.RESEARCH_REQUESTED,
                {"entity_ids": ()},
            ),
            (
                InvestigationTimelineEventType.RESEARCH_REQUESTED,
                {"entity_ids": (uuid4(), uuid4())},
            ),
            (
                InvestigationTimelineEventType.RESEARCH_REQUESTED,
                {"provider": SourceId.GOOGLE_PUBLIC_DNS},
            ),
            (
                InvestigationTimelineEventType.RESEARCH_REQUESTED,
                {"target_entity_id": uuid4()},
            ),
            (
                InvestigationTimelineEventType.RESEARCH_REQUESTED,
                {"error_code": "provider_error"},
            ),
            (
                InvestigationTimelineEventType.RESEARCH_REQUESTED,
                {"reason_code": "sufficient_evidence"},
            ),
            (
                InvestigationTimelineEventType.RESEARCH_REQUESTED,
                {"pivot_depth": 1},
            ),
        ],
    )
    def test_invalid_event_shapes_rejected(
        self, event_type: InvestigationTimelineEventType, overrides: dict[str, Any]
    ) -> None:
        """Each invalid field combination is a deterministic contract failure."""
        with pytest.raises(ValidationError):
            _event(type=event_type, **overrides)

    def test_pivot_enqueued_requires_entity_ids_without_provider(self) -> None:
        """PIVOT_ENQUEUED events need only entity IDs; no provider/target."""
        event = _event(
            type=InvestigationTimelineEventType.PIVOT_ENQUEUED,
            provider=None,
            target_entity_id=None,
            entity_ids=(uuid4(),),
        )
        assert event.entity_ids
        with pytest.raises(ValidationError):
            _event(
                type=InvestigationTimelineEventType.PIVOT_ENQUEUED,
                provider=None,
                target_entity_id=None,
                entity_ids=(),
            )

    def test_pivot_skipped_requires_entity_ids_without_provider(self) -> None:
        """PIVOT_SKIPPED events need only entity IDs; no provider/target."""
        event = _event(
            type=InvestigationTimelineEventType.PIVOT_SKIPPED,
            provider=None,
            target_entity_id=None,
            entity_ids=(uuid4(),),
            reason_code="duplicate_pivot",
        )
        assert event.entity_ids
        assert event.reason_code == "duplicate_pivot"
        with pytest.raises(ValidationError):
            _event(
                type=InvestigationTimelineEventType.PIVOT_SKIPPED,
                provider=None,
                target_entity_id=None,
                entity_ids=(),
                reason_code="duplicate_pivot",
            )
        with pytest.raises(ValidationError):
            _event(
                type=InvestigationTimelineEventType.PIVOT_SKIPPED,
                provider=None,
                target_entity_id=None,
                entity_ids=(uuid4(),),
            )

    def test_assessment_requested_requires_no_provider_or_target(self) -> None:
        """ASSESSMENT_REQUESTED events carry no provider/target/tuples."""
        event = _event(
            type=InvestigationTimelineEventType.ASSESSMENT_REQUESTED,
            provider=None,
            target_entity_id=None,
        )
        assert event.error_code is None
        with pytest.raises(ValidationError):
            _event(
                type=InvestigationTimelineEventType.ASSESSMENT_REQUESTED,
                provider=SourceId.GOOGLE_PUBLIC_DNS,
            )

    def test_investigation_stopped_requires_no_provider_or_target(self) -> None:
        """INVESTIGATION_STOPPED events carry no provider/target/tuples."""
        event = _event(
            type=InvestigationTimelineEventType.INVESTIGATION_STOPPED,
            provider=None,
            target_entity_id=None,
            reason_code="sufficient_evidence",
        )
        assert event.error_code is None
        assert event.reason_code == "sufficient_evidence"
        with pytest.raises(ValidationError):
            _event(
                type=InvestigationTimelineEventType.INVESTIGATION_STOPPED,
                provider=None,
                target_entity_id=None,
                reason_code="sufficient_evidence",
                error_code="fatal_error",
            )
        with pytest.raises(ValidationError):
            _event(
                type=InvestigationTimelineEventType.INVESTIGATION_STOPPED,
                provider=None,
                target_entity_id=None,
            )


class TestResearchRequestedTimelineEvent:
    """PR 22C RESEARCH_REQUESTED event contract (U23-U27)."""

    @staticmethod
    def _research_event(**overrides: Any) -> InvestigationTimelineEvent:
        """Build a RESEARCH_REQUESTED event without provider/target defaults."""
        fields: dict[str, Any] = {
            "type": InvestigationTimelineEventType.RESEARCH_REQUESTED,
            "entity_ids": (uuid4(),),
            "provider": None,
            "target_entity_id": None,
        }
        fields.update(overrides)
        return _event(**fields)

    def test_research_requested_carries_exactly_one_entity(self) -> None:
        """U23: exactly one subject entity ID is carried."""
        entity_id = uuid4()
        event = self._research_event(entity_ids=(entity_id,))
        assert event.entity_ids == (entity_id,)
        assert event.provider is None
        assert event.target_entity_id is None
        assert event.error_code is None
        assert event.reason_code is None
        assert event.pivot_depth is None

    def test_zero_entity_ids_rejected(self) -> None:
        """U24: zero entity IDs are rejected."""
        with pytest.raises(ValidationError, match="exactly one entity ID"):
            self._research_event(entity_ids=())

    def test_multiple_entity_ids_rejected(self) -> None:
        """U24: multiple entity IDs are rejected."""
        with pytest.raises(ValidationError, match="exactly one entity ID"):
            self._research_event(entity_ids=(uuid4(), uuid4()))

    def test_provider_target_error_rejected(self) -> None:
        """U25: provider/target/error fields are rejected."""
        with pytest.raises(ValidationError, match="no provider, target"):
            self._research_event(provider=SourceId.GOOGLE_PUBLIC_DNS)
        with pytest.raises(ValidationError, match="no provider, target"):
            self._research_event(target_entity_id=uuid4())
        with pytest.raises(ValidationError, match="no provider, target"):
            self._research_event(error_code="provider_error")

    def test_no_reason_code_or_pivot_depth(self) -> None:
        """U25: reason_code and pivot_depth are rejected."""
        with pytest.raises(ValidationError, match="reason_code or pivot_depth"):
            self._research_event(reason_code="sufficient_evidence")
        with pytest.raises(ValidationError, match="reason_code or pivot_depth"):
            self._research_event(pivot_depth=1)

    def test_identifier_tuples_other_than_entity_rejected(self) -> None:
        """U25: evidence/relationship tuples are rejected by extra shape."""
        with pytest.raises(ValidationError):
            self._research_event(evidence_ids=(uuid4(),))

    def test_no_research_content_fields_exist(self) -> None:
        """U27: the schema cannot carry query/value/claim content."""
        event = self._research_event()
        payload = event.model_dump()
        assert "query" not in payload
        assert "value" not in payload
        assert "prompt" not in payload
        assert "claims" not in payload
        assert "source_url" not in payload
        assert "failure" not in payload


class TestUnitOfWorkTimelineSink:
    """The UoW-backed sink appends exactly once per event."""

    @pytest.mark.asyncio
    async def test_append_uses_single_short_transaction(self) -> None:
        """Each event opens one UoW, appends through the repository, and commits."""
        appended: list[InvestigationTimelineEvent] = []
        transactions: list[int] = []

        class FakeTimelineRepository:
            async def append(self, event: InvestigationTimelineEvent) -> None:
                appended.append(event)

        class FakeUow:
            def __init__(self) -> None:
                self.timeline_events = FakeTimelineRepository()

            async def __aenter__(self) -> "FakeUow":
                transactions.append(1)
                return self

            async def __aexit__(self, *_args: Any) -> None:
                return None

        sink = UnitOfWorkInvestigationTimelineSink(FakeUow)  # type: ignore[arg-type]
        event = _event()
        await sink.append(event)
        assert appended == [event]
        assert len(transactions) == 1
