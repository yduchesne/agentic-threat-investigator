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
