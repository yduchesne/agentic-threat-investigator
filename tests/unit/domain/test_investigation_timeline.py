# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the investigation timeline domain model and app seam."""

# pylint: disable=missing-function-docstring,missing-class-docstring,too-few-public-methods,redefined-outer-name

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

    def test_blank_error_code_rejected(self) -> None:
        """Blank error codes are rejected; None is allowed."""
        assert _event(error_code=None).error_code is None
        with pytest.raises(ValidationError):
            _event(error_code="   ")

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
