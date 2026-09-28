# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31F-2 fatal-diagnostic orchestration unit tests.

Covers the graph's fatalization boundaries: a caught nested exception keeps
the stable fatal error code while the sanitized root-cause message replaces
the generic loss-of-cause text; persistence failures still propagate; and
``asyncio.CancelledError`` still propagates unchanged. Also covers the
``DeterministicTimelineActionService.investigation_stopped`` derivation of
the final INVESTIGATION_STOPPED event from the authoritative fatal state.

All secret material used here is a conspicuous synthetic sentinel.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID

import pytest

from agentic_threat_investigator.app.error_messages import ErrorMessageSanitizer
from agentic_threat_investigator.app.orchestration.coordinator import (
    AnalysisExecutor,
    AnalysisOutcome,
    CoordinatorAction,
    CoordinatorDecision,
    CoordinatorPolicy,
    CoordinatorPolicyContext,
    MappingProviderWorkPlanner,
)
from agentic_threat_investigator.app.orchestration.graph import (
    analyze,
    coordinator_node,
)
from agentic_threat_investigator.app.orchestration.services import (
    CoordinatorContextLoader,
    CoordinatorTransitionService,
    FatalStopService,
)
from agentic_threat_investigator.app.orchestration.timeline_actions import (
    DeterministicTimelineActionService,
)
from agentic_threat_investigator.app.persistence.repositories import (
    CoordinatorTransitionPersistenceError,
)
from agentic_threat_investigator.domain.investigation import (
    CoordinatorTransitionKind,
    InvestigationError,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    StopReason,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)

SENTINEL = "SENTINEL_GRAPH_SECRET_9b"

_ROOT = UUID("00000000-0000-0000-0000-0000000000aa")
_INVESTIGATION = UUID("00000000-0000-0000-0000-0000000000b1")
_FIXED_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _state() -> InvestigationState:
    """Build one RUNNING InvestigationState for the graph tests."""
    return InvestigationState(
        investigation_id=_INVESTIGATION,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[_ROOT],
        objective="Assess the root indicator.",
        budget=default_investigation_budget(),
        started_at=_FIXED_TS,
        version=1,
    )


def _policy() -> CoordinatorPolicy:
    """Build a deterministic policy over an empty provider map."""
    return CoordinatorPolicy(MappingProviderWorkPlanner({}))


def _raise_nested_with_secret() -> RuntimeError:
    """Build a controlled nested exception containing secret-like text."""
    try:
        raise ValueError(f"underlying provider refused with token={SENTINEL}")
    except ValueError as error:
        try:
            raise RuntimeError("provider dispatch failed") from error
        except RuntimeError as outer:
            return outer


class _RecordingFatalService(FatalStopService):
    """Record fatal stops without persisting."""

    def __init__(self) -> None:
        self.fatalized: list[tuple[UUID, InvestigationError]] = []

    async def fatalize(
        self,
        investigation_id: UUID,
        error: InvestigationError,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationState:
        del actor_id, request_id
        self.fatalized.append((investigation_id, error))
        return _state().model_copy(
            update={
                "status": InvestigationStatus.FAILED,
                "stop_reason": StopReason.FATAL_ERROR.value,
                "errors": [error],
                "version": expected_version + 1,
            }
        )


class _RaisingContextLoader(CoordinatorContextLoader):
    """Context loader that always raises the injected exception."""

    def __init__(self, error: BaseException) -> None:
        self._error = error

    async def load(
        self, investigation_id: UUID, expected_version: int
    ) -> CoordinatorPolicyContext:
        del investigation_id, expected_version
        raise self._error


class _RecordingTransitionService(CoordinatorTransitionService):
    """Minimal transition service recording emits for the analyze node."""

    def __init__(self) -> None:
        self.emitted: list[InvestigationTimelineEvent] = []

    async def emit(self, event: InvestigationTimelineEvent) -> None:
        self.emitted.append(event)

    async def reload(self, investigation_id: UUID) -> InvestigationState:
        del investigation_id
        return _state()

    async def persist(
        self,
        investigation_id: UUID,
        transition_kind: CoordinatorTransitionKind,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        events: tuple[InvestigationTimelineEvent, ...] = (),
        consumes_replan: bool = False,
    ) -> InvestigationState:
        raise AssertionError("persist must not be reached")


class _RaisingAnalysisExecutor(AnalysisExecutor):
    """Analysis executor that always raises the injected exception."""

    def __init__(
        self, error: BaseException, *, bound_investigation_id: UUID | None = None
    ) -> None:
        self._error = error
        self._bound = bound_investigation_id

    @property
    def bound_investigation_id(self) -> UUID | None:
        return self._bound

    async def analyze(self, investigation_id: UUID) -> AnalysisOutcome:
        del investigation_id
        raise self._error


def _fatal_state_with_error(message: str) -> InvestigationState:
    """Build a FAILED state carrying one fatal InvestigationError."""
    error = InvestigationError(
        source="orchestration",
        code="analysis_execution_error",
        message=message,
        recoverable=False,
    )
    return _state().model_copy(
        update={
            "status": InvestigationStatus.FAILED,
            "stop_reason": StopReason.FATAL_ERROR.value,
            "errors": [error],
        }
    )


@pytest.mark.asyncio
async def test_fatal_boundary_keeps_code_and_sanitizes_root_message() -> None:
    """F2-U21: a nested exception keeps the code plus the sanitized root message."""
    caught = _raise_nested_with_secret()
    fatal = _RecordingFatalService()
    loader = _RaisingContextLoader(caught)
    decision = CoordinatorDecision(
        action=CoordinatorAction.STOP,
        stop_reason=StopReason.FATAL_ERROR,
    )
    result = await coordinator_node(
        _policy(),
        loader,
        fatal,
        ErrorMessageSanitizer(known_secrets=(SENTINEL,)),
        {"investigation": _state(), "_coordinator_decision": decision},
    )
    assert result["_coordinator_decision"] == decision
    investigation_id, recorded_error = fatal.fatalized[0]
    assert investigation_id == _INVESTIGATION
    assert recorded_error.code == "coordinator_context_error"
    # The root-cause value is the sanitized inner message, not the outer text.
    assert SENTINEL not in recorded_error.message
    assert "underlying provider refused" in recorded_error.message
    assert "provider dispatch failed" not in recorded_error.message


@pytest.mark.asyncio
async def test_persistence_failure_still_propagates() -> None:
    """F2-U22: a persistence exception is never converted into a fatal diagnostic."""
    fatal = _RecordingFatalService()
    loader = _RaisingContextLoader(
        CoordinatorTransitionPersistenceError("write failed")
    )
    decision = CoordinatorDecision(
        action=CoordinatorAction.STOP,
        stop_reason=StopReason.FATAL_ERROR,
    )
    with pytest.raises(CoordinatorTransitionPersistenceError):
        await coordinator_node(
            _policy(),
            loader,
            fatal,
            ErrorMessageSanitizer(),
            {"investigation": _state(), "_coordinator_decision": decision},
        )
    assert not fatal.fatalized


@pytest.mark.asyncio
async def test_analysis_fatal_boundary_sanitizes_nested_root() -> None:
    """The analysis boundary uses the sanitized root-cause message."""
    caught = _raise_nested_with_secret()
    fatal = _RecordingFatalService()
    executor = _RaisingAnalysisExecutor(caught, bound_investigation_id=_INVESTIGATION)
    await analyze(
        executor,
        _RecordingTransitionService(),
        DeterministicTimelineActionService(clock=lambda: _FIXED_TS),
        fatal,
        ErrorMessageSanitizer(known_secrets=(SENTINEL,)),
        {"investigation": _state(), "_coordinator_decision": None},
    )
    investigation_id, recorded_error = fatal.fatalized[0]
    assert investigation_id == _INVESTIGATION
    assert recorded_error.code == "analysis_execution_error"
    assert SENTINEL not in recorded_error.message
    assert "underlying provider refused" in recorded_error.message


@pytest.mark.asyncio
async def test_cancellation_propagates_unchanged() -> None:
    """F2-U23: cancellation is never converted into a persisted fatal diagnostic."""
    fatal = _RecordingFatalService()
    loader = _RaisingContextLoader(asyncio.CancelledError())
    decision = CoordinatorDecision(
        action=CoordinatorAction.STOP,
        stop_reason=StopReason.FATAL_ERROR,
    )
    with pytest.raises(asyncio.CancelledError):
        await coordinator_node(
            _policy(),
            loader,
            fatal,
            ErrorMessageSanitizer(),
            {"investigation": _state(), "_coordinator_decision": decision},
        )
    assert not fatal.fatalized


def test_fatal_stop_event_carries_sanitized_code_and_message() -> None:
    """F2-U19: a fatal stop state yields the exact safe code/message on the event."""
    service = DeterministicTimelineActionService(clock=lambda: _FIXED_TS)
    state = _fatal_state_with_error("coordinator context could not be loaded")
    event = service.investigation_stopped(
        stop_reason=StopReason.FATAL_ERROR, state=state
    )
    assert event.type is InvestigationTimelineEventType.INVESTIGATION_STOPPED
    assert event.reason_code == StopReason.FATAL_ERROR.value
    assert event.error_code == "analysis_execution_error"
    assert event.error_message == "coordinator context could not be loaded"


def test_fatal_stop_event_without_recorded_error_has_no_diagnostic() -> None:
    """A fatal stop with no recorded error invents no code/message."""
    service = DeterministicTimelineActionService(clock=lambda: _FIXED_TS)
    state = _state().model_copy(
        update={
            "status": InvestigationStatus.FAILED,
            "stop_reason": StopReason.FATAL_ERROR.value,
        }
    )
    event = service.investigation_stopped(
        stop_reason=StopReason.FATAL_ERROR, state=state
    )
    assert event.error_code is None
    assert event.error_message is None


def test_nonfatal_stop_event_has_no_diagnostic_fields() -> None:
    """F2-U20: a nonfatal stop carries neither field even with stored errors."""
    service = DeterministicTimelineActionService(clock=lambda: _FIXED_TS)
    state = _fatal_state_with_error("coordinator context could not be loaded")
    event = service.investigation_stopped(
        stop_reason=StopReason.SUFFICIENT_EVIDENCE, state=state
    )
    assert event.reason_code == StopReason.SUFFICIENT_EVIDENCE.value
    assert event.error_code is None
    assert event.error_message is None
