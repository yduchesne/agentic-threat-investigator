# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 22C durable research execution state unit tests.

Covers :class:`ResearchExecutionState` invariants and the
``InvestigationState`` cross-field coherence rules that make one exact
research context deduplicable without an LLM or a second repository.
"""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.investigation import (
    MAX_RESEARCH_EXECUTION_ATTEMPTS,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    ResearchExecutionState,
    ResearchExecutionStatus,
    default_investigation_budget,
)

_SUBJECT = UUID("00000000-0000-0000-0000-0000000000a1")
_FINGERPRINT = "a" * 64
_RESULT_ID = UUID("00000000-0000-0000-0000-0000000000b1")
_INVESTIGATION = UUID("00000000-0000-0000-0000-0000000000c1")


def _execution(**overrides: object) -> ResearchExecutionState:
    """Build one minimal valid research execution entry."""
    values: dict[str, object] = {
        "subject_entity_id": _SUBJECT,
        "context_fingerprint": _FINGERPRINT,
        "query": "Provide contextual threat-research information.",
        "status": ResearchExecutionStatus.REQUESTED,
        "attempts": 1,
    }
    values.update(overrides)
    return ResearchExecutionState.model_validate(values)


def _state(**overrides: object) -> InvestigationState:
    """Build one minimal running investigation state."""
    params: dict[str, object] = {
        "investigation_id": _INVESTIGATION,
        "status": InvestigationStatus.RUNNING,
        "trigger_type": InvestigationTriggerType.MANUAL,
        "root_entity_ids": [_SUBJECT],
        "objective": "Test investigation.",
        "budget": default_investigation_budget(),
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "version": 1,
    }
    params.update(overrides)
    return InvestigationState.model_validate(params)


class TestResearchExecutionStateValidation:
    """22C-U01..U06: per-entry lifecycle invariants."""

    def test_valid_requested_execution_accepted(self) -> None:
        """U01: a REQUESTED first attempt without a result is accepted."""
        execution = _execution()
        assert execution.status is ResearchExecutionStatus.REQUESTED
        assert execution.attempts == 1
        assert execution.result_id is None

    def test_completed_requires_result(self) -> None:
        """U02: COMPLETED without a result_id is rejected."""
        with pytest.raises(ValidationError, match="requires a result_id"):
            _execution(status=ResearchExecutionStatus.COMPLETED, result_id=None)

    def test_requested_forbids_result(self) -> None:
        """U03: REQUESTED with a result_id is rejected."""
        with pytest.raises(ValidationError, match="must not carry a result_id"):
            _execution(status=ResearchExecutionStatus.REQUESTED, result_id=_RESULT_ID)

    def test_exhausted_before_max_attempts_rejected(self) -> None:
        """U04: EXHAUSTED before the hard attempt bound is rejected."""
        with pytest.raises(ValidationError, match="maximum attempt count"):
            _execution(status=ResearchExecutionStatus.EXHAUSTED, attempts=1)

    def test_exhausted_at_max_attempts_accepted(self) -> None:
        """EXHAUSTED at the hard bound with no result is accepted."""
        execution = _execution(
            status=ResearchExecutionStatus.EXHAUSTED,
            attempts=MAX_RESEARCH_EXECUTION_ATTEMPTS,
        )
        assert execution.status is ResearchExecutionStatus.EXHAUSTED
        assert execution.result_id is None

    def test_attempts_beyond_bound_rejected(self) -> None:
        """An attempt counter above the hard bound is rejected."""
        with pytest.raises(ValidationError):
            _execution(attempts=3)

    def test_blank_query_and_fingerprint_rejected(self) -> None:
        """Blank query/fingerprint values are rejected."""
        with pytest.raises(ValidationError, match="must not be blank"):
            _execution(query="   ")
        with pytest.raises(ValidationError, match="must not be blank"):
            _execution(context_fingerprint="  ")

    def test_max_results_out_of_range_rejected(self) -> None:
        """max_results outside 1..100 is rejected."""
        with pytest.raises(ValidationError):
            _execution(max_results=0)
        with pytest.raises(ValidationError):
            _execution(max_results=101)

    def test_unknown_fields_rejected(self) -> None:
        """extra fields fail closed."""
        with pytest.raises(ValidationError):
            ResearchExecutionState.model_validate(
                {
                    "subject_entity_id": _SUBJECT,
                    "context_fingerprint": _FINGERPRINT,
                    "query": "q",
                    "status": ResearchExecutionStatus.REQUESTED,
                    "attempts": 1,
                    "unexpected": True,
                }
            )

    def test_filter_values_normalized_uniquely(self) -> None:
        """Duplicate filter values are stably deduplicated, blanks rejected."""
        execution = _execution(source_ids=("a", "b", "a"))
        assert execution.source_ids == ("a", "b")
        with pytest.raises(ValidationError, match="must not be blank"):
            _execution(source_ids=("a", "  "))


class TestInvestigationResearchExecutionCoherence:
    """InvestigationState cross-field research coherence rules."""

    def test_duplicate_context_fingerprint_rejected(self) -> None:
        """U05: two executions for one subject/fingerprint are rejected."""
        with pytest.raises(ValidationError, match="unique per subject/fingerprint"):
            _state(
                research_executions=[
                    _execution(),
                    _execution(),
                ]
            )

    def test_duplicate_completed_result_ids_rejected(self) -> None:
        """U06: one result ID linked by two executions is rejected."""
        completed = _execution(
            status=ResearchExecutionStatus.COMPLETED, result_id=_RESULT_ID
        )
        other = completed.model_copy(
            update={
                "context_fingerprint": "b" * 64,
            }
        )
        with pytest.raises(ValidationError, match="result_ids must not repeat"):
            _state(research_executions=[completed, other])

    def test_completed_result_must_be_linked(self) -> None:
        """A COMPLETED execution's result must appear in research_result_ids."""
        completed = _execution(
            status=ResearchExecutionStatus.COMPLETED, result_id=_RESULT_ID
        )
        with pytest.raises(ValidationError, match="not linked"):
            _state(research_executions=[completed])

    def test_result_ids_entry_requires_completed_execution(self) -> None:
        """A result ID without a matching COMPLETED execution fails when
        execution state exists."""
        with pytest.raises(ValidationError, match="lacks a completed execution"):
            _state(
                research_executions=[_execution()],
                research_result_ids=[_RESULT_ID],
            )

    def test_coherent_completed_linkage_accepted(self) -> None:
        """A linked COMPLETED execution with one result ID is accepted."""
        completed = _execution(
            status=ResearchExecutionStatus.COMPLETED, result_id=_RESULT_ID
        )
        state = _state(
            research_executions=[completed],
            research_result_ids=[_RESULT_ID],
        )
        assert state.research_result_ids == [_RESULT_ID]

    def test_legacy_result_ids_without_executions_stay_valid(self) -> None:
        """Pre-22C result identities without execution state remain valid."""
        state = _state(research_result_ids=[_RESULT_ID])
        assert state.research_result_ids == [_RESULT_ID]

    def test_exhausted_context_requires_no_link(self) -> None:
        """An EXHAUSTED unchanged context carries no result ID."""
        state = _state(
            research_executions=[
                _execution(
                    status=ResearchExecutionStatus.EXHAUSTED,
                    attempts=MAX_RESEARCH_EXECUTION_ATTEMPTS,
                )
            ]
        )
        assert state.research_executions[0].result_id is None
