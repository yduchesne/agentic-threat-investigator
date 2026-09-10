# SPDX-License-Identifier: AGPL-3.0-only
"""Durable Investigation LLM-call accounting (PR 20B).

Every actual model invocation is reserved through a short, versioned
Investigation budget update; no database transaction is ever held across LLM
latency. The reservation is durable even if the subsequent model call times
out, fails, or is cancelled, so an attempted invocation is always counted and
no hidden retry can evade accounting.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from agentic_threat_investigator.app.persistence.repositories import (
    InvestigationNotFoundError,
    InvestigationVersionConflictError,
    UnitOfWork,
)


class LlmAccountingService:  # pylint: disable=too-few-public-methods
    """Reserve LLM invocations against the persisted Investigation budget."""

    def __init__(self, uow_factory: Callable[[], UnitOfWork]) -> None:
        """Bind the service to the caller's UnitOfWork factory."""
        self._uow_factory = uow_factory

    async def reserve_call(
        self,
        investigation_id: UUID,
        *,
        expected_version: int | None = None,
    ) -> int:
        """Durably reserve one invocation and return the new Investigation version.

        The caller's ``expected_version`` (when provided) is validated against
        the current visible row before any mutation: a stale expectation
        raises ``InvestigationVersionConflictError`` with no reservation.
        Input-loading and persistence failures never increment the counter.
        """
        async with self._uow_factory() as uow:
            state = await uow.investigations.get_by_id(investigation_id)
            if state is None:
                raise InvestigationNotFoundError(str(investigation_id))
            if expected_version is not None and state.version != expected_version:
                raise InvestigationVersionConflictError(
                    investigation_id, expected_version
                )
            state.budget.record_llm_call()
            result = await uow.investigations.update_budget(
                investigation_id,
                state.budget,
                expected_version=state.version,
            )
            return result.version
