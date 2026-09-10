# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Task dispatching abstractions for investigation orchestration.

Dispatching decides only how an already-authorized provider work item reaches
an executor. It does not select work, persist results, or update investigation
state.
"""

from abc import ABC, abstractmethod
from uuid import UUID

from agentic_threat_investigator.app.orchestration.executor import (
    InvestigationBoundWorkExecutor,
    WorkExecutor,
)
from agentic_threat_investigator.domain.investigation import (
    ProviderExecutionOutcome,
    ProviderWorkItem,
)


class TaskDispatcher(ABC):  # pylint: disable=too-few-public-methods
    """Hand one authorized provider work item to an execution destination."""

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Return the destination binding, or ``None`` for an unbound dispatcher."""
        return None

    @abstractmethod
    async def dispatch(self, work_item: ProviderWorkItem) -> ProviderExecutionOutcome:
        """Dispatch one work item and return the executor's exact outcome."""


class LocalTaskDispatcher(TaskDispatcher):
    """Dispatch work directly to an in-process :class:`WorkExecutor`."""

    def __init__(self, executor: WorkExecutor) -> None:
        """Store the injected executor without copying or mutating it."""
        self._executor = executor

    @property
    def bound_investigation_id(self) -> UUID | None:
        """Expose the wrapped executor's authoritative binding when available."""
        if isinstance(self._executor, InvestigationBoundWorkExecutor):
            return self._executor.bound_investigation_id
        return None

    async def dispatch(self, work_item: ProviderWorkItem) -> ProviderExecutionOutcome:
        """Delegate exactly once and preserve its result, errors, and cancellation."""
        return await self._executor.execute(work_item)
