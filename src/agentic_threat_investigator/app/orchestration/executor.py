# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Work-executor abstraction for investigation orchestration.

Graph execution depends on this application-level contract rather than on
any concrete provider, test fake, or infrastructure component. Real provider
executors arrive with PR 19B.
"""

from abc import ABC, abstractmethod
from uuid import UUID

from agentic_threat_investigator.domain.investigation import (
    ProviderExecutionOutcome,
    ProviderWorkItem,
)


class WorkExecutor(ABC):
    """Execute one approved provider work item and report its outcome.

    Implementations must remain deterministic for the orchestration
    skeleton and must perform no database, network, or LLM I/O in PR 19A.
    """

    @abstractmethod
    async def execute(self, work_item: ProviderWorkItem) -> ProviderExecutionOutcome:
        """Execute one work item and return its deterministic outcome."""


class InvestigationBoundWorkExecutor(WorkExecutor, ABC):
    """A work executor bound to exactly one investigation identity.

    Concrete executors that drive providers, persistence, and timeline events
    under one authoritative ``ProviderExecutionContext.investigation_id``
    expose that identity so the generic graph builder can automatically adopt
    it as the graph's binding. This prevents direct public composition from
    bypassing investigation isolation: the graph rejects any state belonging
    to a different investigation even when the caller omits the explicit
    expected ID.
    """

    @property
    @abstractmethod
    def bound_investigation_id(self) -> UUID:
        """Return the investigation identity this executor may process."""
