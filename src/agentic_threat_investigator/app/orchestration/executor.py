# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Work-executor abstraction for investigation orchestration.

Graph execution depends on this application-level contract rather than on
any concrete provider, test fake, or infrastructure component. Real provider
executors arrive with PR 19B.
"""

from abc import ABC, abstractmethod

from agentic_threat_investigator.domain.investigation import (
    ProviderExecutionOutcome,
    ProviderWorkItem,
)


class WorkExecutor(ABC):  # pylint: disable=too-few-public-methods
    """Execute one approved provider work item and report its outcome.

    Implementations must remain deterministic for the orchestration
    skeleton and must perform no database, network, or LLM I/O in PR 19A.
    """

    @abstractmethod
    async def execute(self, work_item: ProviderWorkItem) -> ProviderExecutionOutcome:
        """Execute one work item and return its deterministic outcome."""
