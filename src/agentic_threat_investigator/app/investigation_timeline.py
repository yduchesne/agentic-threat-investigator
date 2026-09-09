# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Application seam for appending persisted investigation timeline events.

The sink abstraction keeps orchestration independent of PostgreSQL: the
executor depends only on :class:`InvestigationTimelineSink`, while production
composition supplies the UnitOfWork-backed implementation. Every append runs
in its own short explicit UnitOfWork transaction; repositories never commit
themselves.

Timeline appends are not transactionally atomic with provider-observation
persistence (PR 18C). If a timeline append fails after domain data committed,
the committed domain data is never rolled back; the typed operational failure
is surfaced to the caller instead.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
)


class InvestigationTimelineSink(ABC):  # pylint: disable=too-few-public-methods
    """Append one timeline event through a short explicit transaction."""

    @abstractmethod
    async def append(self, event: InvestigationTimelineEvent) -> None:
        """Persist one append-only timeline event."""


class UnitOfWorkInvestigationTimelineSink(  # pylint: disable=too-few-public-methods
    InvestigationTimelineSink
):
    """Append timeline events through one short UnitOfWork transaction."""

    def __init__(self, uow_factory: Callable[[], UnitOfWork]) -> None:
        self._uow_factory = uow_factory

    async def append(self, event: InvestigationTimelineEvent) -> None:
        """Append the event in one transaction that commits exactly once."""
        async with self._uow_factory() as uow:
            await uow.timeline_events.append(event)
