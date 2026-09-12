# SPDX-License-Identifier: AGPL-3.0-only
"""Validated, atomic persistence of one immutable ResearchResult.

This is the narrow PR 22A application seam between a fully constructed valid
``ResearchResult`` (produced by the future PR 22B Research Agent) and durable
append-only state. One short UnitOfWork transaction validates that the
referenced Investigation and subject Entity exist, inserts the immutable
result through its repository, and commits — all together or not at all.

The service deliberately does not retrieve chunks, call embeddings, call an
LLM, decide whether research is needed, or update Investigation research
state, and it does not require every cited chunk to still exist in the active
vector index: ``ResearchCitation`` snapshots exist precisely because active
chunks are replaceable.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from agentic_threat_investigator.app.persistence.repositories import (
    ResearchResultReferenceError,
    UnitOfWork,
)
from agentic_threat_investigator.domain.research import ResearchResult

LOGGER = logging.getLogger(__name__)


class ResearchResultPersistenceService:
    """Persist one assembled ResearchResult atomically without side effects."""

    def __init__(self, uow_factory: Callable[[], UnitOfWork]) -> None:
        """Bind the service to a UnitOfWork factory."""
        self._uow_factory = uow_factory

    async def persist(self, result: ResearchResult) -> None:
        """Validate the root references and insert the immutable result.

        A missing Investigation or subject Entity, or a duplicate result
        identity, fails closed with a typed error and the UnitOfWork rolls
        back; no partial research artifact is ever persisted.
        """
        async with self._uow_factory() as uow:
            investigation = await uow.investigations.get_by_id(result.investigation_id)
            if investigation is None:
                raise ResearchResultReferenceError(
                    f"research result references unknown investigation: "
                    f"{result.investigation_id}"
                )
            entity = await uow.entities.get_by_id(result.subject_entity_id)
            if entity is None:
                raise ResearchResultReferenceError(
                    f"research result references unknown entity: "
                    f"{result.subject_entity_id}"
                )
            await uow.research_results.add(result)
        LOGGER.debug(
            "persisted research result %s for investigation %s",
            result.id,
            result.investigation_id,
        )
