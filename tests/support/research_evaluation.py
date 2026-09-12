# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Research evaluation integration support (PR 22D).

Narrow observation seams for the PR 22D evaluation slices:

* :class:`RecordingResearchRetriever` wraps the **production** retriever and
  records the exact ordered ``RetrievedChunk`` values it returns; it never
  re-ranks, filters, or substitutes scripted results, so the supplied
  citation set is observed exactly at the model boundary.
* :func:`load_epistemic_snapshot` captures the promotion-sensitive identity
  sets (Evidence, RelationshipObservation, Assessment identity/version)
  through the application UnitOfWork seam before and after an isolated
  research interval.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.research import ResearchRetriever
from agentic_threat_investigator.domain.research import ResearchQuery, RetrievedChunk
from agentic_threat_investigator.evaluation.research import ResearchEpistemicSnapshot


class RecordingResearchRetriever(ResearchRetriever):
    """Observation wrapper delegating exactly to the production retriever.

    Every call is forwarded unchanged to the wrapped retriever and its
    returned values are recorded in order. Nothing is altered or filtered:
    the wrapper exists so the canonical evaluation can prove that the exact
    chunks supplied to the model were the chunks the production retrieval
    returned.
    """

    def __init__(self, inner: ResearchRetriever) -> None:
        """Bind the production retriever and an empty call log."""
        self._inner = inner
        self.calls: list[list[RetrievedChunk]] = []

    async def retrieve(self, query: ResearchQuery) -> list[RetrievedChunk]:
        """Delegate to the production retriever and record the response."""
        chunks = await self._inner.retrieve(query)
        self.calls.append(list(chunks))
        return chunks

    @property
    def supplied_citation_ids(self) -> tuple[UUID, ...]:
        """Return the recorded citation IDs of the most recent retrieval."""
        if not self.calls:
            return ()
        return tuple(chunk.citation_id for chunk in self.calls[-1])


async def load_epistemic_snapshot(
    uow_factory: Callable[[], UnitOfWork], investigation_id: UUID
) -> ResearchEpistemicSnapshot:
    """Capture promotion-sensitive identities through one short UnitOfWork."""
    async with uow_factory() as uow:
        evidence = await uow.evidence.list_for_investigation(
            investigation_id, limit=1000
        )
        observations = await uow.relationship_observations.list_for_investigation(
            investigation_id, limit=1000
        )
        assessments = await uow.assessments.list_for_investigation(
            investigation_id, limit=1000
        )
    evidence_ids = tuple(sorted(item.id for item in evidence if item.id is not None))
    observation_ids = tuple(sorted(item.id for item in observations))
    assessment_ids = tuple(
        sorted(
            (item.id, item.version or -1) for item in assessments if item.id is not None
        )
    )
    return ResearchEpistemicSnapshot(
        evidence_ids=evidence_ids,
        relationship_observation_ids=observation_ids,
        assessment_identities=assessment_ids,
    )
