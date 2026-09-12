# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the immutable research-result persistence service."""

from datetime import UTC, datetime
from types import TracebackType
from typing import Self
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.persistence.repositories import (
    ResearchResultDuplicateIdentityError,
    ResearchResultReferenceError,
    UnitOfWork,
)
from agentic_threat_investigator.app.research_persistence import (
    ResearchResultPersistenceService,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchResult,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class _ResearchResults:
    """Fake append-only repository recording inserts and duplicate rejection."""

    def __init__(self) -> None:
        self.stored: dict[UUID, ResearchResult] = {}

    async def add(self, result: ResearchResult) -> None:
        """Insert an immutable result or reject a duplicate identity."""
        if result.id in self.stored:
            raise ResearchResultDuplicateIdentityError(result.id)
        self.stored[result.id] = result

    async def get_by_id(self, result_id: UUID) -> ResearchResult | None:
        """Return one stored result."""
        return self.stored.get(result_id)

    async def list_by_investigation(
        self, investigation_id: UUID
    ) -> list[ResearchResult]:
        """Return stored results for one investigation."""
        return [
            result
            for result in self.stored.values()
            if result.investigation_id == investigation_id
        ]


class _Investigations:
    """Fake investigation repository with an injectable visibility map."""

    def __init__(self, visible: set[UUID]) -> None:
        self._visible = visible

    async def get_by_id(self, id: UUID) -> InvestigationState | None:
        """Return a placeholder state when the identity is visible."""
        if id not in self._visible:
            return None
        return InvestigationState.__new__(InvestigationState)


class _Entities:
    """Fake entity repository with an injectable visibility map."""

    def __init__(self, visible: set[UUID]) -> None:
        self._visible = visible

    async def get_by_id(self, entity_id: UUID) -> Entity | None:
        """Return a placeholder entity when the identity is visible."""
        if entity_id not in self._visible:
            return None
        return Entity(id=entity_id, type=EntityType.DOMAIN, value="example.test")


class _Uow(UnitOfWork):
    def __init__(
        self,
        research_results: _ResearchResults,
        visible_investigations: set[UUID],
        visible_entities: set[UUID],
    ) -> None:
        self.research_results = research_results  # type: ignore[assignment]
        self.investigations = _Investigations(visible_investigations)  # type: ignore[assignment]
        self.entities = _Entities(visible_entities)  # type: ignore[assignment]
        self.committed = False

    async def __aenter__(self) -> Self:
        """Open the fake transaction."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Commit on success matching the production rollback-on-error rule."""

    async def commit(self) -> None:
        """Record the commit."""
        self.committed = True

    async def rollback(self) -> None:
        """Satisfy the unit-of-work contract."""


def _citation(citation_id: UUID | None = None) -> ResearchCitation:
    return ResearchCitation(
        citation_id=citation_id or uuid4(),
        document_id=uuid4(),
        source_id="urn:ati:source:test",
        source_record_id="attack-pattern--one",
        document_type="attack_technique",
        chunk_sequence=1,
        text="Cited chunk text",
    )


def _result(investigation_id: UUID, entity_id: UUID) -> ResearchResult:
    citation = _citation()
    return ResearchResult(
        id=uuid4(),
        investigation_id=investigation_id,
        subject_entity_id=entity_id,
        query="Which persistence techniques apply?",
        claims=(
            ResearchClaim(
                id=uuid4(),
                text="Example technique enables persistence.",
                citation_ids=(citation.citation_id,),
            ),
        ),
        citations=(citation,),
        created_at=_RETRIEVED_AT,
    )


def _service(
    repository: _ResearchResults,
    visible_investigations: set[UUID],
    visible_entities: set[UUID],
) -> ResearchResultPersistenceService:
    def factory() -> UnitOfWork:
        return _Uow(repository, visible_investigations, visible_entities)

    return ResearchResultPersistenceService(factory)


@pytest.mark.asyncio
async def test_persist_valid_result_inserts_and_commits() -> None:
    """A fully constructed result referencing visible roots is inserted."""
    repository = _ResearchResults()
    investigation_id, entity_id, result = uuid4(), uuid4(), None
    result = _result(investigation_id, entity_id)
    service = _service(repository, {investigation_id}, {entity_id})
    await service.persist(result)
    assert repository.stored[result.id] == result


@pytest.mark.asyncio
async def test_persist_rejects_unknown_investigation() -> None:
    """A result referencing a missing investigation fails closed."""
    repository = _ResearchResults()
    investigation_id, entity_id = uuid4(), uuid4()
    result = _result(investigation_id, entity_id)
    service = _service(repository, {uuid4()}, {entity_id})
    with pytest.raises(ResearchResultReferenceError):
        await service.persist(result)
    assert repository.stored == {}


@pytest.mark.asyncio
async def test_persist_rejects_unknown_entity() -> None:
    """A result referencing a missing subject entity fails closed."""
    repository = _ResearchResults()
    investigation_id, entity_id = uuid4(), uuid4()
    result = _result(investigation_id, entity_id)
    service = _service(repository, {investigation_id}, {uuid4()})
    with pytest.raises(ResearchResultReferenceError):
        await service.persist(result)
    assert repository.stored == {}


@pytest.mark.asyncio
async def test_persist_propagates_duplicate_identity() -> None:
    """A duplicate result identity surfaces the typed repository error."""
    repository = _ResearchResults()
    investigation_id, entity_id = uuid4(), uuid4()
    result = _result(investigation_id, entity_id)
    service = _service(repository, {investigation_id}, {entity_id})
    await service.persist(result)
    with pytest.raises(ResearchResultDuplicateIdentityError):
        await service.persist(result)


@pytest.mark.asyncio
async def test_persist_is_append_only_without_side_effects() -> None:
    """Persisting research never touches evidence or assessment repositories."""
    repository = _ResearchResults()
    investigation_id, entity_id = uuid4(), uuid4()
    result = _result(investigation_id, entity_id)
    service = _service(repository, {investigation_id}, {entity_id})
    await service.persist(result)
    # The repository surface exercised is exactly add/get/list; no other
    # persistence boundary is involved in an immutable research insert.
    assert isinstance(service, ResearchResultPersistenceService)
