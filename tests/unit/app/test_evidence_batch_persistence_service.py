# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the atomic Evidence batch persistence service (PR 28E).

Covers the E28E-P matrix with a fake UnitOfWork/repository: the size bound
is enforced before any transaction, one batch maps to exactly one
UnitOfWork, repository failures roll back and never commit, and a
successful batch commits before the service returns.
"""

from __future__ import annotations

from types import TracebackType
from typing import Self
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.evidence_batch_persistence import (
    EVIDENCE_BATCH_DEFAULT_SIZE,
    EVIDENCE_BATCH_HARD_LIMIT,
    EvidenceBatchPersistenceService,
)
from agentic_threat_investigator.app.evidence_consumer import (
    prepare_evidence_batch,
)
from agentic_threat_investigator.app.evidence_message import EvidenceMessage
from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceBatchInputError,
    EvidenceBatchPersistenceItemResult,
    EvidenceBatchPersistenceResult,
    EvidenceBatchRepository,
    EvidenceBatchSizeLimitExceededError,
    EvidencePersistenceOutcome,
    PreparedEvidenceBatch,
    UnitOfWork,
)
from tests.support.evidence_batch_fixtures import message_batch, threatfox_message

pytestmark = pytest.mark.unit


class FakeEvidenceBatchRepository(EvidenceBatchRepository):
    """Deterministic repository double with an injected failure seam."""

    def __init__(self) -> None:
        self.persist_calls: list[PreparedEvidenceBatch] = []
        self.fail: BaseException | None = None
        self.result = EvidenceBatchPersistenceResult(
            items=(
                EvidenceBatchPersistenceItemResult(
                    message_id=uuid4(),
                    evidence_id=uuid4(),
                    evidence_observation_id=uuid4(),
                    outcome=EvidencePersistenceOutcome.CREATED,
                    version=1,
                ),
            )
        )

    async def persist_batch(
        self, batch: PreparedEvidenceBatch
    ) -> EvidenceBatchPersistenceResult:
        """Record the call and apply the injected failure seam."""
        self.persist_calls.append(batch)
        if self.fail is not None:
            raise self.fail
        return self.result


class FakeBatchUnitOfWork(UnitOfWork):
    """Minimal transaction double recording enter/commit/rollback."""

    def __init__(self, repository: FakeEvidenceBatchRepository) -> None:
        self.evidence_batches: EvidenceBatchRepository = repository
        self.entered = 0
        self.committed = 0
        self.rolled_back = 0

    async def __aenter__(self) -> Self:
        """Begin one fake unit of work."""
        self.entered += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Commit on success; roll back when the block raised."""
        if exc_type is None:
            self.committed += 1
        else:
            self.rolled_back += 1

    async def commit(self) -> None:
        """Record one explicit commit."""
        self.committed += 1

    async def rollback(self) -> None:
        """Record one explicit rollback."""
        self.rolled_back += 1


def _prepared_batch(count: int) -> PreparedEvidenceBatch:
    """Build a real prepared batch of ``count`` ThreatFox messages."""
    messages: list[EvidenceMessage] = []
    for index in range(count):
        message, _ = threatfox_message(
            ioc="malicious-domain.test",
            ioc_type="domain",
            source_record_id=f"rec-p-{index}",
            sequence=index,
        )
        messages.append(message)
    return prepare_evidence_batch(message_batch(tuple(messages)))


def _parts() -> tuple[
    EvidenceBatchPersistenceService,
    FakeBatchUnitOfWork,
    FakeEvidenceBatchRepository,
]:
    """Wire the service under test to one fake UnitOfWork and repository."""
    repository = FakeEvidenceBatchRepository()
    uow = FakeBatchUnitOfWork(repository)
    factory = lambda: uow  # noqa: E731 - fixture returns the shared double
    service = EvidenceBatchPersistenceService(factory)
    return service, uow, repository


@pytest.mark.asyncio
async def test_p01_empty_prepared_batch_rejected_without_uow() -> None:
    """An empty prepared batch is rejected before any UnitOfWork is opened."""
    service, uow, _ = _parts()
    with pytest.raises(EvidenceBatchInputError):
        await service.persist(PreparedEvidenceBatch(records=()))
    assert uow.entered == 0


@pytest.mark.asyncio
async def test_p02_within_limit_one_uow_commit() -> None:
    """One in-limit batch maps to exactly one committed UnitOfWork."""
    service, uow, repository = _parts()
    prepared = _prepared_batch(3)
    await service.persist(prepared)
    assert uow.entered == 1
    assert uow.committed == 1
    assert uow.rolled_back == 0
    assert repository.persist_calls == [prepared]


@pytest.mark.asyncio
async def test_p03_oversized_direct_call_rejected_before_uow() -> None:
    """An oversized direct call is rejected before any UnitOfWork is opened."""
    service, uow, _ = _parts()
    prepared = _prepared_batch(EVIDENCE_BATCH_HARD_LIMIT + 1)
    with pytest.raises(EvidenceBatchSizeLimitExceededError):
        await service.persist(prepared)
    assert uow.entered == 0
    assert uow.committed == 0


@pytest.mark.asyncio
async def test_p04_repository_failure_rolls_back() -> None:
    """A repository failure rolls the UnitOfWork back and never commits."""
    service, uow, repository = _parts()
    repository.fail = RuntimeError("injected repository failure")
    with pytest.raises(RuntimeError, match="injected repository failure"):
        await service.persist(_prepared_batch(2))
    assert uow.entered == 1
    assert uow.committed == 0
    assert uow.rolled_back == 1


@pytest.mark.asyncio
async def test_p05_success_commits_before_return() -> None:
    """The UnitOfWork commit completes before the service returns."""
    service, uow, _ = _parts()
    result = await service.persist(_prepared_batch(1))
    assert uow.committed == 1
    assert len(result.items) == 1


@pytest.mark.asyncio
async def test_p06_repository_result_ordering_passthrough() -> None:
    """The service returns the repository result unchanged (input order)."""
    service, uow, repository = _parts()
    first_id = uuid4()
    second_id = uuid4()
    repository.result = EvidenceBatchPersistenceResult(
        items=(
            EvidenceBatchPersistenceItemResult(
                message_id=first_id,
                evidence_id=uuid4(),
                evidence_observation_id=uuid4(),
                outcome=EvidencePersistenceOutcome.CREATED,
                version=1,
            ),
            EvidenceBatchPersistenceItemResult(
                message_id=second_id,
                evidence_id=uuid4(),
                evidence_observation_id=uuid4(),
                outcome=EvidencePersistenceOutcome.APPENDED,
                version=2,
            ),
        )
    )
    result = await service.persist(_prepared_batch(2))
    assert [item.message_id for item in result.items] == [first_id, second_id]
    assert [item.outcome for item in result.items] == [
        EvidencePersistenceOutcome.CREATED,
        EvidencePersistenceOutcome.APPENDED,
    ]


@pytest.mark.asyncio
async def test_p07_default_hard_limit_is_documented() -> None:
    """The default consumer size and hard ceiling are the pinned contract."""
    assert EVIDENCE_BATCH_DEFAULT_SIZE == 100
    assert EVIDENCE_BATCH_HARD_LIMIT == 500
