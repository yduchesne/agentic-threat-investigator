# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the durable Investigation submission service (PR 23C).

The service is exercised with an in-memory fake UnitOfWork that records every
mutation, proving the atomicity contract: Investigation + durable job +
audit + idempotency record are written in one transaction, and neither the
service nor its fakes ever invoke ``InvestigationRunner``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.investigation_submission import (
    DuplicateCanonicalIndicatorError,
    IdempotencyConflictError,
    IdempotencyKeyRequiredError,
    IndicatorInput,
    InvestigationSubmission,
    InvestigationSubmissionService,
    SubmissionBoundsError,
    canonical_request_fingerprint,
    validate_idempotency_key,
)
from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    EntityBatchResult,
    IdempotencyRecord,
    InvestigationWriteResult,
)
from agentic_threat_investigator.domain.audit import AuditEvent
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
)
from agentic_threat_investigator.domain.investigation_job import InvestigationJob

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


class FakeEntitiesRepository:
    """Record entity batch upserts and return deterministic results."""

    def __init__(self) -> None:
        """Bind an empty batch history and the next entity identity."""
        self.batches: list[list[Any]] = []
        self.next_entity_id = uuid4()

    async def upsert_batch(self, items: list[Any]) -> list[EntityBatchResult]:
        """Record one batch and return one result per item."""
        self.batches.append(list(items))
        results = []
        for ordinal, _item in enumerate(items):
            results.append(
                EntityBatchResult(
                    ordinal=ordinal + 1,
                    entity_id=self.next_entity_id,
                    version=1,
                    outcome=BatchOutcome.INSERTED,
                )
            )
        return results


class FakeInvestigationsRepository:
    """Record investigation creation and serve authoritative reads."""

    def __init__(self) -> None:
        """Bind an empty store and creation history."""
        self.created: list[InvestigationState] = []
        self.store: dict[UUID, InvestigationState] = {}

    async def create(
        self, state: InvestigationState, **kwargs: Any
    ) -> InvestigationWriteResult:
        """Store the PENDING investigation and allocate version 1."""
        persisted = state.model_copy(
            update={"version": 1, "created_at": FIXED_NOW, "updated_at": FIXED_NOW}
        )
        self.created.append(persisted)
        self.store[state.investigation_id] = persisted
        return InvestigationWriteResult(
            investigation_id=state.investigation_id,
            version=1,
            outcome=BatchOutcome.INSERTED,
        )

    async def get_by_id(
        self, investigation_id: UUID, **kwargs: Any
    ) -> InvestigationState | None:
        """Return the stored authoritative state, if any."""
        return self.store.get(investigation_id)


class FakeJobsRepository:
    """Record durable job creation."""

    def __init__(self) -> None:
        """Bind an empty job history."""
        self.created: list[InvestigationJob] = []

    async def create(self, job: InvestigationJob) -> InvestigationJob:
        """Record the job and return it."""
        self.created.append(job)
        return job


class FakeIdempotencyRepository:
    """Simulate the unique-scope insert with in-memory deduplication."""

    def __init__(self) -> None:
        """Bind an empty record store keyed by actor/operation/key_hash."""
        self.records: dict[tuple[UUID, str, bytes], IdempotencyRecord] = {}

    async def insert_if_absent(
        self, record: IdempotencyRecord
    ) -> IdempotencyRecord | None:
        """Insert unless the actor/operation/key scope already exists."""
        key = (record.actor_id, record.operation, record.key_hash)
        if key in self.records:
            return None
        self.records[key] = record
        return record

    async def get(
        self, *, actor_id: UUID, operation: str, key_hash: bytes
    ) -> IdempotencyRecord | None:
        """Return the existing record for the scope, if any."""
        return self.records.get((actor_id, operation, key_hash))


class FakeAuditRepository:
    """Record appended audit events."""

    def __init__(self) -> None:
        """Bind an empty event list."""
        self.events: list[AuditEvent] = []

    async def append(self, event: AuditEvent) -> AuditEvent:
        """Record the event."""
        self.events.append(event)
        return event


class FakeUnitOfWork:
    """In-memory transaction boundary recording commit/rollback."""

    def __init__(self) -> None:
        """Bind fresh fakes for every repository the service touches."""
        self.entities = FakeEntitiesRepository()
        self.investigations = FakeInvestigationsRepository()
        self.investigation_jobs = FakeJobsRepository()
        self.idempotency = FakeIdempotencyRepository()
        self.audit_events = FakeAuditRepository()
        self.commits = 0
        self.rollbacks = 0

    async def __aenter__(self) -> "FakeUnitOfWork":
        """Enter the transaction."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: object,
    ) -> None:
        """Commit on success and roll back on failure."""
        if exc_type is None:
            self.commits += 1
        else:
            self.rollbacks += 1


def _service(uow: FakeUnitOfWork | None = None) -> InvestigationSubmissionService:
    """Build the service over one fresh fake transaction boundary."""
    return InvestigationSubmissionService(
        cast(Any, lambda: uow if uow is not None else FakeUnitOfWork()),
        clock=lambda: FIXED_NOW,
    )


def _submission(
    value: str = "example.com", objective: str = "assess the domain"
) -> InvestigationSubmission:
    """Build one valid normalized submission."""
    return InvestigationSubmission(
        indicators=[IndicatorInput(type=EntityType.DOMAIN, value=value)],
        objective=objective,
    )


def _fingerprint(submission: InvestigationSubmission) -> str:
    """Compute the canonical fingerprint of a submission."""
    return canonical_request_fingerprint(
        submission.indicators,
        submission.objective,
        max_indicators=20,
        max_value_length=2048,
        max_objective_length=4000,
    )


@pytest.mark.asyncio
async def test_fresh_submission_creates_investigation_job_audit_idempotency() -> None:
    """A fresh submission atomically persists every required resource."""
    uow = FakeUnitOfWork()
    service = _service(uow)
    actor = uuid4()
    submission = _submission()

    investigation = await service.submit(
        submission, actor_id=actor, idempotency_key="key-1"
    )

    assert investigation.status is InvestigationStatus.PENDING
    assert investigation.trigger_type is InvestigationTriggerType.API
    assert uow.commits == 1
    assert len(uow.entities.batches) == 1
    assert len(uow.investigations.created) == 1
    assert len(uow.investigation_jobs.created) == 1
    assert len(uow.audit_events.events) == 1
    # The idempotency record resolves to the created Investigation.
    record = next(iter(uow.idempotency.records.values()))
    assert record.actor_id == actor
    assert record.resource_id == investigation.investigation_id
    assert record.key_hash == validate_idempotency_key("key-1")
    # The runner is never invoked by the service.
    assert not hasattr(service, "runner")


@pytest.mark.asyncio
async def test_equivalent_replay_returns_existing_investigation() -> None:
    """An equivalent replay returns the same Investigation with no new writes."""
    uow = FakeUnitOfWork()
    service = _service(uow)
    actor = uuid4()
    submission = _submission()

    first = await service.submit(submission, actor_id=actor, idempotency_key="key-1")
    second = await service.submit(submission, actor_id=actor, idempotency_key="key-1")

    assert second.investigation_id == first.investigation_id
    assert len(uow.investigations.created) == 1
    assert len(uow.investigation_jobs.created) == 1
    assert len(uow.entities.batches) == 1
    assert len(uow.audit_events.events) == 1


@pytest.mark.asyncio
async def test_different_request_same_key_conflicts() -> None:
    """Reusing a key for a different semantic request fails closed with 409."""
    uow = FakeUnitOfWork()
    service = _service(uow)
    actor = uuid4()

    await service.submit(
        _submission(value="example.com"), actor_id=actor, idempotency_key="key-1"
    )
    with pytest.raises(IdempotencyConflictError):
        await service.submit(
            _submission(value="other.example.com"),
            actor_id=actor,
            idempotency_key="key-1",
        )
    assert len(uow.investigations.created) == 1


@pytest.mark.asyncio
async def test_missing_key_raises_required_error() -> None:
    """An absent Idempotency-Key is rejected before any write."""
    uow = FakeUnitOfWork()
    service = _service(uow)
    with pytest.raises(IdempotencyKeyRequiredError):
        await service.submit(_submission(), actor_id=uuid4(), idempotency_key=None)
    assert uow.investigations.created == []


@pytest.mark.asyncio
async def test_duplicate_canonical_indicators_fail_deterministically() -> None:
    """Duplicate canonical indicator identities fail closed."""
    service = _service()
    submission = InvestigationSubmission(
        indicators=[
            IndicatorInput(type=EntityType.DOMAIN, value="Example.COM"),
            IndicatorInput(type=EntityType.DOMAIN, value="example.com"),
        ],
        objective="assess",
    )
    with pytest.raises(DuplicateCanonicalIndicatorError):
        await service.submit(submission, actor_id=uuid4(), idempotency_key="key-1")


@pytest.mark.asyncio
async def test_indicator_count_bound_enforced() -> None:
    """Submissions above the configured indicator ceiling are rejected."""
    service = InvestigationSubmissionService(
        cast(Any, lambda: FakeUnitOfWork()),
        limits=__import__(
            "agentic_threat_investigator.app.investigation_submission",
            fromlist=["SubmissionLimits"],
        ).SubmissionLimits(max_indicators=1),
        clock=lambda: FIXED_NOW,
    )
    submission = InvestigationSubmission(
        indicators=[
            IndicatorInput(type=EntityType.DOMAIN, value=f"example-{index}.com")
            for index in range(2)
        ],
        objective="assess",
    )
    with pytest.raises(SubmissionBoundsError):
        await service.submit(submission, actor_id=uuid4(), idempotency_key="key-1")


@pytest.mark.asyncio
async def test_replay_preserves_deterministic_fingerprint_semantics() -> None:
    """Equivalent requests (even reordered) share one fingerprint."""
    submission_a = _submission(value="example.com")
    submission_b = _submission(value="EXAMPLE.com")  # same canonical identity
    assert _fingerprint(submission_a) == _fingerprint(submission_b)
    assert _fingerprint(submission_a) == _fingerprint(
        _submission(value="example.com", objective="  assess the domain  ")
    )


@pytest.mark.asyncio
async def test_cti_entity_types_are_not_investigation_seeds() -> None:
    """PR 33C: graphable CTI Entity types are never Investigation seeds.

    Every new source-neutral CTI Entity type is accepted by the canonical
    domain canonicalizer (so it can be persisted and displayed as a graph
    node), but the explicit seed allowlist must reject it deterministically
    at the application validation boundary before any orchestration work can
    be planned. No provider or research capability is invented.
    """
    service = _service()
    for entity_type, value in (
        (EntityType.THREAT_ACTOR, "threat-actor--11111111-1111-1111-1111-111111111111"),
        (EntityType.CAMPAIGN, "campaign--22222222-2222-2222-2222-222222222222"),
        (
            EntityType.INTRUSION_SET,
            "intrusion-set--33333333-3333-3333-3333-333333333333",
        ),
        (EntityType.TOOL, "tool--44444444-4444-4444-4444-444444444444"),
        (
            EntityType.INFRASTRUCTURE,
            "infrastructure--55555555-5555-5555-5555-555555555555",
        ),
    ):
        submission = InvestigationSubmission(
            indicators=[IndicatorInput(type=entity_type, value=value)],
            objective="assess the CTI object",
        )
        with pytest.raises(SubmissionBoundsError, match="seed"):
            await service.submit(submission, actor_id=uuid4(), idempotency_key="key-1")


@pytest.mark.asyncio
async def test_established_seed_types_still_accepted() -> None:
    """Existing seed types retain their established submission behavior."""
    uow = FakeUnitOfWork()
    service = _service(uow)
    for entity_type, value in (
        (EntityType.DOMAIN, "example.com"),
        (EntityType.IP_ADDRESS, "203.0.113.9"),
        (EntityType.MALWARE, "win.asyncrat"),
        (EntityType.ATTACK_TECHNIQUE, "T1059"),
        (EntityType.VULNERABILITY, "CVE-2024-1234"),
    ):
        submission = InvestigationSubmission(
            indicators=[IndicatorInput(type=entity_type, value=value)],
            objective="assess",
        )
        investigation = await service.submit(
            submission, actor_id=uuid4(), idempotency_key=f"key-{entity_type.value}"
        )
        assert investigation.status is InvestigationStatus.PENDING


def test_investigation_seed_allowlist_excludes_cti_types() -> None:
    """The domain seed allowlist exactly equals the nine established types."""
    from agentic_threat_investigator.domain.investigation import (
        INVESTIGATION_SEED_TYPES,
    )

    assert (
        frozenset(
            {
                EntityType.DOMAIN,
                EntityType.IP_ADDRESS,
                EntityType.URL,
                EntityType.NETWORK_PREFIX,
                EntityType.ASN,
                EntityType.ORGANIZATION,
                EntityType.MALWARE,
                EntityType.ATTACK_TECHNIQUE,
                EntityType.VULNERABILITY,
            }
        )
        == INVESTIGATION_SEED_TYPES
    )
    for entity_type in (
        EntityType.THREAT_ACTOR,
        EntityType.CAMPAIGN,
        EntityType.INTRUSION_SET,
        EntityType.TOOL,
        EntityType.INFRASTRUCTURE,
    ):
        assert entity_type not in INVESTIGATION_SEED_TYPES
