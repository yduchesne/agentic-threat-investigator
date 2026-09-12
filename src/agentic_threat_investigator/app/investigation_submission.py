# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Durable asynchronous Investigation submission (PR 23C).

:class:`InvestigationSubmissionService` is the application seam behind
``POST /api/v1/investigations``. It accepts a normalized submission request,
the authenticated actor, an idempotency identity, and a request ID, and
atomically persists:

1. the canonical root indicator Entities through the existing write seams;
2. the Investigation as ``PENDING``;
3. the durable PostgreSQL investigation job;
4. the required mutation audit event;
5. the actor-scoped idempotency record;

in one transaction that commits exactly once, then returns the authoritative
Investigation. It never invokes ``InvestigationRunner`` and never schedules
in-process work: a worker claims the durable job later.

Idempotency semantics (database-race-safe):

- an absent key raises :class:`IdempotencyKeyRequiredError`;
- an absent record creates the Investigation + job + audit + record;
- an existing record with a matching canonical fingerprint returns the
  existing Investigation (equivalent replay, consistent ``202`` semantics);
- an existing record with a different fingerprint raises
  :class:`IdempotencyConflictError` (fail closed, ``409``).

The canonical request fingerprint is a SHA-256 over the semantic normalized
request (schema marker, sorted canonical indicator identities, normalized
objective); raw HTTP JSON bytes are never fingerprinted, so property
reordering and whitespace differences replay identically.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from re import fullmatch
from typing import Callable
from uuid import UUID, uuid4

from agentic_threat_investigator.app.persistence.repositories import (
    EntityBatchItem,
    IdempotencyRecord,
    InvestigationNotFoundError,
    UnitOfWork,
)
from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType, canonicalize
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.investigation_job import (
    InvestigationJob,
    InvestigationJobStatus,
)

IDEMPOTENCY_OPERATION = "create_investigation"
"""The stable idempotency operation name scoped to Investigation creation."""

IDEMPOTENCY_RESOURCE_TYPE = "investigation"
"""The stable public resource type of an idempotency record."""

IDEMPOTENCY_SCHEMA_MARKER = "create_investigation/v1"
"""Stable schema marker bound to every canonical request fingerprint."""

MAX_IDEMPOTENCY_KEY_LENGTH = 128
"""Hard ceiling on Idempotency-Key length (ASCII characters)."""

IDEMPOTENCY_KEY_RE = r"[A-Za-z0-9._~-]{1,128}"
"""Accepted Idempotency-Key grammar: bounded visible ASCII characters."""


class IdempotencyKeyRequiredError(ValueError):
    """Raised when a state-changing request omits its Idempotency-Key."""


class IdempotencyKeyInvalidError(ValueError):
    """Raised when an Idempotency-Key violates the bounded grammar."""


class IdempotencyConflictError(ValueError):
    """Raised when the same key is reused for a different semantic request."""


class DuplicateCanonicalIndicatorError(ValueError):
    """Raised when a submission repeats one canonical indicator identity."""


class SubmissionBoundsError(ValueError):
    """Raised when a submission violates its configured bounds."""


@dataclass(frozen=True)
class SubmissionLimits:
    """Configured submission bounds shared by the service and its callers."""

    max_indicators: int = 20
    max_indicator_value_length: int = 2048
    max_objective_length: int = 4000

    def __post_init__(self) -> None:
        """Reject non-positive or inverted bounds."""
        if self.max_indicators < 1:
            raise ValueError("max_indicators must be positive")
        if self.max_indicator_value_length < 1:
            raise ValueError("max_indicator_value_length must be positive")
        if self.max_objective_length < 1:
            raise ValueError("max_objective_length must be positive")


class IndicatorInput:
    """A raw indicator submitted by the caller before canonicalization.

    ``value`` is the raw caller value; the service canonicalizes it through
    the existing domain :func:`canonicalize` contract and never invents
    API-only normalization.
    """

    def __init__(self, type: EntityType, value: str) -> None:
        """Bind the raw indicator type and value."""
        self.type = type
        self.value = value


class InvestigationSubmission:
    """The normalized application-level submission request."""

    def __init__(self, *, indicators: list[IndicatorInput], objective: str) -> None:
        """Bind the raw indicators and objective."""
        self.indicators = list(indicators)
        self.objective = objective


def normalize_objective(objective: str) -> str:
    """Return the canonical objective text for fingerprinting.

    Surrounding whitespace is stripped and internal runs of whitespace are
    collapsed to single spaces, so equivalent prose replays identically.
    """
    return " ".join(objective.strip().split())


def canonical_indicator_identities(
    indicators: list[IndicatorInput],
    *,
    max_indicators: int,
    max_value_length: int,
) -> tuple[tuple[str, str], ...]:
    """Canonicalize, bound, and deterministically deduplicate indicators.

    The returned identities are sorted ``(type, canonical_value)`` pairs so
    reordered equivalent submissions fingerprint identically. Duplicate
    canonical indicators fail closed with a typed error.
    """
    if not indicators:
        raise SubmissionBoundsError("at least one indicator is required")
    if len(indicators) > max_indicators:
        raise SubmissionBoundsError(
            f"indicator count {len(indicators)} exceeds limit {max_indicators}"
        )
    canonical: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for indicator in indicators:
        raw = indicator.value.strip()
        if not raw:
            raise SubmissionBoundsError("indicator values must not be blank")
        if len(raw) > max_value_length:
            raise SubmissionBoundsError(
                f"indicator value exceeds limit {max_value_length} characters"
            )
        try:
            identity = (indicator.type.value, canonicalize(indicator.type, raw))
        except ValueError as error:
            raise SubmissionBoundsError(
                f"indicator value is invalid for type {indicator.type.value}"
            ) from error
        if identity in seen:
            raise DuplicateCanonicalIndicatorError(
                f"duplicate canonical indicator: {identity[0]} {identity[1]}"
            )
        seen.add(identity)
        canonical.append(identity)
    return tuple(sorted(canonical))


def canonical_request_fingerprint(
    indicators: list[IndicatorInput],
    objective: str,
    *,
    max_indicators: int,
    max_value_length: int,
    max_objective_length: int,
) -> str:
    """Return the canonical SHA-256 fingerprint of a submission request.

    The payload is the schema marker plus the sorted canonical indicator
    identities and the normalized objective; the result is stable across
    JSON property ordering, whitespace, and indicator order.
    """
    normalized_objective = normalize_objective(objective)
    if not normalized_objective:
        raise SubmissionBoundsError("objective must not be blank")
    if len(normalized_objective) > max_objective_length:
        raise SubmissionBoundsError(
            f"objective exceeds limit {max_objective_length} characters"
        )
    payload = json.dumps(
        {
            "schema": IDEMPOTENCY_SCHEMA_MARKER,
            "indicators": canonical_indicator_identities(
                indicators,
                max_indicators=max_indicators,
                max_value_length=max_value_length,
            ),
            "objective": normalized_objective,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_idempotency_key(key: str | None) -> bytes:
    """Validate and digest an Idempotency-Key.

    Raises :class:`IdempotencyKeyRequiredError` when absent and
    :class:`IdempotencyKeyInvalidError` when it violates the bounded ASCII
    grammar. Only the SHA-256 digest is returned; the raw key is never
    persisted or logged.
    """
    if key is None or not key:
        raise IdempotencyKeyRequiredError(
            "POST /api/v1/investigations requires an Idempotency-Key header"
        )
    if len(key) > MAX_IDEMPOTENCY_KEY_LENGTH or not fullmatch(IDEMPOTENCY_KEY_RE, key):
        raise IdempotencyKeyInvalidError(
            "Idempotency-Key must be 1..128 visible ASCII characters"
        )
    return hashlib.sha256(key.encode("ascii")).digest()


class InvestigationSubmissionService:
    """Coordinate the atomic PENDING Investigation + durable job submission.

    Every successful new submission commits Investigation + durable job +
    success audit + idempotency record atomically; if any step fails the
    whole transaction rolls back. The service never executes the
    Investigation and never owns an in-memory background queue.
    """

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        limits: SubmissionLimits | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind the transaction factory, bounds, and deterministic clock."""
        self._uow_factory = uow_factory
        self._limits = limits or SubmissionLimits()
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC))
        )

    async def submit(
        self,
        submission: InvestigationSubmission,
        *,
        actor_id: UUID,
        idempotency_key: str | None,
        request_id: UUID | None = None,
    ) -> InvestigationState:
        """Create or replay one Investigation under durable idempotency.

        Returns the authoritative persisted Investigation for both a fresh
        submission and an equivalent replay; the caller maps both to a
        consistent ``202 Accepted`` response.
        """
        fingerprint = canonical_request_fingerprint(
            submission.indicators,
            submission.objective,
            max_indicators=self._limits.max_indicators,
            max_value_length=self._limits.max_indicator_value_length,
            max_objective_length=self._limits.max_objective_length,
        )
        key_hash = validate_idempotency_key(idempotency_key)
        now = self._clock()
        investigation_id = uuid4()

        async with self._uow_factory() as uow:
            record = IdempotencyRecord(
                actor_id=actor_id,
                operation=IDEMPOTENCY_OPERATION,
                key_hash=key_hash,
                request_fingerprint=fingerprint,
                resource_type=IDEMPOTENCY_RESOURCE_TYPE,
                resource_id=investigation_id,
                created_at=now,
            )
            inserted = await uow.idempotency.insert_if_absent(record)
            if inserted is None:
                # The actor/operation/key scope already exists (possibly
                # committed by a concurrent identical request). Compare the
                # canonical fingerprint and replay the authoritative resource.
                return await self._replay_existing(
                    uow, actor_id=actor_id, key_hash=key_hash, fingerprint=fingerprint
                )
            return await self._create_fresh(
                uow,
                submission,
                investigation_id=investigation_id,
                actor_id=actor_id,
                request_id=request_id,
                now=now,
            )

    async def _create_fresh(
        self,
        uow: UnitOfWork,
        submission: InvestigationSubmission,
        *,
        investigation_id: UUID,
        actor_id: UUID,
        request_id: UUID | None,
        now: datetime,
    ) -> InvestigationState:
        """Persist entities, Investigation, job, and audit in one transaction."""
        identities = canonical_indicator_identities(
            submission.indicators,
            max_indicators=self._limits.max_indicators,
            max_value_length=self._limits.max_indicator_value_length,
        )
        entity_items = [
            EntityBatchItem(
                entity=Entity(
                    id=uuid4(),
                    type=EntityType(identity[0]),
                    value=identity[1],
                )
            )
            for identity in identities
        ]
        batch = await uow.entities.upsert_batch(entity_items)
        root_entity_ids = [result.entity_id for result in batch]

        state = InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.PENDING,
            trigger_type=InvestigationTriggerType.API,
            root_entity_ids=root_entity_ids,
            objective=normalize_objective(submission.objective),
            budget=default_investigation_budget(),
            started_at=now,
        )
        created = await uow.investigations.create(
            state, actor_id=actor_id, request_id=request_id
        )
        await uow.investigation_jobs.create(
            InvestigationJob(
                id=uuid4(),
                investigation_id=investigation_id,
                status=InvestigationJobStatus.PENDING,
                created_at=now,
            )
        )
        await uow.audit_events.append(
            AuditEvent(
                action=AuditAction.INVESTIGATION_CREATE,
                outcome=AuditOutcome.SUCCESS,
                actor_id=actor_id,
                object_type=IDEMPOTENCY_RESOURCE_TYPE,
                object_id=investigation_id,
                request_id=request_id,
                metadata={"version": created.version},
            )
        )
        return await self._load_investigation(uow, investigation_id)

    async def _replay_existing(
        self,
        uow: UnitOfWork,
        *,
        actor_id: UUID,
        key_hash: bytes,
        fingerprint: str,
    ) -> InvestigationState:
        """Return the existing Investigation for an equivalent replay.

        A fingerprint mismatch fails closed; a missing resource under an
        existing record is an internal inconsistency and raises a typed
        error rather than silently creating a second Investigation.
        """
        existing = await uow.idempotency.get(
            actor_id=actor_id, operation=IDEMPOTENCY_OPERATION, key_hash=key_hash
        )
        if existing is None:  # pragma: no cover - insert_if_absent saw a conflict
            raise IdempotencyConflictError("idempotency record is unavailable")
        if existing.request_fingerprint != fingerprint:
            raise IdempotencyConflictError(
                "Idempotency-Key was already used for a different request"
            )
        return await self._load_investigation(uow, existing.resource_id)

    async def _load_investigation(
        self, uow: UnitOfWork, investigation_id: UUID
    ) -> InvestigationState:
        """Load the authoritative Investigation inside the active transaction."""
        investigation = await uow.investigations.get_by_id(investigation_id)
        if investigation is None:
            raise InvestigationNotFoundError(str(investigation_id))
        return investigation
