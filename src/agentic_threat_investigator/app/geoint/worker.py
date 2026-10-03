# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""GeoResolutionWorker: the bounded async geographic-resolution lifecycle (PR 26C, PR L-2).

One iteration of the durable worker follows the approved transaction split:

```text
short UoW: claim bounded batch        -> COMMIT/CLOSE
claimed rows carry id/version/owner/lease
    -> bounded concurrent item pipelines (max_concurrency)
for each claimed item (independently):
    wait for the worker concurrency permit (no UoW held)
    short UoW: load exact immutable LegacyEvidence -> CLOSE
    extract GeographicClaim                   (no DB I/O)
    LocationResolver.resolve(claim)           (NO UoW open, no locks held)
    short UoW: persist outcome                -> COMMIT/CLOSE
        RESOLVED      complete_resolved       (one atomic stored function)
        UNRESOLVABLE  complete_unresolvable
        retry/failure record_failure
```

Active item pipelines never exceed ``max_concurrency``; a task waiting for
admission holds no UnitOfWork, session, connection, or resolver resource.
Never share a UnitOfWork or SQLAlchemy session between item tasks; every
production resolver call owns its own invocation-local session.

The worker owns no queue, no broker, no generic scheduler framework: it
drives ``GeoResolution`` rows through the SQL API v0024 stored functions,
which remain the final authority for provenance, versions, leases, and
attempt bookkeeping. ``asyncio.CancelledError`` always propagates (parent
cancellation settles outstanding children and no worker transition is
persisted); committed leases recover by expiry. One item failure never
terminates the daemon: a bounded resolver/persistence error is persisted
through the existing retry/failure semantics, and an unexpected exception
escaping an item is logged only (bounded identity/type, never raw
exception text) and reclaimed by lease expiry; no ad-hoc UPDATE recovery
ever runs.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from agentic_threat_investigator.app.geoint.claims import (
    geographic_claim_from_evidence,
)
from agentic_threat_investigator.app.geoint.resolution import LocationResolver
from agentic_threat_investigator.app.persistence.repositories import (
    GeoEvidenceNotFoundError,
    GeoEvidenceSubjectMismatchError,
    GeoEvidenceTypeError,
    InvalidGeographicClaimError,
    UnitOfWork,
)
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceObservation
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolutionStatus,
    EntityLocationObservation,
    GeoResolution,
    observation_uuid_for_resolution,
)
from agentic_threat_investigator.telemetry.decorators import telemetry_operation
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
    get_counter,
)
from agentic_threat_investigator.telemetry.tracing import SpanNames

LOGGER = logging.getLogger(__name__)

# Stable bounded machine code for deterministic ambiguity (PR 26C v0.1 policy:
# canonical AMBIGUOUS is terminal UNRESOLVABLE, never guessed, never retried).
AMBIGUITY_ERROR_CODE = "ambiguous_location"
# Stable machine identity of the v0.1 deterministic resolution method.
CANONICAL_GEOGRAPHY_METHOD = "canonical_geography_v1"
# Fixed bounded codes for worker-side failures; raw exception text is never
# persisted into last_error_code.
FAILURE_EVIDENCE_LOAD = "evidence_load_error"
FAILURE_RESOLVER = "resolver_error"
FAILURE_MALFORMED_EVIDENCE = "malformed_evidence"
FAILURE_MISSING_EVIDENCE = "missing_evidence"
FAILURE_EVIDENCE_TYPE = "evidence_type_invalid"
FAILURE_EVIDENCE_SUBJECT = "evidence_subject_mismatch"


class EvidenceLoadError(RuntimeError):
    """Bounded marker for a transient evidence-load failure.

    Distinct from a missing LegacyEvidence row (which is terminal and
    non-retryable): the load itself could not complete.
    """


class GeoResolutionWorkerConfig(BaseModel):
    """Bounded worker policy; validated fail-closed before any claim is made."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    worker_id: str
    batch_size: int
    lease_seconds: int
    poll_interval_seconds: float
    max_attempts: int
    retry_base_seconds: float
    retry_max_seconds: float
    # PR L-2: explicit bounded concurrency of claimed item pipelines, kept
    # independent from batch_size (the claim-count policy). Never stored as
    # an asyncio primitive: this stays a plain validated integer policy.
    max_concurrency: int

    @field_validator("worker_id")
    @classmethod
    def _validate_worker_id(cls, value: str) -> str:
        """Require a bounded operational worker identity."""
        if not value.strip():
            raise ValueError("worker_id must not be blank")
        if len(value.strip()) > 200:
            raise ValueError("worker_id exceeds the maximum length of 200")
        return value.strip()

    @model_validator(mode="after")
    def _validate_policy_bounds(self) -> "GeoResolutionWorkerConfig":
        """Enforce the bounded retry/lease/batch policy contract."""
        if self.batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        if self.lease_seconds < 1:
            raise ValueError("lease_seconds must be >= 1")
        if self.poll_interval_seconds < 0:
            raise ValueError("poll_interval_seconds must not be negative")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.retry_base_seconds <= 0:
            raise ValueError("retry_base_seconds must be > 0")
        if self.retry_max_seconds < self.retry_base_seconds:
            raise ValueError("retry_max_seconds must be >= retry_base_seconds")
        return self


def retry_delay_seconds(
    attempt_count: int, *, base_seconds: float, max_seconds: float
) -> float:
    """Return the deterministic bounded backoff for the just-failed attempt.

    ``base * 2^(attempt_count - 1)`` capped at ``max_seconds``, with no
    jitter: the same failed attempt always schedules the same delay. Must
    mirror the database-owned formula in ``ati.record_geo_resolution_failure``
    (SQL API v0024).
    """
    if attempt_count < 1:
        raise ValueError("attempt_count must be >= 1")
    delay: float = base_seconds * (2 ** (attempt_count - 1))
    if delay > max_seconds:
        return max_seconds
    return delay


class GeoResolutionWorker:
    """Drive one iteration of the bounded geographic-resolution lifecycle."""

    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        resolver: LocationResolver,
        config: GeoResolutionWorkerConfig,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind the transaction factory, the resolver seam, and the policy."""
        self._uow_factory = uow_factory
        self._resolver = resolver
        self._config = config
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(UTC))
        )

    @telemetry_operation(
        span_name=SpanNames.GEO_RESOLVE,
        duration_metric=DurationMetrics.GEO_RESOLVE,
    )
    async def run_once(self) -> int:
        """Claim a bounded batch, then process items under a concurrency bound.

        Returns the number of claimed items processed. The claim remains one
        short committed UnitOfWork; a non-empty batch then runs through one
        iteration-local ``asyncio.TaskGroup`` whose admitted item pipelines
        are bounded by ``max_concurrency``. Every item keeps its own
        short load/resolve/complete UnitOfWork lifecycle; resolution always
        runs with no UnitOfWork open. Active item pipelines never exceed
        ``max_concurrency`` and a task waiting for admission holds no
        UnitOfWork/session/connection. One ``ati.geo.resolve`` span and
        seconds duration cover the whole iteration; per-item resolved,
        unresolvable, and failed outcomes are counted at their authoritative
        persist points. An empty claim still measures the worker iteration
        and never invents item outcomes. Parent cancellation propagates
        (settling outstanding children) and never fabricates transitions.
        """
        claimed = await self._claim_batch()
        if not claimed:
            return 0
        semaphore = asyncio.Semaphore(self._config.max_concurrency)
        child_cancelled = False

        async def _admit(resolution: GeoResolution) -> None:
            """Admit one claimed item and detect a child-local cancellation.

            ``asyncio.TaskGroup`` treats a child task that re-raises
            ``CancelledError`` as cancelled and does not re-raise it; ATI's
            worker contract is that cancellation always propagates, so the
            occurrence is recorded here and re-raised once the group settles.
            """
            nonlocal child_cancelled
            try:
                await self._run_admitted(resolution, semaphore)
            except asyncio.CancelledError:
                child_cancelled = True
                raise

        async with asyncio.TaskGroup() as task_group:
            for resolution in claimed:
                task_group.create_task(_admit(resolution))
        if child_cancelled:
            raise asyncio.CancelledError()
        return len(claimed)

    async def _run_admitted(
        self, resolution: GeoResolution, semaphore: asyncio.Semaphore
    ) -> None:
        """Wait for one worker concurrency permit, then process one item.

        The permit is acquired BEFORE ``_process_one`` opens any UnitOfWork,
        and released cancellation-safely via ``async with``, so a task
        waiting for admission holds no UnitOfWork, session, connection, or
        resolver resource. An unexpected exception escaping ``_process_one``
        is isolated here (bounded log only) so one item failure never
        cancels sibling item pipelines under ``TaskGroup``; the already-
        claimed row is left to the existing lease-expiry recovery and no
        ad-hoc persistence or raw exception text is ever written.
        """
        async with semaphore:
            try:
                await self._process_one(resolution)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                LOGGER.exception(
                    "geo resolution item failed unexpectedly "
                    "resolution_id=%s error_type=%s",
                    resolution.id,
                    type(error).__name__,
                )

    async def _claim_batch(self) -> list[GeoResolution]:
        """Claim eligible work in one short committed UnitOfWork."""
        async with self._uow_factory() as uow:
            return await uow.geo_resolutions.claim_batch(
                claimed_by=self._config.worker_id,
                limit=self._config.batch_size,
                lease_seconds=self._config.lease_seconds,
                max_attempts=self._config.max_attempts,
            )

    async def _process_one(self, resolution: GeoResolution) -> None:
        """Load evidence, resolve outside a transaction, and persist outcome."""
        resolution_id, expected_version, claimed_by = self._work_identity(resolution)

        try:
            loaded = await self._load_evidence(resolution)
        except EvidenceLoadError:
            await self._persist_failure(
                resolution, code=FAILURE_EVIDENCE_LOAD, retryable=True
            )
            return
        if loaded is None:
            await self._persist_failure(
                resolution, code=FAILURE_MISSING_EVIDENCE, retryable=False
            )
            return
        evidence_stable, evidence = loaded

        try:
            claim = geographic_claim_from_evidence(evidence_stable, evidence)
        except GeoEvidenceTypeError:
            await self._persist_failure(
                resolution, code=FAILURE_EVIDENCE_TYPE, retryable=False
            )
            return
        except InvalidGeographicClaimError:
            await self._persist_failure(
                resolution, code=FAILURE_MALFORMED_EVIDENCE, retryable=False
            )
            return

        try:
            outcome = await self._resolver.resolve(claim)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            LOGGER.warning(
                "geo resolver failure resolution_id=%s code=%s",
                resolution_id,
                FAILURE_RESOLVER,
                exc_info=True,
            )
            _ = error
            await self._persist_failure(
                resolution, code=FAILURE_RESOLVER, retryable=True
            )
            return

        if outcome.status is CanonicalLocationResolutionStatus.RESOLVED:
            if outcome.location is None or outcome.location.id is None:
                LOGGER.warning(
                    "geo resolver returned no location resolution_id=%s",
                    resolution_id,
                )
                await self._persist_failure(
                    resolution, code=FAILURE_RESOLVER, retryable=True
                )
                return
            observation = EntityLocationObservation(
                id=observation_uuid_for_resolution(resolution_id),
                entity_id=resolution.entity_id,
                location_id=outcome.location.id,
                evidence_observation_id=resolution.evidence_observation_id,
                precision=claim.precision,
                observed_at=evidence.observed_at,
                retrieved_at=evidence.retrieved_at,
                resolved_at=self._clock(),
                resolution_method=CANONICAL_GEOGRAPHY_METHOD,
            )
            await self._complete_resolved(resolution, observation)
            return
        if outcome.status is CanonicalLocationResolutionStatus.AMBIGUOUS:
            await self._persist_unresolvable(resolution, AMBIGUITY_ERROR_CODE)
            return
        await self._persist_unresolvable(resolution, outcome.reason_code)

    @staticmethod
    def _work_identity(
        resolution: GeoResolution,
    ) -> tuple[UUID, int, str]:
        """Return the authoritative work identity of one claimed row.

        The stored claim function always returns complete rows; a None field
        would indicate an internal contract violation and fails fast.
        """
        resolution_id = resolution.id
        expected_version = resolution.version
        claimed_by = resolution.claimed_by
        if resolution_id is None or expected_version is None or claimed_by is None:
            raise RuntimeError("claimed geo resolution lacks work identity")
        return resolution_id, expected_version, claimed_by

    async def _load_evidence(
        self, resolution: GeoResolution
    ) -> tuple[Evidence, EvidenceObservation] | None:
        """Load the exact Immutable EvidenceObservation and its stable Evidence.

        A transient load failure (database availability) raises
        :class:`EvidenceLoadError` so the caller persists a retryable bounded
        failure; ``None`` means the observation row is genuinely absent (a
        terminal, non-retryable condition).
        """
        try:
            async with self._uow_factory() as uow:
                observation = await uow.evidence.get_observation(
                    resolution.evidence_observation_id
                )
                if observation is None:
                    return None
                stable = await uow.evidence.get_stable_evidence(observation.evidence_id)
                if stable is None:  # pragma: no cover - FK invariant
                    return None
                return stable, observation
        except asyncio.CancelledError:
            raise
        except Exception as error:
            LOGGER.warning(
                "geo evidence load failed resolution_id=%s code=%s",
                resolution.id,
                FAILURE_EVIDENCE_LOAD,
                exc_info=True,
            )
            raise EvidenceLoadError() from error

    async def _complete_resolved(
        self, resolution: GeoResolution, observation: EntityLocationObservation
    ) -> None:
        """Persist the atomic resolved completion in a short UnitOfWork."""
        resolution_id, expected_version, claimed_by = self._work_identity(resolution)
        try:
            async with self._uow_factory() as uow:
                await uow.geo_resolutions.complete_resolved(
                    resolution_id,
                    expected_version,
                    claimed_by,
                    observation,
                )
            get_counter(Metrics.GEO_RESOLVED).add(1)
        except asyncio.CancelledError:
            raise
        except (
            GeoEvidenceNotFoundError,
            GeoEvidenceTypeError,
            GeoEvidenceSubjectMismatchError,
        ) as error:
            # Wrong/missing LegacyEvidence at database-authoritative completion
            # time: a terminal, non-retryable condition. Provenance is never patched.
            LOGGER.warning(
                "geo completion evidence conflict resolution_id=%s code=%s",
                resolution.id,
                FAILURE_EVIDENCE_SUBJECT,
                exc_info=True,
            )
            _ = error
            await self._persist_failure(
                resolution, code=FAILURE_EVIDENCE_SUBJECT, retryable=False
            )
        except Exception as error:
            LOGGER.warning(
                "geo completion rejected resolution_id=%s error_type=%s",
                resolution.id,
                type(error).__name__,
                exc_info=True,
            )
            # Stale version/claim, expired lease, terminal replay conflict, or
            # any other rejection: never perform ad-hoc UPDATE recovery; the
            # lease expires and the authoritative worker reclaims the row.

    async def _persist_unresolvable(
        self, resolution: GeoResolution, error_code: str | None
    ) -> None:
        """Persist the terminal UNRESOLVABLE transition with a stable code."""
        code = error_code or FAILURE_RESOLVER
        resolution_id, expected_version, claimed_by = self._work_identity(resolution)
        try:
            async with self._uow_factory() as uow:
                await uow.geo_resolutions.complete_unresolvable(
                    resolution_id=resolution_id,
                    expected_version=expected_version,
                    claimed_by=claimed_by,
                    error_code=code,
                )
            get_counter(Metrics.GEO_UNRESOLVABLE).add(1)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            LOGGER.warning(
                "geo unresolvable completion rejected resolution_id=%s error_type=%s",
                resolution.id,
                type(error).__name__,
                exc_info=True,
            )

    async def _persist_failure(
        self,
        resolution: GeoResolution,
        *,
        code: str,
        retryable: bool,
    ) -> None:
        """Persist one bounded failure transition in a short UnitOfWork.

        If persisting the failure itself fails (for example a stale claim),
        the bounded event is logged and lease expiry recovers the row; no
        ad-hoc UPDATE recovery is ever performed.
        """
        resolution_id, expected_version, claimed_by = self._work_identity(resolution)
        try:
            async with self._uow_factory() as uow:
                await uow.geo_resolutions.record_failure(
                    resolution_id,
                    expected_version,
                    claimed_by,
                    code,
                    retryable=retryable,
                    retry_base_seconds=self._config.retry_base_seconds,
                    retry_max_seconds=self._config.retry_max_seconds,
                    max_attempts=self._config.max_attempts,
                )
            get_counter(Metrics.GEO_FAILED).add(1)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            LOGGER.warning(
                "geo failure persistence rejected resolution_id=%s code=%s "
                "error_type=%s",
                resolution.id,
                code,
                type(error).__name__,
                exc_info=True,
            )
