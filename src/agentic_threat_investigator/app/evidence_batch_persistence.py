# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Atomic persistence of one prepared global Evidence batch (PR 28E).

The consumer-side seam between bounded polled Evidence batches and the
PostgreSQL batch persistence API. One non-empty prepared batch maps to
exactly one UnitOfWork transaction; the ``async with`` exit commits before
this service returns, so the caller (the consumer) can then commit the
broker position knowing the PostgreSQL commit has completed.

Batch-size contract:

- ``EVIDENCE_BATCH_DEFAULT_SIZE`` is the consumer's poll bound;
- ``EVIDENCE_BATCH_HARD_LIMIT`` is the maximum accepted by the service, the
  adapter, and the SQL API (each layer independently rejects oversized
  input; this service rejects before opening any transaction).

No provider I/O, extraction, broker poll/commit, sleep, or backoff ever
runs inside the transaction: the prepared batch is already-validated,
already-extracted work (see ``app/evidence_consumer.py``), and this module
only validates the size bound and delegates to
``UnitOfWork.evidence_batches``.
"""

from __future__ import annotations

from collections.abc import Callable

from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceBatchPersistenceResult,
    EvidenceBatchRepository,
    PreparedEvidenceBatch,
    UnitOfWork,
    validate_evidence_batch_size,
)
from agentic_threat_investigator.telemetry.decorators import telemetry_operation
from agentic_threat_investigator.telemetry.metrics import DurationMetrics
from agentic_threat_investigator.telemetry.tracing import SpanNames

EVIDENCE_BATCH_DEFAULT_SIZE = 100
"""Default bounded consumer poll size for one processed Evidence batch (PR 28E)."""

EVIDENCE_BATCH_HARD_LIMIT = 500
"""Hard ceiling every layer (consumer, service, adapter, SQL API) enforces."""


class EvidenceBatchPersistenceService:
    """Persist one complete prepared Evidence batch atomically.

    Owns the UnitOfWork boundary only: the repository never commits, and
    preparation/extraction never run inside the transaction. The commit
    completes during ``async with`` exit, before ``persist`` returns.
    """

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        hard_limit: int = EVIDENCE_BATCH_HARD_LIMIT,
    ) -> None:
        """Bind the service to a UnitOfWork factory and the hard ceiling."""
        if (
            not isinstance(hard_limit, int)
            or isinstance(hard_limit, bool)
            or hard_limit <= 0
        ):
            raise ValueError("evidence batch hard limit must be a positive integer")
        self._uow_factory = uow_factory
        self._hard_limit = hard_limit

    @property
    def hard_limit(self) -> int:
        """Return the configured hard ceiling."""
        return self._hard_limit

    @telemetry_operation(
        span_name=SpanNames.EVIDENCE_PERSIST,
        duration_metric=DurationMetrics.EVIDENCE_PERSIST,
    )
    async def persist(
        self, prepared: PreparedEvidenceBatch
    ) -> EvidenceBatchPersistenceResult:
        """Validate the size, then persist the complete batch in one transaction.

        The PostgreSQL commit completes before this method returns; the
        caller must not acknowledge the broker batch before this call
        succeeds.
        """
        validate_evidence_batch_size(prepared, self._hard_limit)
        async with self._uow_factory() as uow:
            repository: EvidenceBatchRepository = uow.evidence_batches
            return await repository.persist_batch(prepared)
