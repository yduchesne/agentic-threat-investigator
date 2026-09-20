# SPDX-License-Identifier: AGPL-3.0-only
"""Async SQLAlchemy engine, sessions, and UnitOfWork implementation."""

import asyncio
import logging
import time
from types import TracebackType
from typing import Any, Self, cast

from opentelemetry.trace import Status, StatusCode
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from agentic_threat_investigator.app.persistence import UnitOfWork
from agentic_threat_investigator.app.persistence.repositories import (
    AuditEventRepository,
    CredentialRepository,
    InvestigationTimelineRepository,
    SessionRepository,
    UserRepository,
)
from agentic_threat_investigator.config import Settings
from agentic_threat_investigator.telemetry.attributes import (
    AttributeKeys,
    validate_bounded_attributes,
)
from agentic_threat_investigator.telemetry.metrics import (
    DURATION_UNIT,
    DurationMetrics,
    Metrics,
    get_counter,
    get_histogram,
)
from agentic_threat_investigator.telemetry.tracing import SpanNames, get_tracer

from .assessment_repositories import PostgresAssessmentRepository
from .audit_repositories import PostgresAuditEventRepository
from .composites import register_batch_composites
from .datasource_log_repositories import PostgresDatasourceLogRepository
from .evidence_batch_repositories import PostgresEvidenceBatchRepository
from .evidence_repositories import (
    PostgresEvidenceObservationEntityRepository,
    PostgresEvidenceRepository,
    PostgresInvestigationEvidenceRepository,
)
from .geoint_repositories import (
    PostgresEntityLocationObservationRepository,
    PostgresEntityLocationRepository,
    PostgresGeoResolutionRepository,
    PostgresLocationRepository,
)
from .identity_repositories import (
    PostgresCredentialRepository,
    PostgresSessionRepository,
    PostgresUserRepository,
)
from .investigation_job_repositories import (
    PostgresIdempotencyRepository,
    PostgresInvestigationJobRepository,
)
from .investigation_repositories import PostgresInvestigationRepository
from .rag_repositories import (
    PostgresDocumentChunkRepository,
    PostgresDocumentRepository,
    PostgresResearchResultRepository,
)
from .relationship_repositories import (
    PostgresRelationshipObservationRepository,
    PostgresRelationshipRepository,
)
from .report_repositories import PostgresInvestigationReportRepository
from .repositories import PostgresEntityRepository
from .source_repositories import (
    PostgresIngestionCheckpointRepository,
    PostgresSourceRecordRepository,
)
from .timeline_repositories import PostgresInvestigationTimelineRepository

logger = logging.getLogger(__name__)

#: Bounded UoW outcome vocabulary recorded on the transaction-lifetime span
#: and duration histogram (PR 29A-1).
_UOW_OUTCOME_COMMIT = "commit"
_UOW_OUTCOME_ROLLBACK = "rollback"
_UOW_OUTCOME_FAILURE = "failure"
_UOW_OUTCOME_CANCELLED = "cancelled"


class PostgresUnitOfWork(UnitOfWork):
    # The UoW deliberately exposes one repository per persistence boundary.
    """Expose one SQLAlchemy transaction to all repositories."""

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession], batch_size: int = 100
    ) -> None:
        self._session_factory = session_factory
        self._batch_size = batch_size
        # Transaction-lifetime telemetry state (PR 29A-1). The span starts only
        # after ``session.begin()`` succeeds and ends after commit/rollback
        # completes, so it measures transaction lifetime, never entry or
        # session-close cleanup.
        self._uow_span_cm: Any | None = None
        self._uow_span: Any | None = None
        self._uow_start: float | None = None
        self.session: AsyncSession | None = None
        self.entities = cast(PostgresEntityRepository, None)
        self.relationships = cast(PostgresRelationshipRepository, None)
        self.relationship_observations = cast(
            PostgresRelationshipObservationRepository, None
        )
        self.evidence = cast(PostgresEvidenceRepository, None)
        self.evidence_observation_entities = cast(
            PostgresEvidenceObservationEntityRepository, None
        )
        self.investigation_evidence = cast(
            PostgresInvestigationEvidenceRepository, None
        )
        self.investigations = cast(PostgresInvestigationRepository, None)
        self.assessments = cast(PostgresAssessmentRepository, None)
        self.investigation_reports = cast(PostgresInvestigationReportRepository, None)
        self.users = cast(UserRepository, None)
        self.credentials = cast(CredentialRepository, None)
        self.sessions = cast(SessionRepository, None)
        self.audit_events = cast(AuditEventRepository, None)
        self.source_records = cast(PostgresSourceRecordRepository, None)
        self.ingestion_checkpoints = cast(PostgresIngestionCheckpointRepository, None)
        self.documents = cast(PostgresDocumentRepository, None)
        self.document_chunks = cast(PostgresDocumentChunkRepository, None)
        self.research_results = cast(PostgresResearchResultRepository, None)
        self.timeline_events = cast(InvestigationTimelineRepository, None)
        self.investigation_jobs = cast(PostgresInvestigationJobRepository, None)
        self.idempotency = cast(PostgresIdempotencyRepository, None)
        self.locations = cast(PostgresLocationRepository, None)
        self.entity_locations = cast(PostgresEntityLocationRepository, None)
        self.entity_location_observations = cast(
            PostgresEntityLocationObservationRepository, None
        )
        self.geo_resolutions = cast(PostgresGeoResolutionRepository, None)
        self.datasource_logs = cast(PostgresDatasourceLogRepository, None)
        self.evidence_batches = cast(PostgresEvidenceBatchRepository, None)

    async def __aenter__(self) -> Self:
        if self.session is not None:
            raise RuntimeError("UnitOfWork is already active")
        self.session = self._session_factory()
        await self.session.begin()
        self._begin_transaction_telemetry()
        # Session factories supplied by callers other than our engine factory
        # (notably isolated integration fixtures) still need the composite
        # adapter installed on their physical connection.
        raw_connection = await (await self.session.connection()).get_raw_connection()
        await register_batch_composites(cast(Any, raw_connection.driver_connection))
        self.entities = PostgresEntityRepository(self.session, self._batch_size)
        self.users = PostgresUserRepository(self.session)
        self.credentials = PostgresCredentialRepository(self.session)
        self.sessions = PostgresSessionRepository(self.session)
        self.relationships = PostgresRelationshipRepository(self.session)
        self.relationship_observations = PostgresRelationshipObservationRepository(
            self.session
        )
        self.evidence = PostgresEvidenceRepository(self.session)
        self.evidence_observation_entities = (
            PostgresEvidenceObservationEntityRepository(self.session)
        )
        self.investigation_evidence = PostgresInvestigationEvidenceRepository(
            self.session
        )
        self.investigations = PostgresInvestigationRepository(self.session)
        self.assessments = PostgresAssessmentRepository(self.session, self._batch_size)
        self.investigation_reports = PostgresInvestigationReportRepository(
            self.session, self._batch_size
        )
        self.audit_events = PostgresAuditEventRepository(self.session)
        self.source_records = PostgresSourceRecordRepository(
            self.session, self._batch_size
        )
        self.ingestion_checkpoints = PostgresIngestionCheckpointRepository(self.session)
        self.documents = PostgresDocumentRepository(self.session, self._batch_size)
        self.document_chunks = PostgresDocumentChunkRepository(
            self.session, self._batch_size
        )
        self.research_results = PostgresResearchResultRepository(self.session)
        self.timeline_events = PostgresInvestigationTimelineRepository(self.session)
        self.investigation_jobs = PostgresInvestigationJobRepository(self.session)
        self.idempotency = PostgresIdempotencyRepository(self.session)
        self.locations = PostgresLocationRepository(self.session)
        self.entity_locations = PostgresEntityLocationRepository(self.session)
        self.entity_location_observations = PostgresEntityLocationObservationRepository(
            self.session
        )
        self.geo_resolutions = PostgresGeoResolutionRepository(self.session)
        self.datasource_logs = PostgresDatasourceLogRepository(self.session)
        self.evidence_batches = PostgresEvidenceBatchRepository(
            self.session, self._batch_size
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        session = self.session
        if session is None:
            return
        outcome: str = _UOW_OUTCOME_FAILURE
        try:
            if exc_type is None:
                try:
                    await self._measure_transaction_operation(
                        "commit", session.commit()
                    )
                except asyncio.CancelledError:
                    outcome = _UOW_OUTCOME_CANCELLED
                    raise
                except Exception:
                    outcome = _UOW_OUTCOME_FAILURE
                    raise
                else:
                    outcome = _UOW_OUTCOME_COMMIT
            else:
                try:
                    await self._measure_transaction_operation(
                        "rollback", session.rollback()
                    )
                except asyncio.CancelledError:
                    outcome = _UOW_OUTCOME_CANCELLED
                    raise
                except Exception:
                    outcome = _UOW_OUTCOME_FAILURE
                    raise
                else:
                    outcome = (
                        _UOW_OUTCOME_CANCELLED
                        if issubclass(exc_type, asyncio.CancelledError)
                        else _UOW_OUTCOME_ROLLBACK
                    )
        finally:
            end = time.perf_counter()
            try:
                await session.close()
            finally:
                self._finish_transaction_telemetry(outcome, end)
                self.session = None
                self.entities = cast(PostgresEntityRepository, None)
            self.users = cast(PostgresUserRepository, None)
            self.credentials = cast(PostgresCredentialRepository, None)
            self.sessions = cast(PostgresSessionRepository, None)
            self.relationships = cast(PostgresRelationshipRepository, None)
            self.relationship_observations = cast(
                PostgresRelationshipObservationRepository, None
            )
            self.evidence = cast(PostgresEvidenceRepository, None)
            self.evidence_observation_entities = cast(
                PostgresEvidenceObservationEntityRepository, None
            )
            self.investigation_evidence = cast(
                PostgresInvestigationEvidenceRepository, None
            )
            self.investigations = cast(PostgresInvestigationRepository, None)
            self.assessments = cast(PostgresAssessmentRepository, None)
            self.investigation_reports = cast(
                PostgresInvestigationReportRepository, None
            )
            self.audit_events = cast(PostgresAuditEventRepository, None)
            self.source_records = cast(PostgresSourceRecordRepository, None)
            self.ingestion_checkpoints = cast(
                PostgresIngestionCheckpointRepository, None
            )
            self.documents = cast(PostgresDocumentRepository, None)
            self.document_chunks = cast(PostgresDocumentChunkRepository, None)
            self.research_results = cast(PostgresResearchResultRepository, None)
            self.timeline_events = cast(InvestigationTimelineRepository, None)
            self.investigation_jobs = cast(PostgresInvestigationJobRepository, None)
            self.idempotency = cast(PostgresIdempotencyRepository, None)
            self.locations = cast(PostgresLocationRepository, None)
            self.entity_locations = cast(PostgresEntityLocationRepository, None)
            self.entity_location_observations = cast(
                PostgresEntityLocationObservationRepository, None
            )
            self.geo_resolutions = cast(PostgresGeoResolutionRepository, None)
            self.datasource_logs = cast(PostgresDatasourceLogRepository, None)
            self.evidence_batches = cast(PostgresEvidenceBatchRepository, None)

    async def commit(self) -> None:
        """Commit the current transaction while retaining the active session."""
        if self.session is None:
            raise RuntimeError("UnitOfWork is not active")
        await self._measure_transaction_operation("commit", self.session.commit())

    async def rollback(self) -> None:
        """Roll back the current transaction."""
        if self.session is None:
            raise RuntimeError("UnitOfWork is not active")
        await self._measure_transaction_operation("rollback", self.session.rollback())

    def _begin_transaction_telemetry(self) -> None:
        """Open the transaction-lifetime span after ``begin()`` has succeeded.

        The span stays the current span for the whole UoW body, which makes
        nested repository spans deterministic children of it. Purchase-order
        invariant: repository and UoW telemetry are separate and intentionally
        nested.
        """
        try:
            span_cm = get_tracer().start_as_current_span(SpanNames.POSTGRES_UOW)
            self._uow_span = span_cm.__enter__()
            self._uow_span_cm = span_cm
            self._uow_start = time.perf_counter()
        except Exception:  # noqa: BLE001 - telemetry-owned fail-open boundary; UoW entry must never fail for telemetry
            logger.debug("UnitOfWork transaction telemetry could not start")
            self._uow_span = None
            self._uow_span_cm = None
            self._uow_start = None

    def _finish_transaction_telemetry(self, outcome: str, end: float) -> None:
        """Close the transaction-lifetime span and record outcome telemetry.

        ``end`` is captured immediately after commit/rollback completes and
        before session cleanup, so session-close time is never reported as
        transaction duration. Fail-open: any telemetry failure is logged
        safely and never changes the UoW result, exception precedence, or
        transaction behavior.
        """
        start = self._uow_start
        span_cm = self._uow_span_cm
        span = self._uow_span
        self._uow_start = None
        self._uow_span_cm = None
        self._uow_span = None
        try:
            if span is not None:
                span.set_attribute(AttributeKeys.OUTCOME, outcome)
                if outcome == _UOW_OUTCOME_FAILURE:
                    span.set_status(Status(StatusCode.ERROR))
            if span_cm is not None:
                span_cm.__exit__(None, None, None)
            if start is not None:
                duration = end - start
                outcome_attrs = validate_bounded_attributes(
                    {AttributeKeys.OUTCOME: outcome}
                )
                get_histogram(DurationMetrics.POSTGRES_UOW, unit=DURATION_UNIT).record(
                    duration, attributes=outcome_attrs
                )
                self._count_uow_outcome(outcome)
        except Exception:  # noqa: BLE001 - telemetry-owned fail-open boundary; telemetry must never mask UoW results
            logger.debug("UnitOfWork transaction telemetry could not finish")

    def _count_uow_outcome(self, outcome: str) -> None:
        """Increment the bounded UoW outcome counter for a terminal outcome."""
        if outcome == _UOW_OUTCOME_COMMIT:
            get_counter(Metrics.POSTGRES_UOW_COMMITS).add(1)
        elif outcome == _UOW_OUTCOME_ROLLBACK:
            get_counter(Metrics.POSTGRES_UOW_ROLLBACKS).add(1)
        elif outcome == _UOW_OUTCOME_FAILURE:
            get_counter(Metrics.POSTGRES_UOW_FAILURES).add(1)

    async def _measure_transaction_operation(self, operation: str, result: Any) -> None:
        """Measure one explicit COMMIT/ROLLBACK operation in seconds.

        Distinguishes a long transaction lifetime from a fast transaction with
        a slow COMMIT/ROLLBACK. Never changes transaction semantics and never
        raises for telemetry reasons.
        """
        attrs = validate_bounded_attributes(
            {AttributeKeys.POSTGRES_OPERATION: operation}
        )
        histogram = get_histogram(
            DurationMetrics.POSTGRES_TRANSACTION_OPERATION, unit=DURATION_UNIT
        )
        start = time.perf_counter()
        try:
            await result
        except asyncio.CancelledError:
            raise
        except Exception:
            try:
                histogram.record(
                    time.perf_counter() - start,
                    attributes={**attrs, AttributeKeys.OUTCOME: "failure"},
                )
            except Exception:  # noqa: BLE001 - telemetry-owned fail-open boundary; never mask the DB failure
                logger.debug("transaction operation failure telemetry failed")
            raise
        else:
            try:
                histogram.record(
                    time.perf_counter() - start,
                    attributes={**attrs, AttributeKeys.OUTCOME: "success"},
                )
            except Exception:  # noqa: BLE001 - telemetry-owned fail-open boundary; never mask the DB result
                logger.debug("transaction operation telemetry failed")


def create_engine_and_session_factory(
    settings: Settings,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    """Create the async psycopg engine and session factory."""
    url = settings.database_url.replace(
        "postgresql+psycopg://", "postgresql+psycopg_async://", 1
    )
    engine = create_async_engine(
        url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _register_composites(dbapi_connection: object, _record: object) -> None:
        """Register custom types before a pooled connection is used."""
        run_async = getattr(dbapi_connection, "run_async", None)
        if run_async is not None:
            run_async(register_batch_composites)

    return engine, async_sessionmaker(engine, expire_on_commit=False)
