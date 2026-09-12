# SPDX-License-Identifier: AGPL-3.0-only
"""Async persistence contracts owned by the application layer.

Repository interfaces declare only the operations their resource supports;
narrow single-operation interfaces are intentional.
"""

# Filtered audit listing deliberately exposes several independent query fields.

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import TracebackType
from typing import Self
from urllib.parse import urlsplit
from uuid import UUID

from agentic_threat_investigator.domain.assessment import Assessment
from agentic_threat_investigator.domain.audit import AuditEvent, AuditOutcome
from agentic_threat_investigator.domain.documents import Document, DocumentChunk
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.identity import Credential, Session, User
from agentic_threat_investigator.domain.investigation import (
    CoordinatorTransitionKind,
    InvestigationBudget,
    InvestigationState,
    InvestigationStatus,
)
from agentic_threat_investigator.domain.investigation_job import (
    InvestigationJob,
    InvestigationJobStatus,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)
from agentic_threat_investigator.domain.report import InvestigationReport
from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.domain.source import SourceRecord


class BatchOutcome(str, Enum):
    """Classification returned by a database batch write."""

    INSERTED = "INSERTED"
    UPDATED = "UPDATED"
    UNCHANGED = "UNCHANGED"
    CONFLICT = "CONFLICT"


class BatchSizeLimitExceededError(ValueError):
    """Raised when a batch exceeds the configured application limit."""


class InvestigationNotFoundError(LookupError):
    """Raised when an investigation resource is absent or soft-deleted."""


class InvestigationDuplicateIdentityError(ValueError):
    """Raised when an investigation identity already exists."""

    def __init__(self, investigation_id: UUID) -> None:
        """Record the conflicting investigation identity."""
        super().__init__(f"investigation already exists: {investigation_id}")
        self.investigation_id = investigation_id


class CoordinatorTransitionPersistenceError(RuntimeError):
    """A coordinator transition was rejected by durable persistence."""


class InvestigationVersionConflictError(RuntimeError):
    """Raised when a stale expected_version must not silently overwrite state."""

    def __init__(self, investigation_id: UUID, expected_version: int) -> None:
        """Record the conflicting investigation identity and expectation."""
        super().__init__(
            f"investigation version conflict: {investigation_id} "
            f"expected version {expected_version}"
        )
        self.investigation_id = investigation_id
        self.expected_version = expected_version


class InvestigationJobNotFoundError(LookupError):
    """Raised when a durable investigation job is absent."""


class InvestigationJobNotClaimedError(RuntimeError):
    """Raised when a worker completes a job it never claimed."""


class InvestigationJobDuplicateError(ValueError):
    """Raised when a second job is created for one Investigation."""

    def __init__(self, investigation_id: UUID) -> None:
        """Record the conflicting investigation identity."""
        super().__init__(f"investigation job already exists: {investigation_id}")
        self.investigation_id = investigation_id


class InvestigationJobInvalidTransitionError(ValueError):
    """Raised when a job status change violates the job lifecycle."""


class EvidenceDuplicateIdentityError(ValueError):
    """Raised when an evidence identity already exists; never an update."""

    def __init__(self, evidence_id: UUID) -> None:
        """Record the conflicting evidence identity."""
        super().__init__(f"evidence observation already exists: {evidence_id}")
        self.evidence_id = evidence_id


class AssessmentDuplicateIdentityError(ValueError):
    """Raised when an assessment analytical version already exists."""

    def __init__(self, assessment_id: UUID) -> None:
        """Record the conflicting assessment identity."""
        super().__init__(f"assessment already exists: {assessment_id}")
        self.assessment_id = assessment_id


class AssessmentSizeLimitExceededError(ValueError):
    """Raised when an Assessment candidate collection exceeds the configured limit.

    The message reports only the collection name, the count, and the limit;
    it never includes Finding statements, Evidence payloads, summary text,
    or any other analytical content.
    """

    def __init__(self, collection: str, count: int, limit: int) -> None:
        """Record the oversized collection identity and its count."""
        super().__init__(f"assessment {collection} size {count} exceeds limit {limit}")
        self.collection = collection
        self.count = count
        self.limit = limit


ASSESSMENT_BOUNDED_COLLECTIONS = (
    "analyzed_evidence_ids",
    "findings",
    "finding_support",
    "limitations",
    "unresolved_questions",
    "recommended_next_steps",
)
"""The candidate collections independently bounded by the Assessment limit."""


def assessment_collection_sizes(assessment: Assessment) -> dict[str, int]:
    """Return the size of every bounded Assessment candidate collection."""
    return {
        "analyzed_evidence_ids": len(assessment.analyzed_evidence_ids),
        "findings": len(assessment.findings),
        "finding_support": sum(len(finding.support) for finding in assessment.findings),
        "limitations": len(assessment.limitations),
        "unresolved_questions": len(assessment.unresolved_questions),
        "recommended_next_steps": len(assessment.recommended_next_steps),
    }


def enforce_assessment_collection_bounds(assessment: Assessment, limit: int) -> None:
    """Reject any bounded Assessment candidate collection above the limit.

    Shared by the application service (before the UnitOfWork and any
    provenance read) and the PostgreSQL repository (before SQL serialization
    and execution), so oversized aggregates are rejected untouched with only
    the collection name, count, and limit reported.
    """
    for collection, count in assessment_collection_sizes(assessment).items():
        if count > limit:
            raise AssessmentSizeLimitExceededError(collection, count, limit)


class AssessmentCurrentReferenceConflictError(LookupError):
    """Raised when deleting the current Assessment of a visible Investigation.

    Approved PR 20A deletion policy: a soft deletion is rejected while any
    visible Investigation still points at the Assessment, so a visible
    Investigation can never retain a pointer to a deleted/invisible
    Assessment.
    """

    def __init__(self, assessment_id: UUID) -> None:
        """Record the referenced current Assessment identity."""
        super().__init__(
            f"assessment is the current assessment of a visible investigation: "
            f"{assessment_id}"
        )
        self.assessment_id = assessment_id


class InvestigationReportDuplicateIdentityError(ValueError):
    """Raised when a report identity already exists; never an update."""

    def __init__(self, report_id: UUID) -> None:
        """Record the conflicting report identity."""
        super().__init__(f"investigation report already exists: {report_id}")
        self.report_id = report_id


class StaleReportInputError(RuntimeError):
    """Raised when a report's Assessment ceased to be current before commit.

    The report append revalidates under the locked Investigation row that
    ``investigation.assessment_id`` still equals the report's
    ``assessment_id``; a mismatch means the input snapshot is stale and the
    caller must regenerate from fresh inputs. No report row, history, or
    pointer update is committed.
    """

    def __init__(self, investigation_id: UUID, assessment_id: UUID) -> None:
        """Record the stale Investigation/Assessment identities."""
        super().__init__(
            f"report input is stale: investigation {investigation_id} no longer "
            f"points at assessment {assessment_id}"
        )
        self.investigation_id = investigation_id
        self.assessment_id = assessment_id


class ReportReferenceInvalidError(LookupError):
    """Raised when an Investigation report pointer cannot be set.

    The target report is missing, invisible, or belongs to another
    Investigation; the pointer mutation is rejected with no partial change.
    """

    def __init__(self, investigation_id: UUID, report_id: UUID) -> None:
        """Record the conflicting Investigation/report identities."""
        super().__init__(
            f"report reference is invalid for investigation "
            f"{investigation_id}: {report_id}"
        )
        self.investigation_id = investigation_id
        self.report_id = report_id


class ReportCurrentReferenceConflictError(LookupError):
    """Raised when deleting the current report of a visible Investigation.

    Approved PR 23B deletion policy mirrors Assessment: a soft deletion is
    rejected while any visible Investigation still points at the report, so a
    visible Investigation can never retain a pointer to a deleted report.
    """

    def __init__(self, report_id: UUID) -> None:
        """Record the referenced current report identity."""
        super().__init__(
            f"report is the current report of a visible investigation: {report_id}"
        )
        self.report_id = report_id


class ReportCollectionLimitExceededError(ValueError):
    """Raised when a report candidate collection exceeds the configured limit.

    The message reports only the collection name, the count, and the limit;
    it never includes narrative text, finding statements, claim text,
    citations, or source payloads.
    """

    def __init__(self, collection: str, count: int, limit: int) -> None:
        """Record the oversized collection identity and its count."""
        super().__init__(f"report {collection} size {count} exceeds limit {limit}")
        self.collection = collection
        self.count = count
        self.limit = limit


REPORT_BOUNDED_COLLECTIONS = (
    "executive_summary",
    "narrative_support",
    "findings",
    "finding_support",
    "research_context",
    "research_citations",
    "limitations",
    "unresolved_questions",
    "recommended_next_steps",
    "source_evidence_ids",
    "source_relationship_observation_ids",
    "source_research_result_ids",
)
"""The candidate collections independently bounded by the report limit."""


def report_collection_sizes(report: InvestigationReport) -> dict[str, int]:
    """Return the size of every bounded report candidate collection."""
    return {
        "executive_summary": len(report.executive_summary),
        "narrative_support": sum(
            len(statement.support) for statement in report.executive_summary
        ),
        "findings": len(report.findings),
        "finding_support": sum(len(finding.support) for finding in report.findings),
        "research_context": len(report.research_context),
        "research_citations": sum(
            len(snapshot.citations) for snapshot in report.research_context
        ),
        "limitations": len(report.limitations),
        "unresolved_questions": len(report.unresolved_questions),
        "recommended_next_steps": len(report.recommended_next_steps),
        "source_evidence_ids": len(report.source_evidence_ids),
        "source_relationship_observation_ids": len(
            report.source_relationship_observation_ids
        ),
        "source_research_result_ids": len(report.source_research_result_ids),
    }


def enforce_report_collection_bounds(report: InvestigationReport, limit: int) -> None:
    """Reject any bounded report candidate collection above the limit.

    Shared by the application persistence service (before the UnitOfWork and
    any SQL serialization) and the PostgreSQL repository, so oversized
    aggregates are rejected untouched with only the collection name, count,
    and limit reported.
    """
    for collection, count in report_collection_sizes(report).items():
        if count > limit:
            raise ReportCollectionLimitExceededError(collection, count, limit)


class ResearchResultDuplicateIdentityError(ValueError):
    """Raised when an immutable ResearchResult identity already exists."""

    def __init__(self, result_id: UUID) -> None:
        """Record the conflicting research-result identity."""
        super().__init__(f"research result already exists: {result_id}")
        self.result_id = result_id


class ResearchResultReferenceError(LookupError):
    """Raised when a ResearchResult references an unknown Investigation/Entity.

    ResearchResults are append-only contextual artifacts; a reference that
    cannot be resolved to a visible Investigation or Entity is rejected
    rather than persisted with a dangling root.
    """


class SoftDeletedIdentityError(ValueError):
    """Raised when a soft-deleted stable identity is rediscovered.

    The approved PR 18C policy is fail-closed: new observations never attach
    to a deleted graph object, no second canonical row is created, and no
    silent restore occurs. Recovery requires an explicit, separately reviewed
    governance action rather than a persistence-time decision.
    """

    def __init__(self, object_type: str, object_id: UUID) -> None:
        """Record the deleted object type and identity."""
        super().__init__(f"soft-deleted {object_type} rediscovered: {object_id}")
        self.object_type = object_type
        self.object_id = object_id


@dataclass(frozen=True)
class IdempotencyRecord:
    """One durable actor-scoped idempotency record (PR 23C).

    ``key_hash`` is the SHA-256 digest of the raw Idempotency-Key; the raw
    key is never persisted. ``request_fingerprint`` is the canonical SHA-256
    of the semantic normalized request, so equivalent replays resolve to the
    same resource while a semantically different request with the same key
    fails closed.
    """

    actor_id: UUID
    operation: str
    key_hash: bytes
    request_fingerprint: str
    resource_type: str
    resource_id: UUID
    created_at: datetime
    id: UUID | None = None

    def __post_init__(self) -> None:
        """Reject blank identities and malformed fingerprint/key digests."""
        if not self.operation.strip():
            raise ValueError("idempotency operation must not be blank")
        if not self.resource_type.strip():
            raise ValueError("idempotency resource_type must not be blank")
        if len(self.key_hash) != 32:
            raise ValueError("idempotency key_hash must be a SHA-256 digest")
        if len(self.request_fingerprint) != 64 or any(
            char not in "0123456789abcdef" for char in self.request_fingerprint
        ):
            raise ValueError("idempotency fingerprint must be a SHA-256 hex digest")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("idempotency created_at must be timezone-aware")


class IdempotencyRepository(ABC):  # pragma: no cover
    """Repository for durable actor-scoped idempotency records.

    Race safety is owned by the database: ``insert_if_absent`` relies on the
    unique ``(actor_id, operation, key_hash)`` constraint so concurrent
    identical submissions resolve to exactly one record and one resource.
    """

    @abstractmethod
    async def insert_if_absent(
        self, record: IdempotencyRecord
    ) -> IdempotencyRecord | None:
        """Insert unless the actor/operation/key scope already exists.

        Returns the inserted record, or ``None`` when the unique scope is
        already present (committed or in-flight). The caller then re-reads
        the existing record and compares fingerprints.
        """

    @abstractmethod
    async def get(
        self, *, actor_id: UUID, operation: str, key_hash: bytes
    ) -> IdempotencyRecord | None:
        """Return the existing record for one actor/operation/key scope."""


@dataclass(frozen=True)
class EntityBatchItem:
    """An entity and its optional optimistic-concurrency expectation."""

    entity: Entity
    expected_version: int | None = None


@dataclass(frozen=True)
class EntityBatchResult:
    """Authoritative result for one item in an entity batch."""

    ordinal: int
    entity_id: UUID
    version: int
    outcome: BatchOutcome


@dataclass(frozen=True)
class SourceRecordBatchItem:
    """One normalized source record and optional optimistic expectation."""

    record: SourceRecord
    expected_version: int | None = None


@dataclass(frozen=True)
class SourceRecordBatchResult:
    """Authoritative database result correlated by input ordinal."""

    ordinal: int
    record_id: UUID
    version: int
    outcome: BatchOutcome


@dataclass(frozen=True)
class IngestionCheckpoint:
    """Opaque resumable progress scoped to one artifact and normalizer."""

    source_id: str
    artifact_uri: str
    normalization_version: int
    checkpoint: str | None
    complete: bool = False

    def __post_init__(self) -> None:
        """Reject unsafe or ambiguous operational checkpoint identities."""
        if not self.source_id.strip():
            raise ValueError("checkpoint source_id must not be blank")
        parsed = urlsplit(self.artifact_uri)
        if (
            not parsed.scheme
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError(
                "checkpoint artifact_uri must be absolute and credential-free"
            )
        if self.normalization_version < 1:
            raise ValueError("checkpoint normalization_version must be positive")
        if self.checkpoint is not None and not self.checkpoint:
            raise ValueError("checkpoint value must not be blank")


@dataclass(frozen=True)
class InvestigationWriteResult:
    """Authoritative database result for one investigation mutation."""

    investigation_id: UUID
    version: int
    outcome: BatchOutcome


@dataclass(frozen=True)
class DocumentBatchItem:
    """One document and optional optimistic expectation."""

    document: Document
    expected_version: int | None = None


@dataclass(frozen=True)
class DocumentBatchResult:
    """Database result for one document ordinal."""

    ordinal: int
    document_id: UUID
    version: int
    outcome: BatchOutcome


@dataclass(frozen=True)
class DocumentChunkBatchItem:
    """One embedded chunk submitted for replacement."""

    chunk: DocumentChunk


@dataclass(frozen=True)
class DocumentChunkBatchResult:
    """Database result for one chunk ordinal."""

    ordinal: int
    chunk_id: UUID
    version: int
    outcome: BatchOutcome


class DocumentRepository(ABC):
    """Repository for versioned narrative documents."""

    @abstractmethod
    async def upsert_batch(
        self, items: Sequence[DocumentBatchItem]
    ) -> list[DocumentBatchResult]:
        """Persist a bounded batch through the canonical database function."""

    @abstractmethod
    async def get_by_identity(
        self, source_id: str, source_record_id: str
    ) -> Document | None:
        """Return a visible document by durable source identity."""


class DocumentChunkRepository(ABC):
    """Repository for replaceable document chunks."""

    @abstractmethod
    async def replace_batch(
        self, document_ids: Sequence[UUID], items: Sequence[DocumentChunkBatchItem]
    ) -> list[DocumentChunkBatchResult]:
        """Physically replace complete chunk sets for the supplied documents."""

    @abstractmethod
    async def list_by_document(self, document_id: UUID) -> list[DocumentChunk]:
        """Return current chunks in sequence order."""


class ResearchResultRepository(ABC):  # pragma: no cover
    """Append-only repository for immutable contextual research results.

    A persisted ResearchResult is never updated or deleted: repeat research
    executions create a new result rather than mutating a prior one. There
    is deliberately no update/delete/soft_delete operation.
    """

    @abstractmethod
    async def add(self, result: ResearchResult) -> None:
        """Insert one immutable research result in the caller's transaction.

        A duplicate identity is rejected with a typed error and never
        becomes an update of a prior result.
        """

    @abstractmethod
    async def get_by_id(self, result_id: UUID) -> ResearchResult | None:
        """Return one research result with its exact claims and citations."""

    @abstractmethod
    async def list_by_investigation(
        self, investigation_id: UUID
    ) -> list[ResearchResult]:
        """Return an investigation's results in deterministic order."""


class SourceRecordRepository(ABC):
    """Repository for normalized source records."""

    @abstractmethod
    async def upsert_batch(
        self, items: Sequence[SourceRecordBatchItem]
    ) -> list[SourceRecordBatchResult]:
        """Persist a bounded batch through the canonical database function."""

    @abstractmethod
    async def get_by_identity(
        self, source_id: str, source_record_id: str
    ) -> SourceRecord | None:
        """Return the current record for an external source identity."""

    @abstractmethod
    async def get_by_id(self, record_id: UUID) -> SourceRecord | None:
        """Return a current source record by its internal identifier."""


class IngestionCheckpointRepository(ABC):
    """Repository for operational ingestion progress."""

    @abstractmethod
    async def get(
        self, source_id: str, artifact_uri: str, normalization_version: int
    ) -> IngestionCheckpoint | None:
        """Read the latest checkpoint for one artifact identity."""

    @abstractmethod
    async def put(self, checkpoint: IngestionCheckpoint) -> None:
        """Store progress in the caller's transaction."""

    @abstractmethod
    async def reset(
        self, source_id: str, artifact_uri: str, normalization_version: int
    ) -> None:
        """Clear progress for exactly one artifact identity."""


class AuditEventRepository(ABC):  # pragma: no cover
    """Append-only repository for immutable audit events."""

    @abstractmethod
    async def append(self, event: AuditEvent) -> AuditEvent:
        """Append an event in the caller's transaction."""

    @abstractmethod
    async def list_events(
        self,
        *,
        actor_id: UUID | None = None,
        action: str | None = None,
        outcome: AuditOutcome | None = None,
        object_type: str | None = None,
        object_id: UUID | None = None,
        occurred_after: datetime | None = None,
        occurred_before: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """Return bounded events matching the supplied filters."""


class InvestigationJobRepository(ABC):  # pragma: no cover
    """Repository for the durable investigation-level job (PR 23C).

    The database owns claim atomicity (``FOR UPDATE SKIP LOCKED``) and the
    lifecycle transitions through the versioned SQL functions; this
    repository never commits and never owns the transaction lifecycle.
    """

    @abstractmethod
    async def create(self, job: InvestigationJob) -> InvestigationJob:
        """Create one durable pending job in the caller's transaction.

        A second job for the same Investigation is rejected with a typed
        conflict and never becomes an update.
        """

    @abstractmethod
    async def get_by_investigation(
        self, investigation_id: UUID
    ) -> InvestigationJob | None:
        """Return the durable job of one Investigation, if any."""

    @abstractmethod
    async def claim_next(self, claimed_at: datetime) -> InvestigationJob | None:
        """Atomically claim the oldest pending job, if any.

        Concurrent workers claim distinct jobs; an empty queue returns
        ``None``.
        """

    @abstractmethod
    async def complete(
        self,
        job_id: UUID,
        status: InvestigationJobStatus,
        completed_at: datetime,
        error_code: str | None = None,
    ) -> InvestigationJob:
        """Complete a claimed job as succeeded or failed.

        A missing or unclaimed job is rejected with a typed error.
        """


class InvestigationTimelineRepository(ABC):  # pragma: no cover
    """Append-only repository for analyst-facing investigation timeline events.

    Timeline events are immutable: no update or delete operation exists.
    """

    @abstractmethod
    async def append(self, event: InvestigationTimelineEvent) -> None:
        """Append one event in the caller's transaction without committing."""

    @abstractmethod
    async def list_by_investigation(
        self, investigation_id: UUID
    ) -> list[InvestigationTimelineEvent]:
        """Return an investigation's events in chronological deterministic order."""


class EntityRepository(ABC):  # pragma: no cover
    """Repository for canonical, soft-deletable entities."""

    @abstractmethod
    async def get_by_identity(
        self, entity_type: str, canonical_value: str, *, include_deleted: bool = False
    ) -> Entity | None:
        """Return the entity with the given canonical identity, if visible."""

    @abstractmethod
    async def get_by_id(
        self, entity_id: UUID, *, include_deleted: bool = False
    ) -> Entity | None:
        """Return the visible entity with the given identifier, if any."""

    @abstractmethod
    async def upsert(
        self, entity: Entity, *, expected_version: int | None = None
    ) -> Entity:
        """Create or update the entity and return it with its allocated version."""

    @abstractmethod
    async def upsert_batch(
        self, items: Sequence[EntityBatchItem]
    ) -> list[EntityBatchResult]:
        """Persist a bounded entity batch through the database batch function."""

    @abstractmethod
    async def soft_delete(
        self,
        entity_id: UUID,
        *,
        actor_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Entity:
        """Soft-delete the entity and return its post-deletion state."""


class RelationshipRepository(ABC):  # pragma: no cover
    """Repository for stable relationship identities."""

    @abstractmethod
    async def get_by_id(
        self, relationship_id: UUID, *, include_deleted: bool = False
    ) -> Relationship | None:
        """Return the visible relationship with the given identifier, if any."""

    @abstractmethod
    async def get_by_identity(
        self,
        source_entity_id: UUID,
        relationship_type: str,
        target_entity_id: UUID,
        *,
        include_deleted: bool = False,
    ) -> Relationship | None:
        """Return the relationship with the given edge identity, if visible."""

    @abstractmethod
    async def upsert(
        self, relationship: Relationship, *, expected_version: int | None = None
    ) -> Relationship:
        """Create or update the relationship and return its allocated version."""

    @abstractmethod
    async def soft_delete(
        self,
        relationship_id: UUID,
        *,
        actor_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Relationship:
        """Soft-delete the relationship and return its post-deletion state."""


class RelationshipObservationRepository(ABC):  # pragma: no cover
    """Append-only relationship observation repository."""

    @abstractmethod
    async def append(
        self, observation: RelationshipObservation
    ) -> RelationshipObservation:
        """Append a new immutable observation row."""

    @abstractmethod
    async def get_by_id(self, observation_id: UUID) -> RelationshipObservation | None:
        """Return an immutable observation by its identity."""

    @abstractmethod
    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RelationshipObservation]:
        """Return bounded observations backed by the Investigation's Evidence.

        Every returned observation resolves to Evidence belonging to the
        supplied Investigation, so the Evidence Analyst never sees
        observations rendered from another Investigation's Evidence. Ordering
        is deterministic by retrieved/observed time with a stable UUID
        tie-breaker.
        """


class EvidenceRepository(ABC):  # pragma: no cover
    """Append-only evidence repository; immutable observations."""

    @abstractmethod
    async def insert(
        self,
        evidence: Evidence,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> Evidence:
        """Insert a new immutable evidence observation.

        A duplicate evidence identity is rejected with a typed error and
        never becomes an update of a prior observation.
        """

    @abstractmethod
    async def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        """Return an evidence observation by its immutable identity."""

    @abstractmethod
    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Evidence]:
        """Return bounded observations in deterministic newest-first order."""


class InvestigationRepository(ABC):  # pragma: no cover
    """Repository for the mutable, versioned investigation resource.

    The database allocates versions and writes immutable history; this
    repository never commits and never owns the transaction lifecycle.
    """

    @abstractmethod
    async def create(
        self,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> InvestigationWriteResult:
        """Create the resource and return its database-assigned version."""

    @abstractmethod
    async def get_by_id(
        self, investigation_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationState | None:
        """Return the visible investigation resource, if any."""

    @abstractmethod
    async def update_assessment_reference(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Point the investigation at its current/final Assessment version.

        The pointer lives in the operational state of the mutable
        investigation resource; a stale expected version or a reference to an
        Assessment that does not belong to the investigation produces a typed
        conflict with no partial mutation.
        """

    @abstractmethod
    async def update_report_reference(
        self,
        investigation_id: UUID,
        report_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Point the investigation at its current/final report version (PR 23B).

        The pointer lives in the operational state of the mutable
        investigation resource and is advanced only after the report row
        itself has been durably inserted in the same transaction. A stale
        expected version or a reference to a report that does not belong to
        the investigation produces a typed conflict with no partial mutation.
        """

    @abstractmethod
    async def set_analysis_result(
        self,
        investigation_id: UUID,
        assessment_id: UUID,
        analyzed_evidence_ids: list[UUID],
        disposition: object,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
    ) -> InvestigationWriteResult:
        """Atomically record one coherent analysis result (PR 21).

        A single Investigation version/history row records the current
        Assessment pointer, the exact ordered analyzed Evidence identities,
        and the typed disposition. The database verifies the Assessment is
        visible and belongs to the Investigation, that the supplied analyzed
        IDs exactly equal the Assessment's persisted analyzed IDs and all
        belong to the Investigation, and that the disposition is a bounded
        enum value. ``disposition`` is a bounded ``AnalysisDisposition``
        value serialized as its enum value.
        """

    @abstractmethod
    async def update_budget(
        self,
        investigation_id: UUID,
        budget: InvestigationBudget,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Replace the budget under version/history semantics.

        The database validates the supplied budget (nonnegative counters,
        consumed counters within limits), allocates the version, and writes
        immutable history atomically. A semantically identical budget is an
        UNCHANGED no-op that consumes neither a revision nor history.
        """

    @abstractmethod
    async def update_status(
        self,
        investigation_id: UUID,
        status: InvestigationStatus,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Change the status with database-owned version/history semantics."""

    @abstractmethod
    async def update_coordinator_state(
        self,
        investigation_id: UUID,
        transition_kind: CoordinatorTransitionKind,
        state: InvestigationState,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int,
        consumes_replan: bool = False,
    ) -> InvestigationWriteResult:
        """Atomically persist coordinator operational state (PR 21).

        The transition kind bounds the allowed field/counter changes, the
        optimistic ``expected_version`` must be supplied, and the state must
        belong to the target investigation. One versioned mutation with
        immutable history replaces the operational JSON document (pivots,
        queued provider work, research markers, traversal metadata,
        analyzed-evidence/disposition state), the budget, and the status. The
        database revalidates budget monotonicity and maxima and the status
        lifecycle, allocates the version, and sets terminal timestamps
        (``completed_at``) when the transition is terminal. A semantically
        identical state is an UNCHANGED no-op that consumes neither a
        revision nor history.
        """

    @abstractmethod
    async def soft_delete(
        self,
        investigation_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationWriteResult:
        """Soft-delete the resource and return its post-deletion version."""


class AssessmentRepository(ABC):  # pragma: no cover
    """Repository for versioned, insert-only analytical Assessment outputs.

    A later analysis creates a new persisted Assessment row rather than
    silently mutating a prior conclusion; there is deliberately no
    update-in-place operation.
    """

    @abstractmethod
    async def insert(
        self,
        assessment: Assessment,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> Assessment:
        """Persist a new Assessment version and return it with database metadata.

        A duplicate assessment identity or any malformed/cross-investigation
        support reference is a typed error and mutates nothing.
        """

    @abstractmethod
    async def get_by_id(
        self, assessment_id: UUID, *, include_deleted: bool = False
    ) -> Assessment | None:
        """Return the visible Assessment with its exact Findings and supports."""

    @abstractmethod
    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Assessment]:
        """Return bounded Assessments in deterministic newest-first order."""

    @abstractmethod
    async def soft_delete(
        self,
        assessment_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Assessment:
        """Soft-delete the Assessment and return its post-deletion state.

        Deletion is rejected with a typed conflict while any visible
        Investigation still points at the Assessment.
        """


class InvestigationReportRepository(ABC):  # pragma: no cover
    """Repository for versioned, insert-only report outputs (PR 23B).

    A later report generation creates a new persisted report row rather than
    silently mutating a prior report; there is deliberately no
    update-in-place operation. The database owns version allocation and
    immutable history.
    """

    @abstractmethod
    async def append(
        self,
        report: InvestigationReport,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
    ) -> InvestigationReport:
        """Persist a new report version and return it with database metadata.

        A duplicate report identity, a stale Assessment, an oversized
        candidate, or any cross-investigation reference is a typed error and
        mutates nothing.
        """

    @abstractmethod
    async def get_by_id(
        self, report_id: UUID, *, include_deleted: bool = False
    ) -> InvestigationReport | None:
        """Return the visible report with its exact nested snapshots."""

    @abstractmethod
    async def soft_delete(
        self,
        report_id: UUID,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> InvestigationReport:
        """Soft-delete the report and return its post-deletion state.

        Deletion is rejected with a typed conflict while any visible
        Investigation still points at the report.
        """


class UserRepository(ABC):  # pragma: no cover
    """Repository for local users."""

    @abstractmethod
    async def create(self, user: User) -> User:
        """Create a user."""

    @abstractmethod
    async def get_by_username(self, username: str) -> User | None:
        """Find a normalized, non-deleted user."""

    @abstractmethod
    async def get_by_id(self, user_id: UUID) -> User | None:
        """Find a user by identifier."""

    @abstractmethod
    async def count(self) -> int:
        """Return the number of users, including soft-deleted users."""

    @abstractmethod
    async def count_enabled_admins(self, *, excluding: UUID | None = None) -> int:
        """Count enabled, non-deleted administrators transactionally."""


class CredentialRepository(ABC):  # pragma: no cover
    """Repository for password credentials."""

    @abstractmethod
    async def create(
        self, user_id: UUID, password_hash: str, changed_at: datetime
    ) -> Credential:
        """Create a password credential."""

    @abstractmethod
    async def replace(
        self, user_id: UUID, password_hash: str, changed_at: datetime
    ) -> Credential:
        """Replace a password credential."""

    @abstractmethod
    async def get_by_user_id(self, user_id: UUID) -> Credential | None:
        """Return a user's credential."""


class SessionRepository(ABC):  # pragma: no cover
    """Repository for revocable sessions."""

    @abstractmethod
    async def create(self, session: Session) -> Session:
        """Persist a session."""

    @abstractmethod
    async def get_by_token_hash(self, token_hash: bytes) -> Session | None:
        """Find a session by its token digest."""

    @abstractmethod
    async def revoke(self, session_id: UUID) -> None:
        """Revoke a session."""

    @abstractmethod
    async def revoke_by_token_hash(self, token_hash: bytes) -> None:
        """Revoke a session by token digest."""

    @abstractmethod
    async def revoke_by_user_id(self, user_id: UUID) -> None:
        """Revoke every active session belonging to a user."""

    @abstractmethod
    async def touch(self, session_id: UUID, seen_at: datetime) -> None:
        """Update last-seen metadata."""


class UnitOfWork(ABC):  # pragma: no cover
    """Transaction boundary; repositories never commit themselves."""

    entities: EntityRepository
    relationships: RelationshipRepository
    relationship_observations: RelationshipObservationRepository
    evidence: EvidenceRepository
    investigations: InvestigationRepository
    assessments: AssessmentRepository
    investigation_reports: InvestigationReportRepository
    users: UserRepository
    credentials: CredentialRepository
    sessions: SessionRepository
    audit_events: AuditEventRepository
    source_records: SourceRecordRepository
    ingestion_checkpoints: IngestionCheckpointRepository
    documents: DocumentRepository
    document_chunks: DocumentChunkRepository
    research_results: ResearchResultRepository
    timeline_events: InvestigationTimelineRepository
    investigation_jobs: InvestigationJobRepository
    idempotency: IdempotencyRepository

    @abstractmethod
    async def __aenter__(self) -> Self:
        """Begin a unit of work and expose its repositories."""

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Commit on success and roll back when the block raised."""

    @abstractmethod
    async def commit(self) -> None:
        """Commit the transaction owned by this unit of work."""

    @abstractmethod
    async def rollback(self) -> None:
        """Roll back the transaction owned by this unit of work."""
