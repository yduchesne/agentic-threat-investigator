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
from agentic_threat_investigator.domain.datasource import (
    DatasourceLogEvent,
)
from agentic_threat_investigator.domain.documents import Document, DocumentChunk
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservation,
    EvidenceObservationEntity,
    InvestigationEvidence,
)
from agentic_threat_investigator.domain.geoint import (
    EntityLocation,
    EntityLocationObservation,
    GeoResolution,
    Location,
)
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


class LocationReferenceOutcome(str, Enum):
    """Deterministic outcome of one canonical reference/spatial upsert (PR 26B).

    - ``CREATED``: the canonical identity did not exist and was created;
    - ``UNCHANGED``: identity and complete supplied canonical state are
      semantically identical (no version churn);
    - ``ENRICHED``: an approved previously-missing reference/spatial field
      was filled or a deterministic reference-corpus refresh changed approved
      spatial state (new database-issued version);
    - ``CONFLICT``: same canonical identity would be rebound incompatibly.
    """

    CREATED = "CREATED"
    UNCHANGED = "UNCHANGED"
    ENRICHED = "ENRICHED"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True)
class LocationWriteResult:
    """Authoritative result of one canonical reference/spatial upsert."""

    location: Location
    outcome: LocationReferenceOutcome


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
    """Raised when an evidence observation identity already exists; never an update.

    Retained for the transitional v0.1 contract; PR 28B persistence routes
    through :func:`EvidenceRepository.persist` and surfaces the typed PR 28B
    errors below.
    """

    def __init__(self, evidence_id: UUID) -> None:
        """Record the conflicting observation identity."""
        super().__init__(f"evidence observation already exists: {evidence_id}")
        self.evidence_id = evidence_id


class EvidenceMetadataConflictError(ValueError):
    """Raised when one deterministic Evidence ID carries conflicting stable metadata.

    The same stable Evidence identity can never be rebound to a different
    evidence type, source, or source-record identity (SQLSTATE ``U28B1``);
    the conflicting write is rejected with no mutation.
    """

    def __init__(self, evidence_id: UUID) -> None:
        """Record the conflicting stable Evidence identity."""
        super().__init__(f"stable evidence metadata conflict: {evidence_id}")
        self.evidence_id = evidence_id


class EvidenceObservationNotFoundError(LookupError):
    """Raised when an exact EvidenceObservation is missing (SQLSTATE ``U28B2``)."""

    def __init__(self, observation_id: UUID) -> None:
        """Record the missing observation identity."""
        super().__init__(f"evidence observation not found: {observation_id}")
        self.observation_id = observation_id


class EvidenceObservationInputError(ValueError):
    """Raised when malformed evidence-observation input is rejected database-side.

    SQLSTATE ``U28B3``: nullable identifiers, blank stable identity, or an
    impossible transition (a committed Evidence with no observation).
    """

    def __init__(self, detail: str) -> None:
        """Record the database-reported input failure detail."""
        super().__init__(f"invalid evidence observation input: {detail}")
        self.detail = detail


class InvestigationEvidenceAdmissionConflictError(ValueError):
    """Raised when an admission replay changes immutable admission metadata.

    Replaying the exact admission is an idempotent no-op; any change to
    ``inclusion_reason``/``added_by``/``discovered_from`` on replay is a
    typed conflict (SQLSTATE ``U28B5``).
    """

    def __init__(self, investigation_id: UUID, observation_id: UUID) -> None:
        """Record the conflicting admission pair."""
        super().__init__(
            f"investigation admission metadata conflict: investigation "
            f"{investigation_id} observation {observation_id}"
        )
        self.investigation_id = investigation_id
        self.observation_id = observation_id


class InvalidDiscoveredFromProvenanceError(ValueError):
    """Raised when discovered-from references an observation not admitted to the
    same Investigation (SQLSTATE ``U28B6``)."""

    def __init__(self, observation_id: UUID) -> None:
        """Record the invalid discovered-from observation identity."""
        super().__init__(
            f"invalid discovered-from provenance: observation is not admitted "
            f"to the same investigation: {observation_id}"
        )
        self.observation_id = observation_id


class EvidenceObservationEntityAssociationError(ValueError):
    """Raised when an observation/Entity association is rejected database-side.

    SQLSTATE ``U28B7``: a missing observation, or a missing or soft-deleted
    Entity. Association is idempotent for valid pairs only.
    """

    def __init__(self, observation_id: UUID, entity_id: UUID) -> None:
        """Record the rejected pair."""
        super().__init__(
            f"invalid evidence observation entity association: observation "
            f"{observation_id} entity {entity_id}"
        )
        self.observation_id = observation_id
        self.entity_id = entity_id


class RelationshipObservationProvenanceError(ValueError):
    """Raised when a RelationshipObservation references an unknown observation.

    SQLSTATE ``U28B8``: the backing EvidenceObservation must exist.
    """

    def __init__(self, observation_id: UUID) -> None:
        """Record the invalid backing observation identity."""
        super().__init__(
            f"relationship observation provenance is invalid: evidence "
            f"observation not found: {observation_id}"
        )
        self.observation_id = observation_id


class AssessmentDuplicateIdentityError(ValueError):
    """Raised when an assessment analytical version already exists."""

    def __init__(self, assessment_id: UUID) -> None:
        """Record the conflicting assessment identity."""
        super().__init__(f"assessment already exists: {assessment_id}")
        self.assessment_id = assessment_id


class AssessmentSizeLimitExceededError(ValueError):
    """Raised when an Assessment candidate collection exceeds the configured limit.

    The message reports only the collection name, the count, and the limit;
    it never includes Finding statements, LegacyEvidence payloads, summary text,
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


class GeoEntityNotFoundError(LookupError):
    """Raised when a GEOINT write references a missing or invisible Entity."""

    def __init__(self, entity_id: UUID) -> None:
        """Record the missing Entity identity."""
        super().__init__(f"geo entity not found or invisible: {entity_id}")
        self.entity_id = entity_id


class GeoLocationNotFoundError(LookupError):
    """Raised when a GEOINT write references a missing canonical Location."""

    def __init__(self, location_id: UUID | None = None) -> None:
        """Record the missing Location identity when known."""
        super().__init__(
            f"geo location not found: {location_id}"
            if location_id
            else "geo location not found"
        )
        self.location_id = location_id


class GeoEvidenceNotFoundError(LookupError):
    """Raised when a GEOINT write references a missing EvidenceObservation."""

    def __init__(self, evidence_observation_id: UUID) -> None:
        """Record the missing exact-observation identity."""
        super().__init__(
            f"geo evidence observation not found: {evidence_observation_id}"
        )
        self.evidence_observation_id = evidence_observation_id


class GeoEvidenceTypeError(ValueError):
    """Raised when the stable Evidence backing geographic work is not GEOLOCATION."""

    def __init__(self, evidence_observation_id: UUID) -> None:
        """Record the offending observation identity."""
        super().__init__(f"geo evidence is not GEOLOCATION: {evidence_observation_id}")
        self.evidence_observation_id = evidence_observation_id


class GeoEvidenceSubjectMismatchError(ValueError):
    """Raised when the exact observation is not associated with the work Entity.

    Cross-context provenance can never be fabricated: geographic observations
    and resolution work bind the exact EvidenceObservation (through
    ``evidence_observation_entity``) to the exact Entity.
    """

    def __init__(self, evidence_observation_id: UUID, entity_id: UUID) -> None:
        """Record the mismatched observation/Entity identities."""
        super().__init__(
            f"geo evidence subject mismatch: observation "
            f"{evidence_observation_id} is not about entity {entity_id}"
        )
        self.evidence_observation_id = evidence_observation_id
        self.entity_id = entity_id


class EntityLocationObservationDuplicateError(ValueError):
    """Raised when an immutable observation identity already exists."""

    def __init__(self, observation_id: UUID) -> None:
        """Record the conflicting observation identity."""
        super().__init__(
            f"entity location observation already exists: {observation_id}"
        )
        self.observation_id = observation_id


class LocationIdentityConflictError(ValueError):
    """Raised when a canonical Location identity is reused with incompatible state.

    The same canonical identity tuple can never carry a different display
    name or reference parent; the conflicting caller input is rejected with
    no version or history churn.
    """


class CanonicalLocationConflictError(ValueError):
    """Raised when the reference/spatial upsert would rebind a canonical identity.

    The canonical reference upsert (PR 26B) enriches approved spatial state
    but never rebinds the display name or reference parent of an existing
    canonical Location; a conflicting input is rejected (SQLSTATE ``U26B3``)
    with no mutation.
    """

    def __init__(self) -> None:
        """Report the generic canonical rebind conflict; no identity leaks."""
        super().__init__("canonical reference location rebind conflict")


class UnsupportedReferenceRecordError(ValueError):
    """Raised when a reference record cannot be mapped to the canonical model.

    Unsupported location types, malformed shape, or invalid bounded text on
    the reference write path fail closed (SQLSTATE ``U26B4``).
    """

    def __init__(self, detail: str | None = None) -> None:
        """Record the database-reported input failure detail when present."""
        super().__init__(
            f"unsupported reference record: {detail}"
            if detail
            else "unsupported reference record"
        )
        self.detail = detail


class InvalidReferenceHierarchyError(ValueError):
    """Raised when reference parentage is structurally invalid or unresolved.

    A non-country record requires an existing parent; countries must not have
    parents or admin codes; self-parenting is rejected (SQLSTATE ``U26B2``).
    """

    def __init__(self, detail: str | None = None) -> None:
        """Record the database-reported hierarchy failure detail when present."""
        super().__init__(
            f"invalid reference hierarchy: {detail}"
            if detail
            else "invalid reference hierarchy"
        )
        self.detail = detail


class InvalidReferenceGeometryError(ValueError):
    """Raised when supplied reference geometry is outside the spatial contract.

    Covers malformed EWKT, SRID other than 4326, empty geometry, invalid
    polygons, wrong geometry type per Location type, city canonical-point
    violations, and out-of-WGS84-bounds coordinates (SQLSTATE ``U26B1``).
    """

    def __init__(self, detail: str | None = None) -> None:
        """Record the database-reported geometry failure detail when present."""
        super().__init__(
            f"invalid reference geometry: {detail}"
            if detail
            else "invalid reference geometry"
        )
        self.detail = detail


class InvalidGeographicClaimError(ValueError):
    """Raised when a geographic claim violates the bounded claim contract.

    Claim contract violations (coordinates without a pair, non-finite or
    out-of-range coordinates, malformed country codes, precision exceeding
    the supplied semantic fields) are errors; normal no-match/ambiguity
    outcomes are results, never exceptions.
    """


class GeoResolutionDuplicateStateError(ValueError):
    """Raised when a duplicate GeoResolution pair is not in initial pending shape.

    Duplicate creation is idempotent only for the exact pair in the initial
    pending state; a progressed record can never be silently replayed as a
    new request.
    """

    def __init__(self, entity_id: UUID, evidence_id: UUID) -> None:
        """Record the conflicting work-pair identities."""
        super().__init__(
            f"geo resolution pair is not in initial pending state: "
            f"entity {entity_id} evidence {evidence_id}"
        )
        self.entity_id = entity_id
        self.evidence_id = evidence_id


class GeoInvalidInputError(ValueError):
    """Raised when a GEOINT write carries malformed input rejected database-side."""

    def __init__(self, detail: str) -> None:
        """Record the database-reported input failure detail."""
        super().__init__(f"invalid geo input: {detail}")
        self.detail = detail


class GeoResolutionNotFoundError(LookupError):
    """Raised when a GeoResolution lifecycle mutation targets an unknown row."""

    def __init__(self, resolution_id: UUID) -> None:
        """Record the missing work identity."""
        super().__init__(f"geo resolution not found: {resolution_id}")
        self.resolution_id = resolution_id


class GeoResolutionInvalidTransitionError(ValueError):
    """Raised when a lifecycle mutation is illegal for the current status.

    A completion/failure is legal only against claimed PROCESSING work; a
    PENDING row (never claimed) or a row in a status the transition may not
    exit is rejected with no mutation (SQLSTATE ``U26C2``).
    """

    def __init__(self, resolution_id: UUID, status: str | None = None) -> None:
        """Record the work identity and the offending current status when known."""
        super().__init__(
            f"invalid geo resolution transition: resolution {resolution_id} "
            f"cannot mutate in its current status"
            if status is None
            else f"invalid geo resolution transition: resolution "
            f"{resolution_id} is {status}"
        )
        self.resolution_id = resolution_id
        self.status = status


class GeoResolutionVersionConflictError(ValueError):
    """Raised when a lifecycle mutation carries a stale expected version.

    Completion/failure is an optimistic concurrency contract: the supplied
    version must equal the current database version, otherwise another
    worker already mutated the row (SQLSTATE ``U26C3``). A stale worker is
    rejected with no observation or current-state mutation.
    """

    def __init__(self, resolution_id: UUID, expected_version: int) -> None:
        """Record the work identity and the stale supplied version."""
        super().__init__(
            f"stale geo resolution version: resolution {resolution_id} "
            f"expected version {expected_version}"
        )
        self.resolution_id = resolution_id
        self.expected_version = expected_version


class GeoResolutionClaimantMismatchError(RuntimeError):
    """Raised when a lifecycle mutation is not owned by the current claimant.

    The claim owner is the ephemeral lease-holder identity; a different
    worker's completion/failure is rejected with no mutation (SQLSTATE
    ``U26C4``).
    """

    def __init__(self, resolution_id: UUID) -> None:
        """Record the work identity of the rejected mutation."""
        super().__init__(f"geo resolution claim owner mismatch: {resolution_id}")
        self.resolution_id = resolution_id


class GeoResolutionLeaseExpiredError(RuntimeError):
    """Raised when a lifecycle mutation arrives with an expired lease.

    A completed/failed mutation requires a live lease at database time; an
    expired lease means ownership already lapsed and a reclaim may be in
    flight, so the mutation is rejected (SQLSTATE ``U26C5``).
    """

    def __init__(self, resolution_id: UUID) -> None:
        """Record the work identity of the rejected mutation."""
        super().__init__(f"geo resolution lease expired: {resolution_id}")
        self.resolution_id = resolution_id


class GeoResolutionRetryExhaustedError(RuntimeError):
    """Raised when the attempt budget is already violated (defensive).

    Retry/exhaustion bookkeeping is database-authoritative and normally
    transitions exhausted work to FAILED without raising; this code is a
    fail-closed guard for a corrupt work row whose attempt count already
    exceeds the configured budget when a new claim is attempted (SQLSTATE
    ``U26C6``).
    """

    def __init__(self, resolution_id: UUID) -> None:
        """Record the work identity of the inconsistent row."""
        super().__init__(f"geo resolution retry budget violated: {resolution_id}")
        self.resolution_id = resolution_id


class GeoResolutionTerminalReplayConflictError(ValueError):
    """Raised when a terminal replay conflicts with the settled outcome.

    Replaying the exact same successful completion is an idempotent no-op
    (SQL API v0024 returns the authoritative terminal row); a terminal
    replay that disagrees with the settled outcome (for example resolving a
    RESOLVED row to a different Location, or failing a RESOLVED row) is a
    typed conflict with no mutation (SQLSTATE ``U26C7``).
    """

    def __init__(self, resolution_id: UUID) -> None:
        """Record the work identity of the conflicting replay."""
        super().__init__(f"geo resolution terminal replay conflict: {resolution_id}")
        self.resolution_id = resolution_id


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


class DatasourceLogInvalidInputError(ValueError):
    """Raised when the database rejects malformed datasource-log input.

    The database owns bounded canonical validation (SQLSTATE ``U27B1``); a
    bypassed Python model cannot smuggle invalid counts, error codes, or
    event types into the durable log.
    """


class DatasourceLogFirstEventError(ValueError):
    """Raised when an execution's first persisted event is not STARTED.

    The database enforces that STARTED is first (SQLSTATE ``U27B2``); an
    execution identity only exists after its STARTED event.
    """

    def __init__(self, execution_id: UUID) -> None:
        """Record the execution whose first event was not STARTED."""
        super().__init__(
            f"first datasource log event must be STARTED for execution {execution_id}"
        )
        self.execution_id = execution_id


class DatasourceLogDatasourceMismatchError(ValueError):
    """Raised when one execution carries two different datasource IDs.

    The database rejects a mismatched datasource identity (SQLSTATE
    ``U27B3``): all events of one execution share one datasource.
    """

    def __init__(self, execution_id: UUID, datasource_id: str | None = None) -> None:
        """Record the rejected execution and the offending datasource ID."""
        super().__init__(
            f"datasource identity mismatch for execution {execution_id}"
            + (f": {datasource_id}" if datasource_id is not None else "")
        )
        self.execution_id = execution_id
        self.datasource_id = datasource_id


class DatasourceLogDuplicateStartedError(ValueError):
    """Raised when a second STARTED event is appended for one execution.

    The database enforces one STARTED per execution (SQLSTATE ``U27B4``,
    backed by a partial unique index).
    """

    def __init__(self, execution_id: UUID) -> None:
        """Record the execution with a duplicate STARTED attempt."""
        super().__init__(f"duplicate STARTED event for execution {execution_id}")
        self.execution_id = execution_id


class DatasourceLogAppendAfterTerminalError(ValueError):
    """Raised when an event is appended after a terminal outcome.

    The database rejects any append after COMPLETED/FAILED/CANCELLED
    (SQLSTATE ``U27B5``, backed by the partial terminal unique index for
    terminal-vs-terminal races).
    """

    def __init__(self, execution_id: UUID) -> None:
        """Record the terminal execution that received a late append."""
        super().__init__(
            f"cannot append datasource log event after terminal outcome for "
            f"execution {execution_id}"
        )
        self.execution_id = execution_id


class DatasourceLogRepository(ABC):  # pragma: no cover
    """Append-only repository for immutable datasource-log events.

    One acquisition execution is correlated by its ``execution_id``; the
    database owns every lifecycle invariant (STARTED first and unique,
    datasource identity stability, at most one terminal, no append after
    terminal). There is deliberately no update, delete, search, pagination,
    or execution-CRUD operation: mutation is append-only.
    """

    @abstractmethod
    async def append(self, event: DatasourceLogEvent) -> None:
        """Append one event in the caller's transaction without committing.

        The stored function validates the event against the execution's
        durable lifecycle and rejects violations with typed errors; the
        caller's UnitOfWork remains the commit boundary.
        """


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
        """Return bounded observations backed by admitted EvidenceObservations.

        Every returned observation's backing ``evidence_observation_id`` must
        be admitted to the supplied Investigation through
        ``InvestigationEvidence``; the Investigation never infers scope from
        Evidence ownership and never sees observations backed by unadmitted
        global observations. Ordering is deterministic by retrieved/observed
        time with a stable UUID tie-breaker.
        """


class EvidencePersistenceOutcome(str, Enum):
    """Authoritative outcome of one ``EvidenceRepository.persist`` call.

    Mirrors the SQL ``ati.persist_evidence_observation`` outcome:

    - ``CREATED``: new stable Evidence plus observation version 1;
    - ``UNCHANGED``: the latest material state equals the candidate (no new
      row; the existing exact observation is returned);
    - ``APPENDED``: a material change appended the next immutable version.
    """

    CREATED = "CREATED"
    UNCHANGED = "UNCHANGED"
    APPENDED = "APPENDED"


@dataclass(frozen=True)
class EvidencePersistenceResult:
    """Authoritative PR 28B persistence result of one observation candidate.

    Carries the exact stable Evidence, the exact persisted observation, the
    per-Evidence version, and the outcome. Repositories never allocate
    versions and never self-commit.
    """

    evidence: Evidence
    observation: EvidenceObservation
    outcome: EvidencePersistenceOutcome
    version: int


class EvidenceRepository(ABC):  # pragma: no cover
    """PR 28B global Evidence persistence boundary.

    PostgreSQL owns stable Evidence validation, atomic Evidence + v1
    creation, race-safe per-Evidence version allocation, material no-op
    detection, and canonical diffs; this repository never computes
    ``latest.version + 1`` and never self-commits.
    """

    @abstractmethod
    async def persist(
        self, converted: ConvertedEvidence, *, observation_id: UUID | None = None
    ) -> EvidencePersistenceResult:
        """Persist or reuse the exact observation of one ConvertedEvidence.

        A new stable Evidence plus its first observation commits atomically;
        an unchanged material state returns the existing exact observation
        with outcome ``UNCHANGED``; a material change appends the next
        version with the canonical diff. Stable metadata conflicts raise
        :class:`EvidenceMetadataConflictError` and roll back. Evidence and
        EvidenceObservation never write generic history, so no
        actor/request correlation is accepted (audit events carry them).
        ``observation_id`` overrides the created observation identity for
        deterministic evaluation seams only; production callers leave it
        ``None`` so PostgreSQL owns observation identity.
        """

    @abstractmethod
    async def get_stable_evidence(self, evidence_id: UUID) -> Evidence | None:
        """Return the stable global Evidence with the given identity, if any."""

    @abstractmethod
    async def get_observation(self, observation_id: UUID) -> EvidenceObservation | None:
        """Return one exact EvidenceObservation by its immutable identity."""

    @abstractmethod
    async def list_observations(
        self,
        evidence_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceObservation]:
        """Return bounded observations of one stable Evidence, oldest first."""

    @abstractmethod
    async def list_for_investigation(
        self,
        investigation_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceObservation]:
        """Return the exact admitted observations of one Investigation.

        Scope comes exclusively from ``InvestigationEvidence`` admission;
        newer unadmitted global observations never appear. Ordering is
        deterministic newest-first (``retrieved_at DESC, observation id ASC``).
        """


class EvidenceObservationEntityRepository(ABC):  # pragma: no cover
    """Observation-level Entity association repository (PR 28B).

    Associations are structural many-to-many provenance with no role field;
    exact replay is idempotent.
    """

    @abstractmethod
    async def associate(
        self, observation_id: UUID, entity_id: UUID
    ) -> EvidenceObservationEntity:
        """Associate one canonical Entity with one exact observation.

        Reassociation of an existing pair is a harmless no-op; a missing
        observation or a missing/soft-deleted Entity is a typed error.
        """

    @abstractmethod
    async def list_for_observation(
        self, observation_id: UUID
    ) -> list[EvidenceObservationEntity]:
        """Return the exact associated Entities of one observation."""


class InvestigationEvidenceRepository(ABC):  # pragma: no cover
    """Append-only/idempotent exact admission repository (PR 28B).

    One Investigation may admit several observations of the same stable
    Evidence; a newer global observation never silently enters an
    Investigation.
    """

    @abstractmethod
    async def admit(self, admission: InvestigationEvidence) -> InvestigationEvidence:
        """Admit one exact observation into one Investigation.

        Replaying the exact admission is an idempotent no-op; changing
        immutable admission metadata or referencing a discovered-from
        observation that is not admitted to the same Investigation is a
        typed error with no mutation.
        """

    @abstractmethod
    async def list_for_investigation(
        self, investigation_id: UUID
    ) -> list[InvestigationEvidence]:
        """Return the exact admissions of one Investigation."""


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
        Assessment pointer, the exact ordered analyzed LegacyEvidence identities,
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


class LocationRepository(ABC):  # pragma: no cover
    """Repository for canonical geographic/reference Locations (PR 26A/26B).

    Locations are stable reference identities, not Entities. There is no
    delete or soft-delete operation: canonical reference deletion/governance
    is not part of the PR 26A foundation.
    """

    @abstractmethod
    async def get_by_id(self, location_id: UUID) -> Location | None:
        """Return the canonical Location with the given identifier, if any."""

    @abstractmethod
    async def get_by_identity(
        self,
        *,
        location_type: str,
        country_code: str,
        admin1_code: str | None,
        admin2_code: str | None,
        canonical_name: str,
    ) -> Location | None:
        """Return the canonical Location matching the approved identity tuple.

        This is the canonical-identity reader used to locate an existing
        reference row (for example during ingestion pre-validation); it is
        the same tuple as ``location_identity_tuple`` for a persisted
        :class:`Location`.
        """

    @abstractmethod
    async def upsert(self, location: Location) -> Location:
        """Create or reuse the canonical Location through the database function.

        The database owns canonical-identity resolution, race-safe creation,
        and version allocation; reuse is a semantic no-op. Incompatible state
        for the same canonical identity is a typed error.
        """

    @abstractmethod
    async def upsert_reference(self, location: Location) -> LocationWriteResult:
        """Create/enrich/reuse one canonical reference/spatial Location (PR 26B).

        Routes exclusively through ``ati.upsert_reference_location`` (SQL API
        v0023), which owns spatial validity, reference enrichment, version
        allocation, and race-safe creation. The result exposes the
        deterministic :class:`LocationReferenceOutcome`; incompatible
        canonical rebinds and invalid reference input raise typed errors and
        mutate nothing.
        """


class EntityLocationRepository(ABC):  # pragma: no cover
    """Read-only repository for current materialized EntityLocation state.

    Current state is database-maintained from observations; there is
    deliberately no public method that permits callers to mutate it directly.
    """

    @abstractmethod
    async def get_by_entity_id(self, entity_id: UUID) -> EntityLocation | None:
        """Return the current EntityLocation of one Entity, if any."""


class EntityLocationObservationRepository(ABC):  # pragma: no cover
    """Append-only repository for immutable geographic observations.

    One persisted row is one immutable historical observation with exact
    Entity/Location/LegacyEvidence provenance. There is no update, delete, or
    soft-delete path.
    """

    @abstractmethod
    async def append(
        self, observation: EntityLocationObservation
    ) -> EntityLocationObservation:
        """Append one immutable observation and reconcile current state.

        The database validates provenance (Entity visibility, Location and
        LegacyEvidence existence, GEOLOCATION type, exact LegacyEvidence subject) and
        reconciles the current EntityLocation atomically in one transaction.
        """

    @abstractmethod
    async def get_by_id(self, observation_id: UUID) -> EntityLocationObservation | None:
        """Return an immutable observation by its identity."""

    @abstractmethod
    async def list_for_entity(
        self,
        entity_id: UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EntityLocationObservation]:
        """Return bounded observations for one Entity in deterministic order."""


class GeoResolutionRepository(ABC):  # pragma: no cover
    """Repository for durable operational GeoResolution work (PR 26A/26C).

    PR 26A supports creation of initial PENDING work and reads only. PR 26C
    extends the same repository with the bounded lifecycle API:
    claim/lease, atomic resolved completion, unresolvable transition, and
    bounded retry/failure. Mutations route exclusively through the versioned
    SQL API and never commit.
    """

    @abstractmethod
    async def create_pending(self, resolution: GeoResolution) -> GeoResolution:
        """Create (or idempotently reuse) the initial PENDING work record.

        Exactly one row exists per Entity/LegacyEvidence pair; the database owns
        the initial-state invariants and race safety.
        """

    @abstractmethod
    async def get_by_id(self, resolution_id: UUID) -> GeoResolution | None:
        """Return one GeoResolution work record by its identity."""

    @abstractmethod
    async def get_by_entity_evidence(
        self, entity_id: UUID, evidence_id: UUID
    ) -> GeoResolution | None:
        """Return the GeoResolution for one Entity/LegacyEvidence pair, if any."""

    @abstractmethod
    async def claim_batch(
        self,
        *,
        claimed_by: str,
        limit: int,
        lease_seconds: int,
        max_attempts: int,
    ) -> list[GeoResolution]:
        """Claim a bounded batch of eligible work in the active transaction.

        Eligible work is PENDING due now (``next_attempt_at`` is NULL or in
        the past) or PROCESSING with an expired lease. Terminal rows,
        future-scheduled PENDING rows, and unexpired PROCESSING rows are
        never claimed. Expired PROCESSING work already at the attempt budget
        transitions to FAILED instead of being reclaimed. The stored
        function transitions selected rows to PROCESSING, persists the
        claimant/lease, allocates a fresh database version per row, and
        returns the authoritative rows; the caller's UnitOfWork remains the
        commit boundary (repositories never commit).
        """

    @abstractmethod
    async def complete_resolved(
        self,
        resolution_id: UUID,
        expected_version: int,
        claimed_by: str,
        observation: EntityLocationObservation,
    ) -> GeoResolution:
        """Atomically complete one claimed row as RESOLVED.

        One versioned stored function validates the PROCESSING status,
        expected version, claimant, live lease, Entity visibility, LegacyEvidence
        existence/type/subject, and canonical Location; appends the exact
        immutable observation (idempotent under replay); reconciles the
        current EntityLocation; and terminates the work RESOLVED with the
        resolved Location recorded and lease/retry state cleared. Replaying
        the exact same successful completion is a no-op; a conflicting
        terminal replay is a typed error and mutates nothing.
        """

    @abstractmethod
    async def complete_unresolvable(
        self,
        *,
        resolution_id: UUID,
        expected_version: int,
        claimed_by: str,
        error_code: str,
    ) -> GeoResolution:
        """Terminate one claimed row as UNRESOLVABLE with a stable reason code.

        No observation and no EntityLocation mutation are created; the
        resolved Location stays NULL, the reason/error code is recorded, and
        lease/retry state is cleared. Ambiguity is mapped to this transition
        in v0.1 (``ambiguous_location``) and is never guessed or retried.
        """

    @abstractmethod
    async def record_failure(
        self,
        resolution_id: UUID,
        expected_version: int,
        claimed_by: str,
        error_code: str,
        *,
        retryable: bool,
        retry_base_seconds: float,
        retry_max_seconds: float,
        max_attempts: int,
    ) -> GeoResolution:
        """Record one bounded failure on the claimed row.

        A non-retryable failure or an exhausted attempt budget transitions
        the row to FAILED (terminal, no next attempt). A retryable failure
        with budget remaining returns the row to PENDING with a deterministic
        bounded backoff (``base * 2^(attempt_count-1)`` capped at the max,
        no jitter) and clears the lease/claim state. The error code is a
        bounded machine code; raw exception text is never persisted.
        """


class UnitOfWork(ABC):  # pragma: no cover
    """Transaction boundary; repositories never commit themselves."""

    entities: EntityRepository
    relationships: RelationshipRepository
    relationship_observations: RelationshipObservationRepository
    evidence: EvidenceRepository
    evidence_observation_entities: EvidenceObservationEntityRepository
    investigation_evidence: InvestigationEvidenceRepository
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
    locations: LocationRepository
    entity_locations: EntityLocationRepository
    entity_location_observations: EntityLocationObservationRepository
    geo_resolutions: GeoResolutionRepository
    datasource_logs: DatasourceLogRepository

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
