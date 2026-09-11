# SPDX-License-Identifier: AGPL-3.0-only
"""SQLAlchemy mappings for the PR 3 persistence schema.

ORM row mappings carry mapped state rather than behavior.
"""

from datetime import datetime
from typing import Any, Self
from uuid import UUID

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, BYTEA
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import UserDefinedType


class Base(DeclarativeBase):
    """Base for ATI ORM mappings."""


class Vector1536(UserDefinedType[Any]):
    """SQLAlchemy DDL representation of ATI's fixed pgvector dimension."""

    cache_ok = True

    @property
    def python_type(self) -> type[tuple[float, ...]]:
        """Return the application-neutral Python representation type."""
        return tuple

    def _with_collation(self, _collation: str) -> Self:
        """Return self because pgvector does not support text collation."""
        return self

    def get_col_spec(self, **_kwargs: Any) -> str:
        """Render the PostgreSQL fixed-dimension vector type."""
        return "vector(1536)"


class AuditEventRow(Base):
    """Database row for an immutable audit event."""

    __tablename__ = "audit_event"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    action: Mapped[str] = mapped_column(String)
    outcome: Mapped[str] = mapped_column(String)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    actor_username: Mapped[str | None] = mapped_column(String)
    object_type: Mapped[str | None] = mapped_column(String)
    object_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    request_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    version: Mapped[int] = mapped_column(
        BigInteger, server_default=text("nextval('ati.audit_event_version_seq')")
    )


class EntityRow(Base):
    """Database row for an entity."""

    __tablename__ = "entity"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    entity_type: Mapped[str] = mapped_column(String)
    canonical_value: Mapped[str] = mapped_column(String)
    display_name: Mapped[str | None] = mapped_column(String)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    content_hash: Mapped[bytes | None] = mapped_column(BYTEA)
    version: Mapped[int] = mapped_column(
        BigInteger, server_default=text("nextval('ati.entity_version_seq')")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by_actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))


class SourceRecordRow(Base):
    """Current normalized state for one external source identity."""

    __tablename__ = "source_record"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    source_id: Mapped[str] = mapped_column(String)
    source_record_id: Mapped[str] = mapped_column(String)
    record_type: Mapped[str] = mapped_column(String)
    normalization_version: Mapped[int]
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    canonical_payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    raw_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    content_hash: Mapped[bytes] = mapped_column(BYTEA)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    version: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DocumentRow(Base):
    """Current versioned narrative document state."""

    __tablename__ = "document"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    source_id: Mapped[str] = mapped_column(String)
    source_record_id: Mapped[str] = mapped_column(String)
    document_type: Mapped[str] = mapped_column(String)
    title: Mapped[str | None] = mapped_column(String)
    source_url: Mapped[str | None] = mapped_column(String)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    content: Mapped[str] = mapped_column(String)
    normalization_version: Mapped[int]
    chunking_version: Mapped[int]
    content_hash: Mapped[bytes] = mapped_column(BYTEA)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    version: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by_actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))


class DocumentChunkRow(Base):
    """Current replaceable pgvector indexing artifact."""

    __tablename__ = "document_chunk"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    document_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("ati.document.id")
    )
    sequence: Mapped[int]
    text: Mapped[str] = mapped_column(String)
    token_count: Mapped[int]
    embedding: Mapped[Any] = mapped_column(Vector1536())
    embedding_provider: Mapped[str] = mapped_column(String)
    embedding_model: Mapped[str] = mapped_column(String)
    embedding_model_version: Mapped[int]
    embedding_dimension: Mapped[int]
    content_hash: Mapped[bytes] = mapped_column(BYTEA)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    version: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IngestionCheckpointRow(Base):
    """Mutable operational progress for one artifact and normalizer version."""

    __tablename__ = "ingestion_checkpoint"
    __table_args__ = {"schema": "ati"}
    source_id: Mapped[str] = mapped_column(String, primary_key=True)
    artifact_uri: Mapped[str] = mapped_column(String, primary_key=True)
    normalization_version: Mapped[int] = mapped_column(primary_key=True)
    checkpoint: Mapped[str | None] = mapped_column(String)
    complete: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UserRow(Base):
    """Database row for a local user."""

    __tablename__ = "user"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    username: Mapped[str] = mapped_column(String, unique=True)
    display_name: Mapped[str | None] = mapped_column(String)
    role: Mapped[str] = mapped_column(String)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by_actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    version: Mapped[int] = mapped_column(
        BigInteger, server_default=text("nextval('ati.user_version_seq')")
    )


class CredentialRow(Base):
    """Database row for a user's password credential."""

    __tablename__ = "credential"
    __table_args__ = {"schema": "ati"}
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("ati.user.id"), primary_key=True
    )
    password_hash: Mapped[str] = mapped_column(String)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SessionRow(Base):
    """Database row for a revocable server-side session."""

    __tablename__ = "session"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("ati.user.id")
    )
    token_hash: Mapped[bytes] = mapped_column(BYTEA, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RelationshipRow(Base):
    """Database row for a relationship."""

    __tablename__ = "relationship"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    source_entity_id: Mapped[UUID] = mapped_column(ForeignKey("ati.entity.id"))
    target_entity_id: Mapped[UUID] = mapped_column(ForeignKey("ati.entity.id"))
    relationship_type_urn: Mapped[str] = mapped_column(String)
    version: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by_actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))


class InvestigationRow(Base):
    """Database row for the mutable, versioned investigation resource."""

    __tablename__ = "investigation"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    status: Mapped[str] = mapped_column(String)
    trigger_type: Mapped[str] = mapped_column(String)
    objective: Mapped[str] = mapped_column(String)
    budget: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    operational_state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    version: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by_actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))


class EvidenceRow(Base):
    """Database row for immutable evidence."""

    __tablename__ = "evidence"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    investigation_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    evidence_type: Mapped[str] = mapped_column(String)
    subject_entity_id: Mapped[UUID] = mapped_column(ForeignKey("ati.entity.id"))
    source: Mapped[str] = mapped_column(String)
    source_record_id: Mapped[str | None] = mapped_column(String)
    source_url: Mapped[str | None] = mapped_column(String)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    facts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    version: Mapped[int] = mapped_column(BigInteger)


class RelationshipObservationRow(Base):
    """Database row for an immutable relationship observation."""

    __tablename__ = "relationship_observation"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    relationship_id: Mapped[UUID] = mapped_column(ForeignKey("ati.relationship.id"))
    evidence_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    investigation_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String)
    confidence: Mapped[float | None]
    version: Mapped[int] = mapped_column(BigInteger)


class AssessmentRow(Base):
    """Database row for a versioned, insert-only analytical Assessment."""

    __tablename__ = "assessment"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    investigation_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    verdict: Mapped[str] = mapped_column(String)
    confidence: Mapped[str] = mapped_column(String)
    summary: Mapped[str] = mapped_column(String)
    analyzed_evidence_ids: Mapped[list[UUID]] = mapped_column(
        ARRAY(PGUUID(as_uuid=True)), default=list
    )
    limitations: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    unresolved_questions: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    recommended_next_steps: Mapped[list[str]] = mapped_column(
        ARRAY(String), default=list
    )
    version: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by_actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))


class AssessmentFindingRow(Base):
    """Database row for one Finding within a persisted Assessment."""

    __tablename__ = "assessment_finding"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    assessment_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("ati.assessment.id")
    )
    ordinal: Mapped[int]
    category: Mapped[str] = mapped_column(String)
    disposition: Mapped[str] = mapped_column(String)
    statement: Mapped[str] = mapped_column(String)
    confidence: Mapped[str] = mapped_column(String)


class AssessmentFindingSupportRow(Base):
    """Database row for one typed support reference of a Finding."""

    __tablename__ = "assessment_finding_support"
    __table_args__ = {"schema": "ati"}
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    finding_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("ati.assessment_finding.id")
    )
    ordinal: Mapped[int]
    kind: Mapped[str] = mapped_column(String)
    evidence_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    relationship_observation_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True)
    )


class InvestigationTimelineEventRow(Base):
    """Database row for an immutable analyst-facing investigation timeline event."""

    __tablename__ = "investigation_timeline_event"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('investigation_started', 'provider_work_started', "
            "'provider_work_completed', 'provider_work_failed', "
            "'evidence_persisted', 'entities_discovered', 'pivot_enqueued', "
            "'pivot_executed', 'pivot_skipped', 'assessment_requested', "
            "'investigation_stopped')",
            name="investigation_timeline_event_type_check",
        ),
        CheckConstraint(
            "error_code IS NULL OR error_code ~ '^[a-z][a-z0-9_]{0,63}$'",
            name="investigation_timeline_event_error_code_check",
        ),
        {"schema": "ati"},
    )
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("ati.investigation.id"))
    event_type: Mapped[str] = mapped_column(String)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    provider: Mapped[str | None] = mapped_column(String)
    target_entity_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    evidence_ids: Mapped[list[UUID]] = mapped_column(
        ARRAY(PGUUID(as_uuid=True)), default=list
    )
    entity_ids: Mapped[list[UUID]] = mapped_column(
        ARRAY(PGUUID(as_uuid=True)), default=list
    )
    relationship_ids: Mapped[list[UUID]] = mapped_column(
        ARRAY(PGUUID(as_uuid=True)), default=list
    )
    error_code: Mapped[str | None] = mapped_column(String)
    pivot_depth: Mapped[int | None] = mapped_column(Integer)
    reason_code: Mapped[str | None] = mapped_column(String)
    provider_calls_used: Mapped[int | None] = mapped_column(BigInteger)
    replans_used: Mapped[int | None] = mapped_column(BigInteger)
    entity_count: Mapped[int | None] = mapped_column(Integer)
    sequence: Mapped[int] = mapped_column(
        BigInteger,
        server_default=text("nextval('ati.investigation_timeline_event_seq')"),
    )
