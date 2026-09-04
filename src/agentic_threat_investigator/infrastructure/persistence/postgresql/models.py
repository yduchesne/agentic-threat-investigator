# SPDX-License-Identifier: AGPL-3.0-only
"""SQLAlchemy mappings for the PR 3 persistence schema.

ORM row mappings carry mapped state rather than behavior, so the Pylint
minimum public-method rule does not apply to them.
"""

from datetime import datetime
from typing import Any, Self
from uuid import UUID

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, String, text
from sqlalchemy.dialects.postgresql import BYTEA
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import UserDefinedType


class Base(DeclarativeBase):  # pylint: disable=too-few-public-methods
    """Base for ATI ORM mappings."""


class Vector1536(UserDefinedType[Any]):  # pylint: disable=too-few-public-methods
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


class AuditEventRow(Base):  # pylint: disable=too-few-public-methods
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


class EntityRow(Base):  # pylint: disable=too-few-public-methods
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


class SourceRecordRow(Base):  # pylint: disable=too-few-public-methods
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


class DocumentRow(Base):  # pylint: disable=too-few-public-methods
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


class DocumentChunkRow(Base):  # pylint: disable=too-few-public-methods
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


class IngestionCheckpointRow(Base):  # pylint: disable=too-few-public-methods
    """Mutable operational progress for one artifact and normalizer version."""

    __tablename__ = "ingestion_checkpoint"
    __table_args__ = {"schema": "ati"}
    source_id: Mapped[str] = mapped_column(String, primary_key=True)
    artifact_uri: Mapped[str] = mapped_column(String, primary_key=True)
    normalization_version: Mapped[int] = mapped_column(primary_key=True)
    checkpoint: Mapped[str | None] = mapped_column(String)
    complete: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UserRow(Base):  # pylint: disable=too-few-public-methods
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


class CredentialRow(Base):  # pylint: disable=too-few-public-methods
    """Database row for a user's password credential."""

    __tablename__ = "credential"
    __table_args__ = {"schema": "ati"}
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("ati.user.id"), primary_key=True
    )
    password_hash: Mapped[str] = mapped_column(String)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SessionRow(Base):  # pylint: disable=too-few-public-methods
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


class RelationshipRow(Base):  # pylint: disable=too-few-public-methods
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


class EvidenceRow(Base):  # pylint: disable=too-few-public-methods
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


class RelationshipObservationRow(Base):  # pylint: disable=too-few-public-methods
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
