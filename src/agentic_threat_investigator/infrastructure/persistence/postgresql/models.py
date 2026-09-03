# SPDX-License-Identifier: AGPL-3.0-only
"""SQLAlchemy mappings for the PR 3 persistence schema.

ORM row mappings carry mapped state rather than behavior, so the Pylint
minimum public-method rule does not apply to them.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, String, text
from sqlalchemy.dialects.postgresql import BYTEA
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):  # pylint: disable=too-few-public-methods
    """Base for ATI ORM mappings."""


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
    version: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by_actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))


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
