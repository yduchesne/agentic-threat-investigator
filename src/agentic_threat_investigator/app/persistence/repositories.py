# SPDX-License-Identifier: AGPL-3.0-only
"""Async persistence contracts owned by the application layer.

Repository interfaces declare only the operations their resource supports;
narrow single-operation interfaces are intentional, so the Pylint minimum
public-method rule does not apply to them.
"""

from abc import ABC, abstractmethod
from types import TracebackType
from typing import Self
from uuid import UUID

from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)


class EntityRepository(ABC):
    """Repository for canonical, soft-deletable entities."""

    @abstractmethod
    async def get_by_identity(
        self, entity_type: str, canonical_value: str, *, include_deleted: bool = False
    ) -> Entity | None:
        """Return the entity with the given canonical identity, if visible."""

    @abstractmethod
    async def upsert(
        self, entity: Entity, *, expected_version: int | None = None
    ) -> Entity:
        """Create or update the entity and return it with its allocated version."""

    @abstractmethod
    async def soft_delete(
        self,
        entity_id: UUID,
        *,
        actor_id: UUID | None = None,
        expected_version: int | None = None,
    ) -> Entity:
        """Soft-delete the entity and return its post-deletion state."""


class RelationshipRepository(ABC):
    """Repository for stable relationship identities."""

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


class RelationshipObservationRepository(ABC):  # pylint: disable=too-few-public-methods
    """Append-only relationship observation repository."""

    @abstractmethod
    async def append(
        self, observation: RelationshipObservation
    ) -> RelationshipObservation:
        """Append a new immutable observation row."""


class EvidenceRepository(ABC):  # pylint: disable=too-few-public-methods
    """Append-only evidence repository."""

    @abstractmethod
    async def insert(self, evidence: Evidence) -> Evidence:
        """Insert a new immutable evidence observation."""


class UnitOfWork(ABC):
    """Transaction boundary; repositories never commit themselves."""

    entities: EntityRepository
    relationships: RelationshipRepository
    relationship_observations: RelationshipObservationRepository
    evidence: EvidenceRepository

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
