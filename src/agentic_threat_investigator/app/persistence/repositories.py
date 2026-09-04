# SPDX-License-Identifier: AGPL-3.0-only
"""Async persistence contracts owned by the application layer.

Repository interfaces declare only the operations their resource supports;
narrow single-operation interfaces are intentional, so the Pylint minimum
public-method rule does not apply to them.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from types import TracebackType
from typing import Self
from uuid import UUID

from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import Evidence
from agentic_threat_investigator.domain.identity import Credential, Session, User
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)


class EntityRepository(ABC):  # pragma: no cover
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


class RelationshipRepository(ABC):  # pragma: no cover
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


class RelationshipObservationRepository(
    ABC
):  # pylint: disable=too-few-public-methods  # pragma: no cover
    """Append-only relationship observation repository."""

    @abstractmethod
    async def append(
        self, observation: RelationshipObservation
    ) -> RelationshipObservation:
        """Append a new immutable observation row."""


class EvidenceRepository(
    ABC
):  # pylint: disable=too-few-public-methods  # pragma: no cover
    """Append-only evidence repository."""

    @abstractmethod
    async def insert(self, evidence: Evidence) -> Evidence:
        """Insert a new immutable evidence observation."""


class UserRepository(ABC):  # pylint: disable=too-few-public-methods  # pragma: no cover
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


class CredentialRepository(
    ABC
):  # pylint: disable=too-few-public-methods  # pragma: no cover
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


class SessionRepository(
    ABC
):  # pylint: disable=too-few-public-methods  # pragma: no cover
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
    async def touch(self, session_id: UUID, seen_at: object) -> None:
        """Update last-seen metadata."""


class UnitOfWork(ABC):  # pragma: no cover
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
