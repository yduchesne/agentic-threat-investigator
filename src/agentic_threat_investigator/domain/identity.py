# SPDX-License-Identifier: AGPL-3.0-only
"""Framework-independent identity and session domain models."""

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class UserRole(str, Enum):
    """Roles supported by local authentication."""

    ADMIN = "admin"
    ANALYST = "analyst"


class User(BaseModel):
    """A local, soft-deletable user identity."""

    model_config = ConfigDict(frozen=True)
    id: UUID = Field(default_factory=uuid4)
    username: str
    display_name: str | None = None
    role: UserRole = UserRole.ANALYST
    enabled: bool = True
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None
    deleted_by_actor_id: UUID | None = None
    version: int = 1


class Credential(BaseModel):
    """Password credential kept separate from the user identity."""

    model_config = ConfigDict(frozen=True)
    user_id: UUID
    password_hash: str
    password_changed_at: datetime


class Session(BaseModel):
    """Opaque server-side authentication session."""

    model_config = ConfigDict(frozen=True)
    id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    token_hash: bytes
    created_at: datetime
    expires_at: datetime
    last_seen_at: datetime
    revoked_at: datetime | None = None


class ActorContext(BaseModel):
    """Authenticated actor passed explicitly through application services."""

    actor_id: UUID
    username: str
    display_name: str | None = None
    role: UserRole

    @classmethod
    def system(cls) -> "ActorContext":
        """Return the reserved scheduler/system actor context."""
        return cls(
            actor_id=UUID("00000000-0000-0000-0000-000000000001"),
            username="SYSTEM",
            display_name="SYSTEM",
            role=UserRole.ADMIN,
        )
