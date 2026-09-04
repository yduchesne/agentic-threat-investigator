# SPDX-License-Identifier: AGPL-3.0-only
"""Framework-independent immutable security audit records."""

import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_threat_investigator.domain.immutable_json import FrozenDict, freeze_mapping


class AuditOutcome(str, Enum):
    """Result of an attempted security-relevant operation."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AuditAction(str, Enum):
    """Stable URNs for currently implemented audit actions."""

    AUTH_LOGIN = "urn:ati:action:auth:login"
    AUTH_LOGOUT = "urn:ati:action:auth:logout"
    AUTH_CSRF_REJECTED = "urn:ati:action:auth:csrf_rejected"
    USER_CREATE = "urn:ati:action:user:create"
    USER_CHANGE_PASSWORD = "urn:ati:action:user:change_password"
    USER_UPDATE = "urn:ati:action:user:update"
    USER_DISABLE = "urn:ati:action:user:disable"
    USER_DELETE = "urn:ati:action:user:delete"


_FORBIDDEN = re.compile(
    r"(?:password|passwd|token|secret|authorization|api[_-]?key|raw[_-]?payload|"
    r"prompt|chain[_-]?of[_-]?thought)",
    re.IGNORECASE,
)
_URN = re.compile(r"^urn:ati:action:[a-z0-9_]+(?::[a-z0-9_]+)+$")


def sanitize_metadata(metadata: dict[str, Any] | None) -> FrozenDict:
    """Recursively validate and freeze metadata without secret-bearing keys."""
    if metadata is None:
        return FrozenDict()

    def scan(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, nested_value in value.items():
                if isinstance(key, str) and _FORBIDDEN.search(key):
                    raise ValueError(f"forbidden audit metadata key: {key}")
                scan(nested_value)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for nested_value in value:
                scan(nested_value)

    scan(metadata)
    return freeze_mapping(metadata)


class AuditEvent(BaseModel):
    """An immutable, minimized audit observation."""

    model_config = ConfigDict(frozen=True)
    id: UUID = Field(default_factory=uuid4)
    action: str
    outcome: AuditOutcome
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: UUID | None = None
    actor_username: str | None = None
    object_type: str | None = None
    object_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    request_id: UUID | None = None
    version: int = 0

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str | AuditAction) -> str:
        """Require the stable ATI action URN shape."""
        value = value.value if isinstance(value, AuditAction) else value
        if not _URN.fullmatch(value):
            raise ValueError("action must be an ATI action URN")
        return value

    @field_validator("occurred_at")
    @classmethod
    def validate_utc(cls, value: datetime) -> datetime:
        """Require timezone-aware timestamps and normalize them to UTC."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value.astimezone(timezone.utc)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> FrozenDict:
        """Apply the defense-in-depth metadata minimization guard."""
        return sanitize_metadata(value)
