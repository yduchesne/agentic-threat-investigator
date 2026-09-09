# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Application-layer provider contracts.

Defines the ``EvidenceProvider`` ABC, typed error and result models, and
stable error code vocabulary. Providers retrieve and normalize evidence
without persisting, assessing maliciousness, inferring relationships, or
deciding pivots.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from agentic_threat_investigator.domain.entities import (
    Entity,
    EntityType,
    canonicalize,
    validate_dns_name,
)
from agentic_threat_investigator.domain.evidence import Evidence


class ProviderErrorCode(str, Enum):
    """Stable ATI error code vocabulary for live evidence providers."""

    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    AUTHENTICATION_FAILED = "authentication_failed"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    UNSUPPORTED_INDICATOR = "unsupported_indicator"
    INVALID_RESPONSE = "invalid_response"
    PROVIDER_UNAVAILABLE = "provider_unavailable"

    @property
    def retryable(self) -> bool:
        """Return True if the code describes a condition worth retrying."""
        return self in (
            ProviderErrorCode.TIMEOUT,
            ProviderErrorCode.RATE_LIMITED,
            ProviderErrorCode.PROVIDER_UNAVAILABLE,
        )


class ProviderError(BaseModel):
    """A structured, typed error from a live evidence provider."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    code: ProviderErrorCode
    message: str
    retryable: bool
    retry_after_seconds: int | None = None

    @field_validator("provider")
    @classmethod
    def _provider_must_be_source_urn(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("provider must not be blank")
        if not re.fullmatch(r"urn:ati:source:[a-z0-9][a-z0-9_-]*", normalized):
            raise ValueError("provider must be an ATI source URN")
        return normalized

    @field_validator("message")
    @classmethod
    def _message_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("message must not be blank")
        return value.strip()

    @field_validator("retry_after_seconds")
    @classmethod
    def _retry_after_must_be_nonnegative(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("retry_after_seconds must be nonnegative")
        return value

    @field_validator("retryable", mode="before")
    @classmethod
    def _validate_retryable_consistency(
        cls, value: bool, info: ValidationInfo
    ) -> bool:  # pylint: disable=invalid-name
        """Ensure the code's natural retryability matches the declared flag."""
        code = info.data.get("code")
        if code is not None:
            natural = code.retryable
            if natural and not value:
                raise ValueError(f"error code {code.value} is inherently retryable")
            if not natural and value:
                raise ValueError(f"error code {code.value} is not retryable")
        return value


class ProviderResult(BaseModel):
    """The output of a single provider investigation call.

    Contains normalized evidence and typed errors; the two collections are
    validated independently and may legally be present together (for example
    Google Public DNS aggregates independent per-RR-type query outcomes). A
    valid miss is both lists empty; it is not a benign assessment.

    Execution-status contract (approved for PR 19B orchestration): a mixed
    Evidence-plus-errors result is a valid partial provider result. The
    provider executor persists valid Evidence in provider-return order and
    returns ``SUCCEEDED`` when at least one Evidence observation committed
    and no extraction, persistence, or timeline failure subsequently
    occurred; only the first provider error, in provider-return order, is
    retained (its stable code and retryability, never the free-form
    message), and the ``PROVIDER_WORK_COMPLETED`` timeline event exposes the
    retained code. Errors without Evidence fail the work; an all-empty
    result succeeds. No PARTIAL execution status exists in PR 19B.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    evidence: tuple[Evidence, ...] = Field(default_factory=tuple)
    errors: tuple[ProviderError, ...] = Field(default_factory=tuple)

    @field_validator("provider")
    @classmethod
    def _provider_must_be_source_urn(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("provider must not be blank")
        if not re.fullmatch(r"urn:ati:source:[a-z0-9][a-z0-9_-]*", normalized):
            raise ValueError("provider must be an ATI source URN")
        return normalized

    @field_validator("evidence")
    @classmethod
    def _evidence_consistent_provider(
        cls, value: tuple[Evidence, ...], info: ValidationInfo
    ) -> tuple[Evidence, ...]:
        """Reject evidence with a different source than the result provider."""
        provider = info.data.get("provider")
        if provider is not None:
            for ev in value:
                if ev.source != provider:
                    raise ValueError(
                        f"evidence source {ev.source!r} does not match "
                        f"result provider {provider!r}"
                    )
        return value

    @field_validator("errors")
    @classmethod
    def _errors_consistent_provider(
        cls, value: tuple[ProviderError, ...], info: ValidationInfo
    ) -> tuple[ProviderError, ...]:
        """Reject errors with a different provider than the result."""
        provider = info.data.get("provider")
        if provider is not None:
            for err in value:
                if err.provider != provider:
                    raise ValueError(
                        f"error provider {err.provider!r} does not match "
                        f"result provider {provider!r}"
                    )
        return value


class EvidenceProvider(ABC):  # pylint: disable=too-few-public-methods
    """Abstract live evidence provider.

    Providers retrieve external information and normalize it into ATI
    ``Evidence``. They do not persist, assess maliciousness, infer
    relationships, or decide pivots.
    """

    @property
    @abstractmethod
    def id(self) -> str:
        """Return the stable ATI source URN for this provider."""

    @abstractmethod
    def supports(self, entity: Entity) -> bool:
        """Return deterministic applicability without external I/O.

        This method must never make network calls, access mutable state, or
        raise exceptions for unknown entity types.
        """

    @abstractmethod
    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Retrieve and normalize evidence for one supported entity.

        Calling ``investigate`` with an unsupported entity must not issue
        HTTP; return a single ``UNSUPPORTED_INDICATOR`` error instead of
        raising. This method must not swallow ``asyncio.CancelledError``.
        """


def provider_error_result(
    provider_id: str,
    code: ProviderErrorCode,
    message: str,
    *,
    retry_after_seconds: int | None = None,
) -> ProviderResult:
    """Build one typed provider error result attributed to ``provider_id``.

    The error carries the code's natural retryability and an optional
    provider-directed ``retry_after_seconds`` value. This is the shared
    construction for the single-error ``ProviderResult`` shape used by the
    live providers; provider-specific status remapping stays in each
    provider module.
    """
    return ProviderResult(
        provider=provider_id,
        errors=(
            ProviderError(
                provider=provider_id,
                code=code,
                message=message,
                retryable=code.retryable,
                retry_after_seconds=retry_after_seconds,
            ),
        ),
    )


def unsupported_indicator_result(
    provider_id: str, message: str = "invalid entity value"
) -> ProviderResult:
    """Build a standard non-retryable ``UNSUPPORTED_INDICATOR`` result."""
    return ProviderResult(
        provider=provider_id,
        errors=(
            ProviderError(
                provider=provider_id,
                code=ProviderErrorCode.UNSUPPORTED_INDICATOR,
                message=message,
                retryable=False,
            ),
        ),
    )


def validate_investigation_entity(
    provider: EvidenceProvider,
    entity: Entity,
) -> tuple[str | None, ProviderResult | None]:
    """Validate entity support and canonicalization before provider I/O.

    Returns ``(canonical_value, None)`` when the entity is supported and
    canonicalizable. Returns ``(None, error_result)`` with a non-retryable
    UNSUPPORTED_INDICATOR error otherwise.

    Domain entities are strictly validated against the original value via
    :func:`validate_dns_name` before any lossy canonicalization can erase
    malformed syntax such as repeated terminal dots. Non-domain entity
    types use the general canonicalization dispatch.
    """
    if not provider.supports(entity):
        return None, ProviderResult(
            provider=provider.id,
            errors=(
                ProviderError(
                    provider=provider.id,
                    code=ProviderErrorCode.UNSUPPORTED_INDICATOR,
                    message=f"unsupported entity type: {entity.type.value}",
                    retryable=False,
                ),
            ),
        )

    try:
        if entity.type is EntityType.DOMAIN:
            # Validate the original value strictly: the persistence-oriented
            # canonicalizer would silently strip every terminal dot, hiding
            # malformed repeated-dot names before provider I/O.
            canonical_val = validate_dns_name(entity.value)
        else:
            canonical_val = canonicalize(entity.type, entity.value)
        return canonical_val, None
    except ValueError:
        return None, ProviderResult(
            provider=provider.id,
            errors=(
                ProviderError(
                    provider=provider.id,
                    code=ProviderErrorCode.UNSUPPORTED_INDICATOR,
                    message="invalid entity value",
                    retryable=False,
                ),
            ),
        )


def normalize_retrieval_timestamp(clock: Callable[[], datetime]) -> datetime:
    """Evaluate retrieval clock and ensure a normalized timezone-aware UTC datetime."""
    retrieved_at = clock()
    if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
        raise ValueError("retrieved_at clock must return a timezone-aware datetime")
    return retrieved_at.astimezone(UTC)
