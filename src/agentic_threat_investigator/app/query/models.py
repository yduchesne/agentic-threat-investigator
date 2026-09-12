# SPDX-License-Identifier: AGPL-3.0-only
"""Shared query contracts: generic page results, limits, and UTC validation.

The read layer returns validated domain/read models inside a bounded
:class:`QueryPage`. No total count is computed by default; cursors provide
continuation without OFFSET.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

T = TypeVar("T")

DEFAULT_PAGE_SIZE = 50
"""Initial default page size used when a caller supplies no explicit limit.

The authoritative runtime values are injected through :class:`QueryLimits`
from configuration; these module defaults exist only for standalone use.
"""

MAX_PAGE_SIZE = 200
"""Initial hard page-size ceiling for all PR 23A collection queries."""


class QueryPage(BaseModel, Generic[T]):
    """One bounded page of results with an opaque continuation cursor.

    ``items`` carries validated domain/read models in the collection's
    canonical deterministic order. ``next_cursor`` is ``None`` exactly when
    the returned page is the final page. No total count is provided.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: tuple[T, ...]
    next_cursor: str | None = None


class QueryLimits(BaseModel):
    """Configured page-size limits shared by every collection query service.

    ``default_page_size`` is the size applied when an API layer omits a
    limit; ``max_page_size`` is the hard ceiling validated for every query.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    default_page_size: int = Field(default=DEFAULT_PAGE_SIZE, ge=1)
    max_page_size: int = Field(default=MAX_PAGE_SIZE, ge=1)

    @model_validator(mode="after")
    def default_within_maximum(self) -> "QueryLimits":
        """Require the default size not to exceed the configured ceiling."""
        if self.default_page_size > self.max_page_size:
            raise ValueError("query default_page_size must not exceed max_page_size")
        return self

    def validate_limit(self, limit: int) -> int:
        """Return a validated page size within the configured bounds."""
        if limit < 1 or limit > self.max_page_size:
            raise ValueError(f"limit must be between 1 and {self.max_page_size}")
        return limit


def normalize_utc(value: datetime | None) -> datetime | None:
    """Return a timezone-aware UTC-normalized timestamp or ``None``.

    Naive timestamps are rejected: cursor and filter semantics never depend
    on an ambiguous local interpretation.
    """
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("query timestamps must be timezone-aware")
    return value.astimezone(UTC)


def require_ordered_half_open(
    intervals: tuple[tuple[datetime | None, datetime | None, str], ...],
) -> None:
    """Require every half-open ``[start, end)`` interval to be well ordered.

    ``start`` must not exceed ``end``; an equal pair is a valid (empty)
    half-open range. Filter semantics are ``start <= timestamp < end``.
    """
    for start, end, label in intervals:
        if start is not None and end is not None and start > end:
            raise ValueError(f"{label} range start must not exceed its end")
