# SPDX-License-Identifier: AGPL-3.0-only
"""Shared public API DTOs: the generic page response contract."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class PageResponse(BaseModel, Generic[T]):
    """One bounded page of public items with an opaque continuation cursor.

    ``items`` carries explicit allowlisted response DTOs in the collection's
    canonical order; ``next_cursor`` is ``None`` exactly on the final page.
    No total count is ever provided.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: tuple[T, ...]
    next_cursor: str | None = None
