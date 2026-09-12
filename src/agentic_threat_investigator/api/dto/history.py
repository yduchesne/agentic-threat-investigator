# SPDX-License-Identifier: AGPL-3.0-only
"""Public generic history DTOs.

History records carry allowlisted redacted state/diff projections, never raw
JSONB snapshots. Object identity remains ``object_type + object_id``; no
``natural_key`` exists.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class HistoryRecordResponse(BaseModel):
    """One immutable history row with allowlisted public state.

    ``state`` and ``diff`` are per-object-type allowlisted projections of the
    persisted JSONB snapshots; private operational fields never cross the
    HTTP boundary.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    object_type: str
    object_id: UUID
    version: int
    operation: str
    occurred_at: datetime
    actor_id: UUID | None
    state: dict[str, Any] = Field(default_factory=dict)
    diff: dict[str, Any] = Field(default_factory=dict)
