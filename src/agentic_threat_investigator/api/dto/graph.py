# SPDX-License-Identifier: AGPL-3.0-only
"""Public Investigation graph response DTOs (PR 31C).

The graph wire contract is a thin, frontend-independent projection of the
PR 31A application graph read model: canonical Entity identities map to
``GraphNodeResponse`` items, canonical Relationship identities map to
``GraphEdgeResponse`` items, and one bounded neighborhood maps to
:class:`GraphNeighborhoodResponse` with a truthful ``truncated`` flag and no
cursor. No database rows, raw Evidence payloads, Entity persistence
internals, layout coordinates, or frontend-library ``data`` structures ever
cross this boundary.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import RelationshipType


class GraphNodeResponse(BaseModel):
    """One canonical Entity projected as a graph node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    entity_type: EntityType
    value: str
    display_name: str | None = None


class GraphEdgeResponse(BaseModel):
    """One canonical Relationship projected as a graph edge.

    ``observation_count``, ``first_observed_at`` and ``last_observed_at``
    are copied exactly from the application ``GraphEdge`` summary; the wire
    never recomputes or substitutes lifetimes or retrieval times.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    relationship_id: UUID
    source_entity_id: UUID
    target_entity_id: UUID
    relationship_type: RelationshipType
    observation_count: int
    first_observed_at: datetime | None = None
    last_observed_at: datetime | None = None


class GraphNeighborhoodResponse(BaseModel):
    """One bounded Investigation-scoped one-hop neighborhood projection."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes: tuple[GraphNodeResponse, ...]
    edges: tuple[GraphEdgeResponse, ...]
    truncated: bool
