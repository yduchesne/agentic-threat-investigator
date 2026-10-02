# SPDX-License-Identifier: AGPL-3.0-only
"""Public Investigation graph response DTOs (PR 31C; PR 31I).

The graph wire contract is a thin, frontend-independent projection of the
PR 31A application graph read model: canonical Entity identities map to
``GraphNodeResponse`` items, canonical Relationship identities map to
``GraphEdgeResponse`` items, and one bounded neighborhood maps to
:class:`GraphNeighborhoodResponse` with a truthful ``truncated`` flag and no
cursor. PR 31I adds :class:`GraphPathResponse`: the same canonical node/edge
DTOs plus ordered reference-only paths (``GraphPathDto``) and a truthful
path truncation flag. No database rows, raw Evidence payloads, Entity
persistence internals, layout coordinates, PostgreSQL arrays, or
frontend-library ``data`` structures ever cross this boundary.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

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

    ``observation_count``, ``investigation_observation_count``,
    ``first_observed_at`` and ``last_observed_at`` are copied exactly from
    the application ``GraphEdge`` summary; the wire never recomputes or
    substitutes lifetimes or retrieval times, and never infers Investigation
    support. ``investigation_observation_count`` counts the same matching
    observations whose exact EvidenceObservation is admitted to the current
    Investigation and never exceeds ``observation_count``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    relationship_id: UUID
    source_entity_id: UUID
    target_entity_id: UUID
    relationship_type: RelationshipType
    observation_count: int = Field(ge=1)
    investigation_observation_count: int = Field(ge=0)
    first_observed_at: datetime | None = None
    last_observed_at: datetime | None = None

    @model_validator(mode="after")
    def support_within_total(self) -> "GraphEdgeResponse":
        """Require Investigation support never to exceed the filtered total."""
        if self.investigation_observation_count > self.observation_count:
            raise ValueError(
                "graph edge investigation_observation_count must not exceed "
                "observation_count"
            )
        return self


class GraphNeighborhoodResponse(BaseModel):
    """One bounded Investigation-scoped one-hop neighborhood projection."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes: tuple[GraphNodeResponse, ...]
    edges: tuple[GraphEdgeResponse, ...]
    truncated: bool


class GraphPathDto(BaseModel):
    """One ordered simple path of canonical graph references (PR 31I).

    Paths reuse the canonical node/edge vocabulary: ``entity_ids`` and
    ``relationship_ids`` are the authoritative Entity/Relationship UUIDs in
    traversal order (``len(entity_ids) == len(relationship_ids) + 1``, no
    repeated Entity). No PostgreSQL array syntax, SQL signature, recursive
    depth internals or row kinds are exposed; the zero-hop source==target
    path carries one Entity ID and zero Relationship IDs.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_ids: tuple[UUID, ...]
    relationship_ids: tuple[UUID, ...]


class GraphPathResponse(BaseModel):
    """One bounded path-finding projection over canonical graph vocabulary.

    ``nodes`` and ``edges`` reuse the existing node/edge DTOs exactly; each
    canonical Entity/Relationship appears at most once across the selected
    paths. ``paths`` are ordered shortest-first (deterministic tie-break).
    ``truncated`` is true exactly when additional qualifying simple paths
    existed within ``max_depth`` beyond ``max_paths``; a no-path result is
    ``200`` with empty ``paths`` (and the two visible endpoint nodes), never
    a 404. Endpoint-visibility failure is the existing scoped ``404
    graph_entity_not_found``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes: tuple[GraphNodeResponse, ...]
    edges: tuple[GraphEdgeResponse, ...]
    paths: tuple[GraphPathDto, ...]
    truncated: bool
