# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31H stored-function boundary contract tests (H-SF01..H-SF10).

These tests pin the persistence boundary itself: the migration installs the
``ati.traverse_graph`` stored function (H-SF01/H-SF02), the Python adapter
invokes exactly the stored function with the exact validated parameters and
maps only returned rows (H-SF03), and no traversal SELECT / recursive CTE /
join / filter / aggregation / endpoint SQL exists in the Python adapter
(H-SF04/H-SF09). Visibility, eligibility, recursion/cycle safety and
canonical aggregation are enforced by the stored-function SQL and are proven
behaviorally by the real-PostgreSQL integration suite
(``tests/integration/test_query_graph_traversal.py``); the boundary tests
hold the adapter to its invocation/mapping-only shape.
"""

from __future__ import annotations

from datetime import UTC, datetime
from inspect import getsource
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.graph import (
    GraphScope,
    GraphTraversalQuery,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)
from agentic_threat_investigator.infrastructure.persistence.query.graph import (
    PostgresGraphQueryService,
)

INVESTIGATION = UUID("11111111-1111-1111-1111-111111111111")


class _Row:
    """One stored-function output row used by the recording-fake result.

    Explicit typed fields so mypy can follow the row projections the real
    stored function returns; ``__dict__`` injection would hide them.
    """

    kind: str
    node_entity_id: UUID | None
    node_entity_type: str | None
    node_canonical_value: str | None
    node_display_name: str | None
    node_min_depth: int | None
    edge_relationship_id: UUID | None
    edge_source_entity_id: UUID | None
    edge_target_entity_id: UUID | None
    edge_relationship_type_urn: str | None
    edge_observation_count: int | None
    edge_investigation_observation_count: int | None
    edge_first_observed_at: datetime | None
    edge_last_observed_at: datetime | None
    edge_min_depth: int | None
    truncated: bool

    def __init__(self, **fields: Any) -> None:
        """Populate the declared fields from the fixture kwargs."""
        for field, value in fields.items():
            setattr(self, field, value)

    def __getattr__(self, name: str) -> Any:
        """Fail loudly when a tested projection field is not populated."""
        raise AttributeError(name)


class _Result:
    """Buffered sync result shape returned by ``AsyncSession.execute``."""

    def __init__(self, rows: list[_Row]) -> None:
        self._rows = rows

    def all(self) -> list[_Row]:
        """Return the buffered rows synchronously (SQLAlchemy buffered Result)."""
        return self._rows


class _RecordingSession:
    """AsyncSession double recording the exact statement and bound parameters."""

    def __init__(self, rows: list[_Row] | None = None) -> None:
        self._rows = rows or []
        self.executed: list[tuple[str, dict[str, object]]] = []

    async def execute(
        self, statement: object, params: dict[str, object] | None = None
    ) -> _Result:
        """Record one invocation and return the configured buffered result."""
        self.executed.append((str(statement), params or {}))
        return _Result(self._rows)


def _node_row(entity_id: UUID) -> _Row:
    """Build one canonical node row for the recording fake."""
    return _Row(
        kind="node",
        node_entity_id=entity_id,
        node_entity_type="domain",
        node_canonical_value="example.com",
        node_display_name=None,
        node_min_depth=0,
        edge_relationship_id=None,
        edge_source_entity_id=None,
        edge_target_entity_id=None,
        edge_relationship_type_urn=None,
        edge_observation_count=None,
        edge_investigation_observation_count=None,
        edge_first_observed_at=None,
        edge_last_observed_at=None,
        edge_min_depth=None,
        truncated=False,
    )


def _edge_row() -> _Row:
    """Build one canonical edge row for the recording fake."""
    return _Row(
        kind="edge",
        node_entity_id=None,
        node_entity_type=None,
        node_canonical_value=None,
        node_display_name=None,
        node_min_depth=None,
        edge_relationship_id=uuid4(),
        edge_source_entity_id=uuid4(),
        edge_target_entity_id=uuid4(),
        edge_relationship_type_urn=RelationshipType.RESOLVES_TO.value,
        edge_observation_count=2,
        edge_investigation_observation_count=1,
        edge_first_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        edge_last_observed_at=datetime(2026, 1, 3, tzinfo=UTC),
        edge_min_depth=2,
        truncated=False,
    )


def _query(
    *,
    max_depth: int = 2,
    limit: int = 25,
    scope: GraphScope = GraphScope.KNOWN,
    direction: RelationshipDirection = RelationshipDirection.SOURCE,
    relationship_type: RelationshipType | None = RelationshipType.RESOLVES_TO,
    entity_type: EntityType | None = EntityType.IP_ADDRESS,
    source: str | None = "rdap",
) -> GraphTraversalQuery:
    """Build one fully-populated traversal query for boundary tests."""
    return GraphTraversalQuery(
        investigation_id=INVESTIGATION,
        entity_id=uuid4(),
        max_depth=max_depth,
        limit=limit,
        scope=scope,
        direction=direction,
        relationship_type=relationship_type,
        entity_type=entity_type,
        source=source,
        observed_from=datetime(2026, 1, 1, tzinfo=UTC),
        observed_to=datetime(2026, 2, 1, tzinfo=UTC),
    )


def _service(session: _RecordingSession) -> PostgresGraphQueryService:
    """Bind the recording fake as the read session with standard limits."""
    return PostgresGraphQueryService(
        cast("AsyncSession", session),
        QueryLimits(default_page_size=50, max_page_size=200),
    )


# --- H-SF03: Python invokes the stored function with exact parameters --------


@pytest.mark.asyncio
async def test_sf03_adapter_invokes_stored_function_with_exact_parameters() -> None:
    """The adapter issues exactly one stored-function call with validated params."""
    edge = _edge_row()
    target_id = edge.edge_target_entity_id
    source_id = edge.edge_source_entity_id
    assert target_id is not None and source_id is not None
    focal = _node_row(target_id)
    session = _RecordingSession([focal, _node_row(source_id), edge])
    service = _service(session)
    query = _query()

    result = await service.traverse(query)

    assert result is not None
    assert len(session.executed) == 1
    statement, params = session.executed[0]
    assert "SELECT * FROM ati.traverse_graph(" in statement
    assert params == {
        "investigation_id": query.investigation_id,
        "entity_id": query.entity_id,
        "max_depth": 2,
        "scope": "known",
        "direction": "source",
        "relationship_type": RelationshipType.RESOLVES_TO.value,
        "entity_type": EntityType.IP_ADDRESS.value,
        "source": "rdap",
        "observed_from": datetime(2026, 1, 1, tzinfo=UTC),
        "observed_to": datetime(2026, 2, 1, tzinfo=UTC),
        "limit": 25,
    }
    assert len(result.nodes) == 2
    assert len(result.edges) == 1
    edge_projected = result.edges[0]
    assert edge_projected.relationship_id == edge.edge_relationship_id
    assert edge_projected.observation_count == 2
    assert edge_projected.investigation_observation_count == 1
    assert result.truncated is False


@pytest.mark.asyncio
async def test_sf03b_empty_result_maps_to_none() -> None:
    """A stored-function empty result (invisible focal) maps to None."""
    session = _RecordingSession([])
    service = _service(session)
    assert await service.traverse(_query()) is None
    assert len(session.executed) == 1


@pytest.mark.asyncio
async def test_sf03c_limit_is_ceiling_validated() -> None:
    """The adapter still enforces the existing QueryLimits ceiling."""

    class _OversizeQuery:
        """Query double whose limit exceeds the configured ceiling."""

        @property
        def limit(self) -> int:
            """Expose an oversized caller bound."""
            return 9999

    session = _RecordingSession()
    service = _service(session)
    query = _query(limit=500)
    with pytest.raises(ValueError, match="limit must be between"):
        await service.traverse(query)
    assert session.executed == []


# --- H-SF04/H-SF09: no traversal SQL in the Python adapter ---------------------


def test_sf04_adapter_contains_no_direct_traversal_sql() -> None:
    """A source review detects any accidental direct traversal SQL (H-SF04/09).

    The ``traverse`` method must be a stored-function invocation/mapping
    boundary: it may concatenate the function-call text and bind parameters,
    but it must never contain a traversal SELECT, recursive CTE, join,
    filter/aggregation predicate, or endpoint lookup SQL of its own.
    """
    source = getsource(PostgresGraphQueryService.traverse)
    for forbidden in (
        "WITH RECURSIVE",
        "JOIN ati.relationship",
        "JOIN ati.entity",
        "FROM ati.relationship",
        "FROM ati.entity",
        "GROUP BY",
        "ORDER BY",
        "LIMIT :limit + 1",
        "EXISTS (",
        "count(",
        "min(",
        "max(",
    ):
        assert forbidden not in source, (
            f"PostgresGraphQueryService.traverse must not contain {forbidden!r}"
        )
    # The only SQL text allowed is exactly the stored-function invocation.
    assert "SELECT * FROM ati.traverse_graph(" in source
    assert source.count("SELECT * FROM ati.traverse_graph(") == 1
    # The invariant: the invocation is the ONLY query; nothing else reads
    # tables (no direct traversal SELECT / join / endpoint lookup).
    assert source.count("SELECT * FROM ati.") == 1


def test_sf04b_stored_function_invocation_uses_only_bind_parameters() -> None:
    """The invocation text carries no literal SQL fragments or interpolation."""
    source = getsource(PostgresGraphQueryService.traverse)
    assert "text(" in source
    # The SQL region is a plain (non-f-string) literal: it must contain no
    # interpolation braces and exactly the canonical bind-parameter text.
    sql_start = source.index("SELECT * FROM ati.traverse_graph(")
    sql_end = source.index(":limit)", sql_start)
    sql_region = source[sql_start:sql_end]
    assert "{" not in sql_region and "}" not in sql_region
    # Every parameter must arrive through the bind-parameter map.
    for name in (
        "investigation_id",
        "entity_id",
        "max_depth",
        "scope",
        "direction",
        "relationship_type",
        "entity_type",
        "source",
        "observed_from",
        "observed_to",
        "limit",
    ):
        assert f":{name}" in source
        assert f'"{name}":' in source


def test_sf04c_neighborhood_uses_no_stored_function() -> None:
    """The one-hop read keeps its established direct SQLAlchemy shape."""
    neighborhood_source = getsource(PostgresGraphQueryService.neighborhood)
    assert "traverse_graph" not in neighborhood_source
    assert "SELECT * FROM ati." not in neighborhood_source
