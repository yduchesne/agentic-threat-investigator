# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31H/31I stored-function boundary contract tests (H-SF01..H-SF10, P-SF01..P-SF10).

These tests pin the persistence boundary itself: the migration installs the
``ati.traverse_graph`` and ``ati.find_graph_paths`` stored functions
(H-SF01/H-SF02, P-SF01/P-SF02), the Python adapters invoke exactly the
stored functions with the exact validated parameters and map only returned
rows (H-SF03, P-SF03..P-SF08), and no graph SELECT / recursive CTE / join /
filter / aggregation / endpoint SQL exists in the Python adapter
(H-SF04/H-SF09, P-SF10). Visibility, eligibility, recursion/cycle safety and
canonical aggregation are enforced by the stored-function SQL and are proven
behaviorally by the real-PostgreSQL integration suites; the boundary tests
hold the adapters to their invocation/mapping-only shape.

PR 31I additionally pins the one-hop consolidation: ``neighborhood()`` now
invokes the same ``ati.traverse_graph`` stored function with ``max_depth = 1``
(P-N17), the traversal uses the requested depth, and ``find_paths()`` maps
the explicit metadata row to the ``None``/empty-result distinction (P-SF08/
P-SF09) without a second SQL query.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from inspect import getsource
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.graph import (
    GraphPathQuery,
    GraphPathResult,
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
    endpoints_visible: bool
    path_ordinal: int | None
    path_hop_count: int | None
    path_entity_ids: list[UUID] | None
    path_relationship_ids: list[UUID] | None

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
        endpoints_visible=True,
        path_ordinal=None,
        path_hop_count=None,
        path_entity_ids=None,
        path_relationship_ids=None,
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
        endpoints_visible=True,
        path_ordinal=None,
        path_hop_count=None,
        path_entity_ids=None,
        path_relationship_ids=None,
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


# ---------------------------------------------------------------------------
# H-SF04/H-SF09 + P-SF04/P-SF05 + P-N17: no graph SQL in the Python adapter
# ---------------------------------------------------------------------------


def test_sf04_adapter_contains_no_direct_traversal_sql() -> None:
    """A source review detects any accidental direct traversal SQL (H-SF04/09).

    The shared invocation helper must be a stored-function invocation/mapping
    boundary: it may concatenate the function-call text and bind parameters,
    but it must never contain a traversal SELECT, recursive CTE, join,
    filter/aggregation predicate, or endpoint lookup SQL of its own.
    """
    source = getsource(PostgresGraphQueryService._invoke_traverse_graph)
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
            f"PostgresGraphQueryService._invoke_traverse_graph must not contain "
            f"{forbidden!r}"
        )
    # The only SQL text allowed is exactly the stored-function invocation.
    assert "SELECT * FROM ati.traverse_graph(" in source
    assert source.count("SELECT * FROM ati.traverse_graph(") == 1


def test_sf04b_stored_function_invocation_uses_only_bind_parameters() -> None:
    """The invocation text carries no literal SQL fragments or interpolation."""
    source = getsource(PostgresGraphQueryService._invoke_traverse_graph)
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


def test_pn17_neighborhood_is_traverse_depth_one_via_stored_function() -> None:
    """P-N17/P-SF04: one-hop reads reuse traverse_graph at depth 1.

    After the PR 31I consolidation the neighborhood adapter must not contain
    any SELECT/JOIN/CTE/aggregation SQL of its own: it is the exact shared
    ``_invoke_traverse_graph`` invocation with ``max_depth = 1`` plus row
    mapping only.
    """
    source = getsource(PostgresGraphQueryService.neighborhood)
    assert "_invoke_traverse_graph(" in source
    assert "max_depth=1" in source
    for forbidden in (
        "WITH RECURSIVE",
        "JOIN ati.relationship",
        "JOIN ati.entity",
        "FROM ati.relationship",
        "FROM ati.entity",
        "GROUP BY",
        "order_by(",
        "count(",
        "EXISTS (",
    ):
        assert forbidden not in source, (
            f"PostgresGraphQueryService.neighborhood must not contain {forbidden!r}"
        )
    assert "SELECT * FROM ati.traverse_graph(" not in source
    assert "SELECT * FROM ati." not in source
    traversal_source = getsource(PostgresGraphQueryService.traverse)
    assert "_invoke_traverse_graph(" in traversal_source
    assert "max_depth=query.max_depth" in traversal_source
    assert "SELECT * FROM ati." not in traversal_source


def test_pn17b_no_direct_graph_sql_anywhere_in_adapter_module() -> None:
    """P-N17/P-SF10: the whole adapter module contains no graph query SQL.

    The source-boundary guard scans the entire production adapter module: any
    accidental graph SELECT, recursive CTE, JOIN, aggregation, endpoint lookup
    or ORM graph-row read reappears as an explicit regression. The only SQL
    text allowed anywhere is the two stored-function invocation literals.
    """
    module = inspect.getsource(PostgresGraphQueryService)
    for forbidden in (
        "WITH RECURSIVE",
        "JOIN ati.relationship",
        "JOIN ati.entity",
        "FROM ati.relationship",
        "FROM ati.entity",
        "GROUP BY",
        "SELECT ati.",
        "from ati.",
        "EntityRow",
        "RelationshipObservationRow",
        "aliased(",
        "func.",
    ):
        assert forbidden not in module, (
            f"graph adapter module must not contain {forbidden!r}"
        )
    assert module.count("SELECT * FROM ati.traverse_graph(") == 1
    assert module.count("SELECT * FROM ati.find_graph_paths(") == 1


# --- P-SF: PR 31I path-finding stored-function boundary -----------------------


def _path_query(
    *,
    max_depth: int = 4,
    max_paths: int = 10,
    scope: GraphScope = GraphScope.INVESTIGATION,
    direction: RelationshipDirection = RelationshipDirection.EITHER,
    relationship_type: RelationshipType | None = None,
    entity_type: EntityType | None = None,
    source: str | None = None,
) -> GraphPathQuery:
    """Build one fully-populated path query for boundary tests."""
    return GraphPathQuery(
        investigation_id=INVESTIGATION,
        entity_id=SOURCE_ENTITY,
        target_entity_id=TARGET_ENTITY,
        max_depth=max_depth,
        max_paths=max_paths,
        scope=scope,
        direction=direction,
        relationship_type=relationship_type,
        entity_type=entity_type,
        source=source,
        observed_from=datetime(2026, 1, 1, tzinfo=UTC),
        observed_to=datetime(2026, 2, 1, tzinfo=UTC),
    )


SOURCE_ENTITY = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
TARGET_ENTITY = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


async def _path_result_rows(
    *,
    endpoints_visible: bool = True,
    truncated: bool = False,
) -> list[_Row]:
    """Build the canonical meta + node + edge + path rows of one path result."""
    edge_id = uuid4()
    rows: list[_Row] = [
        _Row(
            kind="meta",
            endpoints_visible=endpoints_visible,
            truncated=truncated,
            node_entity_id=None,
            node_entity_type=None,
            node_canonical_value=None,
            node_display_name=None,
            edge_relationship_id=None,
            edge_source_entity_id=None,
            edge_target_entity_id=None,
            edge_relationship_type_urn=None,
            edge_observation_count=None,
            edge_investigation_observation_count=None,
            edge_first_observed_at=None,
            edge_last_observed_at=None,
            path_ordinal=None,
            path_hop_count=None,
            path_entity_ids=None,
            path_relationship_ids=None,
        ),
        _Row(
            kind="node",
            node_entity_id=SOURCE_ENTITY,
            node_entity_type="domain",
            node_canonical_value="source.test",
            node_display_name=None,
            truncated=truncated,
        ),
        _Row(
            kind="node",
            node_entity_id=TARGET_ENTITY,
            node_entity_type="ip_address",
            node_canonical_value="192.0.2.9",
            node_display_name=None,
            truncated=truncated,
        ),
        _Row(
            kind="edge",
            edge_relationship_id=edge_id,
            edge_source_entity_id=SOURCE_ENTITY,
            edge_target_entity_id=TARGET_ENTITY,
            edge_relationship_type_urn=RelationshipType.RESOLVES_TO.value,
            edge_observation_count=2,
            edge_investigation_observation_count=1,
            edge_first_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
            edge_last_observed_at=datetime(2026, 1, 3, tzinfo=UTC),
            truncated=truncated,
        ),
        _Row(
            kind="path",
            path_ordinal=1,
            path_hop_count=1,
            path_entity_ids=[SOURCE_ENTITY, TARGET_ENTITY],
            path_relationship_ids=[edge_id],
            truncated=truncated,
        ),
    ]
    return rows


@pytest.mark.asyncio
async def test_psf03_adapter_invokes_path_function_with_exact_parameters() -> None:
    """P-SF03/P-SF06: exactly one find_graph_paths call with exact params."""
    session = _RecordingSession(await _path_result_rows())
    service = _service(session)
    query = _path_query(
        scope=GraphScope.KNOWN,
        direction=RelationshipDirection.SOURCE,
        relationship_type=RelationshipType.RESOLVES_TO,
        entity_type=EntityType.IP_ADDRESS,
        source="rdap",
    )

    result = await service.find_paths(query)

    assert result is not None
    assert len(session.executed) == 1
    statement, params = session.executed[0]
    assert "SELECT * FROM ati.find_graph_paths(" in statement
    assert params == {
        "investigation_id": query.investigation_id,
        "source_entity_id": query.entity_id,
        "target_entity_id": query.target_entity_id,
        "max_depth": 4,
        "max_paths": 10,
        "scope": "known",
        "direction": "source",
        "relationship_type": RelationshipType.RESOLVES_TO.value,
        "entity_type": EntityType.IP_ADDRESS.value,
        "source": "rdap",
        "observed_from": datetime(2026, 1, 1, tzinfo=UTC),
        "observed_to": datetime(2026, 2, 1, tzinfo=UTC),
    }
    assert len(result.nodes) == 2
    assert len(result.edges) == 1
    assert len(result.paths) == 1
    path = result.paths[0]
    assert path.entity_ids == (SOURCE_ENTITY, TARGET_ENTITY)
    assert len(path.relationship_ids) == 1
    assert result.truncated is False


@pytest.mark.asyncio
async def test_psf07_path_rows_map_to_canonical_models() -> None:
    """P-SF07: path rows map to GraphPath/GrahNode/GraphEdge canonical models."""
    rows = await _path_result_rows()
    session = _RecordingSession(rows)
    service = _service(session)
    result = await service.find_paths(_path_query())
    assert result is not None
    assert isinstance(result, GraphPathResult)
    assert [node.entity_id for node in result.nodes] == [SOURCE_ENTITY, TARGET_ENTITY]
    edge = result.edges[0]
    assert edge.relationship_id == rows[3].edge_relationship_id
    assert edge.observation_count == 2
    assert edge.investigation_observation_count == 1


@pytest.mark.asyncio
async def test_psf08_endpoint_invalid_meta_maps_to_none() -> None:
    """P-SF08: endpoints_visible=false maps to None (no second query)."""
    rows = await _path_result_rows(endpoints_visible=False)
    session = _RecordingSession(rows)
    service = _service(session)
    assert await service.find_paths(_path_query()) is None
    assert len(session.executed) == 1


@pytest.mark.asyncio
async def test_psf09_no_path_meta_maps_to_empty_result() -> None:
    """P-SF09: visible endpoints with no path rows map to an empty result."""
    session = _RecordingSession(
        [
            _Row(
                kind="meta",
                endpoints_visible=True,
                truncated=False,
                node_entity_id=None,
                node_entity_type=None,
                node_canonical_value=None,
                node_display_name=None,
                edge_relationship_id=None,
                edge_source_entity_id=None,
                edge_target_entity_id=None,
                edge_relationship_type_urn=None,
                edge_observation_count=None,
                edge_investigation_observation_count=None,
                edge_first_observed_at=None,
                edge_last_observed_at=None,
                path_ordinal=None,
                path_hop_count=None,
                path_entity_ids=None,
                path_relationship_ids=None,
            ),
            _Row(
                kind="node",
                node_entity_id=SOURCE_ENTITY,
                node_entity_type="domain",
                node_canonical_value="source.test",
                node_display_name=None,
                truncated=False,
            ),
            _Row(
                kind="node",
                node_entity_id=TARGET_ENTITY,
                node_entity_type="ip_address",
                node_canonical_value="192.0.2.9",
                node_display_name=None,
                truncated=False,
            ),
        ]
    )
    service = _service(session)
    result = await service.find_paths(_path_query())
    assert result is not None
    assert result.paths == ()
    assert result.edges == ()
    assert result.truncated is False
    assert [node.entity_id for node in result.nodes] == [SOURCE_ENTITY, TARGET_ENTITY]
    assert len(session.executed) == 1


@pytest.mark.asyncio
async def test_psf09b_unknown_row_kind_fails_closed() -> None:
    """A stored-function row-kind contract violation fails closed."""
    session = _RecordingSession([_Row(kind="unknown", truncated=False)])
    service = _service(session)
    with pytest.raises(AssertionError, match="unknown row kind"):
        await service.find_paths(_path_query())


@pytest.mark.asyncio
async def test_psf09c_misanchored_path_fails_closed() -> None:
    """A path not anchored at the requested endpoints is an invariant error."""
    rows = await _path_result_rows()
    # Re-anchor the path/edge/node at a different target than the query asked
    # for: structurally valid (the edge connects the path entities and every
    # ID is present) but violating the stored-function anchor contract.
    wrong_target = uuid4()
    rows[2].node_entity_id = wrong_target
    rows[3].edge_target_entity_id = wrong_target
    rows[4].path_entity_ids = [SOURCE_ENTITY, wrong_target]
    rows[4].path_hop_count = 1
    session = _RecordingSession(rows)
    service = _service(session)
    with pytest.raises(AssertionError, match="not anchored at the requested endpoints"):
        await service.find_paths(_path_query())
