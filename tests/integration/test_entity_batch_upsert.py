# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL integration coverage for the v0003 entity batch upsert contract.

Covers the full ``docs/TESTING.md`` "Batch persistence and history tests"
checklist: composite-array input, ordinal correlation, INSERTED/UPDATED/
UNCHANGED/CONFLICT outcomes, within-batch duplicates, optimistic conflicts,
set-based version allocation and history insertion, JSONB diff semantics
through the batch path, the application and defensive batch limits, and
transaction rollback semantics.
"""

from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    BatchSizeLimitExceededError,
    EntityBatchItem,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)


def _entity(
    value: str,
    *,
    display_name: str | None = None,
    attributes: dict[str, Any] | None = None,
    entity_id: UUID | None = None,
) -> Entity:
    """Build a domain entity fixture for one canonical domain identity."""
    return Entity(
        id=entity_id,
        type=EntityType.DOMAIN,
        value=value,
        display_name=display_name,
        attributes=attributes if attributes is not None else {},
    )


async def _history(
    session: AsyncSession, entity_id: UUID
) -> list[tuple[str, dict[str, Any]]]:
    """Return the immutable (operation, diff) history of one entity."""
    result = await session.execute(
        text(
            """SELECT operation, diff FROM ati.domain_object_history
                WHERE object_type = 'entity' AND object_id = :id
                ORDER BY version"""
        ),
        {"id": entity_id},
    )
    return [(row[0], row[1]) for row in result]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_batch_mixes_outcomes_with_ordinal_correlation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """One batch returns INSERTED/UPDATED/UNCHANGED correlated by ordinal."""
    async with uow_factory() as uow:
        to_update = await uow.entities.upsert(_entity("update.example"))
        to_keep = await uow.entities.upsert(_entity("keep.example"))
        assert to_update.version is not None
        assert to_keep.version is not None
        results = await uow.entities.upsert_batch(
            [
                EntityBatchItem(
                    entity=_entity("update.example", display_name="Renamed")
                ),
                EntityBatchItem(entity=_entity("keep.example")),
                EntityBatchItem(entity=_entity("fresh.example")),
            ]
        )
        assert [result.ordinal for result in results] == [1, 2, 3]
        assert [result.outcome for result in results] == [
            BatchOutcome.UPDATED,
            BatchOutcome.UNCHANGED,
            BatchOutcome.INSERTED,
        ]
        assert results[0].entity_id == to_update.id
        assert results[0].version is not None and (
            results[0].version > to_update.version
        )
        assert results[1].entity_id == to_keep.id
        assert results[1].version == to_keep.version
        assert results[2].entity_id not in {to_update.id, to_keep.id}
        assert results[2].version is not None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_unchanged_rows_receive_no_new_version_or_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """UNCHANGED rows keep their version and produce no history record."""
    async with uow_factory() as uow:
        created = await uow.entities.upsert(_entity("same.example"))
        assert created.id is not None
        assert created.version is not None
        assert uow.session is not None
        before = await _history(uow.session, created.id)
        results = await uow.entities.upsert_batch(
            [EntityBatchItem(entity=_entity("same.example"))]
        )
        assert results[0].outcome is BatchOutcome.UNCHANGED
        assert results[0].version == created.version
        assert results[0].entity_id == created.id
        after = await _history(uow.session, created.id)
        assert after == before == [("CREATE", {})]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_stale_expected_version_conflicts_without_mutation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A stale expected_version yields CONFLICT with no mutation or history."""
    async with uow_factory() as uow:
        created = await uow.entities.upsert(
            _entity("stale.example", display_name="Original")
        )
        assert created.id is not None
        assert created.version is not None
        stale_version = created.version + 100
        results = await uow.entities.upsert_batch(
            [
                EntityBatchItem(
                    entity=_entity("stale.example", display_name="Hacked"),
                    expected_version=stale_version,
                )
            ]
        )
        assert results[0].outcome is BatchOutcome.CONFLICT
        assert results[0].version == created.version
        assert results[0].entity_id == created.id
        assert uow.session is not None
        assert await _history(uow.session, created.id) == [("CREATE", {})]
    async with uow_factory() as uow:
        reloaded = await uow.entities.get_by_identity("domain", "stale.example")
        assert reloaded is not None
        assert reloaded.display_name == "Original"
        assert reloaded.version == results[0].version


@pytest.mark.asyncio
@pytest.mark.integration
async def test_within_batch_duplicates_classify_conflict_deterministically(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The lowest-ordinal duplicate wins; later duplicates are CONFLICT."""
    async with uow_factory() as uow:
        results = await uow.entities.upsert_batch(
            [
                EntityBatchItem(entity=_entity("dup.example", display_name="First")),
                EntityBatchItem(entity=_entity("dup.example", display_name="Second")),
                EntityBatchItem(entity=_entity("dup.example")),
            ]
        )
        assert [result.outcome for result in results] == [
            BatchOutcome.INSERTED,
            BatchOutcome.CONFLICT,
            BatchOutcome.CONFLICT,
        ]
        winning = results[0]
        assert len({result.entity_id for result in results}) == 1
        assert len({result.version for result in results}) == 1
        assert uow.session is not None
        assert winning.entity_id is not None
        assert await _history(uow.session, winning.entity_id) == [("CREATE", {})]

        # The lowest ordinal wins regardless of content: renaming proposals in
        # a later duplicate position are rejected without aborting the batch.
        renamed = await uow.entities.upsert_batch(
            [
                EntityBatchItem(entity=_entity("dup.example", display_name="First")),
                EntityBatchItem(entity=_entity("dup.example", display_name="Rejected")),
            ]
        )
        assert [result.outcome for result in renamed] == [
            BatchOutcome.UNCHANGED,
            BatchOutcome.CONFLICT,
        ]
    async with uow_factory() as uow:
        stored = await uow.entities.get_by_identity("domain", "dup.example")
        assert stored is not None
        assert stored.display_name == "First"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_large_batch_at_application_boundary(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A batch at the configured application limit writes set-based history."""
    async with uow_factory() as uow:
        items = [
            EntityBatchItem(entity=_entity(f"bulk-{index:03d}.example"))
            for index in range(100)
        ]
        results = await uow.entities.upsert_batch(items)
        assert len(results) == 100
        assert [result.ordinal for result in results] == list(range(1, 101))
        assert all(result.outcome is BatchOutcome.INSERTED for result in results)
        assert len({result.entity_id for result in results}) == 100
        assert all(result.version is not None for result in results)
        with pytest.raises(BatchSizeLimitExceededError):
            await uow.entities.upsert_batch(
                items + [EntityBatchItem(entity=_entity("one-too-many.example"))]
            )
        assert uow.session is not None
        created = await uow.session.execute(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type = 'entity' AND operation = 'CREATE'"
            )
        )
        assert created.scalar_one() == 100


@pytest.mark.asyncio
@pytest.mark.integration
async def test_defensive_hard_ceiling_raises(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The database hard ceiling above 10000 items aborts with 22023."""
    async with session_factory() as session:
        with pytest.raises(DBAPIError) as excinfo:
            async with session.begin():
                await session.execute(
                    text(
                        """SELECT ordinal, id, version, outcome FROM ati.upsert_entities(
                             ARRAY(SELECT (g::bigint, NULL, 'domain', 'bulk-' || g,
                                            NULL, NULL, NULL, NULL)::ati.entity_batch_item
                                   FROM generate_series(1, 10001) AS g))"""
                    )
                )
    assert "defensive limit" in str(excinfo.value)
    sqlstate = getattr(excinfo.value.orig, "sqlstate", None)
    assert sqlstate == "22023"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_batch_update_history_diff_semantics(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Batch UPDATE history records the canonical shallow JSONB row diff.

    The diff is shallow over the complete post-operation row state: attribute
    changes appear as one atomic change of the ``attributes`` column, and the
    granular missing-versus-null and nested-object cases of
    ``ati.ati_jsonb_diff`` are covered directly in ``test_migration.py``.
    """
    initial: dict[str, dict[str, Any]] = {
        "scalar.example": {"score": 20},
        "addition.example": {"a": 1},
        "removal.example": {"a": 1, "b": 2},
        "null-value.example": {},
        "nested.example": {"cfg": {"x": 1}},
        "metadata.example": {"a": 1},
        "null-identical.example": {"a": None},
    }
    async with uow_factory() as uow:
        created: dict[str, UUID] = {}
        for value, attributes in initial.items():
            entity = await uow.entities.upsert(_entity(value, attributes=attributes))
            assert entity.id is not None
            created[value] = entity.id
        updates: dict[str, dict[str, Any]] = {
            "scalar.example": {"score": 30},
            "addition.example": {"a": 1, "b": 2},
            "removal.example": {"a": 1},
            "null-value.example": {"a": None},
            "nested.example": {"cfg": {"x": 2}},
            "metadata.example": {"a": 1},
            "null-identical.example": {"a": None},
        }
        items = [
            EntityBatchItem(
                entity=_entity(
                    value,
                    attributes=attributes,
                    display_name="Renamed" if value == "metadata.example" else None,
                )
            )
            for value, attributes in updates.items()
        ]
        results = await uow.entities.upsert_batch(items)
        by_value = {
            item.entity.value: result
            for item, result in zip(items, results, strict=True)
        }
        assert by_value["null-identical.example"].outcome is BatchOutcome.UNCHANGED
        assert all(
            result.outcome is BatchOutcome.UPDATED
            for value, result in by_value.items()
            if value != "null-identical.example"
        )
        assert uow.session is not None
        diffs: dict[str, dict[str, Any]] = {}
        for value, entity_id in created.items():
            history = await _history(uow.session, entity_id)
            if value == "null-identical.example":
                # Identical JSON null values are not a change: no history row.
                assert history == [("CREATE", {})]
                continue
            assert [operation for operation, _ in history] == ["CREATE", "UPDATE"]
            assert history[0][1] == {}
            diffs[value] = history[1][1]
        assert diffs["scalar.example"] == {
            "attributes": {"old": {"score": 20}, "new": {"score": 30}}
        }
        assert diffs["addition.example"] == {
            "attributes": {"old": {"a": 1}, "new": {"a": 1, "b": 2}}
        }
        assert diffs["removal.example"] == {
            "attributes": {"old": {"a": 1, "b": 2}, "new": {"a": 1}}
        }
        # An explicit JSON null inside attributes is a recorded change; the
        # attributes column itself stays atomic at the top level.
        assert diffs["null-value.example"] == {
            "attributes": {"old": {}, "new": {"a": None}}
        }
        # Nested objects inside attributes stay atomic within the column.
        assert diffs["nested.example"] == {
            "attributes": {
                "old": {"cfg": {"x": 1}},
                "new": {"cfg": {"x": 2}},
            }
        }
        # Only the semantic change is recorded; database-maintained metadata
        # fields are excluded from the human-readable diff.
        assert diffs["metadata.example"] == {
            "display_name": {"old": None, "new": "Renamed"}
        }
        for diff in diffs.values():
            assert (
                not {
                    "version",
                    "created_at",
                    "updated_at",
                    "deleted_at",
                    "deleted_by_actor_id",
                }
                & diff.keys()
            )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_conflict_does_not_abort_surrounding_transaction(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A CONFLICT row neither aborts the batch nor blocks other writes."""
    async with uow_factory() as uow:
        created = await uow.entities.upsert(
            _entity("raced.example", display_name="Original")
        )
        assert created.version is not None
        results = await uow.entities.upsert_batch(
            [
                EntityBatchItem(entity=_entity("survivor.example")),
                EntityBatchItem(
                    entity=_entity("raced.example", display_name="Hacked"),
                    expected_version=created.version + 100,
                ),
            ]
        )
        assert [result.outcome for result in results] == [
            BatchOutcome.INSERTED,
            BatchOutcome.CONFLICT,
        ]
    async with uow_factory() as uow:
        survivor = await uow.entities.get_by_identity("domain", "survivor.example")
        assert survivor is not None
        kept = await uow.entities.get_by_identity("domain", "raced.example")
        assert kept is not None
        assert kept.display_name == "Original"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_caller_rollback_leaves_no_partial_writes(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Rolling back the caller's unit of work discards the whole batch."""

    class Abort(Exception):
        """Sentinel used to abort the unit of work under test."""

    rolled_back_id = uuid4()
    with pytest.raises(Abort):
        async with uow_factory() as uow:
            results = await uow.entities.upsert_batch(
                [
                    EntityBatchItem(
                        entity=_entity("rolled-back.example", entity_id=rolled_back_id)
                    )
                ]
            )
            assert results[0].outcome is BatchOutcome.INSERTED
            raise Abort
    async with uow_factory() as uow:
        assert (
            await uow.entities.get_by_identity("domain", "rolled-back.example") is None
        )
        assert uow.session is not None
        history = await uow.session.execute(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type = 'entity' AND object_id = :id"
            ),
            {"id": rolled_back_id},
        )
        assert history.scalar_one() == 0
