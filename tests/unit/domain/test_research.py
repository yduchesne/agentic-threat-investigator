# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for contextual research domain contracts."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.research import ResearchQuery, RetrievedChunk


def test_query_normalizes_filters_and_preserves_serialization_shape() -> None:
    """Queries trim values and retain list-shaped public fields."""
    investigation_id = uuid4()
    entity_id = uuid4()
    query = ResearchQuery(
        investigation_id=investigation_id,
        query="  suspicious persistence  ",
        entity_ids=[entity_id, entity_id],
        source_ids=[" source-a ", "source-a", "source-b"],
        document_types=[" advisory ", "advisory"],
    )

    assert query.query == "suspicious persistence"
    assert query.entity_ids == [entity_id]
    assert query.source_ids == ["source-a", "source-b"]
    assert query.document_types == ["advisory"]
    assert isinstance(query.model_dump()["source_ids"], list)
    assert query.max_results == 8


@pytest.mark.parametrize("value", [0, 101])
def test_query_bounds_max_results(value: int) -> None:
    """The retrieval boundary rejects unbounded or empty result requests."""
    with pytest.raises(ValidationError):
        ResearchQuery(investigation_id=uuid4(), query="query", max_results=value)


@pytest.mark.parametrize("field", ["query", "source_ids", "document_types"])
def test_query_rejects_blank_values(field: str) -> None:
    """Queries reject blank query and filter values."""
    values: dict[str, Any] = {"investigation_id": uuid4(), "query": "valid"}
    values[field] = " " if field == "query" else [" "]
    with pytest.raises(ValidationError):
        ResearchQuery.model_validate(values)


def test_query_is_frozen_and_rejects_extra_fields() -> None:
    """The public query contract is strict and immutable by assignment."""
    query = ResearchQuery(investigation_id=uuid4(), query="query")
    with pytest.raises(ValidationError):
        ResearchQuery.model_validate(
            {"investigation_id": uuid4(), "query": "query", "unknown": True}
        )
    with pytest.raises(ValidationError):
        query.query = "changed"


def test_retrieved_chunk_freezes_metadata_and_normalizes_timestamp() -> None:
    """Returned metadata is defensive and timestamps are normalized to UTC."""
    metadata = {"nested": {"values": ["one"]}}
    chunk = RetrievedChunk(
        chunk_id=uuid4(),
        document_id=uuid4(),
        source_id="synthetic://source",
        text="untrusted retrieved text",
        published_at=datetime(2026, 1, 1, 1, tzinfo=UTC),
        similarity_score=-1.0,
        metadata=metadata,
    )
    metadata["nested"]["values"].append("outside")
    assert chunk.metadata["nested"]["values"] == ("one",)
    with pytest.raises(TypeError):
        chunk.metadata["new"] = "value"


@pytest.mark.parametrize("score", [-1.0001, 1.0001, float("nan"), float("inf")])
def test_retrieved_chunk_rejects_invalid_scores(score: float) -> None:
    """Similarity scores must be finite values in the cosine interval."""
    with pytest.raises(ValidationError):
        RetrievedChunk(
            chunk_id=uuid4(),
            document_id=uuid4(),
            source_id="source",
            text="text",
            similarity_score=score,
        )


def test_retrieved_chunk_rejects_blank_identity_and_naive_time() -> None:
    """Provenance and optional timestamps retain the domain safety checks."""
    with pytest.raises(ValidationError):
        RetrievedChunk(
            chunk_id=uuid4(),
            document_id=uuid4(),
            source_id=" ",
            text="text",
        )
    with pytest.raises(ValidationError):
        RetrievedChunk(
            chunk_id=uuid4(),
            document_id=uuid4(),
            source_id="source",
            text=" ",
            published_at=datetime(2026, 1, 1),
        )
