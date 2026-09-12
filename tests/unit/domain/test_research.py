# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for contextual research domain contracts."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchQuery,
    ResearchResult,
    RetrievedChunk,
    research_citation_from_retrieved_chunk,
)


def _retrieved_chunk(**overrides: object) -> RetrievedChunk:
    """Build a minimal valid retrieved chunk for provenance tests."""
    values: dict[str, object] = {
        "chunk_id": uuid4(),
        "citation_id": uuid4(),
        "document_id": uuid4(),
        "source_id": "synthetic://source",
        "source_record_id": "record-1",
        "document_type": "advisory",
        "chunk_sequence": 1,
        "text": "untrusted retrieved text",
    }
    values.update(overrides)
    return RetrievedChunk.model_validate(values)


def _research_citation(citation_id: UUID) -> ResearchCitation:
    """Build a minimal valid citation snapshot."""
    return ResearchCitation(
        citation_id=citation_id,
        document_id=uuid4(),
        source_id="urn:test:source",
        source_record_id="record-1",
        document_type="advisory",
        chunk_sequence=1,
        text="Cited chunk text",
    )


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
    chunk = _retrieved_chunk(
        published_at=datetime(2026, 1, 1, 1, tzinfo=UTC),
        similarity_score=-1.0,
        metadata=metadata,
    )
    metadata["nested"]["values"].append("outside")
    assert chunk.metadata["nested"]["values"] == ("one",)
    with pytest.raises(TypeError):
        chunk.metadata["new"] = "value"


def test_retrieved_chunk_exposes_citation_and_source_provenance() -> None:
    """The retrieval surface carries stable citation and source identities."""
    citation_id = uuid4()
    chunk = _retrieved_chunk(
        citation_id=citation_id,
        source_record_id="attack-pattern--one",
        document_type="attack_technique",
        chunk_sequence=3,
    )
    assert chunk.citation_id == citation_id
    assert chunk.source_record_id == "attack-pattern--one"
    assert chunk.document_type == "attack_technique"
    assert chunk.chunk_sequence == 3


def test_citation_from_retrieved_chunk_is_a_durable_snapshot() -> None:
    """The helper copies the full provenance surface without row coupling."""
    retrieved = _retrieved_chunk(
        title="Title",
        source_url="https://example.test/doc",
        published_at=datetime(2026, 1, 1, tzinfo=UTC),
        similarity_score=0.9,
        metadata={"nested": {"values": ["one"]}},
    )
    citation = research_citation_from_retrieved_chunk(retrieved)
    assert citation.citation_id == retrieved.citation_id
    assert citation.document_id == retrieved.document_id
    assert citation.source_record_id == retrieved.source_record_id
    assert citation.document_type == retrieved.document_type
    assert citation.chunk_sequence == retrieved.chunk_sequence
    assert citation.chunk_id == retrieved.chunk_id
    assert citation.similarity_score == 0.9
    assert citation.metadata["nested"]["values"] == ("one",)


@pytest.mark.parametrize("score", [-1.0001, 1.0001, float("nan"), float("inf")])
def test_retrieved_chunk_rejects_invalid_scores(score: float) -> None:
    """Similarity scores must be finite values in the cosine interval."""
    with pytest.raises(ValidationError):
        _retrieved_chunk(similarity_score=score)


@pytest.mark.parametrize(
    "field",
    ["source_id", "source_record_id", "document_type", "text"],
)
def test_retrieved_chunk_rejects_blank_provenance(field: str) -> None:
    """Every provenance identifier and the chunk text must be nonblank."""
    with pytest.raises(ValidationError):
        _retrieved_chunk(**{field: " "})


def test_retrieved_chunk_rejects_naive_time() -> None:
    """Optional provenance timestamps retain the UTC safety check."""
    with pytest.raises(ValidationError):
        _retrieved_chunk(published_at=datetime(2026, 1, 1))


def test_research_claim_requires_citations_and_unique_ids() -> None:
    """Claims need at least one citation and reject duplicate references."""
    citation_id = uuid4()
    claim = ResearchClaim(id=uuid4(), text=" claim ", citation_ids=(citation_id,))
    assert claim.text == "claim"
    with pytest.raises(ValidationError):
        ResearchClaim(id=uuid4(), text="uncited", citation_ids=())
    with pytest.raises(ValidationError):
        ResearchClaim(
            id=uuid4(),
            text="duplicated",
            citation_ids=(citation_id, citation_id),
        )
    with pytest.raises(ValidationError):
        ResearchClaim(id=uuid4(), text=" ", citation_ids=(citation_id,))


def test_research_citation_is_a_frozen_strict_snapshot() -> None:
    """Citation snapshots freeze metadata and reject blank provenance."""
    citation = _research_citation(uuid4())
    with pytest.raises(ValidationError):
        _research_citation(uuid4()).model_validate(
            {
                **citation.model_dump(mode="python"),
                "unknown": True,
            }
        )
    with pytest.raises(ValidationError):
        ResearchCitation(
            citation_id=uuid4(),
            document_id=uuid4(),
            source_id="urn:test:source",
            source_record_id=" ",
            document_type="advisory",
            chunk_sequence=1,
            text="text",
        )


def test_research_result_closure_and_frozen_contract() -> None:
    """Claims must cite included snapshots; results are immutable and strict."""
    citation_id = uuid4()
    citation = _research_citation(citation_id=citation_id)
    claim_id = uuid4()

    valid = ResearchResult(
        id=uuid4(),
        investigation_id=uuid4(),
        subject_entity_id=uuid4(),
        query="  persistence techniques  ",
        claims=(
            ResearchClaim(id=claim_id, text=" claim ", citation_ids=(citation_id,)),
        ),
        citations=(citation,),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert valid.query == "persistence techniques"
    assert valid.claims[0].text == "claim"
    with pytest.raises(ValidationError):
        ResearchResult.model_validate(
            {
                **valid.model_dump(mode="python"),
                "id": uuid4(),
                "claims": (
                    {
                        "id": claim_id,
                        "text": "claim",
                        "citation_ids": (citation_id,),
                    },
                    {
                        "id": uuid4(),
                        "text": "second claim",
                        "citation_ids": (citation_id,),
                    },
                ),
                "claims_duplicated": True,
            }
        )


@pytest.mark.parametrize(
    ("claim_ids", "citation_ids", "result_citation_ids", "query", "created_at"),
    [
        # R2 uncited claim (empty citation list).
        ((uuid4(),), ((),), (uuid4(),), "query", datetime(2026, 1, 1, tzinfo=UTC)),
        # R3 claim cites a citation absent from the result snapshot.
        (
            (uuid4(),),
            ((uuid4(),),),
            (uuid4(),),
            "query",
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
        # R9 blank query.
        ((), (), (), " ", datetime(2026, 1, 1, tzinfo=UTC)),
        # R8 naive (non-UTC) created_at.
        ((), (), (), "query", datetime(2026, 1, 1)),
    ],
)
def test_research_result_rejects_invalid_structures(
    claim_ids: tuple[UUID, ...],
    citation_ids: tuple[tuple[object, ...], ...],
    result_citation_ids: tuple[UUID, ...],
    query: str,
    created_at: datetime,
) -> None:
    """ResearchResult rejects closure, blank, and timezone violations."""
    citations = tuple(_research_citation(cid) for cid in result_citation_ids)
    with pytest.raises(ValidationError):
        ResearchResult.model_validate(
            {
                "id": uuid4(),
                "investigation_id": uuid4(),
                "subject_entity_id": uuid4(),
                "query": query,
                "claims": [
                    {
                        "id": claim_id,
                        "text": "claim text",
                        "citation_ids": tuple(ids),
                    }
                    for claim_id, ids in zip(claim_ids, citation_ids, strict=True)
                ],
                "citations": citations,
                "created_at": created_at,
            }
        )


def test_research_result_accepts_zero_claims_and_zero_citations() -> None:
    """No-context results are valid without inventing Evidence."""
    result = ResearchResult(
        id=uuid4(),
        investigation_id=uuid4(),
        subject_entity_id=uuid4(),
        query="query",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert result.claims == () and result.citations == ()


def test_research_result_rejects_duplicate_citation_ids() -> None:
    """Citation snapshots inside one result must have unique citation IDs."""
    citation_id = uuid4()
    citation = _research_citation(citation_id=citation_id)
    with pytest.raises(ValidationError, match="unique citation_ids"):
        ResearchResult(
            id=uuid4(),
            investigation_id=uuid4(),
            subject_entity_id=uuid4(),
            query="query",
            claims=(
                ResearchClaim(id=uuid4(), text="one", citation_ids=(citation_id,)),
            ),
            citations=(citation, citation),
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_research_result_rejects_blank_claim_text() -> None:
    """A claim with blank text is rejected even inside a valid result."""
    citation_id = uuid4()
    with pytest.raises(ValidationError):
        ResearchResult.model_validate(
            {
                "id": uuid4(),
                "investigation_id": uuid4(),
                "subject_entity_id": uuid4(),
                "query": "query",
                "claims": [
                    {
                        "id": uuid4(),
                        "text": " ",
                        "citation_ids": (citation_id,),
                    }
                ],
                "citations": [
                    _research_citation(citation_id=citation_id).model_dump(
                        mode="python"
                    )
                ],
                "created_at": datetime(2026, 1, 1, tzinfo=UTC),
            }
        )


def test_research_result_rejects_duplicate_claim_ids() -> None:
    """Claim identities remain unique inside one result."""
    citation_id = uuid4()
    claim_id = uuid4()
    citation = _research_citation(citation_id=citation_id)
    with pytest.raises(ValidationError, match="unique ids"):
        ResearchResult(
            id=uuid4(),
            investigation_id=uuid4(),
            subject_entity_id=uuid4(),
            query="query",
            claims=(
                ResearchClaim(id=claim_id, text="one", citation_ids=(citation_id,)),
                ResearchClaim(id=claim_id, text="two", citation_ids=(citation_id,)),
            ),
            citations=(citation,),
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_research_result_is_frozen_and_strict() -> None:
    """Results are immutable and reject extra fields."""
    result = ResearchResult(
        id=uuid4(),
        investigation_id=uuid4(),
        subject_entity_id=uuid4(),
        query="query",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(ValidationError):
        ResearchResult.model_validate(
            {
                **result.model_dump(mode="python"),
                "verdict": "benign",
            }
        )
    with pytest.raises((ValidationError, TypeError)):
        result.query = "changed"
