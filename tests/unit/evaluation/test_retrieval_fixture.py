# SPDX-License-Identifier: AGPL-3.0-only
"""Schema and integrity tests for repository-owned retrieval fixtures."""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field, model_validator

FIXTURE_PATH = Path("evals/fixtures/research/retrieval_cases.json")


class CorpusChunk(BaseModel):
    """One synthetic corpus or setup-variant chunk."""

    model_config = ConfigDict(extra="forbid")
    id: str
    document_id: str
    source_id: str
    source_record_id: str
    document_type: str
    text: str
    vector_label: str
    embedding_model_version: int = 1
    deleted: bool = False


class ExpectedMetrics(BaseModel):
    """Exact deterministic metric values declared by a fixture case."""

    model_config = ConfigDict(extra="forbid")
    recall_at_k: float
    precision_at_k: float
    mrr: float


class RetrievalCase(BaseModel):
    """Expected retrieval truth for one synthetic query."""

    model_config = ConfigDict(extra="forbid")
    id: str
    version: int = Field(ge=1)
    query: str
    query_vector_label: str
    k: int = Field(gt=0)
    source_ids: list[str]
    document_types: list[str]
    expected_relevant_chunk_ids: list[str]
    expected_source_ids: list[str]
    expected_source_max_rank: int | None = Field(default=None, gt=0)
    forbidden_chunk_ids: list[str]
    expected_retrieval_gap: bool = False
    expected_metrics: ExpectedMetrics | None = None


class RetrievalFixtureSet(BaseModel):
    """Versioned fixture set with cross-reference integrity validation."""

    model_config = ConfigDict(extra="forbid")
    fixture_set_id: str
    fixture_set_version: int = Field(ge=1)
    vector_dimension: int = Field(gt=0)
    corpus: list[CorpusChunk]
    setup_variants: list[CorpusChunk]
    cases: list[RetrievalCase]

    @model_validator(mode="after")
    def validate_references(self) -> "RetrievalFixtureSet":
        """Reject duplicate identities and references to unknown chunks."""
        chunks = self.corpus + self.setup_variants
        chunk_ids = [chunk.id for chunk in chunks]
        case_ids = [case.id for case in self.cases]
        if len(chunk_ids) != len(set(chunk_ids)) or len(case_ids) != len(set(case_ids)):
            raise ValueError("fixture and case IDs must be unique")
        known = set(chunk_ids)
        for case in self.cases:
            referenced = set(
                case.expected_relevant_chunk_ids + case.forbidden_chunk_ids
            )
            if not referenced <= known:
                raise ValueError("case references an unknown chunk ID")
        return self


def _load(values: dict[str, Any] | None = None) -> RetrievalFixtureSet:
    """Load and validate the committed fixture or supplied malformed values."""
    raw: dict[str, Any] = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return RetrievalFixtureSet.model_validate(raw if values is None else values)


def test_committed_fixture_is_versioned_complete_and_valid() -> None:
    """The committed fixture covers every required deterministic scenario."""
    fixture = _load()
    assert fixture.fixture_set_id and fixture.fixture_set_version == 1
    assert fixture.vector_dimension == 1536
    assert {case.id for case in fixture.cases} == {
        "top-k-mrr",
        "multiple-relevant-recall",
        "source-filter",
        "document-type-filter",
        "combined-filter",
        "retrieval-gap",
        "embedding-version-isolation",
        "deleted-parent",
    }


@pytest.mark.parametrize("mutation", ["version", "duplicate", "unknown", "invalid-k"])
def test_fixture_loader_rejects_malformed_truth(mutation: str) -> None:
    """Malformed evaluation truth fails during typed fixture loading."""
    raw: dict[str, Any] = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    if mutation == "version":
        del raw["fixture_set_version"]
    elif mutation == "duplicate":
        raw["corpus"][1]["id"] = raw["corpus"][0]["id"]
    elif mutation == "unknown":
        raw["cases"][0]["expected_relevant_chunk_ids"] = ["unknown"]
    else:
        raw["cases"][0]["k"] = 0
    with pytest.raises(ValueError):
        _load(raw)
