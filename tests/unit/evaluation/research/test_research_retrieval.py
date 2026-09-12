# SPDX-License-Identifier: AGPL-3.0-only
"""ResearchRetrievalEvaluator unit tests (PR 22D, matrix 22D-U01..U12)."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.domain.research import RetrievedChunk
from agentic_threat_investigator.evaluation.research import (
    ResearchRetrievalEvaluator,
    ResearchRetrievalFailureCode,
    ResearchRetrievalScenario,
)

_SOURCE = "urn:ati:source:mitre_attack"


def _chunk(
    record_id: str,
    *,
    source_id: str = _SOURCE,
    document_type: str = "attack_technique",
    citation_id: UUID | None = None,
    chunk_id: UUID | None = None,
) -> RetrievedChunk:
    """Build one deterministic retrieved chunk for unit evaluation."""
    return RetrievedChunk(
        chunk_id=chunk_id or uuid4(),
        citation_id=citation_id or uuid4(),
        document_id=uuid4(),
        source_id=source_id,
        source_record_id=record_id,
        document_type=document_type,
        chunk_sequence=1,
        text="deterministic unit fixture text",
    )


def _scenario(**overrides: Any) -> ResearchRetrievalScenario:
    """Build one retrieval scenario expecting record `record-a` at rank one."""
    params: dict[str, Any] = {
        "id": "unit.retrieval-scenario",
        "version": 1,
        "query": "obfuscate command and control traffic",
        "max_results": 3,
        "expected_relevant_source_records": ("record-a",),
        "expected_source_ids": (_SOURCE,),
        "expected_document_types": ("attack_technique",),
        "expected_max_source_rank": 1,
    }
    params.update(overrides)
    return ResearchRetrievalScenario(**params)


def test_u01_recall_exact_hit() -> None:
    """U01: a first-rank expected record scores perfect recall and passes."""
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=_scenario(),
        chunks=(
            _chunk("record-a"),
            _chunk("record-other", document_type="attack_software"),
            _chunk("record-noise", document_type="attack_software"),
        ),
    )
    assert result.passed, result.failures
    assert result.metrics.recall_at_k == pytest.approx(1.0)
    assert result.metrics.precision_at_k == pytest.approx(1 / 3)
    assert result.metrics.mrr == pytest.approx(1.0)
    assert result.metrics.expected_source_rank == 1


def test_u02_partial_recall() -> None:
    """U02: one missing expected record yields partial recall and a failure."""
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=_scenario(
            expected_relevant_source_records=("record-a", "record-b"),
            max_results=4,
            expected_max_source_rank=None,
        ),
        chunks=(
            _chunk("record-a"),
            _chunk("record-other", document_type="attack_software"),
        ),
    )
    assert not result.passed
    assert ResearchRetrievalFailureCode.REQUIRED_RECORD_NOT_RETRIEVED in result.failures
    assert result.metrics.recall_at_k == pytest.approx(0.5)
    assert result.metrics.mrr == pytest.approx(1.0)


def test_u03_precision_with_extra_results() -> None:
    """U03: precision divides hits by unique returned top-k items."""
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=_scenario(max_results=3, expected_max_source_rank=None),
        chunks=(
            _chunk("record-a"),
            _chunk("record-x", document_type="attack_software"),
            _chunk("record-y", document_type="attack_software"),
        ),
    )
    assert result.metrics.precision_at_k == pytest.approx(1 / 3)
    assert result.metrics.recall_at_k == pytest.approx(1.0)


def test_u04_no_relevant_hit_mrr_zero() -> None:
    """U04: no relevant hit means MRR is zero."""
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=_scenario(expected_document_types=(), expected_max_source_rank=None),
        chunks=(_chunk("record-x", document_type="attack_software"),),
    )
    assert not result.passed
    assert ResearchRetrievalFailureCode.REQUIRED_RECORD_NOT_RETRIEVED in result.failures
    assert result.metrics.mrr == pytest.approx(0.0)


def test_u05_first_relevant_rank_n() -> None:
    """U05: the first relevant identity at rank N yields MRR 1/N."""
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=_scenario(
            max_results=4,
            expected_document_types=(),
            expected_max_source_rank=None,
        ),
        chunks=(
            _chunk("record-x", document_type="attack_software"),
            _chunk("record-y", document_type="attack_software"),
            _chunk("record-a"),
        ),
    )
    assert result.metrics.mrr == pytest.approx(1 / 3)
    assert result.metrics.expected_source_rank == 3
    assert result.passed, result.failures


def test_u06_expected_source_rank_beyond_declared_max_fails() -> None:
    """U06: a relevant record beyond the declared maximum rank is a failure."""
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=_scenario(
            max_results=4,
            expected_document_types=(),
            expected_max_source_rank=1,
        ),
        chunks=(
            _chunk("record-x", document_type="attack_software"),
            _chunk("record-y", document_type="attack_software"),
            _chunk("record-a"),
        ),
    )
    assert not result.passed
    assert ResearchRetrievalFailureCode.EXPECTED_RANK_VIOLATION in result.failures
    assert result.metrics.expected_source_rank == 3


def test_u07_expected_retrieval_gap_with_empty_response_passes() -> None:
    """U07: an explicitly declared gap with an empty response scores perfect."""
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=_scenario(
            expected_relevant_source_records=(),
            expected_source_ids=(),
            expected_document_types=(),
            expected_max_source_rank=None,
            expected_retrieval_gap=True,
        ),
        chunks=(),
    )
    assert result.passed, result.failures
    assert result.metrics.recall_at_k == pytest.approx(1.0)
    assert result.metrics.precision_at_k == pytest.approx(1.0)
    assert result.metrics.mrr is None


def test_u08_expected_records_with_empty_response_fails() -> None:
    """U08: expected records with an empty response fail with zeroed metrics."""
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=_scenario(),
        chunks=(),
    )
    assert not result.passed
    assert ResearchRetrievalFailureCode.REQUIRED_RECORD_NOT_RETRIEVED in result.failures
    assert ResearchRetrievalFailureCode.EXPECTED_SOURCE_MISSING in result.failures
    assert result.metrics.recall_at_k == pytest.approx(0.0)
    assert result.metrics.precision_at_k == pytest.approx(0.0)
    assert result.metrics.mrr == pytest.approx(0.0)


def test_u09_forbidden_record_retrieved_fails() -> None:
    """U09: a forbidden record in the response is a stable failure."""
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=_scenario(
            expected_relevant_source_records=(),
            expected_max_source_rank=None,
            expected_forbidden_source_records=("record-a",),
        ),
        chunks=(_chunk("record-a"),),
    )
    assert not result.passed
    assert result.failures == (ResearchRetrievalFailureCode.FORBIDDEN_RECORD_RETRIEVED,)


def test_u10_source_filter_leak_fails() -> None:
    """U10: a returned chunk outside the declared source filter fails."""
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=_scenario(source_ids=("urn:ati:source:advisories",)),
        chunks=(_chunk("record-a"),),
    )
    assert not result.passed
    assert ResearchRetrievalFailureCode.FILTER_VIOLATION in result.failures


def test_u11_document_type_filter_leak_fails() -> None:
    """U11: a returned chunk outside the declared document-type filter fails."""
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=_scenario(document_types=("attack_software",)),
        chunks=(_chunk("record-a"),),
    )
    assert not result.passed
    assert ResearchRetrievalFailureCode.FILTER_VIOLATION in result.failures


def test_u12_duplicate_retrieval_identity_fails_stably() -> None:
    """U12: an identical citation repeated in the response is a stable failure."""
    citation_id = uuid4()
    chunks = (
        _chunk("record-a", citation_id=citation_id),
        _chunk("record-a", citation_id=citation_id),
    )
    result = ResearchRetrievalEvaluator().evaluate(scenario=_scenario(), chunks=chunks)
    assert not result.passed
    assert result.failures == (
        ResearchRetrievalFailureCode.DUPLICATE_RETRIEVAL_IDENTITY,
    )
    # Duplicates never inflate metric denominators.
    assert result.metrics.recall_at_k == pytest.approx(1.0)
    assert result.metrics.precision_at_k == pytest.approx(1.0)


def test_gap_declared_but_material_returned_fails() -> None:
    """An expected gap that still returns material fails both gap codes."""
    scenario = _scenario(
        expected_relevant_source_records=(),
        expected_source_ids=(),
        expected_document_types=(),
        expected_max_source_rank=None,
        expected_retrieval_gap=True,
    )
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=scenario, chunks=(_chunk("record-x", document_type="attack_software"),)
    )
    assert not result.passed
    assert result.failures == (
        ResearchRetrievalFailureCode.EXPECTED_RETRIEVAL_GAP_NOT_OBSERVED,
    )


def test_no_truth_declared_but_material_returned_fails() -> None:
    """A scenario declaring no truth and no gap must not observe material."""
    scenario = _scenario(
        expected_relevant_source_records=(),
        expected_source_ids=(),
        expected_document_types=(),
        expected_max_source_rank=None,
    )
    result = ResearchRetrievalEvaluator().evaluate(
        scenario=scenario, chunks=(_chunk("record-x"),)
    )
    assert not result.passed
    assert result.failures == (
        ResearchRetrievalFailureCode.UNEXPECTED_NONEMPTY_RETRIEVAL,
    )
    assert result.metrics.recall_at_k is None
    assert result.metrics.precision_at_k is None
    assert result.metrics.mrr is None


def test_failure_ordering_is_deterministic() -> None:
    """Multiple failures emit in the stable documented order, deduplicated."""
    citation = uuid4()
    chunks = (
        _chunk("record-a", citation_id=citation),
        _chunk("record-a", citation_id=citation),
    )
    scenario = _scenario(
        expected_relevant_source_records=("record-missing",),
        expected_forbidden_source_records=("record-a",),
        expected_source_ids=("urn:ati:source:reports",),
        expected_max_source_rank=None,
        source_ids=("urn:ati:source:advisories",),
    )
    result = ResearchRetrievalEvaluator().evaluate(scenario=scenario, chunks=chunks)
    assert result.failures == (
        ResearchRetrievalFailureCode.DUPLICATE_RETRIEVAL_IDENTITY,
        ResearchRetrievalFailureCode.FILTER_VIOLATION,
        ResearchRetrievalFailureCode.REQUIRED_RECORD_NOT_RETRIEVED,
        ResearchRetrievalFailureCode.EXPECTED_SOURCE_MISSING,
        ResearchRetrievalFailureCode.FORBIDDEN_RECORD_RETRIEVED,
    )
