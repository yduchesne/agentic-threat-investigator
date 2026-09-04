# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for deterministic retrieval metrics."""

from collections.abc import Callable, Sequence

import pytest

from agentic_threat_investigator.evaluation.retrieval import (
    expected_source_rank,
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
)


def test_retrieval_metrics_handle_top_k_and_duplicates() -> None:
    """Duplicate malformed results do not inflate metric scores."""
    retrieved = ["a", "a", "noise", "b"]
    assert recall_at_k(retrieved, ["a", "b"], 4) == 1.0
    assert precision_at_k(retrieved, ["a", "b"], 3) == pytest.approx(1 / 2)
    assert reciprocal_rank(retrieved, ["b"]) == pytest.approx(1 / 4)


def test_retrieval_metrics_handle_empty_results_and_short_corpus() -> None:
    """Precision does not penalize a corpus with fewer than k results."""
    assert precision_at_k([], ["relevant"], 5) == 0.0
    assert precision_at_k(["relevant"], ["relevant"], 5) == 1.0
    assert reciprocal_rank(["noise"], ["relevant"]) == 0.0


@pytest.mark.parametrize("metric", [recall_at_k, precision_at_k])
def test_metrics_reject_nonpositive_k(
    metric: Callable[[Sequence[str], Sequence[str], int], float],
) -> None:
    """All top-k metrics require a positive k."""
    with pytest.raises(ValueError):
        metric(["a"], ["a"], 0)


def test_recall_and_mrr_require_relevance_truth() -> None:
    """Recall and MRR cannot be evaluated without relevant IDs."""
    with pytest.raises(ValueError):
        recall_at_k(["a"], [], 1)
    with pytest.raises(ValueError):
        reciprocal_rank(["a"], [])


def test_expected_source_rank_returns_first_rank_or_none() -> None:
    """Expected-source rank is one-based and reports absent sources."""
    assert expected_source_rank(["other", "expected", "expected"], "expected") == 2
    assert expected_source_rank(["other"], "missing") is None
