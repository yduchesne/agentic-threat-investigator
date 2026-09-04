# SPDX-License-Identifier: AGPL-3.0-only
"""Provider-independent metrics for deterministic retrieval evaluation."""

from collections.abc import Sequence
from typing import TypeVar

T = TypeVar("T")


def _top_unique(values: Sequence[T], k: int) -> list[T]:
    """Return the first occurrence of each value in the first k positions."""
    if k <= 0:
        raise ValueError("k must be positive")
    result: list[T] = []
    for value in values[:k]:
        if value not in result:
            result.append(value)
    return result


def recall_at_k(retrieved_ids: Sequence[T], relevant_ids: Sequence[T], k: int) -> float:
    """Return relevant IDs found in top-k divided by relevance truth.

    Relevance must be non-empty and duplicate retrieved IDs count once.
    """
    if not relevant_ids:
        raise ValueError("relevant_ids must not be empty")
    top = set(_top_unique(retrieved_ids, k))
    relevant = set(relevant_ids)
    return len(top & relevant) / len(relevant)


def precision_at_k(
    retrieved_ids: Sequence[T], relevant_ids: Sequence[T], k: int
) -> float:
    """Return hits divided by the number of unique returned top-k items."""
    top = _top_unique(retrieved_ids, k)
    if not top:
        return 0.0
    return len(set(top) & set(relevant_ids)) / len(top)


def reciprocal_rank(retrieved_ids: Sequence[T], relevant_ids: Sequence[T]) -> float:
    """Return reciprocal first relevant rank, or zero when none is returned."""
    if not relevant_ids:
        raise ValueError("relevant_ids must not be empty")
    relevant = set(relevant_ids)
    seen: set[T] = set()
    for rank, value in enumerate(retrieved_ids, 1):
        if value in seen:
            continue
        seen.add(value)
        if value in relevant:
            return 1.0 / rank
    return 0.0


def expected_source_rank(
    retrieved_source_ids: Sequence[str], expected_source_id: str
) -> int | None:
    """Return the first 1-based rank of a source, or ``None`` if absent."""
    for rank, source_id in enumerate(retrieved_source_ids, 1):
        if source_id == expected_source_id:
            return rank
    return None
