# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic research retrieval evaluation (PR 22D).

The evaluator consumes an ordered ``RetrievedChunk`` sequence produced by the
production retriever plus one :class:`ResearchRetrievalScenario`. Relevance
is author-declared through stable upstream identities (``source_record_id``,
``source_id``, ``document_type``); free-form text is never inspected, no
embedding is computed here, and no LLM participates. Metric arithmetic
reuses the production-independent helpers in
:mod:`agentic_threat_investigator.evaluation.retrieval`.
"""

from __future__ import annotations

from collections.abc import Sequence

from agentic_threat_investigator.domain.research import RetrievedChunk
from agentic_threat_investigator.evaluation.research.models import (
    ResearchRetrievalEvaluationResult,
    ResearchRetrievalFailureCode,
    ResearchRetrievalMetrics,
    ResearchRetrievalScenario,
)
from agentic_threat_investigator.evaluation.retrieval import (
    expected_source_rank,
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
)

# Stable deterministic emission order for duplicate retrieval identities.
_DUPLICATE_ORDER: tuple[ResearchRetrievalFailureCode, ...] = (
    ResearchRetrievalFailureCode.DUPLICATE_RETRIEVAL_IDENTITY,
    ResearchRetrievalFailureCode.FILTER_VIOLATION,
    ResearchRetrievalFailureCode.EXPECTED_RETRIEVAL_GAP_NOT_OBSERVED,
    ResearchRetrievalFailureCode.UNEXPECTED_NONEMPTY_RETRIEVAL,
    ResearchRetrievalFailureCode.REQUIRED_RECORD_NOT_RETRIEVED,
    ResearchRetrievalFailureCode.EXPECTED_SOURCE_MISSING,
    ResearchRetrievalFailureCode.EXPECTED_RANK_VIOLATION,
    ResearchRetrievalFailureCode.FORBIDDEN_RECORD_RETRIEVED,
)
"""Deterministic failure-code ordering (never set-iteration based)."""


class ResearchRetrievalEvaluator:
    """Evaluate one ordered retrieval response against one scenario.

    Synchronous and pure: no database, network, LLM, environment, or clock
    access. Duplicate chunk identities count once for metrics and are
    reported as a stable failure; an explicit retrieval gap requires an
    empty response; filter expectations are enforced from the durable
    provenance fields of each returned chunk.
    """

    def evaluate(
        self,
        *,
        scenario: ResearchRetrievalScenario,
        chunks: Sequence[RetrievedChunk],
    ) -> ResearchRetrievalEvaluationResult:
        """Return stable failures and denominator-safe retrieval metrics."""
        failures: set[ResearchRetrievalFailureCode] = set()
        ordered = tuple(chunks)

        # Duplicate stable chunk identities can never safely disambiguate.
        citation_ids = [chunk.citation_id for chunk in ordered]
        if len(citation_ids) != len(set(citation_ids)):
            failures.add(ResearchRetrievalFailureCode.DUPLICATE_RETRIEVAL_IDENTITY)

        # Filter boundaries: every returned chunk must honour the scenario's
        # declared source/document-type provenance constraints.
        if scenario.source_ids:
            allowed_sources = set(scenario.source_ids)
            if any(chunk.source_id not in allowed_sources for chunk in ordered):
                failures.add(ResearchRetrievalFailureCode.FILTER_VIOLATION)
        if scenario.document_types:
            allowed_types = set(scenario.document_types)
            if any(chunk.document_type not in allowed_types for chunk in ordered):
                failures.add(ResearchRetrievalFailureCode.FILTER_VIOLATION)

        if scenario.expected_retrieval_gap:
            if ordered:
                failures.add(
                    ResearchRetrievalFailureCode.EXPECTED_RETRIEVAL_GAP_NOT_OBSERVED
                )
        else:
            declared_nothing = not (
                scenario.expected_relevant_source_records
                or scenario.expected_forbidden_source_records
                or scenario.expected_source_ids
                or scenario.expected_document_types
            )
            if declared_nothing and ordered:
                failures.add(ResearchRetrievalFailureCode.UNEXPECTED_NONEMPTY_RETRIEVAL)

        retrieved_records = tuple(chunk.source_record_id for chunk in ordered)
        relevant = tuple(scenario.expected_relevant_source_records)
        retrieved_set = set(retrieved_records)

        for record in relevant:
            if record not in retrieved_set:
                failures.add(ResearchRetrievalFailureCode.REQUIRED_RECORD_NOT_RETRIEVED)
        forbidden_set = set(scenario.expected_forbidden_source_records)
        for record in forbidden_set:
            if record in retrieved_set:
                failures.add(ResearchRetrievalFailureCode.FORBIDDEN_RECORD_RETRIEVED)

        retrieved_sources = {chunk.source_id for chunk in ordered}
        for source_id in scenario.expected_source_ids:
            if source_id not in retrieved_sources:
                failures.add(ResearchRetrievalFailureCode.EXPECTED_SOURCE_MISSING)

        for expected_type in scenario.expected_document_types:
            if not any(chunk.document_type == expected_type for chunk in ordered):
                failures.add(ResearchRetrievalFailureCode.EXPECTED_SOURCE_MISSING)
        if scenario.expected_max_source_rank is not None and relevant:
            first_rank = expected_source_rank(retrieved_records, relevant[0])
            if (
                first_rank is not None
                and first_rank > scenario.expected_max_source_rank
            ):
                failures.add(ResearchRetrievalFailureCode.EXPECTED_RANK_VIOLATION)

        # Deterministic ordered failure emission; set membership above feeds a
        # stable ordering pass, never the other way around.
        seen: set[ResearchRetrievalFailureCode] = set()
        ordered_failures: list[ResearchRetrievalFailureCode] = []
        for code in _DUPLICATE_ORDER:
            if code in failures and code not in seen:
                seen.add(code)
                ordered_failures.append(code)

        metrics = self._metrics(scenario, chunks)
        return ResearchRetrievalEvaluationResult(
            passed=not ordered_failures,
            failures=tuple(ordered_failures),
            metrics=metrics,
        )

    @staticmethod
    def _metrics(
        scenario: ResearchRetrievalScenario,
        chunks: Sequence[RetrievedChunk],
    ) -> ResearchRetrievalMetrics:
        """Compute denominator-safe metrics from the same identities used above."""
        retrieved_records = tuple(chunk.source_record_id for chunk in chunks)
        relevant = tuple(scenario.expected_relevant_source_records)
        k = scenario.max_results
        if relevant:
            recall = recall_at_k(retrieved_records, relevant, k)
            precision = precision_at_k(retrieved_records, relevant, k)
            mrr = reciprocal_rank(retrieved_records, relevant)
            first_relevant = expected_source_rank(retrieved_records, relevant[0])
        elif scenario.expected_retrieval_gap:
            recall = 1.0
            precision = 1.0
            mrr = None
            first_relevant = None
        else:
            recall = None
            precision = None
            mrr = None
            first_relevant = None
        return ResearchRetrievalMetrics(
            recall_at_k=recall,
            precision_at_k=precision,
            mrr=mrr,
            expected_source_rank=first_relevant,
        )
