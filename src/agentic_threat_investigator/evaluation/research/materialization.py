# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic research scenario materialization (PR 22D).

Materialization binds the semantic labels a scenario authors to exact
runtime identities observed from the production corpus. It is a pure
function over the exact ordered ``RetrievedChunk`` sequence the production
retriever returns for the scenario's query, so the evaluation harness never
queries by fuzzy value or source name.

Resolution semantics:

* every declaration in ``scenario.source_records`` must resolve to a chunk
  in the supplied set whose ``source_record_id`` matches exactly;
* a label matching several distinct chunk identities is ambiguous and fails
  closed instead of silently picking a winner;
* the resolved ``citation_id`` values and the supplied citation tuple are
  derived from the same deterministic retrieval response.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from agentic_threat_investigator.domain.research import RetrievedChunk
from agentic_threat_investigator.evaluation.research.models import (
    ResearchScenarioResolution,
    ResearchSynthesisScenario,
)


class ResearchScenarioMaterializationError(ValueError):
    """A scenario label cannot be resolved to exactly one persisted identity."""

    def __init__(self, label: str, message: str) -> None:
        """Record the label and deterministic fail-closed message."""
        super().__init__(f"research scenario label {label!r} {message}")
        self.label = label
        self.message = message


def resolve_research_scenario(
    scenario: ResearchSynthesisScenario,
    chunks: Sequence[RetrievedChunk],
) -> ResearchScenarioResolution:
    """Resolve every declared label against one ordered retrieval response.

    Fails closed on unresolved or ambiguous labels; the returned resolution
    is deterministic for the same retrieval response.
    """
    citations: dict[str, UUID] = {}
    for label, source_record_id in scenario.source_records.items():
        matches = [
            chunk.citation_id
            for chunk in chunks
            if chunk.source_record_id == source_record_id
        ]
        distinct = tuple(dict.fromkeys(matches))
        if len(distinct) == 0:
            raise ResearchScenarioMaterializationError(
                label, "was not retrieved for the scenario query"
            )
        if len(distinct) > 1:
            raise ResearchScenarioMaterializationError(
                label, "is ambiguous across multiple retrieved chunks"
            )
        citations[label] = distinct[0]
    return ResearchScenarioResolution(
        citations=citations,
        source_records=dict(scenario.source_records),
    )
