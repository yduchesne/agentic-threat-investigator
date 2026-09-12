# SPDX-License-Identifier: AGPL-3.0-only
"""Research scenario materialization unit tests (PR 22D)."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.domain.research import RetrievedChunk
from agentic_threat_investigator.evaluation.research import (
    ExpectedResearchResult,
    ResearchFixtureReference,
    ResearchScenarioMaterializationError,
    ResearchSynthesisScenario,
    resolve_research_scenario,
)


def _chunk(record_id: str, *, citation_id: UUID | None = None) -> RetrievedChunk:
    """Build one retrieved chunk bound to a stable source record."""
    return RetrievedChunk(
        chunk_id=uuid4(),
        citation_id=citation_id or uuid4(),
        document_id=uuid4(),
        source_id="urn:ati:source:mitre_attack",
        source_record_id=record_id,
        document_type="attack_technique",
        chunk_sequence=1,
        text="deterministic fixture text",
    )


def _scenario(**overrides: Any) -> ResearchSynthesisScenario:
    """Build a synthesis scenario with one declared label."""
    params: dict[str, Any] = {
        "id": "unit.materialization",
        "version": 1,
        "fixture": ResearchFixtureReference(name="mitre-attack-small"),
        "query": "obfuscate command and control traffic",
        "max_results": 3,
        "source_records": {"alpha": "record-a", "beta": "record-b"},
        "expected": ExpectedResearchResult(min_claims=0, required_claims=()),
    }
    params.update(overrides)
    return ResearchSynthesisScenario(**params)


def test_resolution_binds_labels_to_exact_citation_ids() -> None:
    """Every declared label resolves to its unique supplied citation ID."""
    alpha_id = uuid4()
    beta_id = uuid4()
    resolution = resolve_research_scenario(
        _scenario(),
        (
            _chunk("record-a", citation_id=alpha_id),
            _chunk("record-b", citation_id=beta_id),
        ),
    )
    assert resolution.citations == {"alpha": alpha_id, "beta": beta_id}
    assert resolution.source_records == {"alpha": "record-a", "beta": "record-b"}


def test_unretrieved_label_fails_closed() -> None:
    """A label whose record was never retrieved fails materialization."""
    with pytest.raises(ResearchScenarioMaterializationError):
        resolve_research_scenario(_scenario(), (_chunk("record-a"),))


def test_ambiguous_label_fails_closed() -> None:
    """A label matching several distinct chunks fails as ambiguous."""
    with pytest.raises(ResearchScenarioMaterializationError):
        resolve_research_scenario(
            _scenario(),
            (
                _chunk("record-a", citation_id=uuid4()),
                _chunk("record-b", citation_id=uuid4()),
                _chunk("record-b", citation_id=uuid4()),
            ),
        )


def test_resolution_ignores_unrequested_declarations() -> None:
    """Labels are resolved per scenario; an absent declaration is empty."""
    resolution = resolve_research_scenario(_scenario(source_records={}), ())
    assert resolution.citations == {}
    assert resolution.source_records == {}
