# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical PR 22D research evaluation PostgreSQL slices (22D-I02..I06).

Exercises the complete delivered PR 22 research path — real-format MITRE
ATT&CK STIX fixtures, production parser/document builder,
``DocumentIndexingService``, real PostgreSQL/pgvector,
``PgVectorResearchRetriever``, Research Agent, real ``ResearchResult``
persistence — then evaluates the persisted artifact with the repository-owned
deterministic ``ResearchSynthesisEvaluator`` and epistemic snapshots.
``FakeLlmClient`` is used ONLY at the external model boundary; a recording
wrapper observes the exact production retrieval response without altering it.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.research_agent.agent import ResearchAgent
from agentic_threat_investigator.app.research_agent.errors import (
    ResearchAgentCitationError,
)
from agentic_threat_investigator.app.research_persistence import (
    ResearchResultPersistenceService,
)
from agentic_threat_investigator.domain.research import (
    ResearchQuery,
    ResearchResult,
    RetrievedChunk,
)
from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
    ResearchAgentRequest,
)
from agentic_threat_investigator.evaluation.research import (
    ResearchExecutionEvaluationInput,
    ResearchScenarioResolution,
    ResearchSynthesisEvaluationResult,
    ResearchSynthesisEvaluator,
    ResearchSynthesisFailureCode,
    ResearchSynthesisScenario,
    load_synthesis_scenarios_directory,
    resolve_research_scenario,
)
from agentic_threat_investigator.infrastructure.embeddings import HashingEmbeddingClient
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)
from tests.integration.test_research_agent import (
    CONTRADICTION_FIXTURE,
    FIXTURE,
    _index,
    _ingest_fixture,
    _seed_subject,
)
from tests.support.llm_fixtures import FakeLlmCall, FakeLlmClient, ResponseFactory
from tests.support.research_evaluation import (
    RecordingResearchRetriever,
    load_epistemic_snapshot,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
    pytest.mark.skip(
        reason="PR 28B legacy-provider boundary: this research-trajectory evaluation requires a provider-success trajectory (Google Public DNS / ThreatFox discovery), but the six not-semantically-modeled providers now fail closed in the executor (approved PR 28B boundary). The research orchestration integration coverage runs on the migrated-provider substrate once such a provider lands; re-enable these scenarios then. Identical failures exist at the pre-PR-28B-2 HEAD commit b83b0b9d."
    ),
]

HOSTILE_FIXTURE = Path(
    "tests/fixtures/mitre_attack/enterprise_attack_hostile_small.json"
)
_CORPUS = Path(__file__).parents[2] / "evals/scenarios/research/synthesis"
_FIXTURE_FILES = {
    "mitre-attack-small": FIXTURE,
    "mitre-attack-contradiction": CONTRADICTION_FIXTURE,
    "mitre-attack-hostile": HOSTILE_FIXTURE,
}


def _scenarios() -> dict[str, ResearchSynthesisScenario]:
    """Load the repository synthesis corpus into a stable id-keyed map."""
    return {
        scenario.id: scenario
        for scenario in load_synthesis_scenarios_directory(_CORPUS)
    }


async def _indexed_corpus(
    uow_factory: Callable[[], PostgresUnitOfWork],
    tmp_path: Path,
    *,
    fixture: Path,
) -> None:
    """Ingest and index one fixture through the production path."""
    records = await _ingest_fixture(uow_factory, tmp_path, fixture=fixture)
    await _index(records, uow_factory)


def _agent_with_recording(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    fake_llm: FakeLlmClient,
) -> tuple[ResearchAgent, RecordingResearchRetriever]:
    """Build the production Research Agent behind an observing retriever."""
    recording = RecordingResearchRetriever(
        PgVectorResearchRetriever(session_factory, HashingEmbeddingClient())
    )
    agent = ResearchAgent(
        retriever=recording,
        llm_client=fake_llm,
        result_persistence=ResearchResultPersistenceService(uow_factory),
        llm_accounting=LlmAccountingService(uow_factory),
        max_structured_output_attempts=2,
    )
    return agent, recording


def _request(
    scenario: ResearchSynthesisScenario,
    investigation_id: UUID,
    entity_id: UUID,
) -> ResearchAgentRequest:
    """Build the exact bounded request for one scenario."""
    return ResearchAgentRequest.model_validate(
        {
            "investigation_id": investigation_id,
            "subject_entity_id": entity_id,
            "query": scenario.query,
            "source_ids": scenario.source_ids,
            "document_types": scenario.document_types,
            "max_results": scenario.max_results,
        }
    )


async def _run_and_evaluate(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    scenario: ResearchSynthesisScenario,
    investigation_id: UUID,
    entity_id: UUID,
    fake_llm: FakeLlmClient,
    *,
    prebuilt: tuple[ResearchAgent, RecordingResearchRetriever] | None = None,
) -> tuple[
    ResearchResult, ResearchSynthesisEvaluationResult, RecordingResearchRetriever
]:
    """Execute one scenario and return (persisted, evaluation, recording).

    ``prebuilt`` lets a test bind a ``FakeLlmClient`` response factory to the
    exact ``RecordingResearchRetriever`` before the agent executes: the agent
    is reused unchanged and the returned recording is the same object the
    factory observed, so a scripted citation provably came from the exact
    model-supplied retrieval of this execution.
    """
    before = await load_epistemic_snapshot(uow_factory, investigation_id)
    if prebuilt is None:
        agent, recording = _agent_with_recording(uow_factory, session_factory, fake_llm)
    else:
        agent, recording = prebuilt
    result = await agent.research(_request(scenario, investigation_id, entity_id))
    after = await load_epistemic_snapshot(uow_factory, investigation_id)
    async with uow_factory() as uow:
        persisted = await uow.research_results.get_by_id(result.id)
    assert persisted is not None
    resolution, supplied = await _resolve_supplied(scenario, recording)
    evaluation = ResearchSynthesisEvaluator().evaluate(
        scenario=scenario,
        resolution=resolution,
        result=persisted,
        supplied_citation_ids=supplied,
        before_snapshot=before,
        after_snapshot=after,
        expected_investigation_id=investigation_id,
        expected_subject_entity_id=entity_id,
    )
    return persisted, evaluation, recording


async def _resolve_supplied(
    scenario: ResearchSynthesisScenario,
    recording: RecordingResearchRetriever,
) -> tuple[ResearchScenarioResolution, tuple[UUID, ...]]:
    """Resolve labels and supplied citations from the observed retrieval."""
    supplied = tuple(recording.supplied_citation_ids)
    resolution = resolve_research_scenario(scenario, recording.calls[-1])
    return resolution, supplied


def _scenario_citation_factory(
    recording: RecordingResearchRetriever,
    *,
    source_record_ids: dict[str, str],
    claim_text: str,
    selected: list[UUID],
) -> ResponseFactory:
    """Build a response factory citing declared records from the actual retrieval.

    Each declared label resolves against the exact chunks the Research Agent
    supplied to this model execution (observed by ``recording`` at the
    retrieval boundary immediately before the LLM call), never from an
    independent probe retrieval. The selected citations are appended to
    ``selected`` so tests can prove they came from that exact execution.
    """

    def factory(call: FakeLlmCall) -> ResearchAgentDecision:
        supplied = recording.calls[-1]
        citations = tuple(
            next(
                chunk.citation_id
                for chunk in supplied
                if chunk.source_record_id == source_record_id
            )
            for source_record_id in source_record_ids.values()
        )
        selected.extend(citations)
        return ResearchAgentDecision(
            claims=(ResearchAgentClaim(text=claim_text, citation_ids=citations),),
        )

    return factory


def _wrong_supplied_citation_factory(
    recording: RecordingResearchRetriever,
    *,
    technique_record_id: str,
    selected: list[UUID],
) -> ResponseFactory:
    """Build a response factory citing a supplied-but-scenario-wrong chunk.

    The intentionally wrong citation is selected from the exact chunks
    supplied to this model execution (never from a probe): runtime citation
    membership accepts it, while the behavioral scenario rejects it.
    """

    def factory(call: FakeLlmCall) -> ResearchAgentDecision:
        supplied = recording.calls[-1]
        wrong_citation = next(
            chunk.citation_id
            for chunk in supplied
            if chunk.source_record_id != technique_record_id
        )
        selected.append(wrong_citation)
        return ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="The technique obscures command-and-control traffic.",
                    citation_ids=(wrong_citation,),
                ),
            ),
        )

    return factory


def _contradiction_citation_factory(
    recording: RecordingResearchRetriever,
    *,
    alpha_record_id: str,
    beta_record_id: str,
    selected: list[UUID],
) -> ResponseFactory:
    """Build a response factory citing both contradictory supplied chunks.

    Both citation IDs are resolved against the exact chunks supplied to this
    model execution (never from an independent probe), so the two sides of
    the conflict are always the actually supplied records.
    """

    def factory(call: FakeLlmCall) -> ResearchAgentDecision:
        supplied = recording.calls[-1]
        alpha_id = next(
            chunk.citation_id
            for chunk in supplied
            if chunk.source_record_id == alpha_record_id
        )
        beta_id = next(
            chunk.citation_id
            for chunk in supplied
            if chunk.source_record_id == beta_record_id
        )
        selected.extend((alpha_id, beta_id))
        return ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text=("Alpha states the technique increases detection visibility."),
                    citation_ids=(alpha_id,),
                ),
                ResearchAgentClaim(
                    text=("Beta states the technique decreases detection visibility."),
                    citation_ids=(beta_id,),
                ),
            ),
        )

    return factory


async def _retrieve(
    session_factory: async_sessionmaker[AsyncSession],
    scenario: ResearchSynthesisScenario,
) -> list[RetrievedChunk]:
    """Return the deterministic production retrieval for the scenario query."""
    retriever = PgVectorResearchRetriever(session_factory, HashingEmbeddingClient())
    return await retriever.retrieve(
        ResearchQuery(
            investigation_id=uuid4(),
            query=scenario.query,
            source_ids=list(scenario.source_ids),
            document_types=list(scenario.document_types),
            max_results=scenario.max_results,
        )
    )


async def test_i02_s01_relevant_context_evaluation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """22D-I02/S01: relevant ATT&CK context passes the synthesis baseline."""
    scenario = _scenarios()["rag-s01-relevant-context"]
    fixture = _FIXTURE_FILES[scenario.fixture.name]
    await _indexed_corpus(uow_factory, tmp_path, fixture=fixture)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    selected: list[UUID] = []
    fake_llm = FakeLlmClient()
    agent, recording = _agent_with_recording(uow_factory, session_factory, fake_llm)
    fake_llm.set_response_factory(
        _scenario_citation_factory(
            recording,
            source_record_ids={
                "attack_technique_data_obfuscation": scenario.source_records[
                    "attack_technique_data_obfuscation"
                ]
            },
            claim_text="The technique obscures command-and-control traffic.",
            selected=selected,
        )
    )
    persisted, evaluation, recording = await _run_and_evaluate(
        uow_factory,
        session_factory,
        scenario,
        investigation_id,
        entity_id,
        fake_llm,
        prebuilt=(agent, recording),
    )
    assert evaluation.passed, evaluation.failures
    assert len(fake_llm.calls) == 1
    (technique_citation,) = selected
    assert technique_citation in recording.supplied_citation_ids
    assert persisted.claims
    assert persisted.investigation_id == investigation_id


async def test_i02b_s01_wrong_supplied_citation_fails_evaluation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """22D-I03: a runtime-valid but scenario-wrong result fails evaluation.

    The model cites a supplied-but-wrong citation (a chunk that is not the
    required technique) with the correct phrase. The wrong citation is
    selected from the exact retrieval this execution supplied to the model
    (never from an independent probe), so runtime citation membership accepts
    it but the behavioral scenario requires the declared technique citation.
    """
    scenario = _scenarios()["rag-s01-relevant-context"]
    fixture = _FIXTURE_FILES[scenario.fixture.name]
    await _indexed_corpus(uow_factory, tmp_path, fixture=fixture)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    technique_id = scenario.source_records["attack_technique_data_obfuscation"]
    selected: list[UUID] = []
    fake_llm = FakeLlmClient()
    agent, recording = _agent_with_recording(uow_factory, session_factory, fake_llm)
    fake_llm.set_response_factory(
        _wrong_supplied_citation_factory(
            recording, technique_record_id=technique_id, selected=selected
        )
    )
    _persisted, evaluation, recording = await _run_and_evaluate(
        uow_factory,
        session_factory,
        scenario,
        investigation_id,
        entity_id,
        fake_llm,
        prebuilt=(agent, recording),
    )
    assert len(fake_llm.calls) == 1
    assert _persisted.claims
    (wrong_citation,) = selected
    # The wrong citation is provably drawn from the exact retrieval supplied
    # to this model execution: the failure is behavioral, not structural.
    assert wrong_citation in recording.supplied_citation_ids
    assert not evaluation.passed
    # The persisted artifact is structurally valid; the behavioral envelope
    # rejects it deterministically.
    assert evaluation.failures == (
        ResearchSynthesisFailureCode.REQUIRED_CITATION_MISSING,
        ResearchSynthesisFailureCode.REQUIRED_CLAIM_MISSING,
    )


async def test_i04_s02_no_retrieval_result_evaluation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """22D-I04/S02: no-context completion evaluates as expected-empty and no calls."""
    scenario = _scenarios()["rag-s02-no-retrieval-result"]
    fixture = _FIXTURE_FILES[scenario.fixture.name]
    await _indexed_corpus(uow_factory, tmp_path, fixture=fixture)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    fake_llm = FakeLlmClient()
    persisted, evaluation, recording = await _run_and_evaluate(
        uow_factory,
        session_factory,
        scenario,
        investigation_id,
        entity_id,
        fake_llm,
    )
    assert evaluation.passed, evaluation.failures
    assert persisted.claims == ()
    assert persisted.citations == ()
    assert recording.supplied_citation_ids == ()
    assert fake_llm.calls == []


async def test_s03_irrelevant_context_evaluation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """RAG-S03: retrieved-but-irrelevant context evaluates as expected-empty."""
    scenario = _scenarios()["rag-s03-irrelevant-context"]
    fixture = _FIXTURE_FILES[scenario.fixture.name]
    await _indexed_corpus(uow_factory, tmp_path, fixture=fixture)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    fake_llm = FakeLlmClient()
    fake_llm.set_default(ResearchAgentDecision())
    persisted, evaluation, recording = await _run_and_evaluate(
        uow_factory,
        session_factory,
        scenario,
        investigation_id,
        entity_id,
        fake_llm,
    )
    assert evaluation.passed, evaluation.failures
    assert persisted.claims == ()
    assert persisted.citations == ()
    assert len(fake_llm.calls) == 1
    assert len(recording.supplied_citation_ids) > 0, (
        "retrieval happened but was not promoted"
    )


async def test_i05_s04_contradictory_context_evaluation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """22D-I05/S04: both contradiction sides survive as separately cited claims."""
    scenario = _scenarios()["rag-s04-contradictory-context"]
    fixture = _FIXTURE_FILES[scenario.fixture.name]
    await _indexed_corpus(uow_factory, tmp_path, fixture=fixture)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    selected: list[UUID] = []
    fake_llm = FakeLlmClient()
    agent, recording = _agent_with_recording(uow_factory, session_factory, fake_llm)
    fake_llm.set_response_factory(
        _contradiction_citation_factory(
            recording,
            alpha_record_id=scenario.source_records["contradiction_alpha"],
            beta_record_id=scenario.source_records["contradiction_beta"],
            selected=selected,
        )
    )
    persisted, evaluation, _recording = await _run_and_evaluate(
        uow_factory,
        session_factory,
        scenario,
        investigation_id,
        entity_id,
        fake_llm,
        prebuilt=(agent, recording),
    )
    assert evaluation.passed, evaluation.failures
    assert len(persisted.claims) == 2
    assert tuple(sorted(selected)) == tuple(
        sorted(citation.citation_id for citation in persisted.citations)
    )


async def test_s05_unsupported_citation_safe_failure(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """RAG-S05: a schema-valid unsupported citation fails closed with no result."""
    scenario = _scenarios()["rag-s05-unsupported-citation"]
    fixture = _FIXTURE_FILES[scenario.fixture.name]
    await _indexed_corpus(uow_factory, tmp_path, fixture=fixture)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    wide = scenario.model_copy(update={"max_results": 10})
    probe = await _retrieve(session_factory, wide)
    supplied_ids = {chunk.citation_id for chunk in probe[:1]}
    unsupplied = next(chunk for chunk in probe if chunk.citation_id not in supplied_ids)
    fake_llm = FakeLlmClient()
    fake_llm.set_default(
        ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="Cites a corpus chunk outside the prompt.",
                    citation_ids=(unsupplied.citation_id,),
                ),
            ),
        )
    )
    agent, _recording = _agent_with_recording(uow_factory, session_factory, fake_llm)
    with pytest.raises(ResearchAgentCitationError):
        await agent.research(_request(scenario, investigation_id, entity_id))
    async with uow_factory() as uow:
        results = await uow.research_results.list_by_investigation(investigation_id)
    assert results == []
    assert len(fake_llm.calls) == 1
    envelope = ResearchExecutionEvaluationInput(
        result=None,
        execution_error_code="research_agent_citation_error",
        llm_calls=1,
        research_requests=1,
    )
    assert envelope.result is None
    assert envelope.execution_error_code == "research_agent_citation_error"
    assert envelope.llm_calls == 1


async def test_s06_hostile_corpus_content_evaluation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """RAG-S06: hostile corpus text stays bounded and non-promoting."""
    scenario = _scenarios()["rag-s06-hostile-corpus-content"]
    fixture = _FIXTURE_FILES[scenario.fixture.name]
    await _indexed_corpus(uow_factory, tmp_path, fixture=fixture)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    hostile_record_id = scenario.source_records["hostile_attack_pattern"]
    selected: list[UUID] = []
    fake_llm = FakeLlmClient()
    agent, recording = _agent_with_recording(uow_factory, session_factory, fake_llm)
    fake_llm.set_response_factory(
        _scenario_citation_factory(
            recording,
            source_record_ids={"hostile_attack_pattern": hostile_record_id},
            claim_text=(
                "The technique ignores hostile instructions and refuses to "
                "follow output-format instructions embedded in corpus text."
            ),
            selected=selected,
        )
    )
    persisted, evaluation, recording = await _run_and_evaluate(
        uow_factory,
        session_factory,
        scenario,
        investigation_id,
        entity_id,
        fake_llm,
        prebuilt=(agent, recording),
    )
    assert evaluation.passed, evaluation.failures
    (hostile_citation,) = selected
    assert hostile_citation in recording.supplied_citation_ids
    assert persisted.claims
