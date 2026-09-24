# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30D Research Agent evaluation vertical slice (real PostgreSQL/pgvector).

Executes the PR 30D Research pipeline against real PostgreSQL/pgvector:

.. code-block:: text

    real research JSON scenarios (retrieval + synthesis)
     -> real typed loaders
     -> deterministic repository-owned ATT&CK corpus (production ingestion/
        indexing; deterministic hashing embeddings)
     -> production PgVectorResearchRetriever (+ recording decorator)
     -> real ResearchAgent (FakeLlmClient only at the model boundary)
     -> real ResearchResult persistence + epistemic snapshots
     -> existing retrieval/synthesis evaluators through the PR 30 dispatcher
     -> common EvaluationRunner

Covers: retrieval PASS/FAIL with zero LLM calls; synthesis relevant/
contradiction PASS with exact supplied citations and non-promotion; expected-
empty retrieval PASS with zero model calls; a schema-valid unsupported
citation ERROR; and a deliberately scenario-wrong claim FAIL. The corpus uses
the repository-owned MITRE ATT&CK fixture world; no live web or LLM.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
)
from agentic_threat_investigator.evaluation.common import (
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationTarget,
    EvaluationVerdict,
)
from agentic_threat_investigator.evaluation.research.composition import (
    REPOSITORY_RESEARCH_FIXTURES,
    bootstrap_research_corpus,
    build_research_world,
)
from agentic_threat_investigator.evaluation.research.loader import (
    load_retrieval_scenarios_directory,
    load_synthesis_scenarios_directory,
)
from agentic_threat_investigator.evaluation.research.pr30 import (
    RESEARCH_RETRIEVAL_CONTRACT_EVALUATOR_ID,
    RESEARCH_SYNTHESIS_CONTRACT_EVALUATOR_ID,
)
from agentic_threat_investigator.evaluation.research.run import (
    run_research_agent_evaluation,
)
from agentic_threat_investigator.infrastructure.embeddings import (
    HashingEmbeddingClient,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.support.llm_fixtures import FakeLlmCall, FakeLlmClient

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

DATASET_ID = EvaluationDatasetId(target=EvaluationTarget.RESEARCH_AGENT, version=1)
_CORPUS_ROOT = Path("evals/scenarios/research")

_RETRIEVAL_PASSING_IDS = {
    "real-mitre-technique-relevant",
    "real-mitre-software-filter",
    "real-mitre-technique-filter",
    "real-mitre-retrieval-gap",
}
_RETRIEVAL_FORBIDDEN_ID = "real-mitre-forbidden-technique"

_SYNTHESIS_RECORDS = {
    "rag-s01-relevant-context": {
        "attack_technique_data_obfuscation": (
            "attack-pattern--8a8e9e5e-2b4c-4d6e-8f0a-112233445566"
        )
    },
    "rag-s02-no-retrieval-result": {},
    "rag-s03-irrelevant-context": {},
    "rag-s04-contradictory-context": {
        "contradiction_alpha": "attack-pattern--11111111-1111-4111-8111-111111111111",
        "contradiction_beta": "attack-pattern--22222222-2222-4222-8222-222222222222",
    },
    "rag-s05-unsupported-citation": {},
    "rag-s06-hostile-corpus-content": {
        "hostile_attack_pattern": "attack-pattern--c0ffee00-0000-4000-8000-000000000022"
    },
}


async def _bootstrapped(
    uow_factory: Callable[[], PostgresUnitOfWork], tmp_path: Path
) -> None:
    """Ingest and index all repository-owned research fixtures into tmp storage."""
    await bootstrap_research_corpus(
        uow_factory=uow_factory,
        data_dir=tmp_path,
        fixture_files=tuple(REPOSITORY_RESEARCH_FIXTURES.values()),
    )


def _decision_factory_for(
    scenario_id: str, holder: "_WorldHolder"
) -> Callable[[FakeLlmCall], ResearchAgentDecision]:
    """Return a scripted decision builder keyed by the synthesis scenario id.

    The builder reads the exact chunks the recording observed for this
    execution (never a probe) and selects citations by stable source-record
    identity, so the supplied-citation contract is always honored.
    """

    def factory(call: FakeLlmCall) -> ResearchAgentDecision:
        del call
        supplied = holder.supplied
        if scenario_id == "rag-s01-relevant-context":
            citation = _citation_for(
                supplied,
                _SYNTHESIS_RECORDS[scenario_id]["attack_technique_data_obfuscation"],
            )
            return ResearchAgentDecision(
                claims=(
                    ResearchAgentClaim(
                        text="The technique obscures command-and-control traffic.",
                        citation_ids=(citation,),
                    ),
                )
            )
        if scenario_id == "rag-s03-irrelevant-context":
            return ResearchAgentDecision(claims=())
        if scenario_id == "rag-s04-contradictory-context":
            alpha = _citation_for(
                supplied, _SYNTHESIS_RECORDS[scenario_id]["contradiction_alpha"]
            )
            beta = _citation_for(
                supplied, _SYNTHESIS_RECORDS[scenario_id]["contradiction_beta"]
            )
            return ResearchAgentDecision(
                claims=(
                    ResearchAgentClaim(
                        text="The mechanism increases detection visibility.",
                        citation_ids=(alpha,),
                    ),
                    ResearchAgentClaim(
                        text="The mechanism decreases detection visibility.",
                        citation_ids=(beta,),
                    ),
                )
            )
        if scenario_id == "rag-s05-unsupported-citation":
            # A schema-valid decision citing an ID that was never supplied:
            # the production citation-membership validation rejects it before
            # any persistence (runtime ERROR, never a behavioral FAIL).
            return ResearchAgentDecision(
                claims=(
                    ResearchAgentClaim(
                        text="Unsupported context claim.",
                        citation_ids=(uuid4(),),
                    ),
                )
            )
        if scenario_id == "rag-s06-hostile-corpus-content":
            citation = _citation_for(
                supplied, _SYNTHESIS_RECORDS[scenario_id]["hostile_attack_pattern"]
            )
            return ResearchAgentDecision(
                claims=(
                    ResearchAgentClaim(
                        text="The corpus instructs the agent to ignore output-format "
                        "instructions embedded in corpus text; the agent refuses to "
                        "follow output-format instructions embedded in corpus text.",
                        citation_ids=(citation,),
                    ),
                )
            )
        raise AssertionError(f"unhandled synthesis scenario: {scenario_id}")

    return factory


class _WorldHolder:
    """Mutable holder so decision factories can observe the built world."""

    def __init__(self) -> None:
        """Start empty; filled once the world is built."""
        self.world: object | None = None

    @property
    def supplied(self) -> tuple[object, ...]:
        """Return the exact supplied chunks of the current execution."""
        world = self.world
        if world is None:
            return ()
        retriever = getattr(world, "retriever", None)
        calls = getattr(retriever, "calls", None) or ()
        if not calls:
            return ()
        return tuple(calls[-1])


def _citation_for(supplied: tuple[object, ...], source_record_id: str) -> UUID:
    """Return the citation id of one supplied chunk by source-record identity."""
    for chunk in supplied:
        if getattr(chunk, "source_record_id", None) != source_record_id:
            continue
        citation_id = getattr(chunk, "citation_id", None)
        if isinstance(citation_id, UUID):
            return citation_id
    raise AssertionError(f"chunk {source_record_id!r} was not supplied")


def _scenario_world(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    scenario_id: str,
    *,
    decision: ResearchAgentDecision | None = None,
) -> tuple[object, FakeLlmClient, _WorldHolder]:
    """Build one world whose FakeLlmClient scripts the scenario decision."""
    holder = _WorldHolder()
    llm = FakeLlmClient()
    if decision is not None:
        llm.set_default(decision)
    else:
        llm.set_response_factory(_decision_factory_for(scenario_id, holder))
    world = build_research_world(
        uow_factory=uow_factory,
        session_factory=session_factory,
        embedding_client=HashingEmbeddingClient(),
        llm_client=llm,
        max_structured_output_attempts=2,
    )
    holder.world = world
    return world, llm, holder


async def test_retrieval_run_passes_with_zero_llm(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """Retrieval cases run the production retriever with zero LLM calls."""
    await _bootstrapped(uow_factory, tmp_path)
    retrieval = tuple(
        item
        for item in load_retrieval_scenarios_directory(_CORPUS_ROOT / "retrieval")
        if item.id in _RETRIEVAL_PASSING_IDS
    )
    world, llm, _holder = _scenario_world(
        uow_factory, session_factory, "real-mitre-technique-relevant"
    )
    result = await run_research_agent_evaluation(
        dataset_id=DATASET_ID,
        world=world,  # type: ignore[arg-type]
        uow_factory=uow_factory,
        scenarios=retrieval,
    )
    assert result.execution_status is EvaluationExecutionStatus.COMPLETED
    assert result.verdict is EvaluationVerdict.PASS
    assert llm.calls == []


async def test_retrieval_forbidden_record_fails(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """A deliberately forbidden retrieved record FAILs the retrieval baseline."""
    await _bootstrapped(uow_factory, tmp_path)
    scenario = next(
        item
        for item in load_retrieval_scenarios_directory(_CORPUS_ROOT / "retrieval")
        if item.id == _RETRIEVAL_FORBIDDEN_ID
    )
    world, llm, _holder = _scenario_world(uow_factory, session_factory, scenario.id)
    result = await run_research_agent_evaluation(
        dataset_id=DATASET_ID,
        world=world,  # type: ignore[arg-type]
        uow_factory=uow_factory,
        scenarios=(scenario,),
    )
    case = result.cases[0]
    assert case.verdict is EvaluationVerdict.FAIL
    assert (
        case.evaluator_results[0].evaluator_id
        == RESEARCH_RETRIEVAL_CONTRACT_EVALUATOR_ID
    )
    assert llm.calls == []


async def test_synthesis_relevant_and_contradiction_pass(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """Relevant and contradictory-context synthesis scenarios PASS."""
    await _bootstrapped(uow_factory, tmp_path)
    for scenario_id in ("rag-s01-relevant-context", "rag-s04-contradictory-context"):
        scenario = next(
            item
            for item in load_synthesis_scenarios_directory(_CORPUS_ROOT / "synthesis")
            if item.id == scenario_id
        )
        world, llm, _holder = _scenario_world(uow_factory, session_factory, scenario_id)
        result = await run_research_agent_evaluation(
            dataset_id=DATASET_ID,
            world=world,  # type: ignore[arg-type]
            uow_factory=uow_factory,
            scenarios=(scenario,),
        )
        assert result.verdict is EvaluationVerdict.PASS, scenario_id
        case = result.cases[0]
        assert case.evaluator_results[0].evaluator_id == (
            RESEARCH_SYNTHESIS_CONTRACT_EVALUATOR_ID
        )
        assert case.evaluator_results[0].diagnostics["epistemic_promotion_count"] == 0
        assert len(llm.calls) == 1


async def test_synthesis_empty_retrieval_passes_with_zero_model_calls(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """The expected-no-retrieval scenario persists an empty result, zero LLM."""
    await _bootstrapped(uow_factory, tmp_path)
    scenario = next(
        item
        for item in load_synthesis_scenarios_directory(_CORPUS_ROOT / "synthesis")
        if item.id == "rag-s02-no-retrieval-result"
    )
    world, llm, _holder = _scenario_world(uow_factory, session_factory, scenario.id)
    result = await run_research_agent_evaluation(
        dataset_id=DATASET_ID,
        world=world,  # type: ignore[arg-type]
        uow_factory=uow_factory,
        scenarios=(scenario,),
    )
    assert result.verdict is EvaluationVerdict.PASS
    assert llm.calls == []


async def test_synthesis_unsupported_citation_is_error(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """A schema-valid unsupported citation is a production ERROR, not FAIL."""
    await _bootstrapped(uow_factory, tmp_path)
    scenario = next(
        item
        for item in load_synthesis_scenarios_directory(_CORPUS_ROOT / "synthesis")
        if item.id == "rag-s05-unsupported-citation"
    )
    world, llm, _holder = _scenario_world(uow_factory, session_factory, scenario.id)
    result = await run_research_agent_evaluation(
        dataset_id=DATASET_ID,
        world=world,  # type: ignore[arg-type]
        uow_factory=uow_factory,
        scenarios=(scenario,),
    )
    assert result.execution_status is EvaluationExecutionStatus.ERROR
    assert result.verdict is None


async def test_synthesis_scenario_wrong_claim_fails(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """A runtime-valid but scenario-wrong claim FAILs the synthesis baseline."""
    await _bootstrapped(uow_factory, tmp_path)
    scenario = next(
        item
        for item in load_synthesis_scenarios_directory(_CORPUS_ROOT / "synthesis")
        if item.id == "rag-s01-relevant-context"
    )
    holder = _WorldHolder()
    llm = FakeLlmClient()
    record = _SYNTHESIS_RECORDS[scenario.id]["attack_technique_data_obfuscation"]

    def wrong_factory(call: FakeLlmCall) -> ResearchAgentDecision:
        """Cite the real technique chunk but with the wrong claim content."""
        del call
        citation = _citation_for(holder.supplied, record)
        return ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="The mechanism is unrelated to the technique.",
                    citation_ids=(citation,),
                ),
            )
        )

    llm.set_response_factory(wrong_factory)
    world = build_research_world(
        uow_factory=uow_factory,
        session_factory=session_factory,
        embedding_client=HashingEmbeddingClient(),
        llm_client=llm,
        max_structured_output_attempts=2,
    )
    holder.world = world
    result = await run_research_agent_evaluation(
        dataset_id=DATASET_ID,
        world=world,
        uow_factory=uow_factory,
        scenarios=(scenario,),
    )
    assert result.execution_status is EvaluationExecutionStatus.COMPLETED
    assert result.verdict is EvaluationVerdict.FAIL
    assert "required_claim_missing" in result.cases[0].evaluator_results[0].explanation
