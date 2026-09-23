# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30D Research evaluator dispatcher tests (R-E01..E14).

The thin PR 30 dispatch adapter is tested offline with the **real** existing
retrieval and synthesis evaluators, synthetic chunks and persisted-shaped
Research results, and hand-built epistemic snapshots. Proves PASS/FAIL
mapping, per-kind evaluator ids, JSON-safe diagnostics without numeric
thresholds, the epistemic non-promotion hard gates, runner ERROR conversion,
and cancellation propagation.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

import pytest

from agentic_threat_investigator.domain.research import (
    ResearchClaim,
    ResearchResult,
    RetrievedChunk,
    research_citation_from_retrieved_chunk,
)
from agentic_threat_investigator.evaluation.common import (
    EvaluationContext,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationRunner,
    EvaluationTarget,
    EvaluationVerdict,
    evaluation_case_from,
)
from agentic_threat_investigator.evaluation.research.materialization import (
    resolve_research_scenario,
)
from agentic_threat_investigator.evaluation.research.models import (
    ExpectedResearchResult,
    ResearchEpistemicSnapshot,
    ResearchFixtureReference,
    ResearchRetrievalScenario,
    ResearchSynthesisScenario,
)
from agentic_threat_investigator.evaluation.research.pr30 import (
    RESEARCH_RETRIEVAL_CONTRACT_EVALUATOR_ID,
    RESEARCH_SYNTHESIS_CONTRACT_EVALUATOR_ID,
    ResearchAgentEvaluatorDispatcher,
)
from agentic_threat_investigator.evaluation.research.target import (
    ResearchEvaluationOutput,
    ResearchRetrievalEvaluationOutput,
    ResearchScenarioLookup,
    ResearchSynthesisEvaluationOutput,
)

_RECORD = "attack-pattern--11111111-2222-3333-4444-555555555555"
_RECORD_BETA = "attack-pattern--22222222-2222-2222-2222-222222222222"
_RECORD_GAMMA = "attack-pattern--33333333-3333-3333-3333-333333333333"
_NS = UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
_INVESTIGATION = UUID("00000000-0000-0000-0000-0000000000f1")
_SUBJECT = UUID("00000000-0000-0000-0000-0000000000f2")


def _spec() -> Any:
    """Build one common research scenario specification."""
    from agentic_threat_investigator.evaluation.common import (
        ExpectedBehavior,
        ScenarioSpecification,
    )

    return ScenarioSpecification(
        title="Unit research scenario",
        description="A fully described research unit scenario.",
        target=EvaluationTarget.RESEARCH_AGENT,
        purpose="Exercises the research dispatch contract.",
        operational_relevance="Relevant to research evaluation coverage.",
        regression_risk="Protects against research dispatch regressions.",
        expected_behavior=ExpectedBehavior(
            required=("Context does not invent Evidence.",),
            forbidden=("Research never promotes into Evidence.",),
        ),
    )


def _chunk(*, source_record_id: str = _RECORD) -> RetrievedChunk:
    """Build one deterministic retrieved chunk."""
    citation = uuid5(_NS, source_record_id)
    return RetrievedChunk(
        chunk_id=citation,
        citation_id=citation,
        document_id=uuid5(_NS, f"doc:{source_record_id}"),
        source_id="urn:ati:source:mitre_attack",
        source_record_id=source_record_id,
        document_type="attack-pattern",
        chunk_sequence=1,
        text="The technique obfuscates command-and-control traffic.",
        title="Data Obfuscation",
    )


def _retrieval_scenario(
    *, relevant: tuple[str, ...] = (_RECORD,)
) -> ResearchRetrievalScenario:
    """Build one deterministic retrieval scenario."""
    return ResearchRetrievalScenario(
        id="retrieval.s1",
        version=1,
        specification=_spec(),
        query="obfuscate command-and-control traffic",
        max_results=4,
        expected_relevant_source_records=relevant,
    )


def _synthesis_scenario(
    *,
    expected: ExpectedResearchResult | None = None,
    source_records: dict[str, str] | None = None,
) -> ResearchSynthesisScenario:
    """Build one deterministic synthesis scenario."""
    return ResearchSynthesisScenario(
        id="synthesis.s1",
        version=1,
        specification=_spec(),
        fixture=ResearchFixtureReference(name="mitre-attack-small"),
        query="obfuscate command-and-control traffic",
        max_results=4,
        source_records=source_records or {"technique": _RECORD},
        expected=expected
        or ExpectedResearchResult(
            min_claims=1,
            max_claims=2,
            required_citation_labels=("technique",),
            required_claims=(),
        ),
    )


def _result(
    *,
    chunks: tuple[RetrievedChunk, ...] = (_chunk(),),
    text: str = "The technique obfuscates traffic.",
) -> ResearchResult:
    """Build a persisted-shaped ResearchResult citing the given chunks."""
    citations = tuple(research_citation_from_retrieved_chunk(chunk) for chunk in chunks)
    claim = ResearchClaim(
        id=uuid4(),
        text=text,
        citation_ids=tuple(chunk.citation_id for chunk in chunks),
    )
    return ResearchResult(
        id=uuid4(),
        investigation_id=_INVESTIGATION,
        subject_entity_id=_SUBJECT,
        query="obfuscate command-and-control traffic",
        claims=(claim,),
        citations=citations,
        created_at=datetime(2026, 1, 15, tzinfo=UTC),
    )


def _snapshot(*, evidence: tuple[UUID, ...] = ()) -> ResearchEpistemicSnapshot:
    """Build one epistemic snapshot."""
    return ResearchEpistemicSnapshot(
        evidence_ids=evidence,
        relationship_observation_ids=(),
        assessment_identities=(),
    )


def _synthesis_output(
    *,
    result: ResearchResult | None = None,
    chunks: tuple[RetrievedChunk, ...] = (_chunk(),),
    before: ResearchEpistemicSnapshot | None = None,
    after: ResearchEpistemicSnapshot | None = None,
    scenario: ResearchSynthesisScenario | None = None,
) -> ResearchEvaluationOutput:
    """Build one synthesis-branch output from the same supplied response."""
    scenario = scenario or _synthesis_scenario()
    resolution = resolve_research_scenario(scenario, chunks)
    supplied = tuple(chunk.citation_id for chunk in chunks)
    return ResearchEvaluationOutput(
        synthesis=ResearchSynthesisEvaluationOutput(
            result=result or _result(chunks=chunks),
            resolution=resolution,
            supplied_citation_ids=supplied,
            before_snapshot=before or _snapshot(),
            after_snapshot=after or _snapshot(),
            investigation_id=_INVESTIGATION,
            subject_entity_id=_SUBJECT,
        )
    )


def _retrieval_output(chunks: tuple[RetrievedChunk, ...]) -> ResearchEvaluationOutput:
    """Build one retrieval-branch output."""
    return ResearchEvaluationOutput(
        retrieval=ResearchRetrievalEvaluationOutput(chunks=chunks)
    )


def _context(case_id: str) -> EvaluationContext:
    """Build one minimal evaluation context."""
    return EvaluationContext(dataset_id="research-agent/v1", case_id=case_id)


class TestRetrievalAdapter:
    """R-E01/R-E02/R-E05 retrieval contract mapping."""

    @pytest.mark.asyncio
    async def test_e01_retrieval_pass_maps_to_pass(self) -> None:
        """E01 a passing retrieval maps to COMPLETED/PASS."""
        scenario = _retrieval_scenario()
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=_retrieval_output((_chunk(),)),
            context=_context(scenario.id),
        )
        assert result.evaluator_id == RESEARCH_RETRIEVAL_CONTRACT_EVALUATOR_ID
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.PASS

    @pytest.mark.asyncio
    async def test_e02_retrieval_fail_maps_to_fail(self) -> None:
        """E02 a missing expected record maps to COMPLETED/FAIL."""
        scenario = _retrieval_scenario(relevant=(_RECORD_BETA,))
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=_retrieval_output((_chunk(),)),
            context=_context(scenario.id),
        )
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.FAIL
        assert "required_record_not_retrieved" in result.explanation

    @pytest.mark.asyncio
    async def test_e05_retrieval_metrics_diagnostics_only(self) -> None:
        """E05 retrieval metrics appear as JSON-safe descriptive diagnostics."""
        scenario = _retrieval_scenario()
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=_retrieval_output((_chunk(),)),
            context=_context(scenario.id),
        )
        assert result.diagnostics["recall_at_k"] == 1.0
        assert result.diagnostics["mrr"] == 1.0
        import json

        json.dumps(dict(result.diagnostics))


class TestSynthesisAdapter:
    """R-E03/R-E04/R-E06..E12 synthesis contract mapping."""

    @pytest.mark.asyncio
    async def test_e03_synthesis_pass_maps_to_pass(self) -> None:
        """E03 a compliant persisted result maps to COMPLETED/PASS."""
        scenario = _synthesis_scenario()
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=_synthesis_output(),
            context=_context(scenario.id),
        )
        assert result.evaluator_id == RESEARCH_SYNTHESIS_CONTRACT_EVALUATOR_ID
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.PASS

    @pytest.mark.asyncio
    async def test_e04_synthesis_fail_maps_to_fail(self) -> None:
        """E04 a mismatched subject anchors the result to COMPLETED/FAIL."""
        scenario = _synthesis_scenario()
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        base = _synthesis_output()
        assert base.synthesis is not None
        mismatched = base.synthesis.model_copy(update={"subject_entity_id": uuid4()})
        wrong = base.model_copy(update={"synthesis": mismatched})
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=wrong,
            context=_context(scenario.id),
        )
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.FAIL
        assert "result_subject_mismatch" in result.explanation

    @pytest.mark.asyncio
    async def test_e06_synthesis_metrics_diagnostics_only(self) -> None:
        """E06 synthesis metrics appear as JSON-safe descriptive diagnostics."""
        scenario = _synthesis_scenario()
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=_synthesis_output(),
            context=_context(scenario.id),
        )
        assert result.diagnostics["citation_validity_rate"] == 1.0
        assert result.diagnostics["epistemic_promotion_count"] == 0

    @pytest.mark.asyncio
    async def test_e07_no_numeric_correctness(self) -> None:
        """E07 the adapter never emits a numeric correctness verdict."""
        scenario = _synthesis_scenario()
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=_synthesis_output(),
            context=_context(scenario.id),
        )
        assert isinstance(result.verdict, EvaluationVerdict)
        assert not isinstance(result.verdict.value, float)
        assert "score" not in " ".join(str(key) for key in result.diagnostics)

    @pytest.mark.asyncio
    async def test_e08_required_citation_missing_is_fail(self) -> None:
        """E08 a required citation absent from the result is FAIL."""
        scenario = _synthesis_scenario(
            source_records={"technique": _RECORD_BETA},
            expected=ExpectedResearchResult(
                min_claims=0,
                required_citation_labels=("technique",),
            ),
        )
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        required = _chunk(source_record_id=_RECORD_BETA)
        other = _chunk(source_record_id=_RECORD_GAMMA)
        # The result satisfies the supplied-membership and closure contracts
        # but omits the required technique citation.
        output = _synthesis_output(
            chunks=(required, other),
            result=_result(chunks=(other,)),
            scenario=scenario,
        )
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=output,
            context=_context(scenario.id),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "required_citation_missing" in result.explanation

    @pytest.mark.asyncio
    async def test_e09_forbidden_citation_used_is_fail(self) -> None:
        """E09 a forbidden citation in the result is FAIL."""
        scenario = _synthesis_scenario(
            source_records={
                "technique": _RECORD,
                "beta": _RECORD_BETA,
            },
            expected=ExpectedResearchResult(
                min_claims=0,
                forbidden_citation_labels=("beta",),
            ),
        )
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        beta_chunk = _chunk(source_record_id=_RECORD_BETA)
        alpha_chunk = _chunk(source_record_id=_RECORD)
        output = _synthesis_output(
            chunks=(alpha_chunk, beta_chunk),
            result=_result(chunks=(beta_chunk,)),
            scenario=scenario,
        )
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=output,
            context=_context(scenario.id),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "forbidden_citation_used" in result.explanation

    @pytest.mark.asyncio
    async def test_e10_evidence_promotion_is_fail(self) -> None:
        """E10 Evidence promotion across the interval FAILs."""
        scenario = _synthesis_scenario()
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        output = _synthesis_output(
            before=_snapshot(),
            after=_snapshot(evidence=(uuid4(),)),
        )
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=output,
            context=_context(scenario.id),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "evidence_promotion_detected" in result.explanation

    @pytest.mark.asyncio
    async def test_e11_relationship_promotion_is_fail(self) -> None:
        """E11 RelationshipObservation promotion across the interval FAILs."""
        scenario = _synthesis_scenario()
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        output = _synthesis_output(
            before=_snapshot(),
            after=ResearchEpistemicSnapshot(
                evidence_ids=(),
                relationship_observation_ids=(uuid4(),),
                assessment_identities=(),
            ),
        )
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=output,
            context=_context(scenario.id),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "relationship_observation_promotion_detected" in result.explanation

    @pytest.mark.asyncio
    async def test_e12_assessment_promotion_is_fail(self) -> None:
        """E12 Assessment promotion across the interval FAILs."""
        scenario = _synthesis_scenario()
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario])
        )
        output = _synthesis_output(
            before=_snapshot(),
            after=ResearchEpistemicSnapshot(
                evidence_ids=(),
                relationship_observation_ids=(),
                assessment_identities=((uuid4(), 1),),
            ),
        )
        result = await dispatcher.evaluate(
            case=evaluation_case_from(scenario),
            output=output,
            context=_context(scenario.id),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "assessment_promotion_detected" in result.explanation


class TestAdapterFailures:
    """R-E13/R-E14 boundary failures."""

    @pytest.mark.asyncio
    async def test_e13_evaluator_exception_is_error(self) -> None:
        """E13 an evaluator exception surfaces as a runner ERROR."""

        class ExplodingRetrieval:
            """Retrieval-evaluator double raising from evaluate."""

            def evaluate(self, **_: object) -> object:
                """Raise a bounded failure."""
                raise RuntimeError("retrieval evaluator blew up")

        scenario = _retrieval_scenario()
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario]),
            retrieval_evaluator=cast(Any, ExplodingRetrieval()),
        )
        result = await EvaluationRunner().run(
            dataset_id=EvaluationDatasetId(
                target=EvaluationTarget.RESEARCH_AGENT, version=1
            ),
            cases=[evaluation_case_from(scenario)],
            target=cast(Any, _passing_retrieval_target(_retrieval_output((_chunk(),)))),
            evaluators=(dispatcher,),  # type: ignore[arg-type]
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR
        assert result.verdict is None

    @pytest.mark.asyncio
    async def test_e14_cancellation_propagates(self) -> None:
        """E14 asyncio.CancelledError propagates unchanged."""

        class CancellingSynthesis:
            """Synthesis-evaluator double raising cancellation."""

            def evaluate(self, **_: object) -> object:
                """Raise cancellation."""
                raise asyncio.CancelledError("cancelled")

        scenario = _synthesis_scenario()
        dispatcher = ResearchAgentEvaluatorDispatcher(
            scenario_lookup=ResearchScenarioLookup([scenario]),
            synthesis_evaluator=cast(Any, CancellingSynthesis()),
        )
        with pytest.raises(asyncio.CancelledError):
            await dispatcher.evaluate(
                case=evaluation_case_from(scenario),
                output=_synthesis_output(),
                context=_context(scenario.id),
            )


def _passing_retrieval_target(output: ResearchEvaluationOutput) -> Any:
    """Build a target double returning the retrieval output."""

    class ReturningTarget:
        """Target double returning the fixed output."""

        async def execute(self, *, case: object, context: object) -> object:
            """Return the fixed output."""
            del case, context
            return output

    return ReturningTarget()
