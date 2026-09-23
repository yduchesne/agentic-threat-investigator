# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 22D deterministic Threat Research / RAG evaluation.

The package owns the narrow repository-owned evaluation baseline for the
delivered PR 22 runtime: retrieval evaluators (with pure metric helpers),
structured synthesis evaluators over persisted ``ResearchResult`` artifacts,
epistemic non-promotion snapshots, strict scenario loaders, and the
coordinator trajectory research lifecycle. Everything is offline,
deterministic, and repository-owned: no LLM judge, no generic PR 27
evaluation platform, no evaluation persistence.
"""

from agentic_threat_investigator.evaluation.research.composition import (
    REPOSITORY_RESEARCH_FIXTURES,
    RecordingResearchRetriever,
    ResearchWorld,
    bootstrap_research_corpus,
    build_research_world,
    load_epistemic_snapshot,
    scenario_anchor_ids,
    seed_research_anchors,
)
from agentic_threat_investigator.evaluation.research.loader import (
    ResearchScenarioLoadError,
    load_retrieval_scenarios_directory,
    load_synthesis_scenarios_directory,
)
from agentic_threat_investigator.evaluation.research.materialization import (
    ResearchScenarioMaterializationError,
    resolve_research_scenario,
)
from agentic_threat_investigator.evaluation.research.models import (
    ExpectedResearchClaim,
    ExpectedResearchResult,
    ResearchEpistemicSnapshot,
    ResearchExecutionEvaluationInput,
    ResearchFixtureReference,
    ResearchRetrievalEvaluationResult,
    ResearchRetrievalFailureCode,
    ResearchRetrievalMetrics,
    ResearchRetrievalScenario,
    ResearchScenarioResolution,
    ResearchSynthesisEvaluationResult,
    ResearchSynthesisFailureCode,
    ResearchSynthesisMetrics,
    ResearchSynthesisScenario,
)
from agentic_threat_investigator.evaluation.research.pr30 import (
    RESEARCH_RETRIEVAL_CONTRACT_EVALUATOR_ID,
    RESEARCH_SYNTHESIS_CONTRACT_EVALUATOR_ID,
    ResearchAgentEvaluatorDispatcher,
)
from agentic_threat_investigator.evaluation.research.retrieval import (
    ResearchRetrievalEvaluator,
)
from agentic_threat_investigator.evaluation.research.run import (
    run_research_agent_evaluation,
)
from agentic_threat_investigator.evaluation.research.synthesis import (
    ResearchSynthesisEvaluator,
)
from agentic_threat_investigator.evaluation.research.target import (
    ResearchAgentTargetExecutor,
    ResearchEvaluationOutput,
    ResearchRetrievalEvaluationOutput,
    ResearchScenarioLookup,
    ResearchSynthesisEvaluationOutput,
)

__all__ = [
    "ExpectedResearchClaim",
    "ExpectedResearchResult",
    "REPOSITORY_RESEARCH_FIXTURES",
    "RESEARCH_RETRIEVAL_CONTRACT_EVALUATOR_ID",
    "RESEARCH_SYNTHESIS_CONTRACT_EVALUATOR_ID",
    "RecordingResearchRetriever",
    "ResearchAgentEvaluatorDispatcher",
    "ResearchAgentTargetExecutor",
    "ResearchEpistemicSnapshot",
    "ResearchEvaluationOutput",
    "ResearchExecutionEvaluationInput",
    "ResearchFixtureReference",
    "ResearchRetrievalEvaluationOutput",
    "ResearchRetrievalEvaluationResult",
    "ResearchRetrievalEvaluator",
    "ResearchRetrievalFailureCode",
    "ResearchRetrievalMetrics",
    "ResearchRetrievalScenario",
    "ResearchScenarioLoadError",
    "ResearchScenarioLookup",
    "ResearchScenarioMaterializationError",
    "ResearchScenarioResolution",
    "ResearchSynthesisEvaluationOutput",
    "ResearchSynthesisEvaluationResult",
    "ResearchSynthesisEvaluator",
    "ResearchSynthesisFailureCode",
    "ResearchSynthesisMetrics",
    "ResearchSynthesisScenario",
    "ResearchWorld",
    "bootstrap_research_corpus",
    "build_research_world",
    "load_epistemic_snapshot",
    "resolve_research_scenario",
    "scenario_anchor_ids",
    "seed_research_anchors",
    "load_retrieval_scenarios_directory",
    "load_synthesis_scenarios_directory",
    "run_research_agent_evaluation",
]
