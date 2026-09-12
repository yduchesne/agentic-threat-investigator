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
from agentic_threat_investigator.evaluation.research.retrieval import (
    ResearchRetrievalEvaluator,
)
from agentic_threat_investigator.evaluation.research.synthesis import (
    ResearchSynthesisEvaluator,
)

__all__ = [
    "ExpectedResearchClaim",
    "ExpectedResearchResult",
    "ResearchEpistemicSnapshot",
    "ResearchExecutionEvaluationInput",
    "ResearchFixtureReference",
    "ResearchRetrievalEvaluationResult",
    "ResearchRetrievalEvaluator",
    "ResearchRetrievalFailureCode",
    "ResearchRetrievalMetrics",
    "ResearchRetrievalScenario",
    "ResearchScenarioLoadError",
    "ResearchScenarioMaterializationError",
    "ResearchScenarioResolution",
    "ResearchSynthesisEvaluationResult",
    "ResearchSynthesisEvaluator",
    "ResearchSynthesisFailureCode",
    "ResearchSynthesisMetrics",
    "ResearchSynthesisScenario",
    "load_retrieval_scenarios_directory",
    "resolve_research_scenario",
    "load_synthesis_scenarios_directory",
]
