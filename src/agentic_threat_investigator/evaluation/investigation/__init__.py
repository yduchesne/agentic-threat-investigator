# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end Investigation deterministic evaluation baseline (PR 30F).

PR 30F answers one question about a complete investigation world executed
through the production investigation orchestration and the production Report
Writer: did the end-to-end investigation produce the expected durable
outcome, trajectory, provenance, and report for the authored scenario?
Evaluation is deterministic, repository-owned, and consumes persisted state
plus structured timeline actions only.
"""

from agentic_threat_investigator.evaluation.investigation.evaluator import (
    InvestigationEvaluator,
)
from agentic_threat_investigator.evaluation.investigation.fixtures import (
    SUPPORTED_FIXTURE_NAMES,
    InvestigationFixture,
    InvestigationFixtureError,
    build_investigation_provider_registry,
    investigation_fixture,
)
from agentic_threat_investigator.evaluation.investigation.loader import (
    InvestigationScenarioLoadError,
    load_investigation_scenario_file,
    load_investigation_scenarios_directory,
)
from agentic_threat_investigator.evaluation.investigation.materialization import (
    InvestigationMaterializationError,
    InvestigationScenarioMaterializer,
    planned_investigation_id,
)
from agentic_threat_investigator.evaluation.investigation.models import (
    AssessmentExpectation,
    EfficiencyExpectation,
    EvidenceExpectation,
    ExpectedInvestigationOutcome,
    InvestigationEvaluationOutput,
    InvestigationEvaluationResult,
    InvestigationExecutionMetrics,
    InvestigationFailureCode,
    InvestigationRoot,
    InvestigationScenario,
    InvestigationScenarioResolution,
    RelationshipExpectation,
    ReportExpectation,
    ResearchExpectation,
    TerminalExpectation,
    TrajectoryExpectation,
)
from agentic_threat_investigator.evaluation.investigation.target import (
    InvestigationScenarioLookup,
    InvestigationScenarioLookupError,
    InvestigationSnapshot,
    InvestigationTargetError,
    InvestigationTargetExecutor,
)

__all__ = [
    "AssessmentExpectation",
    "EfficiencyExpectation",
    "EvidenceExpectation",
    "ExpectedInvestigationOutcome",
    "InvestigationEvaluationOutput",
    "InvestigationEvaluationResult",
    "InvestigationEvaluator",
    "InvestigationExecutionMetrics",
    "InvestigationFailureCode",
    "InvestigationFixture",
    "InvestigationFixtureError",
    "InvestigationMaterializationError",
    "InvestigationRoot",
    "InvestigationScenario",
    "InvestigationScenarioLoadError",
    "InvestigationScenarioLookup",
    "InvestigationScenarioLookupError",
    "InvestigationScenarioMaterializer",
    "InvestigationScenarioResolution",
    "InvestigationSnapshot",
    "InvestigationTargetError",
    "InvestigationTargetExecutor",
    "RelationshipExpectation",
    "ReportExpectation",
    "ResearchExpectation",
    "SUPPORTED_FIXTURE_NAMES",
    "TerminalExpectation",
    "TrajectoryExpectation",
    "build_investigation_provider_registry",
    "investigation_fixture",
    "load_investigation_scenario_file",
    "load_investigation_scenarios_directory",
    "planned_investigation_id",
]
