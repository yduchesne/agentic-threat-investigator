# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence Analyst deterministic evaluation baseline (PR 20C).

PR 20C answers one question about a persisted
:class:`~agentic_threat_investigator.domain.assessment.Assessment` produced
through the unchanged PR 20B execution path: did the analyst make an
acceptable analytical decision for a known scenario? Evaluation is
deterministic, repository-owned, and consumes persisted Assessments only.
"""

from agentic_threat_investigator.evaluation.analyst.evaluator import (
    EvidenceAnalystEvaluator,
)
from agentic_threat_investigator.evaluation.analyst.loader import (
    AnalystScenarioLoadError,
    load_scenario_file,
    load_scenarios_directory,
)
from agentic_threat_investigator.evaluation.analyst.materializer import (
    AnalystScenarioMaterializer,
)
from agentic_threat_investigator.evaluation.analyst.models import (
    AnalystEvaluationFailure,
    AnalystEvaluationFailureCode,
    AnalystEvaluationMetrics,
    AnalystEvaluationResult,
    AnalystFixture,
    AnalystScenario,
    AnalystScenarioResolution,
    ExpectedAssessment,
    ExpectedFinding,
    FixtureEntity,
    FixtureEvidence,
    FixtureObservation,
    FixtureRelationship,
    ForbiddenFinding,
    RequiredContradiction,
    UnknownFixtureLabelError,
)

__all__ = [
    "AnalystEvaluationFailure",
    "AnalystEvaluationFailureCode",
    "AnalystEvaluationMetrics",
    "AnalystEvaluationResult",
    "AnalystFixture",
    "AnalystScenario",
    "AnalystScenarioLoadError",
    "AnalystScenarioMaterializer",
    "AnalystScenarioResolution",
    "EvidenceAnalystEvaluator",
    "ExpectedAssessment",
    "ExpectedFinding",
    "FixtureEntity",
    "FixtureEvidence",
    "FixtureObservation",
    "FixtureRelationship",
    "ForbiddenFinding",
    "RequiredContradiction",
    "UnknownFixtureLabelError",
    "load_scenario_file",
    "load_scenarios_directory",
]
