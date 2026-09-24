# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A common evaluation foundation.

The common package freezes the backend-neutral evaluation contract that PR
30B and later evaluation suites build on: binary verdicts, an execution
status distinct from ``FAIL``, evaluator/case/dataset aggregation, dataset
identity and versioning, the canonical scenario-quality contract, the
backend-neutral evaluator/runner seams, and deterministic local reporting.

Nothing in this package imports LangSmith, provider SDKs, or LLM clients,
and nothing performs network I/O.
"""

from agentic_threat_investigator.evaluation.common.evaluator import (
    EvaluationContext,
    Evaluator,
    TargetExecutor,
)
from agentic_threat_investigator.evaluation.common.loader import (
    DatasetLoadError,
    DuplicateJsonKeyError,
    read_json_object,
    validate_dataset_cases,
    validate_dataset_id,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCase,
    EvaluationCaseResult,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationRunResult,
    EvaluationTarget,
    EvaluationVerdict,
    ExpectedBehavior,
    JudgeDecision,
    ScenarioSpecification,
    evaluation_case_from,
    sanitize_explanation,
)
from agentic_threat_investigator.evaluation.common.reporting import (
    render_human_report,
    render_machine_report,
)
from agentic_threat_investigator.evaluation.common.runner import EvaluationRunner

__all__ = [
    "DatasetLoadError",
    "DuplicateJsonKeyError",
    "EvaluationCase",
    "EvaluationCaseResult",
    "EvaluationContext",
    "EvaluationDatasetId",
    "EvaluationExecutionStatus",
    "EvaluationResult",
    "EvaluationRunner",
    "EvaluationRunResult",
    "EvaluationTarget",
    "EvaluationVerdict",
    "Evaluator",
    "ExpectedBehavior",
    "JudgeDecision",
    "ScenarioSpecification",
    "TargetExecutor",
    "evaluation_case_from",
    "read_json_object",
    "render_human_report",
    "render_machine_report",
    "sanitize_explanation",
    "validate_dataset_cases",
    "validate_dataset_id",
]
