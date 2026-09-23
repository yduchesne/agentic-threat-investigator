# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Categorical result publication tests (LS-R01..R10).

Deterministic, offline: PASS/FAIL/ERROR map to the categorical vocabulary
(never to a numeric correctness score), explanations stay bounded and
sanitized, diagnostics are never published by default, feedback keys and
ordering are stable, and the experiment-metadata builder omits unset values.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithEvaluationPublication,
)
from agentic_threat_investigator.evaluation.backends.langsmith.results import (
    build_experiment_metadata,
    build_publication,
    categorical_status,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCaseResult,
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationRunResult,
    EvaluationVerdict,
)
from tests.support.evaluation_common import (
    COMPLETED,
    ERROR,
    FAIL,
    PASS,
    unit_case,
    unit_case_result,
    unit_dataset,
    unit_result,
)


def _run(
    *, case_results: tuple[EvaluationCaseResult, ...] | None = None
) -> EvaluationRunResult:
    """Build one deterministic run result from case results."""
    from agentic_threat_investigator.evaluation.common.models import dataset_aggregate

    results = case_results or (unit_case_result(status=COMPLETED, verdict=PASS),)
    status, verdict = dataset_aggregate(results)
    return EvaluationRunResult(
        dataset_id=unit_dataset(),
        execution_status=status,
        verdict=verdict,
        cases=results,
    )


def _fail_case() -> EvaluationCaseResult:
    """Build one COMPLETED/FAIL case with a matching evaluator result."""
    return unit_case_result(
        status=COMPLETED,
        verdict=FAIL,
        results=(unit_result(status=COMPLETED, verdict=FAIL),),
    )


def _error_case() -> EvaluationCaseResult:
    """Build one ERROR case with a matching evaluator result."""
    return unit_case_result(
        status=ERROR,
        verdict=None,
        results=(unit_result(status=ERROR, verdict=None),),
    )


def _publication(
    status: EvaluationExecutionStatus, verdict: EvaluationVerdict | None
) -> LangSmithEvaluationPublication:
    """Build one publication for a single-result state."""
    from tests.support.evaluation_common import unit_result as _result

    results = (_result(status=status, verdict=verdict),)
    return build_publication(
        _run(
            case_results=(
                unit_case_result(status=status, verdict=verdict, results=results),
            )
        )
    )


class TestCategoricalMapping:
    """LS-R01..R03/R08 the frozen categorical vocabulary."""

    def test_r01_pass_is_categorical_pass(self) -> None:
        """R01 COMPLETED/PASS maps to the categorical value 'pass'."""
        publication = _publication(COMPLETED, PASS)
        assert publication.run_status == "pass"
        assert publication.feedback[0].value == "pass"
        assert categorical_status(COMPLETED, PASS) == "pass"

    def test_r02_fail_is_categorical_fail(self) -> None:
        """R02 COMPLETED/FAIL maps to the categorical value 'fail'."""
        publication = _publication(COMPLETED, FAIL)
        assert publication.run_status == "fail"
        assert publication.feedback[0].value == "fail"
        assert categorical_status(COMPLETED, FAIL) == "fail"

    def test_r03_error_is_categorical_error(self) -> None:
        """R03 ERROR maps to the categorical value 'error', never 'fail'."""
        publication = _publication(ERROR, None)
        assert publication.run_status == "error"
        assert publication.feedback[0].value == "error"
        assert categorical_status(ERROR, None) == "error"

    def test_r08_run_error_remains_error(self) -> None:
        """R08 a run-level ERROR stays error regardless of any case verdict."""
        failing_case = _fail_case()
        error_case = unit_case_result(
            status=ERROR,
            verdict=None,
            results=(unit_result(status=ERROR, verdict=None),),
        )
        run = EvaluationRunResult(
            dataset_id=unit_dataset(),
            execution_status=ERROR,
            verdict=None,
            cases=(failing_case, error_case),
        )
        publication = build_publication(run)
        assert publication.run_status == "error"
        assert publication.feedback[0].value == "error"


class TestExplanationAndDiagnostics:
    """LS-R04..R06 bounded/sanitized explanations, no default diagnostics."""

    def test_r04_bounded_explanation_preserved(self) -> None:
        """R04 a bounded author explanation is preserved verbatim."""
        result = unit_result(
            status=COMPLETED,
            verdict=FAIL,
            explanation="the Assessment omitted the required limitation",
        )
        case = unit_case_result(status=COMPLETED, verdict=FAIL, results=(result,))
        publication = build_publication(_run(case_results=(case,)))
        evaluator_items = [
            item for item in publication.feedback if "evaluator" in item.key
        ]
        assert (
            evaluator_items[0].comment
            == "the Assessment omitted the required limitation"
        )

    def test_r05_error_explanation_sanitized(self) -> None:
        """R05 an ERROR explanation is re-sanitized (control chars, bounded)."""
        result = EvaluationResult(
            evaluator_id="explode",
            execution_status=ERROR,
            explanation="boom\nwith\ttabs and a very long tail: " + "x" * 2000,
        )
        case = unit_case_result(status=ERROR, verdict=None, results=(result,))
        publication = build_publication(_run(case_results=(case,)))
        evaluator_items = [
            item for item in publication.feedback if "evaluator" in item.key
        ]
        comment = evaluator_items[0].comment
        assert "\n" not in comment
        assert "\t" not in comment
        assert len(comment) <= 500 + len("[truncated]")
        assert "x" * 2000 not in comment

    def test_r06_diagnostics_never_published(self) -> None:
        """R06 arbitrary diagnostics are never published by default."""
        result = EvaluationResult(
            evaluator_id="truth",
            execution_status=COMPLETED,
            verdict=PASS,
            explanation="deterministic unit explanation",
            diagnostics={"provider_calls": 12, "secret_marker": "sk-leak"},
        )
        case = unit_case_result(status=COMPLETED, verdict=PASS, results=(result,))
        publication = build_publication(_run(case_results=(case,)))
        rendered = publication.model_dump(mode="python")
        assert "diagnostics" not in rendered
        assert "secret_marker" not in str(rendered)


class TestFeedbackShape:
    """LS-R07/R09/R10 stable keys, order, and categorical-only values."""

    def test_r07_case_fail_is_categorical_only(self) -> None:
        """R07 a case FAIL projects a categorical case feedback item with no score."""
        publication = build_publication(_run(case_results=(_fail_case(),)))
        case_items = [
            item for item in publication.feedback if item.key.startswith("ati.case.")
        ]
        assert case_items[0].key == "ati.case.unit-case"
        assert case_items[0].value == "fail"

    def test_r09_stable_evaluator_keys_and_order(self) -> None:
        """R09 evaluator feedback keys are stable and follow declared order."""
        results = (
            EvaluationResult(
                evaluator_id="z-evaluator",
                execution_status=COMPLETED,
                verdict=PASS,
                explanation="deterministic unit explanation",
            ),
            EvaluationResult(
                evaluator_id="a-evaluator",
                execution_status=COMPLETED,
                verdict=PASS,
                explanation="deterministic unit explanation",
            ),
        )
        case = unit_case_result(status=COMPLETED, verdict=PASS, results=results)
        second_case = unit_case_result(
            case=unit_case(case_id="second"),
            status=COMPLETED,
            verdict=FAIL,
            results=(
                EvaluationResult(
                    evaluator_id="b-evaluator",
                    execution_status=COMPLETED,
                    verdict=FAIL,
                    explanation="deterministic unit explanation",
                ),
            ),
        )
        publication = build_publication(_run(case_results=(case, second_case)))
        keys = [item.key for item in publication.feedback]
        expected = [
            "ati.run.status",
            "ati.case.unit-case",
            "ati.evaluator.z-evaluator",
            "ati.evaluator.a-evaluator",
            "ati.case.second",
            "ati.evaluator.b-evaluator",
        ]
        assert keys == expected

    def test_r10_no_score_weight_or_percentage(self) -> None:
        """R10 no numeric correctness value ever enters the categorical boundary."""
        results = (
            EvaluationResult(
                evaluator_id="truth",
                execution_status=COMPLETED,
                verdict=PASS,
                explanation="deterministic unit explanation",
            ),
            EvaluationResult(
                evaluator_id="structure",
                execution_status=COMPLETED,
                verdict=FAIL,
                explanation="structure violated the envelope",
            ),
        )
        case = unit_case_result(status=COMPLETED, verdict=FAIL, results=results)
        publication = build_publication(_run(case_results=(case,)))
        for item in publication.feedback:
            assert item.value in {"pass", "fail", "error"}
            assert item.key not in {
                "score",
                "weight",
                "percentage",
                "confidence",
                "severity",
            }
        assert publication.run_status == "fail"


class TestExperimentMetadata:
    """Optional adapter-only experiment metadata building."""

    def test_unset_values_omitted(self) -> None:
        """Unset experiment metadata values are omitted entirely."""
        metadata = build_experiment_metadata(
            dataset_id="evidence-analyst/v1",
            model_name="gpt-4o-mini",
        )
        assert metadata == {
            "ati.dataset_id": "evidence-analyst/v1",
            "ati.model_name": "gpt-4o-mini",
        }

    def test_full_envelope_bounded(self) -> None:
        """The complete optional envelope is emitted with bounded values."""
        metadata = build_experiment_metadata(
            commit_sha="abc123",
            dataset_id="evidence-analyst/v1",
            projection_schema_version=1,
            agent_implementation_version="v1",
            prompt_version="v3",
            model_provider="openai",
            model_name="gpt-4o-mini",
            model_parameters={"temperature": 0.0},
            fixture_set_version="f2",
            normalization_version="n1",
            retriever_version="r1",
            embedding_version="e1",
            evaluator_version="ev1",
            judge_model="judge-x",
            judge_prompt_version="j2",
            timestamp="2026-01-01T00:00:00+00:00",
        )
        assert metadata["ati.commit_sha"] == "abc123"
        assert metadata["ati.model_parameters"] == {"temperature": 0.0}
        assert len(metadata) == 16

    def test_secret_like_values_rejected(self) -> None:
        """Secret-like text and unbounded model parameters fail closed."""
        with pytest.raises(ValidationError):
            build_experiment_metadata(
                model_parameters={"api_key": "sk-injected-secret"}
            )
        with pytest.raises(ValidationError):
            build_experiment_metadata(model_name="x" * 1000)
