# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30A common evaluation runner tests (EVAL-R01..R10).

Deterministic, fully offline test doubles prove the frozen failure
taxonomy: PASS/FAIL aggregation, evaluator/target exceptions becoming
ERROR (never FAIL), cancellation propagation, continued independent-cases
execution after an ERROR, and deterministic case/evaluator ordering.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from pathlib import Path

import pytest

from agentic_threat_investigator.evaluation.common import (
    EvaluationCase,
    EvaluationContext,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationRunner,
    EvaluationTarget,
    EvaluationVerdict,
    Evaluator,
    TargetExecutor,
)
from agentic_threat_investigator.evaluation.common.loader import (
    DatasetLoadError,
)
from agentic_threat_investigator.evaluation.common.runner import (
    TARGET_EXECUTION_EVALUATOR_ID,
)
from tests.support.evaluation_common import (
    COMPLETED,
    PASS,
    unit_case,
    unit_dataset,
    unit_fail,
    unit_pass,
)

OutputT = object


class FakeTarget(TargetExecutor[OutputT]):
    """Deterministic target executor; raises when ``fail`` is set."""

    def __init__(self, *, fail: bool = False) -> None:
        """Bind the deterministic failure flag."""
        self.fail = fail

    async def execute(
        self, *, case: EvaluationCase, context: EvaluationContext
    ) -> OutputT:
        """Return a stable output or raise the configured failure."""
        _ = case, context
        if self.fail:
            raise RuntimeError("target blew up")
        return "executed-output"


class RecordingEvaluator(Evaluator[OutputT]):
    """Deterministic fake evaluator with an optional failure mode."""

    def __init__(
        self,
        *,
        evaluator_id: str,
        result: EvaluationResult | None = None,
        raise_exception: bool = False,
        raise_for_case: frozenset[str] = frozenset(),
        cancel: bool = False,
        log: list[str] | None = None,
    ) -> None:
        """Bind the stable id, result, failure modes, and call log."""
        self._evaluator_id = evaluator_id
        self.result = result
        self.raise_exception = raise_exception
        self.raise_for_case = raise_for_case
        self.cancel = cancel
        self.log = log

    @property
    def evaluator_id(self) -> str:
        """Return the stable evaluator identifier."""
        return self._evaluator_id

    async def evaluate(
        self,
        *,
        case: EvaluationCase,
        output: OutputT,
        context: EvaluationContext,
    ) -> EvaluationResult:
        """Return the configured result or raise per the failure mode."""
        _ = output, context
        if self.log is not None:
            self.log.append(self._evaluator_id)
        if self.cancel:
            raise asyncio.CancelledError("cancelled")
        if self.raise_exception or case.case_id in self.raise_for_case:
            raise RuntimeError("evaluator blew up")
        assert self.result is not None
        return self.result


async def _run(
    *,
    cases: Sequence[EvaluationCase],
    evaluators: Sequence[Evaluator[OutputT]],
    target: TargetExecutor[OutputT] | None = None,
    dataset_id: EvaluationDatasetId | None = None,
) -> object:
    """Run the common runner once with the given doubles."""
    runner = EvaluationRunner()
    return await runner.run(
        dataset_id=dataset_id or unit_dataset(),
        cases=cases,
        target=target or FakeTarget(),
        evaluators=evaluators,
    )


@pytest.mark.asyncio
async def test_r01_all_pass_aggregates_dataset_pass() -> None:
    """All evaluator PASS results yield a COMPLETED/PASS run."""
    from agentic_threat_investigator.evaluation.common import (
        EvaluationRunResult,
    )

    cases = [unit_case("case-a"), unit_case("case-b")]
    evaluators = [
        RecordingEvaluator(evaluator_id="e1", result=unit_pass()),
        RecordingEvaluator(evaluator_id="e2", result=unit_pass()),
    ]
    result = await _run(cases=cases, evaluators=evaluators)
    assert isinstance(result, EvaluationRunResult)
    assert result.execution_status is COMPLETED
    assert result.verdict is PASS
    assert [case.case_id for case in result.cases] == ["case-a", "case-b"]
    assert all(case.verdict is PASS for case in result.cases)


@pytest.mark.asyncio
async def test_r02_evaluator_fail_aggregates_fail() -> None:
    """A completed evaluator FAIL verdict yields a FAIL dataset."""
    from agentic_threat_investigator.evaluation.common import (
        EvaluationRunResult,
    )

    evaluators = [
        RecordingEvaluator(evaluator_id="e1", result=unit_fail()),
        RecordingEvaluator(evaluator_id="e2", result=unit_pass()),
    ]
    result = await _run(cases=[unit_case()], evaluators=evaluators)
    assert isinstance(result, EvaluationRunResult)
    assert result.verdict is EvaluationVerdict.FAIL
    assert result.cases[0].verdict is EvaluationVerdict.FAIL


@pytest.mark.asyncio
async def test_r03_evaluator_exception_is_error_never_fail() -> None:
    """An evaluator exception becomes ERROR, never FAIL."""
    from agentic_threat_investigator.evaluation.common import (
        EvaluationRunResult,
    )

    evaluators = [
        RecordingEvaluator(evaluator_id="e1", result=unit_pass()),
        RecordingEvaluator(evaluator_id="e2", raise_exception=True),
    ]
    result = await _run(cases=[unit_case()], evaluators=evaluators)
    assert isinstance(result, EvaluationRunResult)
    assert result.execution_status is EvaluationExecutionStatus.ERROR
    assert result.verdict is None
    case = result.cases[0]
    assert case.execution_status is EvaluationExecutionStatus.ERROR
    error_result = case.evaluator_results[1]
    assert error_result.execution_status is EvaluationExecutionStatus.ERROR
    assert error_result.verdict is None
    assert error_result.explanation  # nonblank sanitized explanation
    # The runner must never convert a failure into a PASS/FAIL verdict.
    assert not any(
        evaluator.verdict is not None
        for evaluator in case.evaluator_results
        if evaluator.execution_status is EvaluationExecutionStatus.ERROR
    )


@pytest.mark.asyncio
async def test_r04_target_exception_is_case_error() -> None:
    """A target execution exception yields a case ERROR with no verdict."""
    from agentic_threat_investigator.evaluation.common import (
        EvaluationRunResult,
    )

    result = await _run(
        cases=[unit_case()],
        evaluators=[RecordingEvaluator(evaluator_id="e1", result=unit_pass())],
        target=FakeTarget(fail=True),
    )
    assert isinstance(result, EvaluationRunResult)
    assert result.execution_status is EvaluationExecutionStatus.ERROR
    assert result.verdict is None
    case = result.cases[0]
    assert case.execution_status is EvaluationExecutionStatus.ERROR
    assert case.verdict is None
    assert len(case.evaluator_results) == 1
    assert case.evaluator_results[0].evaluator_id == TARGET_EXECUTION_EVALUATOR_ID
    assert case.evaluator_results[0].execution_status is EvaluationExecutionStatus.ERROR


@pytest.mark.asyncio
async def test_r05_cancellation_propagates() -> None:
    """CancelledError is never swallowed by the runner."""
    runner = EvaluationRunner()
    with pytest.raises(asyncio.CancelledError):
        await runner.run(
            dataset_id=unit_dataset(),
            cases=[unit_case()],
            target=FakeTarget(),
            evaluators=[RecordingEvaluator(evaluator_id="e1", cancel=True)],
        )


@pytest.mark.asyncio
async def test_r06_independent_cases_continue_after_error() -> None:
    """A failing/erroring case does not stop later independent cases."""
    from agentic_threat_investigator.evaluation.common import (
        EvaluationRunResult,
    )

    cases = [unit_case("good"), unit_case("bad"), unit_case("good-again")]
    evaluators = [
        RecordingEvaluator(
            evaluator_id="e1",
            result=unit_pass(),
            raise_for_case=frozenset({"bad"}),
        ),
        RecordingEvaluator(evaluator_id="e2", result=unit_fail()),
    ]
    result = await _run(cases=cases, evaluators=evaluators)
    assert isinstance(result, EvaluationRunResult)
    assert len(result.cases) == 3
    assert [case.case_id for case in result.cases] == [
        "good",
        "bad",
        "good-again",
    ]
    # Case "bad" errored, but the later independent case still executed and
    # produced its own eigen result.
    assert result.cases[1].execution_status is EvaluationExecutionStatus.ERROR
    assert result.cases[2].execution_status is EvaluationExecutionStatus.COMPLETED
    assert result.cases[2].verdict is EvaluationVerdict.FAIL
    assert result.execution_status is EvaluationExecutionStatus.ERROR


@pytest.mark.asyncio
async def test_r07_deterministic_case_ordering() -> None:
    """Case results preserve the provided case order exactly."""
    from agentic_threat_investigator.evaluation.common import (
        EvaluationRunResult,
    )

    order = ["z-case", "a-case", "m-case"]
    cases = [unit_case(case_id) for case_id in order]
    result = await _run(
        cases=cases,
        evaluators=[RecordingEvaluator(evaluator_id="e1", result=unit_pass())],
    )
    assert isinstance(result, EvaluationRunResult)
    assert [case.case_id for case in result.cases] == order


@pytest.mark.asyncio
async def test_r08_deterministic_evaluator_ordering() -> None:
    """Evaluators run in their declared order for every case."""
    from agentic_threat_investigator.evaluation.common import (
        EvaluationRunResult,
    )

    log: list[str] = []
    evaluators = [
        RecordingEvaluator(evaluator_id="first", result=unit_pass(), log=log),
        RecordingEvaluator(evaluator_id="second", result=unit_pass(), log=log),
        RecordingEvaluator(evaluator_id="third", result=unit_pass(), log=log),
    ]
    cases = [unit_case("a"), unit_case("b")]
    result = await _run(cases=cases, evaluators=evaluators)
    assert isinstance(result, EvaluationRunResult)
    assert log == ["first", "second", "third", "first", "second", "third"]


@pytest.mark.asyncio
async def test_r09_no_backend_network_dependency() -> None:
    """The common evaluation sources never import LangSmith/provider SDKs."""
    package_root = (
        Path(__file__).parents[4]
        / "src"
        / "agentic_threat_investigator"
        / "evaluation"
        / "common"
    )
    for path in sorted(package_root.glob("*.py")):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip().lower()
            assert not stripped.startswith(
                (
                    "import langsmith",
                    "from langsmith",
                    "import openai",
                    "from openai",
                    "import httpx",
                    "from httpx",
                    "import urllib",
                    "from urllib",
                )
            )
    await _run(
        cases=[unit_case()],
        evaluators=[RecordingEvaluator(evaluator_id="e1", result=unit_pass())],
    )


@pytest.mark.asyncio
async def test_r10_diagnostics_never_affect_aggregation() -> None:
    """Wild but JSON-safe diagnostics leave the dataset verdict untouched."""
    from agentic_threat_investigator.evaluation.common import (
        EvaluationRunResult,
    )

    noisy_pass = EvaluationResult(
        evaluator_id="noisy",
        execution_status=COMPLETED,
        verdict=PASS,
        explanation="deterministic",
        diagnostics={
            "depth-first": 1,
            "times": [1, 2, 3],
            "meta": {"x": "y"},
        },
    )
    evaluators = [
        RecordingEvaluator(evaluator_id="noisy", result=noisy_pass),
        RecordingEvaluator(evaluator_id="e2", result=unit_pass()),
    ]
    result = await _run(cases=[unit_case()], evaluators=evaluators)
    assert isinstance(result, EvaluationRunResult)
    assert result.verdict is PASS


@pytest.mark.asyncio
async def test_runner_refuses_malformed_input() -> None:
    """The runner refuses to start on malformed datasets."""
    runner = EvaluationRunner()
    with pytest.raises(DatasetLoadError):
        await runner.run(
            dataset_id=unit_dataset(),
            cases=[],
            target=FakeTarget(),
            evaluators=[RecordingEvaluator(evaluator_id="e1", result=unit_pass())],
        )
    with pytest.raises(DatasetLoadError):
        await runner.run(
            dataset_id=unit_dataset(),
            cases=[unit_case()],
            target=FakeTarget(),
            evaluators=[],
        )
    from agentic_threat_investigator.evaluation.common.loader import (
        validate_dataset_cases,
    )

    duplicate = [unit_case("dup"), unit_case("dup")]
    with pytest.raises(DatasetLoadError):
        validate_dataset_cases(duplicate, dataset_id=unit_dataset())


@pytest.mark.asyncio
async def test_runner_rejects_target_mismatch() -> None:
    """A case whose target differs from the dataset refuses to start."""

    from tests.support.evaluation_common import unit_specification

    mismatched = unit_case()
    mismatched = mismatched.model_copy(
        update={
            "specification": unit_specification(target=EvaluationTarget.COORDINATOR)
        }
    )
    runner = EvaluationRunner()
    with pytest.raises(DatasetLoadError):
        await runner.run(
            dataset_id=unit_dataset(),
            cases=[mismatched],
            target=FakeTarget(),
            evaluators=[RecordingEvaluator(evaluator_id="e1", result=unit_pass())],
        )
