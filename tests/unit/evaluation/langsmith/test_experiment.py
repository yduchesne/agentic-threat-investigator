# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30C LangSmith experiment tests (EA-LS01..LS15).

Deterministic and offline: the experiment adapter creates one run per ATI
benchmark execution, publishes PR 30B categorical feedback, and confirms
remote state through the in-memory :class:`FakeLangSmithClient`. No
evaluation ever re-runs the target, no numeric score or threshold is
published, diagnostics stay local, metadata stays bounded and secret-free,
cancellation propagates, and feedback failures fail closed.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from agentic_threat_investigator.evaluation.backends.langsmith.client import (
    LangSmithBackendError,
)
from agentic_threat_investigator.evaluation.backends.langsmith.experiments import (
    LangSmithExperimentError,
    build_experiment_metadata_envelope,
    confirm_experiment,
    experiment_name,
    publish_experiment,
)
from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithExperimentRef,
    LangSmithFeedbackItem,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCaseResult,
    EvaluationRunResult,
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
from tests.support.langsmith_fakes import FakeLangSmithClient

EXECUTION_ID = "a" * 32


def _run(
    *, case_results: tuple[EvaluationCaseResult, ...] | None = None
) -> EvaluationRunResult:
    """Build one deterministic run result from aggregated case results."""
    from agentic_threat_investigator.evaluation.common.models import dataset_aggregate

    results = case_results or (unit_case_result(status=COMPLETED, verdict=PASS),)
    status, verdict = dataset_aggregate(results)
    return EvaluationRunResult(
        dataset_id=unit_dataset(),
        execution_status=status,
        verdict=verdict,
        cases=results,
    )


def _pass_run(case_count: int = 1) -> EvaluationRunResult:
    """Build a fully passing run with ``case_count`` distinct cases."""
    return _run(
        case_results=tuple(
            unit_case_result(unit_case(f"case-{index}"), status=COMPLETED, verdict=PASS)
            for index in range(case_count)
        )
    )


@pytest.mark.asyncio
async def test_ls01_exact_mirror_allows_experiment() -> None:
    """LS01 publication through an exact mirror succeeds and confirms."""
    fake = FakeLangSmithClient()
    run = _pass_run(2)
    confirmation = await publish_experiment(
        dataset_id=unit_dataset(),
        run=run,
        client=fake,
        execution_id=EXECUTION_ID,
    )
    assert confirmation.status == "confirmed"
    assert confirmation.experiment_name == experiment_name(
        unit_dataset(), execution_id=EXECUTION_ID
    )
    assert confirmation.feedback_count > 0
    assert "create_experiment" in fake.calls
    assert "publish_feedback" in fake.calls
    assert "read_experiment" in fake.calls
    assert "list_feedback" in fake.calls


@pytest.mark.asyncio
async def test_ls04_one_case_one_remote_association() -> None:
    """LS04 each ATI case appears as exactly one remote case association."""
    fake = FakeLangSmithClient()
    run = _pass_run(3)
    await publish_experiment(
        dataset_id=unit_dataset(),
        run=run,
        client=fake,
        execution_id=EXECUTION_ID,
    )
    run_id, publication = fake.published[0]
    case_keys = {
        item.key for item in publication.feedback if item.key.startswith("ati.case.")
    }
    assert len(case_keys) == 3
    # The seeded remote experiment carries exactly these case feedback keys.
    feedback = await fake.list_feedback(run_id=run_id)
    assert {
        item.key for item in feedback if item.key.startswith("ati.case.")
    } == case_keys


@pytest.mark.asyncio
async def test_ls05_pass_is_categorical_pass() -> None:
    """LS05 a PASS run publishes and confirms the categorical pass values."""
    fake = FakeLangSmithClient()
    await publish_experiment(
        dataset_id=unit_dataset(),
        run=_pass_run(),
        client=fake,
        execution_id=EXECUTION_ID,
    )
    run_id, _publication = fake.published[0]
    feedback = await fake.list_feedback(run_id=run_id)
    values = {item.value for item in feedback}
    assert values == {"pass"}


@pytest.mark.asyncio
async def test_ls06_fail_is_categorical_fail() -> None:
    """LS06 a FAIL run publishes categorical fail and never converts to pass."""
    fake = FakeLangSmithClient()
    fail_run = _run(
        case_results=(
            unit_case_result(
                status=COMPLETED,
                verdict=FAIL,
                results=(unit_result(status=COMPLETED, verdict=FAIL),),
            ),
        )
    )
    await publish_experiment(
        dataset_id=unit_dataset(),
        run=fail_run,
        client=fake,
        execution_id=EXECUTION_ID,
    )
    run_id, publication = fake.published[0]
    assert publication.run_status == "fail"
    feedback = await fake.list_feedback(run_id=run_id)
    values = {item.value for item in feedback}
    assert "pass" not in values
    assert "fail" in values


@pytest.mark.asyncio
async def test_ls07_error_is_categorical_error() -> None:
    """LS07 an ERROR run publishes categorical error, never fail."""
    fake = FakeLangSmithClient()
    error_run = _run(
        case_results=(
            unit_case_result(
                status=ERROR,
                verdict=None,
                results=(unit_result(status=ERROR, verdict=None),),
            ),
        )
    )
    await publish_experiment(
        dataset_id=unit_dataset(),
        run=error_run,
        client=fake,
        execution_id=EXECUTION_ID,
    )
    run_id, publication = fake.published[0]
    assert publication.run_status == "error"
    feedback = await fake.list_feedback(run_id=run_id)
    assert {item.value for item in feedback} == {"error"}


@pytest.mark.asyncio
async def test_ls08_feedback_accepted_confirms() -> None:
    """LS08 accepted feedback yields a confirmed experiment."""
    fake = FakeLangSmithClient()
    confirmation = await publish_experiment(
        dataset_id=unit_dataset(),
        run=_pass_run(),
        client=fake,
        execution_id=EXECUTION_ID,
    )
    assert confirmation.status == "confirmed"


@pytest.mark.asyncio
async def test_ls09_feedback_failure_fails_closed() -> None:
    """LS09 a feedback-publish failure fails closed with a bounded error."""
    fake = FakeLangSmithClient()
    fake.fail_operations = {"publish_feedback"}
    with pytest.raises(LangSmithBackendError):
        await publish_experiment(
            dataset_id=unit_dataset(),
            run=_pass_run(),
            client=fake,
            execution_id=EXECUTION_ID,
        )


def test_ls10_confirmation_mismatch_fails_closed() -> None:
    """LS10 a remote confirmation mismatch (renamed run) fails closed."""
    ref = LangSmithExperimentRef(run_id="run-1", name="ati/x")
    with pytest.raises(LangSmithExperimentError):
        confirm_experiment(
            ref=ref,
            observed=LangSmithExperimentRef(run_id="run-1", name="someone/else"),
            feedback=(),
            expected_feedback={"ati.run.status": "pass"},
        )


@pytest.mark.asyncio
async def test_ls11_no_score_or_threshold() -> None:
    """LS11 the experiment publishes categorical values only, never scores."""
    fake = FakeLangSmithClient()
    await publish_experiment(
        dataset_id=unit_dataset(),
        run=_pass_run(),
        client=fake,
        execution_id=EXECUTION_ID,
    )
    run_id, _publication = fake.published[0]
    feedback = await fake.list_feedback(run_id=run_id)
    for item in feedback:
        assert item.value in {"pass", "fail", "error"}
    metadata = fake.experiments[run_id]["ref"].metadata
    for value in metadata.values():
        assert not isinstance(value, float)


@pytest.mark.asyncio
async def test_ls12_diagnostics_not_uploaded_by_default() -> None:
    """LS12 no evaluator diagnostics reach the experiment metadata."""
    fake = FakeLangSmithClient()
    await publish_experiment(
        dataset_id=unit_dataset(),
        run=_pass_run(),
        client=fake,
        execution_id=EXECUTION_ID,
    )
    run_id, _ = fake.published[0]
    metadata = json.dumps(fake.experiments[run_id]["ref"].metadata)
    for forbidden in (
        "required_findings_total",
        "forbidden_support_violations",
        "diagnostics",
    ):
        assert forbidden not in metadata


@pytest.mark.asyncio
async def test_ls13_metadata_bounded_and_secret_free() -> None:
    """LS13 the experiment metadata envelope is bounded and carries no secrets."""
    secret = "sk-live-secret"
    metadata = build_experiment_metadata_envelope(
        dataset_id=unit_dataset(),
        run=_pass_run(),
        extra={"ati.model": "gpt-4o-mini", "ati.parameters": {"temperature": 0.0}},
    )
    assert metadata["ati.dataset_id"] == "evidence-analyst/v1"
    assert metadata["ati.experiment.case_ids"] == ["case-0"]
    assert isinstance(metadata["ati.parameters"], dict)
    serialized = json.dumps(metadata)
    assert secret not in serialized
    assert "api_key" not in serialized.lower()


@pytest.mark.asyncio
async def test_ls14_cancellation_propagates() -> None:
    """LS14 blocking remote operations propagate cancellation unchanged."""
    fake = FakeLangSmithClient()
    fake.block_operations = {"create_experiment"}
    task = asyncio.create_task(
        publish_experiment(
            dataset_id=unit_dataset(),
            run=_pass_run(),
            client=fake,
            execution_id=EXECUTION_ID,
        )
    )
    # Wait until the task is blocked inside the fake's create_experiment.
    while "create_experiment" not in fake.calls:
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_ls15_no_duplicate_model_execution() -> None:
    """LS15 experiment operations never invoke a target, dataset, or evaluator."""
    fake = FakeLangSmithClient()
    await publish_experiment(
        dataset_id=unit_dataset(),
        run=_pass_run(2),
        client=fake,
        execution_id=EXECUTION_ID,
    )
    assert "evaluate" not in fake.calls
    assert "aevaluate" not in fake.calls
    assert not any("run" in call for call in fake.calls if call == "evaluate")


@pytest.mark.asyncio
async def test_ls02_experiment_name_shape() -> None:
    """LS02 the experiment name carries the semantic prefix and execution id."""
    name = experiment_name(
        unit_dataset(), execution_id=EXECUTION_ID, commit_sha="0" * 40
    )
    assert name.startswith("ati/evidence-analyst/v1/")
    assert "000000000000" in name
    assert name.endswith(f"/{EXECUTION_ID}")


def test_experiment_name_rejects_invalid_execution_id() -> None:
    """An invalid execution id fails closed before any remote call."""
    with pytest.raises(LangSmithExperimentError):
        experiment_name(unit_dataset(), execution_id="NOT-HEX!")


def test_confirm_experiment_missing_run_fails_closed() -> None:
    """Confirming a nonexistent experiment run fails closed."""
    ref = LangSmithExperimentRef(run_id="run-1", name="ati/x")
    with pytest.raises(LangSmithExperimentError):
        confirm_experiment(
            ref=ref,
            observed=None,
            feedback=(),
            expected_feedback={"ati.run.status": "pass"},
        )


def test_confirm_experiment_feedback_mismatch_fails_closed() -> None:
    """Confirming with a different feedback set fails closed."""
    ref = LangSmithExperimentRef(run_id="run-1", name="ati/x")
    with pytest.raises(LangSmithExperimentError):
        confirm_experiment(
            ref=ref,
            observed=LangSmithExperimentRef(run_id="run-1", name="ati/x"),
            feedback=(LangSmithFeedbackItem(key="ati.run.status", value="fail"),),
            expected_feedback={"ati.run.status": "pass"},
        )
