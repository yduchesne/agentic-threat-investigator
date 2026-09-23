# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30C ati-eval run CLI tests (EA-R06..R12, EA-LS02/LS03).

Deterministic and offline: the real corpus loads locally, the benchmark seam
(``_execute_evidence_analyst_benchmark``) is injected, and the LangSmith
client is the in-memory fake. Proves the run exit semantics (0 PASS, 1 FAIL,
2 ERROR/config/backend/publication), verify-before-model ordering, remote
drift refusal, missing-credential bounded errors, and the deterministic
driver rejection. No real LLM, database, or LangSmith service participates.
"""

from __future__ import annotations

import asyncio

import pytest

from agentic_threat_investigator.cli import evaluation_main
from agentic_threat_investigator.config.settings import LlmDriver, Settings
from agentic_threat_investigator.evaluation.backends.langsmith.datasets import (
    synchronize_dataset,
)
from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
    project_dataset_name,
    project_remote_metadata,
)
from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithExampleMetadata,
    LangSmithExampleRef,
)
from agentic_threat_investigator.evaluation.common import (
    EvaluationDatasetId,
    EvaluationRunResult,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCaseResult,
    EvaluationExecutionStatus,
)
from tests.support.evaluation_common import (
    COMPLETED,
    FAIL,
    PASS,
    unit_result,
)
from tests.support.langsmith_fakes import FakeLangSmithClient

DATASET = "evidence-analyst/v1"


def _pass_run_result() -> EvaluationRunResult:
    """Build one deterministic COMPLETED/PASS canonical run result."""
    return EvaluationRunResult(
        dataset_id=EvaluationDatasetId.from_canonical(DATASET),
        execution_status=COMPLETED,
        verdict=PASS,
        cases=(
            EvaluationCaseResult(
                case_id="cloud_asn_context",
                execution_status=COMPLETED,
                verdict=PASS,
                evaluator_results=(unit_result(status=COMPLETED, verdict=PASS),),
            ),
        ),
    )


def _fail_run_result() -> EvaluationRunResult:
    """Build one deterministic COMPLETED/FAIL canonical run result."""
    return EvaluationRunResult(
        dataset_id=EvaluationDatasetId.from_canonical(DATASET),
        execution_status=COMPLETED,
        verdict=FAIL,
        cases=(
            EvaluationCaseResult(
                case_id="cloud_asn_context",
                execution_status=COMPLETED,
                verdict=FAIL,
                evaluator_results=(unit_result(status=COMPLETED, verdict=FAIL),),
            ),
        ),
    )


def _error_run_result() -> EvaluationRunResult:
    """Build one deterministic ERROR canonical run result."""
    return EvaluationRunResult(
        dataset_id=EvaluationDatasetId.from_canonical(DATASET),
        execution_status=EvaluationExecutionStatus.ERROR,
        verdict=None,
        cases=(
            EvaluationCaseResult(
                case_id="cloud_asn_context",
                execution_status=EvaluationExecutionStatus.ERROR,
                verdict=None,
                evaluator_results=(
                    unit_result(status=EvaluationExecutionStatus.ERROR, verdict=None),
                ),
            ),
        ),
    )


def _install_benchmark(
    monkeypatch: pytest.MonkeyPatch,
    result: EvaluationRunResult,
    *,
    fail: BaseException | None = None,
    calls: list[str] | None = None,
) -> None:
    """Inject one scripted benchmark seam and a fixed git SHA."""

    async def benchmark(**_: object) -> EvaluationRunResult:
        """Return the scripted result or raise the scripted failure."""
        if calls is not None:
            calls.append("benchmark")
        if fail is not None:
            raise fail
        return result

    monkeypatch.setattr(
        "agentic_threat_investigator.cli._execute_evidence_analyst_benchmark",
        benchmark,
    )
    monkeypatch.setattr(
        "agentic_threat_investigator.cli._current_commit_sha",
        lambda: "a" * 40,
    )


def _install_fake(monkeypatch: pytest.MonkeyPatch, fake: FakeLangSmithClient) -> None:
    """Inject one fake client into the CLI's client factory."""

    def factory() -> FakeLangSmithClient:
        return fake

    monkeypatch.setattr(
        "agentic_threat_investigator.cli._build_langsmith_evaluation_client",
        factory,
    )


def _seeded_mirror() -> FakeLangSmithClient:
    """Build a fake client seeded with the exact evidence-analyst/v1 mirror."""
    from agentic_threat_investigator.evaluation.common import (
        EvaluationDatasetId,
    )
    from agentic_threat_investigator.evaluation.datasets import (
        load_evaluation_scenarios,
    )

    fake = FakeLangSmithClient()
    scenarios = load_evaluation_scenarios(EvaluationDatasetId.from_canonical(DATASET))
    asyncio.run(
        synchronize_dataset(
            dataset_id=EvaluationDatasetId.from_canonical(DATASET),
            client=fake,
            scenarios=scenarios,
        )
    )
    return fake


def _drifted_mirror() -> FakeLangSmithClient:
    """Build a fake client whose remote mirror carries a stale digest."""
    fake = _seeded_mirror()
    dataset_id = EvaluationDatasetId.from_canonical(DATASET)
    name = project_dataset_name(dataset_id)
    entry = fake.datasets[name]
    stale = LangSmithExampleMetadata(
        ati_dataset_id=DATASET,
        ati_case_id="cloud_asn_context",
        ati_case_version=1,
        ati_target="evidence-analyst",
        ati_title="title",
        ati_purpose="purpose",
        ati_operational_relevance="relevance",
        ati_regression_risk="risk",
        ati_projection_schema_version=1,
        ati_content_digest="f" * 64,
    )
    entry["examples"]["stale-example"] = LangSmithExampleRef(
        example_id="stale-example",
        dataset_id=entry["ref"].dataset_id,
        metadata=project_remote_metadata(stale),
    )
    return fake


class TestRunExitSemantics:
    """EA-R03/R04/R05/R06/R10/R11/R12 exit semantics."""

    def test_r06_local_run_constructs_no_langsmith_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R06 a local run (no --langsmith) never constructs a LangSmith client."""
        _install_benchmark(monkeypatch, _pass_run_result())

        def exploding() -> object:
            raise AssertionError("LangSmith client must not be constructed")

        monkeypatch.setattr(
            "agentic_threat_investigator.cli._build_langsmith_evaluation_client",
            exploding,
        )
        assert evaluation_main(["run", DATASET]) == 0

    def test_r03_pass_exits_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """R03 a COMPLETED/PASS run exits 0."""
        _install_benchmark(monkeypatch, _pass_run_result())
        assert evaluation_main(["run", DATASET]) == 0

    def test_r04_fail_exits_one(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """R04 a COMPLETED/FAIL run exits 1."""
        _install_benchmark(monkeypatch, _fail_run_result())
        assert evaluation_main(["run", DATASET]) == 1

    def test_r05_error_exits_two(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """R05 an ERROR run exits 2."""
        _install_benchmark(monkeypatch, _error_run_result())
        assert evaluation_main(["run", DATASET]) == 2

    def test_r11_missing_model_credential_bounded_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R11 a missing model credential surfaces as a bounded exit-2 failure."""
        from agentic_threat_investigator.app.secrets import SecretNotFoundError

        _install_benchmark(
            monkeypatch,
            _pass_run_result(),
            fail=SecretNotFoundError("ATI_OPENAI_API_KEY"),
        )
        assert evaluation_main(["run", DATASET]) == 2

    def test_r12_deterministic_driver_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R12 the deterministic driver is never silently used for a real run."""
        calls: list[str] = []
        _install_benchmark(monkeypatch, _pass_run_result(), calls=calls)
        monkeypatch.setattr(
            "agentic_threat_investigator.cli.get_settings",
            lambda: Settings(llm_driver=LlmDriver.DETERMINISTIC),
        )
        assert evaluation_main(["run", DATASET]) == 2
        assert calls == []

    def test_r14_non_analyst_dataset_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-evidence-analyst dataset is rejected before any model work."""
        calls: list[str] = []
        _install_benchmark(monkeypatch, _pass_run_result(), calls=calls)
        assert evaluation_main(["run", "coordinator/v1"]) == 2
        assert calls == []


class TestRunLangSmith:
    """EA-R07..R10 and EA-LS02/LS03 LangSmith-backed run behavior."""

    def test_r07_langsmith_verifies_before_model_execution(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R07 --langsmith verifies the remote mirror before any model work."""
        fake = _seeded_mirror()
        _install_fake(monkeypatch, fake)
        _install_benchmark(monkeypatch, _pass_run_result())
        assert evaluation_main(["run", DATASET, "--langsmith"]) == 0
        assert fake.calls[0] == "find_dataset"
        assert "list_examples" in fake.calls
        assert fake.published

    def test_r08_missing_remote_dataset_refuses_before_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R08 a missing remote dataset refuses before any model execution."""
        calls: list[str] = []
        fake = FakeLangSmithClient()
        _install_fake(monkeypatch, fake)
        _install_benchmark(monkeypatch, _pass_run_result(), calls=calls)
        assert evaluation_main(["run", DATASET, "--langsmith"]) == 2
        assert calls == []

    def test_ls03_digest_drift_refuses_before_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LS03 semantic digest drift refuses the run before any model work."""
        calls: list[str] = []
        _install_fake(monkeypatch, _drifted_mirror())
        _install_benchmark(monkeypatch, _pass_run_result(), calls=calls)
        assert evaluation_main(["run", DATASET, "--langsmith"]) == 2
        assert calls == []

    def test_r09_publication_failure_is_operational_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R09 a LangSmith publication failure is a nonzero operational failure."""
        fake = _seeded_mirror()
        fake.fail_operations = {"create_experiment"}
        _install_fake(monkeypatch, fake)
        _install_benchmark(monkeypatch, _pass_run_result())
        assert evaluation_main(["run", DATASET, "--langsmith"]) == 2

    def test_r10_fail_remains_fail_after_successful_publication(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R10 LangSmith acceptance never converts an ATI FAIL to success."""
        fake = _seeded_mirror()
        _install_fake(monkeypatch, fake)
        _install_benchmark(monkeypatch, _fail_run_result())
        assert evaluation_main(["run", DATASET, "--langsmith"]) == 1
        assert fake.published
        run_id, publication = fake.published[0]
        assert publication.run_status == "fail"
