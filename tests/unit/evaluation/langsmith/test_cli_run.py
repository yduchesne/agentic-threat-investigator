# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30C/30D ati-eval run CLI tests (EA-R/D-R/D-LS matrices).

Deterministic and offline: the real corpora load locally, the benchmark seams
are injected per target, and the LangSmith client is the in-memory fake.
Proves the run exit semantics (0 PASS, 1 FAIL, 2 ERROR/config/backend/
publication) for every supported target, verify-before-model ordering, remote
drift refusal, missing-credential bounded errors, the deterministic-driver
rejection, and per-target LangSmith publication (categorical values only, no
raw diagnostics/content, no duplicate execution). No real LLM, database, or
LangSmith service participates.
"""

from __future__ import annotations

import asyncio
import inspect

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
    EvaluationVerdict,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCaseResult,
    EvaluationExecutionStatus,
)
from tests.support.evaluation_common import (
    COMPLETED,
    ERROR,
    FAIL,
    PASS,
    unit_result,
)
from tests.support.langsmith_fakes import FakeLangSmithClient

DATASET = "evidence-analyst/v1"
COORDINATOR_DATASET = "coordinator/v1"
RESEARCH_DATASET = "research-agent/v1"
REPORT_WRITER_DATASET = "report-writer/v1"
UNSUPPORTED_DATASET = "investigation/v1"


def _run_result(
    dataset: str,
    *,
    status: EvaluationExecutionStatus = COMPLETED,
    verdict: EvaluationVerdict | None = PASS,
    case_ids: tuple[str, ...] = ("case-a",),
) -> EvaluationRunResult:
    """Build one deterministic canonical run result."""
    results = tuple(
        EvaluationCaseResult(
            case_id=case_id,
            execution_status=status,
            verdict=verdict,
            evaluator_results=(unit_result(status=status, verdict=verdict),),
        )
        for case_id in case_ids
    )
    return EvaluationRunResult(
        dataset_id=EvaluationDatasetId.from_canonical(dataset),
        execution_status=status,
        verdict=verdict,
        cases=results,
    )


def _pass_run_result(dataset: str = DATASET) -> EvaluationRunResult:
    """Build one deterministic COMPLETED/PASS canonical run result."""
    return _run_result(dataset)


def _fail_run_result(dataset: str = DATASET) -> EvaluationRunResult:
    """Build one deterministic COMPLETED/FAIL canonical run result."""
    return _run_result(dataset, status=COMPLETED, verdict=FAIL)


def _error_run_result(dataset: str = DATASET) -> EvaluationRunResult:
    """Build one deterministic ERROR canonical run result."""
    return _run_result(dataset, status=ERROR, verdict=None)


def _install_benchmark(
    monkeypatch: pytest.MonkeyPatch,
    result: EvaluationRunResult,
    *,
    fail: BaseException | None = None,
    calls: list[str] | None = None,
    seam: str = "_execute_evidence_analyst_benchmark",
) -> None:
    """Inject one scripted benchmark seam and a fixed git SHA."""

    async def benchmark(**_: object) -> EvaluationRunResult:
        """Return the scripted result or raise the scripted failure."""
        if calls is not None:
            calls.append("benchmark")
        if fail is not None:
            raise fail
        return result

    monkeypatch.setattr(f"agentic_threat_investigator.cli.{seam}", benchmark)
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


def _seeded_mirror(dataset: str = DATASET) -> FakeLangSmithClient:
    """Build a fake client seeded with the exact mirror of one dataset."""
    from agentic_threat_investigator.evaluation.datasets import (
        load_evaluation_scenarios,
    )

    fake = FakeLangSmithClient()
    dataset_id = EvaluationDatasetId.from_canonical(dataset)
    scenarios = load_evaluation_scenarios(dataset_id)
    asyncio.run(
        synchronize_dataset(
            dataset_id=dataset_id,
            client=fake,
            scenarios=scenarios,
        )
    )
    return fake


def _drifted_mirror(dataset: str = DATASET) -> FakeLangSmithClient:
    """Build a fake client whose remote mirror carries a stale digest."""
    fake = _seeded_mirror(dataset)
    dataset_id = EvaluationDatasetId.from_canonical(dataset)
    name = project_dataset_name(dataset_id)
    entry = fake.datasets[name]
    stale = LangSmithExampleMetadata(
        ati_dataset_id=dataset,
        ati_case_id="stale-case",
        ati_case_version=1,
        ati_target=dataset_id.target.value,
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
    """EA-R03..R12/D-R03..R13 exit semantics for every supported target."""

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

    def test_r01_coordinator_run_supported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """D-R01 coordinator/v1 dispatches to the Coordinator benchmark."""
        _install_benchmark(
            monkeypatch,
            _pass_run_result(COORDINATOR_DATASET),
            seam="_execute_coordinator_benchmark",
        )
        assert evaluation_main(["run", COORDINATOR_DATASET]) == 0

    def test_r02_research_run_supported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """D-R02 research-agent/v1 dispatches to the Research benchmark."""
        _install_benchmark(
            monkeypatch,
            _pass_run_result(RESEARCH_DATASET),
            seam="_execute_research_benchmark",
        )
        assert evaluation_main(["run", RESEARCH_DATASET]) == 0

    def test_r01_report_writer_run_supported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RPT-R01 report-writer/v1 dispatches to the Report Writer benchmark."""
        _install_benchmark(
            monkeypatch,
            _pass_run_result(REPORT_WRITER_DATASET),
            seam="_execute_report_writer_benchmark",
        )
        assert evaluation_main(["run", REPORT_WRITER_DATASET]) == 0

    def test_r04_unsupported_target_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """D-R04 an unsupported target is rejected before any model work."""
        calls: list[str] = []
        _install_benchmark(monkeypatch, _pass_run_result(), calls=calls)
        assert evaluation_main(["run", UNSUPPORTED_DATASET]) == 2
        assert calls == []

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

    def test_r15_cancellation_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """D-R15 cancellation propagates out of the CLI run handler."""

        async def cancelled(**_: object) -> object:
            """Raise cancellation from the benchmark seam."""
            raise asyncio.CancelledError("cancelled")

        monkeypatch.setattr(
            "agentic_threat_investigator.cli._execute_evidence_analyst_benchmark",
            cancelled,
        )
        with pytest.raises(asyncio.CancelledError):
            evaluation_main(["run", DATASET])


class TestRunLangSmith:
    """EA-R07..R10 and D-LS01..LS10 LangSmith-backed run behavior."""

    @pytest.mark.parametrize(
        ("dataset", "seam"),
        [
            (DATASET, "_execute_evidence_analyst_benchmark"),
            (COORDINATOR_DATASET, "_execute_coordinator_benchmark"),
            (RESEARCH_DATASET, "_execute_research_benchmark"),
            (REPORT_WRITER_DATASET, "_execute_report_writer_benchmark"),
        ],
    )
    def test_ls01_mirror_exact_run_allowed(
        self, monkeypatch: pytest.MonkeyPatch, dataset: str, seam: str
    ) -> None:
        """D-LS01/02/EA-LS01/RPT-LS01 an exact mirror allows a LangSmith-backed run."""
        fake = _seeded_mirror(dataset)
        _install_fake(monkeypatch, fake)
        _install_benchmark(monkeypatch, _pass_run_result(dataset), seam=seam)
        assert evaluation_main(["run", dataset, "--langsmith"]) == 0
        assert fake.published
        run_id, publication = fake.published[0]
        assert publication.dataset_id == dataset

    @pytest.mark.parametrize(
        ("dataset", "seam"),
        [
            (COORDINATOR_DATASET, "_execute_coordinator_benchmark"),
            (RESEARCH_DATASET, "_execute_research_benchmark"),
            (REPORT_WRITER_DATASET, "_execute_report_writer_benchmark"),
        ],
    )
    def test_ls03_drift_refuses_before_target(
        self, monkeypatch: pytest.MonkeyPatch, dataset: str, seam: str
    ) -> None:
        """D-LS03 semantic drift refuses the run before any target work."""
        calls: list[str] = []
        _install_fake(monkeypatch, _drifted_mirror(dataset))
        _install_benchmark(
            monkeypatch, _pass_run_result(dataset), calls=calls, seam=seam
        )
        assert evaluation_main(["run", dataset, "--langsmith"]) == 2
        assert calls == []

    def test_ls04_one_ati_execution_per_case(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """D-LS04 the run executes once and publishes one feedback set."""
        fake = _seeded_mirror(COORDINATOR_DATASET)
        _install_fake(monkeypatch, fake)
        _install_benchmark(
            monkeypatch,
            _run_result(
                COORDINATOR_DATASET,
                case_ids=("domain-discovers-ip", "depth-limit"),
            ),
            seam="_execute_coordinator_benchmark",
        )
        assert evaluation_main(["run", COORDINATOR_DATASET, "--langsmith"]) == 0
        run_id, publication = fake.published[0]
        case_keys = {
            item.key
            for item in publication.feedback
            if item.key.startswith("ati.case.")
        }
        assert len(case_keys) == 2

    def test_ls07_categorical_mapping_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """D-LS07 FAIL publishes categorical fail and remains exit 1."""
        fake = _seeded_mirror(COORDINATOR_DATASET)
        _install_fake(monkeypatch, fake)
        _install_benchmark(
            monkeypatch,
            _fail_run_result(COORDINATOR_DATASET),
            seam="_execute_coordinator_benchmark",
        )
        assert evaluation_main(["run", COORDINATOR_DATASET, "--langsmith"]) == 1
        run_id, publication = fake.published[0]
        assert publication.run_status == "fail"

    def test_ls08_no_raw_content_published(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """D-LS08 publication metadata carries no raw research content."""
        fake = _seeded_mirror(RESEARCH_DATASET)
        _install_fake(monkeypatch, fake)
        _install_benchmark(
            monkeypatch,
            _pass_run_result(RESEARCH_DATASET),
            seam="_execute_research_benchmark",
        )
        assert evaluation_main(["run", RESEARCH_DATASET, "--langsmith"]) == 0
        run_id, _publication = fake.published[0]
        metadata = fake.experiments[run_id]["ref"].metadata
        rendered = f"{metadata}"
        for forbidden in ("obfuscat", "claims", "chunks", "prompt"):
            assert forbidden not in rendered

    def test_r07_missing_remote_dataset_refuses_before_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R07 a missing remote dataset refuses before any model execution."""
        calls: list[str] = []
        fake = FakeLangSmithClient()
        _install_fake(monkeypatch, fake)
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
        run_id, publication = fake.published[0]
        assert publication.run_status == "fail"

    def test_ls10_cancellation_never_swallowed_by_run(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """D-LS10 the CLI run path never swallows cancellation.

        The handler catches only ordinary exceptions; CancelledError (a
        ``BaseException``) always propagates. Backend-level blocking/
        cancellation is covered by the experiment tests (EA-LS14) and the
        benchmark-seam propagation by ``test_r15``.
        """
        from agentic_threat_investigator import cli as cli_module

        source = inspect.getsource(cli_module._evaluation_run_main)
        assert "except BaseException" not in source
        assert "except asyncio.CancelledError" not in source


class TestReportWriterRun:
    """RPT-R01/RPT-R06/RPT-R11/RPT-LS08 report-writer-specific run contract."""

    def test_rpt_r06_local_run_constructs_no_langsmith_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R06 a report-writer local run never constructs a LangSmith client."""
        _install_benchmark(
            monkeypatch,
            _pass_run_result(REPORT_WRITER_DATASET),
            seam="_execute_report_writer_benchmark",
        )

        def exploding() -> object:
            raise AssertionError("LangSmith client must not be constructed")

        monkeypatch.setattr(
            "agentic_threat_investigator.cli._build_langsmith_evaluation_client",
            exploding,
        )
        assert evaluation_main(["run", REPORT_WRITER_DATASET]) == 0

    def test_rpt_r11_missing_model_credential_bounded_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R11 a missing model credential surfaces as a bounded exit-2 failure."""
        from agentic_threat_investigator.app.secrets import SecretNotFoundError

        _install_benchmark(
            monkeypatch,
            _pass_run_result(REPORT_WRITER_DATASET),
            fail=SecretNotFoundError("ATI_OPENAI_API_KEY"),
            seam="_execute_report_writer_benchmark",
        )
        assert evaluation_main(["run", REPORT_WRITER_DATASET]) == 2

    def test_rpt_ls08_no_raw_report_content_published(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RPT-LS08 publication metadata carries no raw report/model content."""
        fake = _seeded_mirror(REPORT_WRITER_DATASET)
        _install_fake(monkeypatch, fake)
        _install_benchmark(
            monkeypatch,
            _pass_run_result(REPORT_WRITER_DATASET),
            seam="_execute_report_writer_benchmark",
        )
        assert evaluation_main(["run", REPORT_WRITER_DATASET, "--langsmith"]) == 0
        run_id, _publication = fake.published[0]
        metadata = fake.experiments[run_id]["ref"].metadata
        rendered = f"{metadata}"
        for forbidden in (
            "reputation",
            "malicious indicator",
            "prompt",
            "chain_of_thought",
        ):
            assert forbidden not in rendered

    def test_rpt_no_research_corpus_bootstrap_for_report_writer(self) -> None:
        """The Report Writer benchmark never bootstraps the research corpus."""
        import inspect as _inspect

        from agentic_threat_investigator import cli as cli_module

        source = _inspect.getsource(cli_module._execute_report_writer_benchmark)
        assert "_bootstrap_research_corpus_if_needed" not in source
        assert "run_report_writer_evaluation" in source
