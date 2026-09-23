# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""LangSmith SDK client boundary tests (LS-C01..C06).

Deterministic, offline: SDK objects convert to bounded adapter DTOs, SDK
exceptions become bounded backend errors, credential-like text is bounded
out of messages, cancellation propagates, and no arbitrary SDK object
escapes the adapter boundary.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agentic_threat_investigator.evaluation.backends.langsmith.client import (
    LangSmithBackendError,
    LangSmithSdkEvaluationClient,
)
from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
    project_case,
)
from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithDatasetRef,
    LangSmithExampleProjection,
    LangSmithExampleRef,
)
from tests.support.evaluation_common import unit_case, unit_dataset
from tests.support.langsmith_fakes import FakeDataset, FakeExample, FakeSdkClient


def _client(sdk: Any) -> LangSmithSdkEvaluationClient:
    """Wrap one fake SDK object in the real adapter client."""
    return LangSmithSdkEvaluationClient(sdk=sdk)


def _projection() -> list[LangSmithExampleProjection]:
    """Build one projection payload for create_examples tests."""
    case = unit_case()
    return [
        project_case(
            case=case,
            dataset_id=unit_dataset(),
            digest="a" * 64,
        )
    ]


class TestDtoConversion:
    """LS-C01/C02 SDK objects convert to bounded DTOs."""

    @pytest.mark.asyncio
    async def test_c01_dataset_object_to_bounded_dto(self) -> None:
        """C01 one SDK dataset object converts to a bounded dataset DTO."""
        sdk = FakeSdkClient()
        sdk.create_dataset(
            "ati/evidence-analyst/v1",
            metadata={"ati.dataset_id": "evidence-analyst/v1"},
        )
        client = _client(sdk)
        ref = await client.find_dataset(name="ati/evidence-analyst/v1")
        assert ref is not None
        assert ref.name == "ati/evidence-analyst/v1"
        assert ref.dataset_id == "ds-uuid-1"
        assert ref.metadata["ati.dataset_id"] == "evidence-analyst/v1"

    @pytest.mark.asyncio
    async def test_c01_dataset_metadata_filtered_to_ati_namespace(self) -> None:
        """C01 foreign dataset metadata never enters the adapter DTO."""
        sdk = FakeSdkClient()
        sdk.datasets["x"] = FakeDataset(
            "x",
            "ds-9",
            metadata={"tenant_id": "leak", "ati.dataset_id": "evidence-analyst/v1"},
        )
        client = _client(sdk)
        ref = await client.find_dataset(name="x")
        assert ref is not None
        assert ref.metadata == {"ati.dataset_id": "evidence-analyst/v1"}

    @pytest.mark.asyncio
    async def test_c02_example_object_to_bounded_dto(self) -> None:
        """C02 one SDK example object converts to a bounded example DTO."""
        sdk = FakeSdkClient()
        sdk.create_dataset(
            "ati/evidence-analyst/v1",
            metadata={"ati.dataset_id": "evidence-analyst/v1"},
        )
        sdk.examples.append(
            FakeExample(
                "ex-1",
                "ds-uuid-1",
                inputs={"ati_case_id": "c"},
                outputs={"required_behavior": ["x"]},
                metadata={
                    "atenant": "junk",
                    "ati.dataset_id": "evidence-analyst/v1",
                    "ati.case_id": "c-1",
                    "ati.case_version": 1,
                    "ati.target": "evidence-analyst",
                    "ati.projection_schema_version": 1,
                    "ati.content_digest": "a" * 64,
                    "ati.title": "t",
                    "ati.purpose": "p",
                    "ati.operational_relevance": "o",
                    "ati.regression_risk": "r",
                },
            )
        )
        client = _client(sdk)
        dataset = await client.find_dataset(name="ati/evidence-analyst/v1")
        assert dataset is not None
        refs = await client.list_examples(dataset=dataset)
        assert len(refs) == 1
        assert refs[0].example_id == "ex-1"
        assert refs[0].metadata["ati.case_id"] == "c-1"
        assert "atenant" not in refs[0].metadata
        assert "inputs" not in refs[0].model_fields_set

    @pytest.mark.asyncio
    async def test_c06_no_sdk_object_escapes_boundary(self) -> None:
        """C06 protocol operations return only bounded adapter DTOs."""
        sdk = FakeSdkClient()
        sdk.create_dataset(
            "ati/evidence-analyst/v1",
            metadata={"ati.dataset_id": "evidence-analyst/v1"},
        )
        client = _client(sdk)
        ref = await client.find_dataset(name="ati/evidence-analyst/v1")
        assert ref is not None
        count = await client.create_examples(dataset=ref, examples=_projection())
        assert isinstance(count, int)
        assert count == 1
        refs = await client.list_examples(dataset=ref)
        assert len(refs) == 1
        assert isinstance(refs[0], LangSmithExampleRef)
        assert isinstance(ref, LangSmithDatasetRef)


class TestErrorBoundary:
    """LS-C03/C04 SDK failures become bounded backend errors."""

    @pytest.mark.asyncio
    async def test_c03_sdk_exception_becomes_bounded_error(self) -> None:
        """C03 an SDK exception surfaces as a bounded backend error."""
        sdk = FakeSdkClient()
        sdk.fail_operations = {"create_dataset"}
        client = _client(sdk)
        with pytest.raises(LangSmithBackendError, match="create_dataset"):
            await client.create_dataset(
                name="ati/evidence-analyst/v1",
                metadata={"ati.dataset_id": "evidence-analyst/v1"},
            )

    @pytest.mark.asyncio
    async def test_c04_credential_like_text_bounded_out(self) -> None:
        """C04 long credential-like SDK text is bounded out of the message."""

        class SecretiveSdk:
            """SDK stand-in that leaks a long secret in the exception."""

            def list_datasets(
                self,
                *,
                dataset_name: str | None = None,
                limit: int | None = None,
            ) -> None:
                """Raise a credential-laden error (never reached for results)."""
                del dataset_name, limit
                raise RuntimeError("api_key=sk-super-secret-" + "s" * 4000)

        client = _client(SecretiveSdk())
        with pytest.raises(LangSmithBackendError) as excinfo:
            await client.find_dataset(name="ati/evidence-analyst/v1")
        message = str(excinfo.value)
        assert "s" * 4000 not in message
        assert len(message) <= 250

    @pytest.mark.asyncio
    async def test_c04_sanitization_strips_control_characters(self) -> None:
        """C04 control characters in SDK errors are stripped from messages."""

        class NoisySdk:
            """SDK stand-in that raises a control-character-laden error."""

            def list_datasets(
                self,
                *,
                dataset_name: str | None = None,
                limit: int | None = None,
            ) -> None:
                """Raise a control-character error (never reached for results)."""
                del dataset_name, limit
                raise RuntimeError("token\nwith\tprivate details")

        client = _client(NoisySdk())
        with pytest.raises(LangSmithBackendError) as excinfo:
            await client.find_dataset(name="x")
        assert "\n" not in str(excinfo.value)
        assert "\t" not in str(excinfo.value)


class TestCancellation:
    """LS-C05 cancellation propagates through the SDK boundary."""

    @pytest.mark.asyncio
    async def test_c05_cancellation_propagates(self) -> None:
        """C05 a CancelledError is never converted into a backend error."""

        class CancelSdk:
            """SDK stand-in whose batch creation raises CancelledError."""

            def create_examples(
                self,
                *,
                dataset_id: str | None = None,
                examples: Any = None,
            ) -> dict[str, Any]:
                """Raise CancelledError instead of creating examples."""
                del dataset_id, examples
                raise asyncio.CancelledError("cancelled by operator")

        client = _client(CancelSdk())
        with pytest.raises(asyncio.CancelledError):
            await client.create_examples(
                dataset=LangSmithDatasetRef(name="x", dataset_id="ds-1"),
                examples=_projection(),
            )


class TestExperimentBoundary:
    """PR 30C experiment SDK operations stay on the bounded adapter boundary."""

    @pytest.mark.asyncio
    async def test_experiment_create_read_feedback_round_trip(self) -> None:
        """Experiment creation, feedback publication, and read-back round trip."""
        from agentic_threat_investigator.evaluation.backends.langsmith.models import (
            LangSmithEvaluationPublication,
            LangSmithPublicationFeedback,
        )

        sdk = FakeSdkClient()
        client = _client(sdk)
        ref = await client.create_experiment(
            name="ati/evidence-analyst/v1/abc/123",
            metadata={"ati.dataset_id": "evidence-analyst/v1"},
        )
        assert ref.run_id
        assert ref.name == "ati/evidence-analyst/v1/abc/123"
        await client.publish_feedback(
            run_id=ref.run_id,
            publication=LangSmithEvaluationPublication(
                dataset_id="evidence-analyst/v1",
                run_status="pass",
                feedback=(
                    LangSmithPublicationFeedback(key="ati.run.status", value="pass"),
                ),
            ),
        )
        observed = await client.read_experiment(run_id=ref.run_id)
        assert observed is not None
        assert observed.name == ref.name
        assert observed.metadata == {"ati.dataset_id": "evidence-analyst/v1"}
        items = await client.list_feedback(run_id=ref.run_id)
        assert [(item.key, item.value) for item in items] == [
            ("ati.run.status", "pass")
        ]

    @pytest.mark.asyncio
    async def test_experiment_read_missing_returns_none(self) -> None:
        """Reading a nonexistent experiment run returns ``None``."""
        client = _client(FakeSdkClient())
        assert await client.read_experiment(run_id="missing") is None

    @pytest.mark.asyncio
    async def test_experiment_sdk_failure_is_bounded_error(self) -> None:
        """An SDK failure in experiment creation becomes a bounded backend error."""
        sdk = FakeSdkClient()
        sdk.fail_operations = {"create_run"}
        client = _client(sdk)
        with pytest.raises(LangSmithBackendError, match="create_experiment"):
            await client.create_experiment(
                name="ati/x", metadata={"ati.dataset_id": "x/v1"}
            )

    @pytest.mark.asyncio
    async def test_experiment_no_sdk_object_escapes_boundary(self) -> None:
        """Experiment operations return bounded adapter DTOs only."""
        from agentic_threat_investigator.evaluation.backends.langsmith.models import (
            LangSmithExperimentRef,
            LangSmithFeedbackItem,
        )

        sdk = FakeSdkClient()
        client = _client(sdk)
        ref = await client.create_experiment(
            name="ati/x", metadata={"ati.dataset_id": "x/v1"}
        )
        assert isinstance(ref, LangSmithExperimentRef)
        observed = await client.read_experiment(run_id=ref.run_id)
        assert isinstance(observed, LangSmithExperimentRef)
        items = await client.list_feedback(run_id=ref.run_id)
        assert all(isinstance(item, LangSmithFeedbackItem) for item in items)

    @pytest.mark.asyncio
    async def test_experiment_cancellation_propagates(self) -> None:
        """Cancellation in experiment creation propagates unchanged."""

        class CancelSdk(FakeSdkClient):
            """SDK stand-in whose create_run raises CancelledError."""

            def create_run(
                self,
                name: str,
                inputs: dict[str, Any],
                run_type: str,
                **kwargs: Any,
            ) -> None:
                """Raise CancelledError instead of creating the run."""
                del name, inputs, run_type, kwargs
                raise asyncio.CancelledError("cancelled by operator")

        client = _client(CancelSdk())
        with pytest.raises(asyncio.CancelledError):
            await client.create_experiment(
                name="ati/x", metadata={"ati.dataset_id": "x/v1"}
            )
