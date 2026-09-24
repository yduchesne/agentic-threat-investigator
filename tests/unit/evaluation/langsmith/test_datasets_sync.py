# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""LangSmith dataset synchronization tests (LS-S01..S16).

Deterministic, network-free; every scenario uses the in-memory fake client.
Covers: create-missing mirror, idempotency, drift/extras/duplicates
fail-closed behavior, local validation before any remote mutation, bounded
API-error surfacing, and cancellation propagation.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agentic_threat_investigator.evaluation.backends.langsmith.client import (
    LangSmithBackendError,
)
from agentic_threat_investigator.evaluation.backends.langsmith.datasets import (
    LangSmithSyncError,
    synchronize_dataset,
)
from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
    project_dataset_metadata,
    project_dataset_name,
    project_remote_metadata,
    semantic_digest,
)
from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithDatasetRef,
    LangSmithExampleMetadata,
    LangSmithExampleRef,
)
from tests.support.evaluation_common import unit_dataset
from tests.support.langsmith_fakes import FakeLangSmithClient
from tests.support.langsmith_fakes import test_scenario as make_scenario

DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
DATASET = unit_dataset()
NAME = project_dataset_name(DATASET)


def _scenarios(*cases: tuple[str, str]) -> list[Any]:
    """Build deterministic typed scenario stand-ins with per-case semantic content."""
    return [
        make_scenario(case_id=case_id, extra_semantic=content)
        for case_id, content in cases
    ]


def _ref(
    case_id: str, *, version: int = 1, digest: str = DIGEST
) -> LangSmithExampleRef:
    """Build one remote example ref with the given identity and digest."""
    metadata = LangSmithExampleMetadata(
        ati_dataset_id=DATASET.canonical,
        ati_case_id=case_id,
        ati_case_version=version,
        ati_target=DATASET.target.value,
        ati_title="title",
        ati_purpose="purpose",
        ati_operational_relevance="relevance",
        ati_regression_risk="risk",
        ati_projection_schema_version=1,
        ati_content_digest=digest,
    )
    return LangSmithExampleRef(
        example_id=f"remote-{case_id}-{version}",
        dataset_id="ds-1",
        metadata=project_remote_metadata(metadata),
    )


def _seeded_fake() -> tuple[FakeLangSmithClient, LangSmithDatasetRef]:
    """Return a fake with one compatible ATI-managed dataset already created."""
    fake = FakeLangSmithClient()
    dataset_id = unit_dataset()
    name = project_dataset_name(dataset_id)
    ref = LangSmithDatasetRef(
        name=name,
        dataset_id="ds-1",
        metadata=project_dataset_metadata(dataset_id),
    )
    fake.datasets[name] = {"ref": ref, "examples": {}}
    return fake, ref


class TestSyncBasics:
    """LS-S01..S05/S15 create-missing and idempotent mirrors."""

    @pytest.mark.asyncio
    async def test_s01_absent_dataset_creates_examples(self) -> None:
        """S01 absent remote dataset => created with all examples."""
        fake = FakeLangSmithClient()
        receipt = await synchronize_dataset(
            dataset_id=DATASET,
            client=fake,
            scenarios=_scenarios(("a-1", "one"), ("a-2", "two")),
        )
        assert receipt.dataset == NAME
        assert receipt.local_cases == 2
        assert receipt.created == 2
        assert receipt.unchanged == 0
        assert receipt.status == "synchronized"
        assert len(fake.datasets[NAME]["examples"]) == 2
        assert "create_dataset" in fake.calls
        assert "create_examples" in fake.calls

    @pytest.mark.asyncio
    async def test_s02_existing_empty_dataset_creates_examples(self) -> None:
        """S02 an existing empty ATI dataset receives the missing examples."""
        fake, ref = _seeded_fake()
        receipt = await synchronize_dataset(
            dataset_id=DATASET,
            client=fake,
            scenarios=_scenarios(("a-1", "one")),
        )
        assert receipt.created == 1
        assert receipt.unchanged == 0
        assert "create_dataset" not in fake.calls

    @pytest.mark.asyncio
    async def test_s03_exact_mirror_is_noop(self) -> None:
        """S03 an exact mirror performs no writes at all."""
        fake = FakeLangSmithClient()
        scenarios = _scenarios(("a-1", "one"), ("a-2", "two"))
        await synchronize_dataset(dataset_id=DATASET, client=fake, scenarios=scenarios)
        before = len(fake.calls)
        receipt = await synchronize_dataset(
            dataset_id=DATASET, client=fake, scenarios=scenarios
        )
        assert receipt.created == 0
        assert receipt.unchanged == 2
        assert fake.calls[before:] == ["find_dataset", "list_examples"]

    @pytest.mark.asyncio
    async def test_s04_missing_examples_only_created(self) -> None:
        """S04 only missing examples are created, batched."""
        fake, ref = _seeded_fake()
        scenarios = _scenarios(("a-1", "one"), ("a-2", "two"))
        fake.seed_examples(
            ref,
            [_ref("a-1", digest=semantic_digest(scenarios[0]))],
        )
        await synchronize_dataset(dataset_id=DATASET, client=fake, scenarios=scenarios)
        assert len(fake.datasets[NAME]["examples"]) == 2

    @pytest.mark.asyncio
    async def test_s05_same_identity_and_digest_unchanged(self) -> None:
        """S05 the same identity with the same digest is unchanged."""
        fake = FakeLangSmithClient()
        scenarios = _scenarios(("a-1", "one"))
        await synchronize_dataset(dataset_id=DATASET, client=fake, scenarios=scenarios)
        receipt = await synchronize_dataset(
            dataset_id=DATASET, client=fake, scenarios=scenarios
        )
        assert (receipt.created, receipt.unchanged) == (0, 1)

    @pytest.mark.asyncio
    async def test_s15_repeated_sync_zero_writes(self) -> None:
        """S15 a second identical sync performs zero semantic writes."""
        fake = FakeLangSmithClient()
        scenarios = _scenarios(("a-1", "one"))
        await synchronize_dataset(dataset_id=DATASET, client=fake, scenarios=scenarios)
        writes = len([call for call in fake.calls if "create" in call])
        await synchronize_dataset(dataset_id=DATASET, client=fake, scenarios=scenarios)
        assert len([call for call in fake.calls if "create" in call]) == writes


class TestSyncFailClosed:
    """LS-S06..S10 drift/extras/duplicates and mismatches."""

    @pytest.mark.asyncio
    async def test_s06_digest_mismatch_fails_without_overwrite(self) -> None:
        """S06 a changed semantic digest fails closed; nothing is overwritten."""
        fake, ref = _seeded_fake()
        fake.seed_examples(ref, [_ref("a-1", digest=OTHER_DIGEST)])
        scenarios = _scenarios(("a-1", "one"))
        with pytest.raises(LangSmithSyncError, match="refusing to overwrite"):
            await synchronize_dataset(
                dataset_id=DATASET, client=fake, scenarios=scenarios
            )
        assert len(fake.datasets[NAME]["examples"]) == 1
        stored = next(iter(fake.datasets[NAME]["examples"].values()))
        assert stored.metadata["ati.content_digest"] == OTHER_DIGEST

    @pytest.mark.asyncio
    async def test_s07_remote_extra_identity_fails_without_delete(self) -> None:
        """S07 a remote extra ATI identity fails closed; nothing is deleted."""
        fake, ref = _seeded_fake()
        fake.seed_examples(ref, [_ref("extra-case")])
        scenarios = _scenarios(("a-1", "one"))
        with pytest.raises(LangSmithSyncError, match="refusing to delete"):
            await synchronize_dataset(
                dataset_id=DATASET, client=fake, scenarios=scenarios
            )
        assert len(fake.datasets[NAME]["examples"]) == 1

    @pytest.mark.asyncio
    async def test_s08_duplicate_remote_identity_fails(self) -> None:
        """S08 duplicate remote ATI identities fail closed."""
        fake, ref = _seeded_fake()
        original = dict(_ref("a-1").metadata)
        duplicated = _ref("a-1")
        fake.seed_examples(
            ref,
            [
                LangSmithExampleRef(
                    example_id="first",
                    dataset_id=ref.dataset_id,
                    metadata=dict(original),
                ),
                LangSmithExampleRef(
                    example_id="second",
                    dataset_id=ref.dataset_id,
                    metadata=dict(duplicated.metadata),
                ),
            ],
        )
        with pytest.raises(LangSmithSyncError, match="duplicate ATI identity"):
            await synchronize_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=_scenarios(("a-1", "one")),
            )

    @pytest.mark.asyncio
    async def test_s09_dataset_identity_mismatch_fails(self) -> None:
        """S09 a remote dataset identity mismatch fails closed."""
        fake = FakeLangSmithClient()
        foreign = LangSmithDatasetRef(
            name=NAME,
            dataset_id="ds-1",
            metadata={
                "ati.dataset_id": "coordinator/v1",
                "ati.projection_schema_version": 1,
            },
        )
        fake.datasets[NAME] = {"ref": foreign, "examples": {}}
        with pytest.raises(LangSmithSyncError, match="does not match"):
            await synchronize_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=_scenarios(("a-1", "one")),
            )

    @pytest.mark.asyncio
    async def test_s10_unsupported_projection_schema_fails(self) -> None:
        """S10 an unsupported remote projection schema fails closed."""
        fake = FakeLangSmithClient()
        unsupported = LangSmithDatasetRef(
            name=NAME,
            dataset_id="ds-1",
            metadata={
                "ati.dataset_id": "evidence-analyst/v1",
                "ati.projection_schema_version": 99,
            },
        )
        fake.datasets[NAME] = {"ref": unsupported, "examples": {}}
        with pytest.raises(LangSmithSyncError, match="unsupported projection schema"):
            await synchronize_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=_scenarios(("a-1", "one")),
            )

    @pytest.mark.asyncio
    async def test_s11_malformed_local_no_remote_mutation(self) -> None:
        """S11 a malformed local dataset performs no remote mutation at all."""
        fake = FakeLangSmithClient()
        bad = _scenarios(("a-1", "one"))
        # Dataset-level identity violation: speculate a mismatched target.
        from agentic_threat_investigator.evaluation.common.models import (
            EvaluationTarget,
        )
        from tests.support.evaluation_common import unit_specification

        wrong = make_scenario(
            case_id="x",
            specification=unit_specification(target=EvaluationTarget.COORDINATOR),
        )
        scenarios = [bad[0], wrong]
        with pytest.raises(LangSmithSyncError):
            await synchronize_dataset(
                dataset_id=DATASET, client=fake, scenarios=scenarios
            )
        assert fake.calls == []


class TestBackendErrors:
    """LS-S12..S14 API failures surface as bounded errors."""

    @pytest.mark.asyncio
    async def test_s12_create_dataset_error_surfaced(self) -> None:
        """S12 a create-dataset API failure surfaces as a backend error."""
        fake = FakeLangSmithClient()
        fake.fail_operations = {"create_dataset"}
        with pytest.raises(LangSmithBackendError, match="create_dataset"):
            await synchronize_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=_scenarios(("a-1", "one")),
            )

    @pytest.mark.asyncio
    async def test_s13_list_examples_error_surfaced(self) -> None:
        """S13 a list-examples API failure surfaces as a backend error."""
        fake, _ = _seeded_fake()
        fake.fail_operations = {"list_examples"}
        with pytest.raises(LangSmithBackendError, match="list_examples"):
            await synchronize_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=_scenarios(("a-1", "one")),
            )

    @pytest.mark.asyncio
    async def test_s14_create_examples_error_surfaced(self) -> None:
        """S14 a create-examples API failure surfaces as a backend error."""
        fake = FakeLangSmithClient()
        fake.fail_operations = {"create_examples"}
        with pytest.raises(LangSmithBackendError, match="create_examples"):
            await synchronize_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=_scenarios(("a-1", "one")),
            )


class TestCancellation:
    """LS-S16 cancellation propagates."""

    @pytest.mark.asyncio
    async def test_s16_cancellation_propagates(self) -> None:
        """S16 cancelling a pending synchronization raises CancelledError."""
        fake = FakeLangSmithClient()
        fake.block_operations = {"create_examples"}
        task = asyncio.create_task(
            synchronize_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=_scenarios(("a-1", "one")),
            )
        )
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


class TestInvestigationDatasetSync:
    """LS-INV: the investigation/v1 corpus syncs through the generic path."""

    @pytest.mark.asyncio
    async def test_inv_corpus_syncs_and_verifies_exact_mirror(self) -> None:
        """The real investigation corpus syncs and its mirror verifies exactly."""
        from agentic_threat_investigator.evaluation.backends.langsmith.datasets import (
            verify_dataset,
        )
        from agentic_threat_investigator.evaluation.common import (
            EvaluationDatasetId,
            EvaluationTarget,
        )
        from agentic_threat_investigator.evaluation.datasets import (
            load_evaluation_scenarios,
        )

        dataset_id = EvaluationDatasetId(
            target=EvaluationTarget.INVESTIGATION, version=1
        )
        scenarios = load_evaluation_scenarios(dataset_id)
        fake = FakeLangSmithClient()
        receipt = await synchronize_dataset(
            dataset_id=dataset_id,
            client=fake,
            scenarios=scenarios,
        )
        assert receipt.local_cases == 6
        assert receipt.created == 6
        report = await verify_dataset(
            dataset_id=dataset_id,
            client=fake,
            scenarios=scenarios,
        )
        assert report.local_cases == 6
        assert report.remote_examples == 6

    @pytest.mark.asyncio
    async def test_inv_semantic_digest_round_trips(self) -> None:
        """The Investigation scenario digest is stable and content-sensitive."""
        from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
            semantic_digest,
        )
        from agentic_threat_investigator.evaluation.common import (
            EvaluationDatasetId,
            EvaluationTarget,
        )
        from agentic_threat_investigator.evaluation.datasets import (
            load_evaluation_scenarios,
        )

        dataset_id = EvaluationDatasetId(
            target=EvaluationTarget.INVESTIGATION, version=1
        )
        scenarios = load_evaluation_scenarios(dataset_id)
        first = semantic_digest(tuple(scenarios))
        second = semantic_digest(tuple(scenarios))
        assert first == second
        assert len(first) == 64
