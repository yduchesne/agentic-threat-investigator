# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""LangSmith dataset verification tests (LS-V01..V08).

Read-only exact-mirror verification: every check either reports success or
raises a bounded :class:`LangSmithSyncError`, and verification never
performs a write.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentic_threat_investigator.evaluation.backends.langsmith.datasets import (
    LangSmithSyncError,
    verify_dataset,
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
from tests.support.langsmith_fakes import test_scenario as scenario_factory

DATASET = unit_dataset()
NAME = project_dataset_name(DATASET)


def _ref(
    case_id: str, *, version: int = 1, digest: str = "a" * 64
) -> LangSmithExampleRef:
    """Build one remote example ref with deterministic ATI metadata."""
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


def _seeded_fake_with(scenarios: list[Any]) -> FakeLangSmithClient:
    """Return a fake whose remote dataset mirrors ``scenarios`` exactly."""
    fake = FakeLangSmithClient()
    name = project_dataset_name(DATASET)
    ref = LangSmithDatasetRef(
        name=name,
        dataset_id="ds-1",
        metadata=project_dataset_metadata(DATASET),
    )
    fake.datasets[name] = {"ref": ref, "examples": {}}
    for scenario in scenarios:
        digest = semantic_digest(scenario)
        case_id = scenario.id
        fake.datasets[name]["examples"][f"remote-{case_id}"] = _ref(
            case_id, digest=digest
        )
    return fake


class TestVerify:
    """LS-V01..V08 read-only verification behavior."""

    @pytest.mark.asyncio
    async def test_v01_exact_mirror_success(self) -> None:
        """V01 an exact mirror verifies successfully."""
        fake = _seeded_fake_with([scenario_factory("a-1"), scenario_factory("a-2")])
        report = await verify_dataset(
            dataset_id=DATASET,
            client=fake,
            scenarios=[scenario_factory("a-1"), scenario_factory("a-2")],
        )
        assert report.status == "verified"
        assert report.local_cases == 2
        assert report.remote_examples == 2
        assert report.dataset == NAME

    @pytest.mark.asyncio
    async def test_v02_missing_dataset_failure(self) -> None:
        """V02 a missing remote dataset fails verification."""
        fake = FakeLangSmithClient()
        with pytest.raises(LangSmithSyncError, match="does not exist"):
            await verify_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=[scenario_factory("a-1")],
            )

    @pytest.mark.asyncio
    async def test_v03_missing_example_failure(self) -> None:
        """V03 a remote example missing locally fails verification."""
        fake = _seeded_fake_with([scenario_factory("a-1")])
        with pytest.raises(LangSmithSyncError, match="missing"):
            await verify_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=[scenario_factory("a-1"), scenario_factory("a-2")],
            )

    @pytest.mark.asyncio
    async def test_v04_extra_example_failure(self) -> None:
        """V04 a remote extra example fails verification."""
        fake = _seeded_fake_with([scenario_factory("a-1"), scenario_factory("extra")])
        with pytest.raises(LangSmithSyncError, match="extra"):
            await verify_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=[scenario_factory("a-1")],
            )

    @pytest.mark.asyncio
    async def test_v05_digest_mismatch_failure(self) -> None:
        """V05 a remote digest mismatch fails verification."""
        fake = _seeded_fake_with([scenario_factory("a-1")])
        name = project_dataset_name(DATASET)
        fake.datasets[name]["examples"]["remote-a-1"] = _ref("a-1", digest="b" * 64)
        with pytest.raises(LangSmithSyncError, match="digest mismatch"):
            await verify_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=[scenario_factory("a-1")],
            )

    @pytest.mark.asyncio
    async def test_v06_duplicate_identity_failure(self) -> None:
        """V06 duplicate remote ATI identities fail verification."""
        fake = _seeded_fake_with([scenario_factory("a-1")])
        name = project_dataset_name(DATASET)
        duplicate = _ref("a-1", digest=semantic_digest(scenario_factory("a-1")))
        fake.datasets[name]["examples"]["remote-a-1b"] = duplicate
        with pytest.raises(LangSmithSyncError, match="duplicate ATI identity"):
            await verify_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=[scenario_factory("a-1")],
            )

    @pytest.mark.asyncio
    async def test_v07_malformed_metadata_failure(self) -> None:
        """V07 a remote example with malformed ATI metadata fails verification."""
        fake = _seeded_fake_with([])
        name = project_dataset_name(DATASET)
        fake.datasets[name]["examples"]["foreign"] = LangSmithExampleRef(
            example_id="foreign",
            dataset_id="ds-1",
            metadata={"ati.case_id": "x"},
        )
        with pytest.raises(LangSmithSyncError, match="malformed"):
            await verify_dataset(
                dataset_id=DATASET,
                client=fake,
                scenarios=[scenario_factory("a-1")],
            )

    @pytest.mark.asyncio
    async def test_v08_verification_performs_no_writes(self) -> None:
        """V08 verification never performs a write operation."""
        fake = _seeded_fake_with([scenario_factory("a-1")])
        await verify_dataset(
            dataset_id=DATASET,
            client=fake,
            scenarios=[scenario_factory("a-1")],
        )
        assert "create_dataset" not in fake.calls
        assert "create_examples" not in fake.calls
        assert "publish_feedback" not in fake.calls
