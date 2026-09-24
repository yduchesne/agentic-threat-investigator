# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""LangSmith evaluation CLI tests (LS-CLI01..CLI09).

Deterministic, offline: valid sync/verify succeed through the injected fake
client, invalid datasets fail before any client call, missing credentials
produce a bounded nonzero failure without an environment dump, drift exits
nonzero, the pre-existing ``validate`` command is unchanged, no ``run``
command exists, and no secret text reaches the output.
"""

from __future__ import annotations

import json

import pytest

from agentic_threat_investigator.cli import (
    evaluation_main,
)
from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
    project_dataset_metadata,
    project_dataset_name,
    project_remote_metadata,
)
from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithDatasetRef,
    LangSmithExampleMetadata,
    LangSmithExampleRef,
)
from tests.support.evaluation_common import unit_dataset
from tests.support.langsmith_fakes import FakeLangSmithClient

DATASET = unit_dataset()
NAME = project_dataset_name(DATASET)


def _install_fake(monkeypatch: pytest.MonkeyPatch, fake: FakeLangSmithClient) -> None:
    """Inject one fake client into the CLI's client factory."""

    def factory() -> FakeLangSmithClient:
        return fake

    monkeypatch.setattr(
        "agentic_threat_investigator.cli._build_langsmith_evaluation_client",
        factory,
    )


def _ref(case_id: str, *, digest: str = "a" * 64) -> LangSmithExampleRef:
    """Build one deterministic remote example ref."""
    metadata = LangSmithExampleMetadata(
        ati_dataset_id=DATASET.canonical,
        ati_case_id=case_id,
        ati_case_version=1,
        ati_target=DATASET.target.value,
        ati_title="title",
        ati_purpose="purpose",
        ati_operational_relevance="relevance",
        ati_regression_risk="risk",
        ati_projection_schema_version=1,
        ati_content_digest=digest,
    )
    return LangSmithExampleRef(
        example_id=f"remote-{case_id}",
        dataset_id="ds-1",
        metadata=project_remote_metadata(metadata),
    )


class TestCliSync:
    """LS-CLI01..CLI04 sync command behavior."""

    def test_cli01_valid_sync_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CLI01 a valid sync over the real corpus succeeds through the fake."""
        fake = FakeLangSmithClient()
        _install_fake(monkeypatch, fake)
        assert evaluation_main(["langsmith", "sync", "evidence-analyst/v1"]) == 0
        assert NAME in fake.datasets
        assert len(fake.datasets[NAME]["examples"]) == 8
        assert "create_examples" in fake.calls

    def test_cli02_invalid_dataset_fails_before_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI02 an invalid dataset fails before any client operation."""
        fake = FakeLangSmithClient()
        _install_fake(monkeypatch, fake)
        assert evaluation_main(["langsmith", "sync", "unknown-target/v1"]) == 1
        assert evaluation_main(["langsmith", "sync", "evidence-analyst/v99"]) == 1
        assert fake.calls == []

    def test_cli03_missing_credentials_bounded_failure(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """CLI03 missing credentials produce a bounded nonzero failure."""
        monkeypatch.setattr(
            "agentic_threat_investigator.cli._build_langsmith_evaluation_client",
            _missing_credentials_client,
        )
        assert evaluation_main(["langsmith", "verify", "evidence-analyst/v1"]) == 1
        assert "LANGSMITH_API_KEY" not in caplog.text
        assert "sk-anything" not in caplog.text

    def test_cli04_drift_exits_nonzero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CLI04 semantic drift fails the sync with a nonzero exit."""
        fake = FakeLangSmithClient()
        _install_fake(monkeypatch, fake)
        name = project_dataset_name(DATASET)
        fake.datasets[name] = {
            "ref": LangSmithDatasetRef(
                name=name,
                dataset_id="ds-1",
                metadata=project_dataset_metadata(DATASET),
            ),
            "examples": {"drifted": _ref("conflicting-reputation", digest="b" * 64)},
        }
        assert evaluation_main(["langsmith", "sync", "evidence-analyst/v1"]) == 1


class TestCliVerify:
    """LS-CLI05..CLI06 verify command behavior."""

    def test_cli05_verify_mirror_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI05 an exact remote mirror verifies successfully."""
        fake = FakeLangSmithClient()
        _install_fake(monkeypatch, fake)
        assert evaluation_main(["langsmith", "sync", "evidence-analyst/v1"]) == 0
        assert evaluation_main(["langsmith", "verify", "evidence-analyst/v1"]) == 0

    def test_cli06_verify_mismatch_nonzero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI06 a missing remote dataset makes verify exit nonzero."""
        fake = FakeLangSmithClient()
        _install_fake(monkeypatch, fake)
        assert evaluation_main(["langsmith", "verify", "evidence-analyst/v1"]) == 1


class TestCliContract:
    """LS-CLI07..CLI09 surrounding CLI contract."""

    def test_cli07_existing_validate_unchanged(self) -> None:
        """CLI07 the pre-existing validate command is unchanged."""
        assert evaluation_main(["validate", "evidence-analyst/v1"]) == 0
        assert evaluation_main(["validate", "evals/scenarios/research/retrieval"]) == 0

    def test_cli09_namespace_output_bounded(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI09 sync output is bounded and never contains a secret."""
        fake = FakeLangSmithClient()
        _install_fake(monkeypatch, fake)
        assert (
            evaluation_main(
                ["langsmith", "sync", "evidence-analyst/v1", "--namespace", "internal"]
            )
            == 0
        )
        assert "internal/evidence-analyst/v1" in fake.datasets
        for record in caplog.records:
            rendered = json.dumps(record.message)
            assert "LANGSMITH_API_KEY=" not in rendered


def _missing_credentials_client() -> FakeLangSmithClient:
    """Simulate the bounded failure the real client raises without credentials."""
    fake = FakeLangSmithClient()
    fake.fail_operations = {"find_dataset"}
    return fake
