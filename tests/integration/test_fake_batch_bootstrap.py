# SPDX-License-Identifier: AGPL-3.0-only
"""Fake batch bootstrap integration tests (PR 23D).

Proves the explicit one-shot fake-data bootstrap over real PostgreSQL: the
packaged MITRE STIX fixture is materialized into the datasets object store
and ingested through the production ``MitreAttackBatchSource`` /
``IngestionService`` persistence path, changed records are indexed into the
research corpus, repeated runs are idempotent, production mode refuses the
bootstrap, and malformed fixtures fail closed. Stable IDs: 23D-I01 through
23D-I04 and the production-refusal matrix.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.config import OperatingMode, Settings
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.infrastructure.bootstrap import (
    FakeDataBootstrap,
    FakeDataBootstrapError,
)
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FakeBatchArtifactData,
    FakeWorldCatalog,
    FakeWorldValidationError,
)

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_MITRE_SOURCE_ID = SourceId.MITRE_ATTACK.value
_FIXTURE_RECORD_COUNT = 9
_FIXTURE_DOCUMENT_COUNT = 5


def _fake_settings(tmp_path: Path) -> Settings:
    """Return fake-mode settings rooted at an isolated test data directory."""
    return Settings(operating_mode=OperatingMode.FAKE, data_dir=tmp_path)


async def test_i01_bootstrap_ingests_fixture_through_production_parser(
    uow_factory: Callable[[], UnitOfWork], tmp_path: Path
) -> None:
    """First bootstrap ingests records and indexes documents through real paths."""
    summary = await FakeDataBootstrap(
        settings=_fake_settings(tmp_path), uow_factory=uow_factory
    ).run()
    assert len(summary.fixtures) == 1
    fixture = summary.fixtures[0]
    assert fixture.source_id == _MITRE_SOURCE_ID
    assert fixture.inserted == _FIXTURE_RECORD_COUNT
    assert fixture.complete is True
    assert fixture.documents_indexed == _FIXTURE_DOCUMENT_COUNT

    async with uow_factory() as uow:
        record = await uow.source_records.get_by_identity(
            _MITRE_SOURCE_ID,
            "attack-pattern--a934d7f9-1f15-4d3f-b7a1-2a7f0a1b1c01",
        )
        checkpoint = await uow.ingestion_checkpoints.get(
            _MITRE_SOURCE_ID,
            fixture.artifact_uri,
            1,
        )
        document = await uow.documents.get_by_identity(
            _MITRE_SOURCE_ID,
            "attack-pattern--a934d7f9-1f15-4d3f-b7a1-2a7f0a1b1c01",
        )
    assert record is not None
    assert record.source_id == _MITRE_SOURCE_ID
    assert checkpoint is not None and checkpoint.complete is True
    assert document is not None
    # The artifact was materialized inside the isolated datasets root.
    assert fixture.artifact_uri.startswith(tmp_path.as_uri())


async def test_i02_repeated_bootstrap_is_idempotent(
    uow_factory: Callable[[], UnitOfWork], tmp_path: Path
) -> None:
    """A second bootstrap creates no semantic duplicates and no new documents."""
    bootstrap = FakeDataBootstrap(
        settings=_fake_settings(tmp_path), uow_factory=uow_factory
    )
    first = await bootstrap.run()
    second = await bootstrap.run()
    assert first.total_records_changed == _FIXTURE_RECORD_COUNT
    assert second.total_records_changed == 0
    assert second.fixtures[0].inserted == 0
    assert second.fixtures[0].unchanged == 0
    assert second.fixtures[0].complete is True

    async with uow_factory() as uow:
        from sqlalchemy import text as _text

        assert uow.session is not None  # type: ignore[attr-defined]
        count = await uow.session.scalar(  # type: ignore[attr-defined]
            _text("SELECT count(*) FROM ati.source_record WHERE source_id = :sid"),
            {"sid": _MITRE_SOURCE_ID},
        )
    assert count == _FIXTURE_RECORD_COUNT


async def test_i03_malformed_fixture_fails_closed(
    uow_factory: Callable[[], UnitOfWork], tmp_path: Path
) -> None:
    """A malformed packaged artifact fails the bootstrap with a clear error."""
    world = FakeWorldCatalog.load_packaged()
    bad = FakeBatchArtifactData(
        source_id=_MITRE_SOURCE_ID,
        package_path="v1/batch/missing_artifact.json",
        dataset_path="mitre-attack/missing.json",
    )
    # Reuse the loaded world but substitute the missing artifact binding.
    modified_world = _with_artifact_binding(world, bad)
    bootstrap = FakeDataBootstrap(
        settings=_fake_settings(tmp_path),
        uow_factory=uow_factory,
        catalog=modified_world,
    )
    with pytest.raises(
        (FakeDataBootstrapError, FakeWorldValidationError), match="missing"
    ):
        await bootstrap.run()


async def test_i04_production_mode_refuses_bootstrap(
    uow_factory: Callable[[], UnitOfWork], tmp_path: Path
) -> None:
    """ATI_OPERATING_MODE=production never runs the fake-data bootstrap."""
    settings = Settings(operating_mode=OperatingMode.PRODUCTION, data_dir=tmp_path)
    bootstrap = FakeDataBootstrap(settings=settings, uow_factory=uow_factory)
    with pytest.raises(FakeDataBootstrapError, match="ATI_OPERATING_MODE=fake"):
        await bootstrap.run()
    async with uow_factory() as uow:
        from sqlalchemy import text as _text

        assert uow.session is not None  # type: ignore[attr-defined]
        count = await uow.session.scalar(  # type: ignore[attr-defined]
            _text("SELECT count(*) FROM ati.source_record WHERE source_id = :sid"),
            {"sid": _MITRE_SOURCE_ID},
        )
    assert count == 0


async def test_i03b_importing_fake_runtime_never_mutates_postgresql(
    uow_factory: Callable[[], UnitOfWork], tmp_path: Path
) -> None:
    """Module import and composition alone never ingest fake batch data."""
    # Importing the fake runtime package, the catalog, and the composition
    # module is side-effect free by contract; only the explicit bootstrap
    # path performs fake batch initialization.
    import agentic_threat_investigator.infrastructure.fake_runtime.catalog
    import agentic_threat_investigator.infrastructure.intelligence_composition  # noqa: F401
    from agentic_threat_investigator.infrastructure.intelligence_composition import (
        build_fake_intelligence_sources,
    )

    sources = build_fake_intelligence_sources(
        Settings(operating_mode=OperatingMode.FAKE, data_dir=tmp_path),
        catalog=FakeWorldCatalog.load_packaged(),
    )
    assert sources.provider_registry
    async with uow_factory() as uow:
        from sqlalchemy import text as _text

        assert uow.session is not None  # type: ignore[attr-defined]
        count = await uow.session.scalar(  # type: ignore[attr-defined]
            _text("SELECT count(*) FROM ati.source_record")
        )
    assert count == 0


def _with_artifact_binding(
    catalog: FakeWorldCatalog, binding: FakeBatchArtifactData
) -> FakeWorldCatalog:
    """Return a catalog whose batch bindings are replaced by ``binding``."""
    original = catalog.batch_artifacts()
    assert len(original) == 1
    # Rebuild through the public JSON path so validation runs once more.
    world_json = json.loads(
        (
            __import__("pathlib").Path(
                "src/agentic_threat_investigator/infrastructure/fake_runtime/data/v1/world.json"
            )
        ).read_text()
    )
    scenarios_json = json.loads(
        (
            __import__("pathlib").Path(
                "src/agentic_threat_investigator/infrastructure/fake_runtime/data/v1/scenarios.json"
            )
        ).read_text()
    )
    world_json["batch_artifacts"] = [
        {
            "source_id": binding.source_id,
            "package_path": binding.package_path,
            "dataset_path": binding.dataset_path,
        }
    ]
    return FakeWorldCatalog.load(
        json.dumps(world_json).encode("utf-8"),
        json.dumps(scenarios_json).encode("utf-8"),
    )
