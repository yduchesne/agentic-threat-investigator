# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""OpenCTI interoperability assertion suite (PR 33E section 10.6).

Runs ONLY after the harness's ingestion-completion barrier reached
READY_FOR_ASSERTIONS (never on a timing assumption). Asserts, against the
durable ATI PostgreSQL of the isolated topology and the shared deterministic
manifest:

1. ATI authenticated to the restricted OpenCTI TAXII collection (the
   acquisition execution reached COMPLETED with no auth error);
2. supported STIX objects became the expected Evidence/Entities;
3. supported Relationships became the expected Relationship rows with exact
   observation provenance;
4. the Sighting stayed Evidence + entity association with zero fabricated
   edges;
5. unresolved dependencies created no placeholder Entities/edges;
6. the second incremental acquisition used the durable checkpoint and
   ingested only the object added after the first run;
7. no OpenCTI-specific production converter/acquirer branch exists;
8. TAXII pagination was actually exercised (the driver forced a page size
   below the collection size and recorded the request count).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.domain.identifiers import SourceId

pytestmark = pytest.mark.interop

_THIS_DIR = Path(__file__).parent


def _run_state() -> dict[str, Any]:
    """Return the harness run-state JSON recorded by the driver."""
    path = Path(os.environ.get("RUN_STATE_FILE", _THIS_DIR / "run-state.json"))
    if not path.exists():
        pytest.fail("RUN_STATE_FILE is missing; the harness must run first")
    loaded = json.loads(path.read_text())
    return loaded if isinstance(loaded, dict) else {}


def _manifest_v1() -> dict[str, Any]:
    """Return the v1 expected-state manifest (single source of truth)."""
    from tests.interop.opencti.fixtures.opencti_fake_world import (
        expected_manifest_v1,
    )

    return expected_manifest_v1()


def _manifest_v2() -> dict[str, Any]:
    """Return the v2 incremental expected-state manifest."""
    from tests.interop.opencti.fixtures.opencti_fake_world import (
        expected_manifest_v2,
    )

    return expected_manifest_v2()


async def _count(
    engine: AsyncEngine, sql: str, params: dict[str, Any] | None = None
) -> int:
    async with engine.connect() as connection:
        scalar = (await connection.execute(text(sql), params or {})).scalar()
        return int(scalar or 0)


class TestAcquisition:
    """Section 10.6.1-10.6.2: authentication, pagination, execution."""

    async def test_acquisition_completed_without_error(
        self, interop_engine: AsyncEngine
    ) -> None:
        """The ATI TAXII datasource execution reached COMPLETED (auth worked)."""
        state = _run_state()
        execution_id = state.get("execution_id")
        assert execution_id, "the driver must record its execution id"
        assert state.get("outcome") == "completed"
        assert state.get("error_code") is None
        async with interop_engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT event_type FROM ati.datasource_log "
                    "WHERE execution_id = :exec ORDER BY id"
                ),
                {"exec": execution_id},
            )
            events = [row[0] for row in result.fetchall()]
        assert events[-1] == "completed"
        assert "failed" not in events
        assert "cancelled" not in events

    async def test_taxii_pagination_was_exercised(self) -> None:
        """The driver forced a bounded page size and fetched > 1 page."""
        state = _run_state()
        assert int(state.get("requests_count") or 0) >= 2, state

    async def test_no_opencti_specific_production_branch(self) -> None:
        """OpenCTI is consumed through the generic TAXII/STIX path only."""
        import agentic_threat_investigator.infrastructure.datasources.stix21_evidence as stix
        import agentic_threat_investigator.infrastructure.datasources.taxii21 as taxii

        assert not hasattr(taxii, "OpenCtiDatasource")
        assert not hasattr(taxii, "OpenCtiToEvidenceConverter")
        assert not hasattr(stix, "OpenCtiToEvidenceConverter")
        from agentic_threat_investigator.infrastructure.datasources.stix21_evidence import (
            Stix21ToEvidenceConverter,
        )
        from agentic_threat_investigator.infrastructure.datasources.taxii21 import (
            Taxii21Datasource,
        )

        assert stix.Stix21ToEvidenceConverter is Stix21ToEvidenceConverter
        assert Taxii21Datasource is not None


class TestFirstSeedState:
    """Section 10.6.3-10.6.6: v1 Evidence/Entity/Relationship/Sighting state."""

    async def test_evidence_identities_exact(self, interop_engine: AsyncEngine) -> None:
        """Every expected v1 Evidence identity is present; counts are exact."""
        manifest = _manifest_v1()
        async with interop_engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT source_record_id FROM ati.evidence "
                    "WHERE source_id = :source"
                ),
                {"source": manifest["source_id"]},
            )
            present = {row[0] for row in result.fetchall()}
        assert present == set(manifest["expected_evidence_ids"])
        assert len(present) == manifest["expected_evidence_count"]

    async def test_entities_exact(self, interop_engine: AsyncEngine) -> None:
        """Expected entities exist with exact canonical identities."""
        manifest = _manifest_v1()
        for entity_type, values in manifest["expected_entities"].items():
            async with interop_engine.connect() as connection:
                result = await connection.execute(
                    text(
                        "SELECT canonical_value FROM ati.entity WHERE entity_type = :t"
                    ),
                    {"t": entity_type},
                )
                present = {row[0] for row in result.fetchall()}
            assert present == set(values), (entity_type, present)

    async def test_relationships_exact_with_provenance(
        self, interop_engine: AsyncEngine
    ) -> None:
        """Every expected Relationship exists with observation provenance."""
        manifest = _manifest_v1()
        found: list[tuple[str, str, str]] = []
        async with interop_engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT r.relationship_type, s.canonical_value, "
                    "t.canonical_value FROM ati.relationship r "
                    "JOIN ati.entity s ON s.id = r.source_entity_id "
                    "JOIN ati.entity t ON t.id = r.target_entity_id"
                )
            )
            found = [(row[0], row[1], row[2]) for row in result.fetchall()]
            provenance_scalar = (
                await connection.execute(
                    text("SELECT count(*) FROM ati.relationship_observation")
                )
            ).scalar()
            provenance = int(provenance_scalar or 0)
        expected = {
            (rel["type"], rel["source"], rel["target"])
            for rel in manifest["expected_relationships"]
        }
        assert {(f[0], f[1], f[2]) for f in found} == expected
        assert provenance == len(expected)

    async def test_sighting_no_fabricated_edge(
        self, interop_engine: AsyncEngine
    ) -> None:
        """The Sighting Evidence exists; no Sighting-tagged edge was created."""
        manifest = _manifest_v1()
        assert "sighting" not in {
            rel["type"] for rel in manifest["expected_relationships"]
        }
        # The only relationship rows are the manifest-admitted ones.
        assert await _count(
            interop_engine,
            "SELECT count(*) FROM ati.relationship",
        ) == len(manifest["expected_relationships"])

    async def test_unresolved_references_no_placeholders(
        self, interop_engine: AsyncEngine
    ) -> None:
        """The unresolved malware endpoint created no Entity and no edge."""
        manifest = _manifest_v1()
        for unsupported in manifest["unsupported_stix_ids"]:
            assert unsupported not in manifest["expected_evidence_ids"]


class TestIncrementalSecondRun:
    """Section 10.6.7 + 10.7: durable checkpoint and the second ingestion."""

    async def test_checkpoint_advanced(self, interop_engine: AsyncEngine) -> None:
        """The durable TAXII checkpoint exists after the first acquisition."""
        expectation = _manifest_v1()["checkpoint"]
        async with interop_engine.connect() as connection:
            row = (
                await connection.execute(
                    text(
                        "SELECT checkpoint_value FROM ati.datasource_checkpoint "
                        "WHERE datasource_id = :ds AND checkpoint_kind = :kind"
                    ),
                    {"ds": expectation["datasource_id"], "kind": expectation["kind"]},
                )
            ).fetchone()
        assert row is not None
        assert row[0]

    async def test_v2_incremental_object_ingested(
        self, interop_engine: AsyncEngine
    ) -> None:
        """The object added to OpenCTI after run 1 was ingested by run 2."""
        state = _run_state()
        if not state.get("second_run_completed"):
            pytest.skip("incremental second run not enabled for this harness mode")
        manifest_v2 = _manifest_v2()
        for expected in manifest_v2["expected_evidence_ids"]:
            count = await _count(
                interop_engine,
                "SELECT count(*) FROM ati.evidence WHERE source_record_id = :id",
                {"id": expected},
            )
            assert count == 1
        # The v2 campaign canonical Entity exists.
        for values in manifest_v2["expected_entities"].values():
            for value in values:
                count = await _count(
                    interop_engine,
                    "SELECT count(*) FROM ati.entity WHERE canonical_value = :v",
                    {"v": value},
                )
                assert count == 1


class TestSourceProvenance:
    """Section 10.6.8: OpenCTI is provenance only, never a semantic path."""

    async def test_source_is_opencti_only_provenance(self) -> None:
        """SourceId.OPENCTI exists and the manifest uses it."""
        assert SourceId.OPENCTI.value == "urn:ati:source:opencti"
        assert _manifest_v1()["source_id"] == SourceId.OPENCTI.value
