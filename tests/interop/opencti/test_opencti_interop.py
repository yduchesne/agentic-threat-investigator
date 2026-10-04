# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""OpenCTI interoperability assertion suite (PR 33E section 10.6, 33E-1 Option C).

Runs ONLY after the harness's ingestion-completion barrier reached
READY_FOR_ASSERTIONS (never on a timing assumption). Asserts, against the
durable ATI PostgreSQL of the isolated topology and the shared deterministic
**canonical** manifest (seed IDs translated to the canonical OpenCTI
identities ATI actually received through TAXII, PR 33E-1 Option C):

1. ATI authenticated to the restricted OpenCTI TAXII collection (the
   acquisition execution reached COMPLETED with no auth error);
2. the seed -> OpenCTI canonical identity -> TAXII identity -> ATI provenance
   mapping is recorded and every expected supported canonical identity became
   Evidence/Entity;
3. the real-OpenCTI-materializable Relationship instances (uses,
   attributed-to) became the expected Relationship rows with exact
   observation provenance and canonical endpoint identities;
4. the Sighting (with its mandatory ``where_sighted_refs`` Identity) stayed
   Evidence + entity association with zero fabricated edges;
5. MATERIALIZABLE_BUT_ATI_UNSUPPORTED objects (the Identity and the generic
   attack-pattern) reached ATI through TAXII but produced zero
   Entity/Evidence/Relationship semantics;
6. REJECTED_BY_OPENCTI_PROFILE objects were never materialized, never reached
   ATI, and are deliberately not counted as unsupported-object coverage;
7. the second incremental acquisition used the durable checkpoint and
   ingested only the object added after the first run;
8. no OpenCTI-specific production converter/acquirer branch exists;
9. TAXII pagination was actually exercised (the driver forced a page size
   below the collection size and recorded the request count).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.domain.identifiers import SourceId
from tests.interop.opencti.fixtures.opencti_fake_world import (
    CATEGORY_REJECTED,
    CATEGORY_SUPPORTED,
    CATEGORY_UNSUPPORTED,
    expected_manifest_v1,
    object_category_seed_ids_v1,
)

pytestmark = pytest.mark.interop

_THIS_DIR = Path(__file__).parent


def _run_state() -> dict[str, Any]:
    """Return the harness run-state JSON recorded by the driver."""
    path = Path(os.environ.get("RUN_STATE_FILE", _THIS_DIR / "run-state.json"))
    if not path.exists():
        pytest.fail("RUN_STATE_FILE is missing; the harness must run first")
    loaded = json.loads(path.read_text())
    return loaded if isinstance(loaded, dict) else {}


def _second_run_completed() -> bool:
    """True when the incremental v2 acquisition actually completed."""
    return bool(_run_state().get("second_run_completed"))


def _canonical_manifest(env_name: str, fallback_name: str) -> dict[str, Any]:
    """Return the canonical (ATI-received identity) manifest path.

    The assertion suite must consume the canonical manifests the harness
    wrote after resolving the seed -> OpenCTI identity mapping; it never
    falls back to the seed-level manifest so expectations cannot diverge.
    """
    path = os.environ.get(env_name)
    if not path:
        path = str(_run_state_file_dir() / fallback_name)
    manifest_path = Path(path)
    if not manifest_path.exists():
        pytest.fail(f"canonical manifest {manifest_path} is missing")
    loaded = json.loads(manifest_path.read_text())
    assert loaded.get("canonical") is True, f"manifest {manifest_path} is not canonical"
    return cast(dict[str, Any], loaded)


def _run_state_file_dir() -> Path:
    state_file = Path(os.environ.get("RUN_STATE_FILE", _THIS_DIR / "run-state.json"))
    return state_file.parent


def _manifest_v1() -> dict[str, Any]:
    """Return the canonical v1 expected-state manifest."""
    return _canonical_manifest(
        "ATI_MANIFEST_V1_CANONICAL", "manifest-v1-canonical.json"
    )


def _manifest_v2() -> dict[str, Any]:
    """Return the canonical v2 incremental expected-state manifest."""
    return _canonical_manifest(
        "ATI_MANIFEST_V2_CANONICAL", "manifest-v2-canonical.json"
    )


def _seed_manifest_v1() -> dict[str, Any]:
    """Return the seed-level v1 manifest (seed ID expectations)."""
    return expected_manifest_v1()


async def _count(
    engine: AsyncEngine, sql: str, params: dict[str, Any] | None = None
) -> int:
    async with engine.connect() as connection:
        scalar = (await connection.execute(text(sql), params or {})).scalar()
        return int(scalar or 0)


class TestAcquisition:
    """Section 10.6.1-10.6.2: authentication, pagination, execution."""

    pytestmark = pytest.mark.asyncio

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
        # The first acquisition is the pagination proof; when the incremental
        # second run recorded its own count, prefer the first run's value.
        first = state.get("requests_count_first")
        count = first if isinstance(first, int) else state.get("requests_count")
        assert int(count or 0) >= 2, state

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


class TestCanonicalProvenance:
    """PR 33E-1 Option C: seed -> canonical -> TAXII -> ATI provenance."""

    def test_identity_map_recorded_and_bijective(self) -> None:
        """The seed -> canonical mapping exists and covers every supported seed."""
        state = _run_state()
        mapping = state.get("identity_map")
        assert isinstance(mapping, dict) and mapping, "identity_map missing"
        assert len(set(mapping.values())) == len(mapping), "mapping not bijective"
        seed_categories = object_category_seed_ids_v1()
        supported = set(seed_categories[CATEGORY_SUPPORTED])
        unsupported = set(seed_categories[CATEGORY_UNSUPPORTED])
        assert supported.issubset(mapping), "supported objects missing from mapping"
        assert unsupported.issubset(mapping), "unsupported objects missing from mapping"
        rejected = set(seed_categories[CATEGORY_REJECTED])
        assert not (rejected & set(mapping)), "rejected objects must stay unmapped"

    def test_feed_verification_recorded(self) -> None:
        """Canonical IDs + relation/sighting refs verified against real TAXII."""
        verification = _run_state().get("feed_verification")
        assert isinstance(verification, dict) and verification.get("ok") is True
        assert verification.get("relationship_refs_canonicalized") is True
        assert verification.get("sighting_refs_canonicalized") is True
        assert verification.get("rejected_absent") is True

    def test_evidence_ids_are_canonical_never_seed(self) -> None:
        """ATI persisted the IDs it received through TAXII (canonical only)."""
        canonical = _manifest_v1()
        mapping = _run_state()["identity_map"]
        supported = object_category_seed_ids_v1()[CATEGORY_SUPPORTED]
        expected_canonical = {mapping[seed] for seed in supported}
        seed_ids = set(expected_manifest_v1()["stix_ids"])
        assert expected_canonical == set(canonical["expected_evidence_ids"])
        # No seed ID may leak into ATI persistence as an evidence identity.
        assert not (expected_canonical & seed_ids)


class TestFirstSeedState:
    """Section 10.6.3-10.6.6: v1 Evidence/Entity/Relationship/Sighting state."""

    pytestmark = pytest.mark.asyncio

    async def test_evidence_identities_exact(self, interop_engine: AsyncEngine) -> None:
        """Every expected canonical Evidence identity is present; counts exact.

        In the incremental mode the durable checkpoint later ingests the v2
        campaign into the same database, so the v1 assertion is the exact
        union of the v1 and (optional) v2 expectations with nothing foreign.
        """
        manifest = _manifest_v1()
        extra: set[str] = set()
        if _second_run_completed():
            extra = set(_manifest_v2()["expected_evidence_ids"])
        async with interop_engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT source_record_id FROM ati.evidence WHERE source = :source"
                ),
                {"source": manifest["source_id"]},
            )
            present = {row[0] for row in result.fetchall()}
        assert present == set(manifest["expected_evidence_ids"]) | extra
        assert len(present) == manifest["expected_evidence_count"] + len(extra)

    async def test_entities_exact(self, interop_engine: AsyncEngine) -> None:
        """Expected entities exist with exact canonical identities.

        Same incremental-union semantics as the Evidence assertion: the v2
        campaign entity joins the v1 set when the second run completed.
        """
        manifest = _manifest_v1()
        extra: dict[str, list[str]] = {}
        if _second_run_completed():
            extra = _manifest_v2()["expected_entities"]
        for entity_type, values in manifest["expected_entities"].items():
            async with interop_engine.connect() as connection:
                result = await connection.execute(
                    text(
                        "SELECT canonical_value FROM ati.entity WHERE entity_type = :t"
                    ),
                    {"t": entity_type},
                )
                present = {row[0] for row in result.fetchall()}
            assert present == set(values) | set(extra.get(entity_type, [])), (
                entity_type,
                present,
            )

    async def test_relationships_exact_with_provenance(
        self, interop_engine: AsyncEngine
    ) -> None:
        """Every expected Relationship exists with observation provenance."""
        manifest = _manifest_v1()
        found: list[tuple[str, str, str]] = []
        async with interop_engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT r.relationship_type_urn, s.canonical_value, "
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
        normalized = {
            (urn.replace("urn:ati:relationship:threat:", "").replace("_", "-"), s, t)
            for urn, s, t in found
        }
        assert normalized == expected
        assert provenance == len(expected)
        assert {f[0] for f in normalized} == {"uses", "attributed-to"}

    async def test_sighting_no_fabricated_edge(
        self, interop_engine: AsyncEngine
    ) -> None:
        """The Sighting Evidence exists; no Sighting-tagged edge was created."""
        manifest = _manifest_v1()
        sighting = manifest["expected_sighting_evidence"] or {}
        assert sighting.get("evidence_id"), "canonical sighting evidence expected"
        async with interop_engine.connect() as connection:
            count = await connection.execute(
                text("SELECT count(*) FROM ati.evidence WHERE source_record_id = :id"),
                {"id": sighting["evidence_id"]},
            )
            assert int(count.scalar() or 0) == 1
            # The Sighting's sighting_of endpoint resolved to the canonical
            # threat-actor Entity without creating any relationship row.
            result = await connection.execute(
                text("SELECT count(*) FROM ati.entity WHERE canonical_value = :v"),
                {"v": sighting["sighting_of"]},
            )
            assert int(result.scalar() or 0) == 1
        assert "sighting" not in {
            rel["type"] for rel in manifest["expected_relationships"]
        }
        assert await _count(
            interop_engine,
            "SELECT count(*) FROM ati.relationship",
        ) == len(manifest["expected_relationships"])

    async def test_materializable_but_unsupported_zero_semantics(
        self, interop_engine: AsyncEngine
    ) -> None:
        """Identity + generic attack-pattern reached TAXII but produced nothing.

        The canonical identities are recorded as materialized (they were
        visible through the real TAXII collection per the feed verification),
        while ATI persisted zero Evidence/Entity/Relationship for them.
        """
        manifest = _manifest_v1()
        unsupported = manifest["unsupported_stix_ids"]
        assert len(unsupported) == 2
        assert "identity--" in unsupported[0] or "identity--" in unsupported[1]
        evidence: set[str] = set()
        async with interop_engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT source_record_id FROM ati.evidence WHERE source = :source"
                ),
                {"source": manifest["source_id"]},
            )
            evidence = {row[0] for row in result.fetchall()}
            entity_values = {
                row[0]
                for row in (
                    await connection.execute(
                        text("SELECT canonical_value FROM ati.entity")
                    )
                ).fetchall()
            }
        assert not (set(unsupported) & evidence)
        assert not (set(unsupported) & entity_values)

    async def test_rejected_never_materialized_or_persisted(
        self, interop_engine: AsyncEngine
    ) -> None:
        """REJECTED_BY_OPENCTI_PROFILE objects stayed out of everything."""
        seed_manifest = _seed_manifest_v1()
        rejected = seed_manifest["object_categories"][CATEGORY_REJECTED]
        reasons = seed_manifest["rejected_by_opencti_profile_reasons"]
        assert set(reasons) == set(rejected)
        mapping = _run_state()["identity_map"]
        assert not (set(rejected) & set(mapping))
        # No ATI row can reference a rejected object (no canonical identity
        # exists, and ATI never saw them through TAXII).
        async with interop_engine.connect() as connection:
            result = await connection.execute(
                text("SELECT source_record_id FROM ati.evidence")
            )
            evidence = {row[0] for row in result.fetchall()}
            entity_values = {
                row[0]
                for row in (
                    await connection.execute(
                        text("SELECT canonical_value FROM ati.entity")
                    )
                ).fetchall()
            }
        assert not (set(rejected) & evidence)
        assert not (set(rejected) & entity_values)


class TestIncrementalSecondRun:
    """Section 10.6.7 + 10.7: durable checkpoint and the second ingestion."""

    pytestmark = pytest.mark.asyncio

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

    pytestmark = pytest.mark.asyncio

    async def test_source_is_opencti_only_provenance(self) -> None:
        """SourceId.OPENCTI exists and the manifest uses it."""
        assert SourceId.OPENCTI.value == "urn:ati:source:opencti"
        assert _manifest_v1()["source_id"] == SourceId.OPENCTI.value
