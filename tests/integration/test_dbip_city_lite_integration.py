# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests for the local DB-IP City Lite geolocation source.

Exercises the real ``DbIpCityLiteProvider`` over real artifact-URI
resolution, the real ``FileSystemObjectStore``, and the real MMDB reader
against the ATI-authored synthetic MMDB fixture. No DB-IP network access,
API key, external HTTP, download, or persistence occurs.
"""

from __future__ import annotations

import datetime
import pathlib
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.providers import ProviderErrorCode, ProviderResult
from agentic_threat_investigator.app.secrets import SecretsResolver
from agentic_threat_investigator.config import settings_from_config
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.infrastructure.object_store import (
    ArtifactNotFoundError,
    FileSystemObjectStore,
)
from agentic_threat_investigator.infrastructure.providers.composition import (
    ProviderComposition,
)
from agentic_threat_investigator.infrastructure.providers.dbip_city_lite import (
    MmdbOpenError,
)
from tests.support.mmdb import (
    CITY_IPV4,
    CITY_IPV6,
    COUNTRY_IPV4,
    MISS_IPV4,
    MISS_IPV6,
    REGION_IPV4,
    build_scalar_record_city_lite_mmdb,
    build_synthetic_city_lite_mmdb,
    build_wrong_product_city_lite_mmdb,
)

pytestmark = [pytest.mark.integration, pytest.mark.provider_contract]

_PROVIDER_ID = "urn:ati:source:dbip_city_lite"


class _StaticSecretsResolver(SecretsResolver):
    """Deterministic resolver for the unrelated IPinfo composition seam.

    DB-IP holds no secret; this only satisfies the IPinfo composition step
    so the full provider stack can be composed without any credential.
    """

    def get(self, name: str) -> str | None:
        """Return a resolved fake value for any reference name."""
        return "integration-fake-token"


async def _composed(
    tmp_path: pathlib.Path, artifact: bytes | None
) -> ProviderComposition:
    """Compose the full provider stack over a written synthetic artifact."""
    uri = f"file://{tmp_path}/datasets/dbip-city-lite/city-lite.mmdb"
    store = FileSystemObjectStore(pathlib.Path(tmp_path) / "datasets")
    if artifact is not None:
        await store.write(uri, artifact)
    settings = settings_from_config(
        {"data_dir": str(tmp_path), "dbip_city_lite_artifact_uri": uri}
    )
    return await ProviderComposition.create(settings, secrets=_StaticSecretsResolver())


async def _lookup(composition: ProviderComposition, value: str) -> "ProviderResult":
    """Run one provider lookup for an IP entity and return the result."""
    assert composition.dbip_city_lite is not None
    return await composition.dbip_city_lite.investigate(
        uuid.UUID(int=1),
        Entity(id=uuid.UUID(int=2), type=EntityType.IP_ADDRESS, value=value),
    )


class TestDbIpCityLiteIntegration:
    """End-to-end local geolocation lookups over the synthetic MMDB."""

    @pytest.mark.asyncio
    async def test_ipv4_city_hit(self, tmp_path: pathlib.Path) -> None:
        """An IPv4 hit emits exactly one normalized GEOLOCATION evidence."""
        async with await _composed(tmp_path, build_synthetic_city_lite_mmdb()) as comp:
            result = await _lookup(comp, CITY_IPV4)
        assert result.provider == _PROVIDER_ID
        assert result.errors == ()
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.type is EvidenceType.GEOLOCATION
        assert evidence.source == _PROVIDER_ID
        assert evidence.subject.type is EntityType.IP_ADDRESS
        assert evidence.subject.value == CITY_IPV4
        assert evidence.observed_at is None
        assert evidence.raw_payload is None
        assert evidence.facts["country_code"] == "US"
        assert evidence.facts["city"] == "Example City"
        assert evidence.facts["latitude"] == -33.5
        assert evidence.facts["longitude"] == 150.25
        assert evidence.facts["precision"] == "city"
        assert evidence.facts["provider"] == _PROVIDER_ID

    @pytest.mark.asyncio
    async def test_ipv6_city_hit(self, tmp_path: pathlib.Path) -> None:
        """An IPv6 hit emits normalized GEOLOCATION evidence."""
        async with await _composed(tmp_path, build_synthetic_city_lite_mmdb()) as comp:
            result = await _lookup(comp, CITY_IPV6)
        assert result.errors == ()
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.subject.value == CITY_IPV6
        assert evidence.facts["city"] == "Example V6 City"
        assert evidence.facts["precision"] == "city"

    @pytest.mark.asyncio
    async def test_region_precision_hit(self, tmp_path: pathlib.Path) -> None:
        """A region-precision record normalizes with REGION precision."""
        async with await _composed(tmp_path, build_synthetic_city_lite_mmdb()) as comp:
            result = await _lookup(comp, REGION_IPV4)
        assert result.errors == ()
        assert result.evidence[0].facts["region"] == "New South Wales"
        assert result.evidence[0].facts["city"] is None
        assert result.evidence[0].facts["precision"] == "region"

    @pytest.mark.asyncio
    async def test_country_precision_hit(self, tmp_path: pathlib.Path) -> None:
        """A country-only record normalizes with COUNTRY precision."""
        async with await _composed(tmp_path, build_synthetic_city_lite_mmdb()) as comp:
            result = await _lookup(comp, COUNTRY_IPV4)
        assert result.errors == ()
        assert result.evidence[0].facts["country_code"] == "AU"
        assert result.evidence[0].facts["precision"] == "country"

    @pytest.mark.asyncio
    async def test_lookup_miss_is_valid_empty_result(
        self, tmp_path: pathlib.Path
    ) -> None:
        """An unlisted address yields no evidence and no error."""
        async with await _composed(tmp_path, build_synthetic_city_lite_mmdb()) as comp:
            result = await _lookup(comp, MISS_IPV4)
        assert result.provider == _PROVIDER_ID
        assert result.evidence == ()
        assert result.errors == ()

    @pytest.mark.asyncio
    async def test_ipv6_lookup_miss_is_valid_empty_result(
        self, tmp_path: pathlib.Path
    ) -> None:
        """An unlisted IPv6 address yields no evidence and no error."""
        async with await _composed(tmp_path, build_synthetic_city_lite_mmdb()) as comp:
            result = await _lookup(comp, MISS_IPV6)
        assert result.provider == _PROVIDER_ID
        assert result.evidence == ()
        assert result.errors == ()

    @pytest.mark.asyncio
    async def test_scalar_record_is_invalid_response(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A matched non-object record is INVALID_RESPONSE, not unavailability."""
        async with await _composed(
            tmp_path, build_scalar_record_city_lite_mmdb()
        ) as comp:
            result = await _lookup(comp, CITY_IPV4)
        assert result.evidence == ()
        assert len(result.errors) == 1
        error = result.errors[0]
        assert error.code is ProviderErrorCode.INVALID_RESPONSE
        assert error.retryable is False
        assert "192.0.2.10" not in error.message

    @pytest.mark.asyncio
    async def test_evidence_shape_is_geolocation_only(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Evidence carries provenance only: no verdict, scores, or payload."""
        async with await _composed(tmp_path, build_synthetic_city_lite_mmdb()) as comp:
            result = await _lookup(comp, CITY_IPV4)
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.source_url is None
        assert evidence.raw_payload is None
        assert evidence.observed_at is None
        assert evidence.retrieved_at.tzinfo is not None
        assert (
            evidence.retrieved_at.utcoffset()
            == datetime.datetime.now(datetime.UTC).utcoffset()
        )
        assert set(evidence.facts) == {
            "country_code",
            "region",
            "city",
            "latitude",
            "longitude",
            "provider",
            "precision",
        }

    @pytest.mark.asyncio
    async def test_wrong_product_artifact_fails_composition(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A valid MMDB of a different product edition fails composition."""
        with pytest.raises(MmdbOpenError):
            await _composed(tmp_path, build_wrong_product_city_lite_mmdb())

    @pytest.mark.asyncio
    async def test_private_address_misses(self, tmp_path: pathlib.Path) -> None:
        """A private address deterministically misses: City Lite never has one."""
        async with await _composed(tmp_path, build_synthetic_city_lite_mmdb()) as comp:
            result = await _lookup(comp, "10.0.0.1")
        assert result.evidence == ()
        assert result.errors == ()

    @pytest.mark.asyncio
    async def test_missing_artifact_fails_composition(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A configured but absent artifact fails composition clearly."""
        with pytest.raises(ArtifactNotFoundError):
            await _composed(tmp_path, None)

    @pytest.mark.asyncio
    async def test_corrupt_artifact_fails_composition(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A corrupt artifact cannot be opened and fails composition."""
        with pytest.raises(MmdbOpenError):
            await _composed(tmp_path, b"not an mmdb database at all")

    @pytest.mark.asyncio
    async def test_no_persistence_occurs(
        self, tmp_path: pathlib.Path, integration_engine: AsyncEngine
    ) -> None:
        """Lookups persist nothing: the evidence table remains empty."""
        async with await _composed(tmp_path, build_synthetic_city_lite_mmdb()) as comp:
            await _lookup(comp, CITY_IPV4)
            await _lookup(comp, CITY_IPV6)
            await _lookup(comp, MISS_IPV4)
        async with integration_engine.begin() as connection:
            count = await connection.scalar(text("SELECT count(*) FROM ati.evidence"))
        assert count == 0
