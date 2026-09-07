# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the DB-IP City Lite provider and record normalization.

All records are synthetic dictionaries or the ATI-authored synthetic MMDB
fixture; no DB-IP network access, download, or real dataset is involved.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.providers import ProviderErrorCode
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.geolocation import GeoPrecision
from agentic_threat_investigator.infrastructure.providers.dbip_city_lite import (
    CityLiteDatabase,
    CityLiteMmdb,
    CityLiteRecordError,
    DbIpCityLiteProvider,
    MmdbLookupError,
    MmdbOpenError,
    normalize_city_lite_record,
)
from tests.support.mmdb import (
    CITY_IPV4,
    CITY_IPV6,
    MISS_IPV4,
    build_scalar_record_city_lite_mmdb,
    build_synthetic_city_lite_mmdb,
    build_wrong_product_city_lite_mmdb,
)

pytestmark = [pytest.mark.unit, pytest.mark.provider_contract]

_FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")
_FIXED_TS = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
_PROVIDER_ID = "urn:ati:source:dbip_city_lite"
_CITY_KEY = "192.0.2.10"


def _city_record(**overrides: Any) -> dict[str, Any]:
    """Build a canonical synthetic city-precision record."""
    record: dict[str, Any] = {
        "country": {"iso_code": "US"},
        "city": {"names": {"en": "Example City"}},
        "subdivisions": [{"iso_code": "CA", "names": {"en": "California"}}],
        "location": {"latitude": 37.5, "longitude": -122.25},
    }
    record.update(overrides)
    return record


def _ip_entity(
    value: str, *, entity_type: EntityType = EntityType.IP_ADDRESS
) -> Entity:
    """Build a deterministic IP entity fixture."""
    return Entity(id=uuid4(), type=entity_type, value=value)


class _FakeDatabase(CityLiteDatabase):
    """Deterministic in-memory ``CityLiteDatabase`` stub with lookup tracing."""

    def __init__(
        self,
        records: dict[str, Any] | None = None,
        *,
        fail: bool = False,
        lookup_error: Exception | None = None,
    ) -> None:
        """Initialize with per-IP values, a forced reader failure, or both."""
        self._records = records or {}
        self._fail = fail
        self._lookup_error = lookup_error
        self.lookups: list[str] = []
        self.closed = False
        self.close_count = 0

    def lookup(self, ip: str) -> Any:
        """Return the record for one IP, tracing the lookup attempt."""
        self.lookups.append(ip)
        if self._lookup_error is not None:
            raise self._lookup_error
        if self._fail:
            raise MmdbLookupError("forced reader failure")
        return self._records.get(ip)

    def close(self) -> None:
        """Mark the reader closed and count close attempts."""
        self.closed = True
        self.close_count += 1


def _provider(database: _FakeDatabase) -> DbIpCityLiteProvider:
    """Build the provider under test with a deterministic clock."""
    return DbIpCityLiteProvider(database, clock=lambda: _FIXED_TS)


# -- Record normalization ---------------------------------------------------


class TestCityLiteRecordNormalization:
    """Strict validation and normalization of raw City Lite records."""

    def test_city_precision_record(self) -> None:
        """City plus country yields CITY precision with normalized fields."""
        geolocation = normalize_city_lite_record(_city_record())
        assert geolocation is not None
        assert geolocation.country_code == "US"
        assert geolocation.city == "Example City"
        assert geolocation.region == "California"
        assert geolocation.latitude == 37.5
        assert geolocation.longitude == -122.25
        assert geolocation.provider == _PROVIDER_ID
        assert geolocation.precision is GeoPrecision.CITY

    def test_region_precision_record(self) -> None:
        """Region plus country without city yields REGION precision."""
        record = _city_record(city={"names": {"de": "Beispiel"}})
        geolocation = normalize_city_lite_record(record)
        assert geolocation is not None
        assert geolocation.city is None
        assert geolocation.region == "California"
        assert geolocation.precision is GeoPrecision.REGION

    def test_country_precision_record(self) -> None:
        """Country alone yields COUNTRY precision."""
        geolocation = normalize_city_lite_record(
            {"country": {"iso_code": "us"}, "location": {"latitude": 0, "longitude": 0}}
        )
        assert geolocation is not None
        assert geolocation.country_code == "US"
        assert geolocation.precision is GeoPrecision.COUNTRY


@pytest.mark.unit
@pytest.mark.provider_contract
class TestCityLiteCountryAndCoordinates:
    """Country-code and coordinate adversarial validation."""

    def test_lowercase_country_code_normalized(self) -> None:
        """A lowercase country code is normalized to uppercase."""
        geolocation = normalize_city_lite_record({"country": {"iso_code": "us"}})
        assert geolocation is not None
        assert geolocation.country_code == "US"

    def test_mixed_case_country_code_normalized(self) -> None:
        """A mixed-case raw ASCII country code is accepted and uppercased."""
        geolocation = normalize_city_lite_record({"country": {"iso_code": "uS"}})
        assert geolocation is not None
        assert geolocation.country_code == "US"

    @pytest.mark.parametrize(
        "code",
        [
            "\u00df",
            "\u0130\u0130",
            "\u0130\u0131",
            "\u00e9\u00e9",
            "\uff35\uff33",
            "\u00dfS",
        ],
    )
    def test_unicode_country_codes_rejected(self, code: str) -> None:
        """Unicode letters and case-expanding characters never pass as ASCII."""
        with pytest.raises(ValueError):
            normalize_city_lite_record({"country": {"iso_code": code}})

    def test_padded_country_code_rejected(self) -> None:
        """Padded country codes are not exactly two letters and are malformed."""
        with pytest.raises(ValueError):
            normalize_city_lite_record({"country": {"iso_code": " US "}})

    def test_coordinates_only_yields_unknown_precision(self) -> None:
        """Coordinates alone never establish granularity (UNKNOWN)."""
        geolocation = normalize_city_lite_record(
            {"location": {"latitude": 10.0, "longitude": -10.0}}
        )
        assert geolocation is not None
        assert geolocation.precision is GeoPrecision.UNKNOWN
        assert geolocation.latitude == 10.0
        assert geolocation.longitude == -10.0


@pytest.mark.unit
@pytest.mark.provider_contract
class TestCityLiteNameShapes:
    """English-name, subdivision, and miss-shape validation."""

    def test_multiple_subdivisions_first_selected(self) -> None:
        """The first subdivision is selected deterministically."""
        record = _city_record(
            subdivisions=[
                {"iso_code": "CA", "names": {"en": "California"}},
                {"iso_code": "OR", "names": {"en": "Oregon"}},
            ]
        )
        geolocation = normalize_city_lite_record(record)
        assert geolocation is not None
        assert geolocation.region == "California"

    def test_missing_english_names_yield_none(self) -> None:
        """Missing English names yield None without arbitrary fallback."""
        record = {
            "country": {"iso_code": "US"},
            "city": {"names": {"de": "Beispielstadt"}},
            "subdivisions": [{"names": {"fr": "Région"}}],
        }
        geolocation = normalize_city_lite_record(record)
        assert geolocation is not None
        assert geolocation.city is None
        assert geolocation.region is None
        assert geolocation.precision is GeoPrecision.COUNTRY

    def test_subdivision_without_names_member(self) -> None:
        """A first subdivision without a names member yields no region."""
        geolocation = normalize_city_lite_record(
            _city_record(subdivisions=[{"iso_code": "CA"}])
        )
        assert geolocation is not None
        assert geolocation.region is None

    @pytest.mark.parametrize(
        "names",
        [None, "", "   ", 7, True, ["California"], {"en": 7}, {"en": ["x"]}],
    )
    def test_wrong_region_names_shapes_rejected(self, names: Any) -> None:
        """Explicit null and wrong subdivision names shapes are malformed."""
        with pytest.raises(ValueError):
            normalize_city_lite_record(_city_record(subdivisions=[{"names": names}]))

    def test_names_whitespace_stripped(self) -> None:
        """Outer whitespace around English names is stripped."""
        geolocation = normalize_city_lite_record(
            _city_record(city={"names": {"en": "  Example City  "}})
        )
        assert geolocation is not None
        assert geolocation.city == "Example City"

    def test_empty_record_is_documented_miss(self) -> None:
        """A record with no usable approved data at all is a miss."""
        assert normalize_city_lite_record({}) is None

    @pytest.mark.parametrize(
        "record",
        [
            {"country": "US"},
            {"country": {"iso_code": "US"}, "city": "Example City"},
            {
                "country": {"iso_code": "US"},
                "city": {"names": ["Example City"]},
            },
            {"country": {"iso_code": "US"}, "location": [1.0, 2.0]},
            {"country": {"iso_code": "US"}, "subdivisions": "California"},
            {"country": {"iso_code": "US"}, "subdivisions": ["California"]},
            {"country": {"iso_code": "US"}, "subdivisions": [{"names": 7}]},
        ],
    )
    def test_malformed_nested_shapes_rejected(self, record: dict[str, Any]) -> None:
        """Wrong nested shapes make the record malformed."""
        with pytest.raises(ValueError):
            normalize_city_lite_record(record)

    @pytest.mark.parametrize(
        "code",
        ["U", "USA", "U1", "U-", "US ", "", "   ", 8, True, None, ["US"], {"c": "US"}],
    )
    def test_invalid_country_codes_rejected(self, code: Any) -> None:
        """Invalid country codes make the record malformed."""
        with pytest.raises(ValueError):
            normalize_city_lite_record({"country": {"iso_code": code}})

    @pytest.mark.parametrize(
        "name",
        ["", "   ", 7, True, None, ["Example"], {"n": "x"}, "x" * 201],
    )
    def test_invalid_city_names_rejected(self, name: Any) -> None:
        """Blank, overlong, or non-string city English names are malformed."""
        with pytest.raises(ValueError):
            normalize_city_lite_record({"city": {"names": {"en": name}}})

    def test_overlong_region_name_rejected(self) -> None:
        """An overlong region English name is malformed."""
        with pytest.raises(ValueError):
            normalize_city_lite_record(
                _city_record(subdivisions=[{"names": {"en": "x" * 201}}])
            )

    @pytest.mark.parametrize("label", ["city", "region"])
    def test_exact_200_character_name_accepted(self, label: str) -> None:
        """A 200-character English name sits exactly at the accepted bound."""
        name = "E" * 200
        if label == "city":
            geolocation = normalize_city_lite_record(
                _city_record(city={"names": {"en": name}})
            )
            assert geolocation is not None
            assert geolocation.city == name
        else:
            geolocation = normalize_city_lite_record(
                _city_record(subdivisions=[{"names": {"en": name}}])
            )
            assert geolocation is not None
            assert geolocation.region == name

    def test_no_usable_data_with_extra_fields_is_miss(self) -> None:
        """Ignored extra fields alone never turn an empty record into data."""
        assert (
            normalize_city_lite_record(
                {"postal": {"code": "12345"}, "future_member": {"x": 1}}
            )
            is None
        )

    def test_non_mapping_top_level_record_rejected(self) -> None:
        """A matched list or scalar record is malformed, not a miss."""
        with pytest.raises(ValueError):
            normalize_city_lite_record(["not", "a", "record"])
        with pytest.raises(ValueError):
            normalize_city_lite_record("scalar record")

    def test_coordinate_boundaries_accepted(self) -> None:
        """Exact latitude/longitude boundaries are accepted."""
        for lat, lon in [(0.0, 0.0), (-90.0, -180.0), (90.0, 180.0), (-0.0, 0.0)]:
            geolocation = normalize_city_lite_record(
                {"location": {"latitude": lat, "longitude": lon}}
            )
            assert geolocation is not None
            assert geolocation.latitude == lat
            assert geolocation.longitude == lon

    @pytest.mark.parametrize(
        "lat,lon",
        [(-90.5, 0.0), (90.5, 0.0), (0.0, -180.5), (0.0, 180.5)],
    )
    def test_out_of_range_coordinates_rejected(self, lat: float, lon: float) -> None:
        """Out-of-range coordinates are malformed."""
        with pytest.raises(ValueError):
            normalize_city_lite_record(
                {"location": {"latitude": lat, "longitude": lon}}
            )

    @pytest.mark.parametrize(
        "lat,lon",
        [
            (float("nan"), 0.0),
            (0.0, float("nan")),
            (float("inf"), 0.0),
            (0.0, float("-inf")),
            (True, 0.0),
            (0.0, False),
            ("10.0", 0.0),
            (0.0, "10.0"),
            (None, 0.0),
        ],
    )
    def test_invalid_coordinate_values_rejected(self, lat: Any, lon: Any) -> None:
        """NaN, infinities, booleans, strings, and nulls are malformed."""
        with pytest.raises(ValueError):
            normalize_city_lite_record(
                {"location": {"latitude": lat, "longitude": lon}}
            )

    @pytest.mark.parametrize(
        "location",
        [
            {"latitude": 10.0},
            {"longitude": 10.0},
            {"latitude": None, "longitude": 0.0},
            {"latitude": 0.0, "longitude": None},
        ],
    )
    def test_partial_coordinate_pairs_rejected(self, location: dict[str, Any]) -> None:
        """Exactly one coordinate present is INVALID_RESPONSE-grade malformed."""
        with pytest.raises(ValueError):
            normalize_city_lite_record({"location": location})

    def test_location_without_coordinates_accepted(self) -> None:
        """A location member without coordinates is simply absent data."""
        geolocation = normalize_city_lite_record(
            {"country": {"iso_code": "US"}, "location": {}}
        )
        assert geolocation is not None
        assert geolocation.latitude is None
        assert geolocation.longitude is None

    def test_integer_coordinates_accepted(self) -> None:
        """Integer coordinates are real numbers and normalize to floats."""
        geolocation = normalize_city_lite_record(
            {"location": {"latitude": 10, "longitude": -20}}
        )
        assert geolocation is not None
        assert geolocation.latitude == 10.0
        assert geolocation.longitude == -20.0

    def test_extra_fields_ignored(self) -> None:
        """Unknown and out-of-scope members never influence normalization."""
        record = _city_record(
            postal={"code": "12345"},
            timezone="America/Los_Angeles",
            asn="AS64496",
            future_member={"x": 1},
        )
        geolocation = normalize_city_lite_record(record)
        assert geolocation is not None
        assert geolocation.city == "Example City"
        assert geolocation.precision is GeoPrecision.CITY


# -- MMDB reader adapter -----------------------------------------------------


class TestCityLiteMmdb:
    """Ownership and lookup behavior of the local MMDB reader adapter."""

    def test_open_reads_synthetic_fixture(self) -> None:
        """The adapter reads the ATI-authored synthetic fixture offline."""
        database = CityLiteMmdb(build_synthetic_city_lite_mmdb())
        try:
            assert database.lookup(CITY_IPV4) is not None
            assert database.lookup(CITY_IPV6) is not None
        finally:
            database.close()

    def test_miss_returns_none(self) -> None:
        """An unlisted address yields a None miss."""
        database = CityLiteMmdb(build_synthetic_city_lite_mmdb())
        try:
            assert database.lookup(MISS_IPV4) is None
        finally:
            database.close()

    def test_corrupt_artifact_raises_open_error(self) -> None:
        """A corrupt artifact cannot be opened as a reader."""
        with pytest.raises(MmdbOpenError):
            CityLiteMmdb(b"not an mmdb database at all")

    def test_non_object_record_raises_record_error(self) -> None:
        """A matched non-object record is malformed data, not unavailability."""
        database = CityLiteMmdb(build_scalar_record_city_lite_mmdb())
        try:
            with pytest.raises(CityLiteRecordError):
                database.lookup(CITY_IPV4)
        finally:
            database.close()

    def test_wrong_product_metadata_rejected(self) -> None:
        """A valid MMDB of a different product edition fails to open."""
        with pytest.raises(MmdbOpenError):
            CityLiteMmdb(build_wrong_product_city_lite_mmdb())

    def test_close_is_idempotent(self) -> None:
        """Closing twice is safe and does not raise."""
        database = CityLiteMmdb(build_synthetic_city_lite_mmdb())
        database.close()
        database.close()

    def test_lookup_after_close_raises(self) -> None:
        """Lookups after close fail with a typed error."""
        database = CityLiteMmdb(build_synthetic_city_lite_mmdb())
        database.close()
        with pytest.raises(MmdbLookupError):
            database.lookup(CITY_IPV4)


# -- Provider contract --------------------------------------------------------


class TestDbIpCityLiteProviderContract:
    """Deterministic provider contract tests for DbIpCityLiteProvider."""

    def test_provider_identity(self) -> None:
        """The provider exposes the stable DB-IP City Lite source URN."""
        assert _provider(_FakeDatabase()).id == _PROVIDER_ID

    def test_supports_ip_address_entities_only(self) -> None:
        """IPv4 and IPv6 IP-address entities are supported; nothing else is."""
        provider = _provider(_FakeDatabase())
        assert provider.supports(_ip_entity("192.0.2.10"))
        assert provider.supports(_ip_entity(CITY_IPV6))
        unsupported = [
            entity_type
            for entity_type in EntityType
            if entity_type is not EntityType.IP_ADDRESS
        ]
        assert len(unsupported) == len(EntityType) - 1
        for entity_type in unsupported:
            assert not provider.supports(
                _ip_entity("example.com", entity_type=entity_type)
            )

    @pytest.mark.parametrize(
        "entity_type",
        [
            EntityType.DOMAIN,
            EntityType.URL,
            EntityType.NETWORK_PREFIX,
            EntityType.ASN,
            EntityType.ORGANIZATION,
            EntityType.MALWARE,
            EntityType.ATTACK_TECHNIQUE,
            EntityType.VULNERABILITY,
        ],
    )
    @pytest.mark.asyncio
    async def test_unsupported_entity_types_skip_lookup(
        self, entity_type: EntityType
    ) -> None:
        """Unsupported entity types yield one typed error and zero lookups."""
        database = _FakeDatabase()
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity("example.com", entity_type=entity_type)
        )
        assert result.evidence == ()
        assert len(result.errors) == 1
        error = result.errors[0]
        assert error.code is ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert error.retryable is False
        assert not database.lookups

    @pytest.mark.asyncio
    async def test_invalid_ip_skips_lookup(self) -> None:
        """An invalid IP value is rejected before any lookup."""
        database = _FakeDatabase()
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity("999.999.999.999")
        )
        assert result.evidence == ()
        assert result.errors[0].code is ProviderErrorCode.UNSUPPORTED_INDICATOR
        assert not database.lookups

    @pytest.mark.asyncio
    async def test_lookup_miss_is_valid_empty_result(self) -> None:
        """A miss yields no evidence and no error; it is not benign."""
        database = _FakeDatabase()
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity(MISS_IPV4)
        )
        assert result.provider == _PROVIDER_ID
        assert result.evidence == ()
        assert result.errors == ()
        assert database.lookups == [MISS_IPV4]

    @pytest.mark.asyncio
    async def test_private_address_deterministically_misses(self) -> None:
        """A private/reserved address misses: City Lite never contains one."""
        database = _FakeDatabase()
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity("10.0.0.1")
        )
        assert result.evidence == ()
        assert result.errors == ()

    @pytest.mark.asyncio
    async def test_successful_hit_emits_one_geolocation_evidence(self) -> None:
        """A usable hit emits exactly one immutable GEOLOCATION observation."""
        database = _FakeDatabase({_CITY_KEY: _city_record()})
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity("192.0.2.10")
        )
        assert result.errors == ()
        assert len(result.evidence) == 1
        evidence = result.evidence[0]
        assert evidence.type is EvidenceType.GEOLOCATION
        assert evidence.source == _PROVIDER_ID
        assert evidence.subject.type is EntityType.IP_ADDRESS
        assert evidence.subject.value == "192.0.2.10"
        assert evidence.observed_at is None
        assert evidence.retrieved_at == _FIXED_TS
        assert evidence.raw_payload is None
        assert evidence.facts == {
            "country_code": "US",
            "region": "California",
            "city": "Example City",
            "latitude": 37.5,
            "longitude": -122.25,
            "provider": _PROVIDER_ID,
            "precision": "city",
        }

    @pytest.mark.asyncio
    async def test_entity_id_carried_into_subject(self) -> None:
        """The queried entity identity is carried into the evidence subject."""
        entity = _ip_entity("192.0.2.10")
        database = _FakeDatabase({"192.0.2.10": _city_record()})
        result = await _provider(database).investigate(_FIXED_UUID, entity)
        assert result.evidence[0].subject.id == entity.id

    @pytest.mark.asyncio
    async def test_malformed_record_is_invalid_response(self) -> None:
        """A malformed matched record yields a non-retryable typed error."""
        database = _FakeDatabase({"192.0.2.10": {"country": {"iso_code": "USA"}}})
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity("192.0.2.10")
        )
        assert result.evidence == ()
        assert len(result.errors) == 1
        error = result.errors[0]
        assert error.code is ProviderErrorCode.INVALID_RESPONSE
        assert error.retryable is False

    @pytest.mark.asyncio
    async def test_partial_coordinate_pair_is_invalid_response(self) -> None:
        """A partial coordinate pair is INVALID_RESPONSE, not partial data."""
        database = _FakeDatabase({"192.0.2.10": {"location": {"latitude": 10.0}}})
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity("192.0.2.10")
        )
        assert result.evidence == ()
        assert result.errors[0].code is ProviderErrorCode.INVALID_RESPONSE

    @pytest.mark.asyncio
    async def test_no_usable_record_is_documented_miss(self) -> None:
        """A record without usable data behaves exactly like a miss."""
        database = _FakeDatabase({"192.0.2.10": {}})
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity("192.0.2.10")
        )
        assert result.evidence == ()
        assert result.errors == ()

    @pytest.mark.asyncio
    async def test_reader_failure_is_provider_unavailable(self) -> None:
        """A reader failure maps to retryable PROVIDER_UNAVAILABLE."""
        database = _FakeDatabase(fail=True)
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity("192.0.2.10")
        )
        assert result.evidence == ()
        assert result.errors[0].code is ProviderErrorCode.PROVIDER_UNAVAILABLE
        assert result.errors[0].retryable is True

    @pytest.mark.asyncio
    async def test_malformed_top_level_from_lookup_is_invalid_response(self) -> None:
        """A record error raised during lookup is INVALID_RESPONSE, not unavailable."""
        database = _FakeDatabase(
            lookup_error=CityLiteRecordError(
                "City Lite MMDB record is not a JSON object"
            )
        )
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity("192.0.2.10")
        )
        assert result.evidence == ()
        assert len(result.errors) == 1
        error = result.errors[0]
        assert error.code is ProviderErrorCode.INVALID_RESPONSE
        assert error.retryable is False

    @pytest.mark.asyncio
    async def test_non_mapping_record_is_invalid_response(self) -> None:
        """A matched scalar/list record never becomes evidence or unavailability."""
        database = _FakeDatabase({"192.0.2.10": ["not", "a", "record"]})
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity("192.0.2.10")
        )
        assert result.evidence == ()
        assert result.errors[0].code is ProviderErrorCode.INVALID_RESPONSE
        assert result.errors[0].retryable is False

    @pytest.mark.asyncio
    async def test_canonicalization_before_lookup(self) -> None:
        """The canonical IP form is used for the lookup and subject value."""
        database = _FakeDatabase(
            {"2001:db8::1": _city_record(city={"names": {"en": "Example V6 City"}})}
        )
        result = await _provider(database).investigate(
            _FIXED_UUID, _ip_entity("2001:0DB8:0000:0000:0000:0000:0000:0001")
        )
        assert database.lookups == ["2001:db8::1"]
        assert result.evidence[0].subject.value == "2001:db8::1"
