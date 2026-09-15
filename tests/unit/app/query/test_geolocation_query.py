# SPDX-License-Identifier: AGPL-3.0-only
"""PR 25A unit tests: geolocation read models and persisted-facts mapping.

Covers the typed read-contract model invariants (G-Q01..G-Q10) and the pure
mapping of persisted normalized ``GEOLOCATION`` facts (G-M01..G-M10). The
mapper never reinterprets malformed persisted data: it fails closed with
:class:`GeolocationFactsError` so the API can surface a safe internal
contract error instead of an incomplete map.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.query.geolocation import (
    GeolocationFactsError,
    InvestigationGeolocationItem,
    InvestigationGeolocationResult,
    geolocation_item_from_persisted_facts,
)
from agentic_threat_investigator.domain.geolocation import GeoPrecision

FIXED = datetime(2026, 1, 1, tzinfo=UTC)
PROVIDER = "urn:ati:source:dbip_city_lite"


def _city_facts() -> dict[str, Any]:
    """Build the canonical fully mappable persisted geolocation facts."""
    return {
        "country_code": "US",
        "region": "Washington",
        "city": "Seattle",
        "latitude": 47.6062,
        "longitude": -122.3321,
        "provider": PROVIDER,
        "precision": "city",
    }


def _item_kwargs(**overrides: Any) -> dict[str, Any]:
    """Return one valid InvestigationGeolocationItem keyword set."""
    kwargs: dict[str, Any] = {
        "evidence_id": uuid4(),
        "entity_id": uuid4(),
        "ip_address": "203.0.113.10",
        "country_code": "US",
        "region": "Washington",
        "city": "Seattle",
        "latitude": 47.6062,
        "longitude": -122.3321,
        "precision": GeoPrecision.CITY,
        "provider": PROVIDER,
        "observed_at": None,
        "retrieved_at": FIXED,
    }
    kwargs.update(overrides)
    return kwargs


def _mapped(facts: dict[str, Any] | None) -> InvestigationGeolocationItem:
    """Map one facts payload through the pure persisted-facts mapper."""
    return geolocation_item_from_persisted_facts(
        evidence_id=uuid4(),
        entity_id=uuid4(),
        ip_address="203.0.113.10",
        facts=facts,
        observed_at=None,
        retrieved_at=FIXED,
    )


# --- Read-model invariants (G-Q01..G-Q10) --------------------------------


def test_gq01_valid_fully_mappable_item() -> None:
    """A fully mappable item carries every approved typed field."""
    evidence_id, entity_id = uuid4(), uuid4()
    item = InvestigationGeolocationItem(
        **_item_kwargs(evidence_id=evidence_id, entity_id=entity_id)
    )
    assert item.evidence_id == evidence_id
    assert item.entity_id == entity_id
    assert item.ip_address == "203.0.113.10"
    assert item.country_code == "US"
    assert item.region == "Washington"
    assert item.city == "Seattle"
    assert item.latitude == 47.6062
    assert item.longitude == -122.3321
    assert item.precision is GeoPrecision.CITY
    assert item.provider == PROVIDER
    assert item.observed_at is None
    assert item.retrieved_at == FIXED


def test_gq02_coordinate_less_context_accepted() -> None:
    """Valid location context without coordinates remains valid (None pair)."""
    item = InvestigationGeolocationItem(**_item_kwargs(latitude=None, longitude=None))
    assert item.latitude is None
    assert item.longitude is None


@pytest.mark.parametrize(
    ("latitude", "longitude"),
    [(47.6, None), (None, -122.3)],
)
def test_gq03_partial_coordinate_pair_rejected(
    latitude: float | None, longitude: float | None
) -> None:
    """A partial coordinate pair fails closed at the read contract."""
    with pytest.raises(ValidationError):
        InvestigationGeolocationItem(
            **_item_kwargs(latitude=latitude, longitude=longitude)
        )


@pytest.mark.parametrize("latitude", [-90.1, 90.1, 91, -91])
def test_gq04_latitude_bounds_rejected(latitude: float) -> None:
    """Latitude outside [-90, 90] fails validation."""
    with pytest.raises(ValidationError):
        InvestigationGeolocationItem(**_item_kwargs(latitude=latitude, longitude=0.0))


@pytest.mark.parametrize("longitude", [-180.1, 180.1, 181, -181])
def test_gq05_longitude_bounds_rejected(longitude: float) -> None:
    """Longitude outside [-180, 180] fails validation."""
    with pytest.raises(ValidationError):
        InvestigationGeolocationItem(**_item_kwargs(latitude=0.0, longitude=longitude))


def test_gq06_precision_vocabulary_limited() -> None:
    """Only the existing persisted precision vocabulary is accepted."""
    for value in ("country", "region", "city", "unknown"):
        item = InvestigationGeolocationItem(
            **_item_kwargs(precision=value, latitude=None, longitude=None)
        )
        assert item.precision.value == value
    with pytest.raises(ValidationError):
        InvestigationGeolocationItem(**_item_kwargs(precision="town"))


def test_gq07_provider_required_and_non_blank() -> None:
    """A missing or blank provider fails validation."""
    with pytest.raises(ValidationError):
        InvestigationGeolocationItem(**_item_kwargs(provider=""))
    with pytest.raises(ValidationError):
        InvestigationGeolocationItem(**_item_kwargs(provider="   "))


def test_gq08_canonical_ip_subject_carried() -> None:
    """The item carries the exact canonical subject value from the Entity."""
    item = InvestigationGeolocationItem(**_item_kwargs(ip_address="2001:db8::1"))
    assert item.ip_address == "2001:db8::1"


def test_gq09_timestamps_require_timezone() -> None:
    """Naive timestamps are rejected; aware timestamps normalize to UTC."""
    naive = datetime(2026, 1, 1)
    with pytest.raises(ValidationError):
        InvestigationGeolocationItem(**_item_kwargs(retrieved_at=naive))
    aware = datetime(2026, 1, 1, tzinfo=UTC)
    item = InvestigationGeolocationItem(**_item_kwargs(retrieved_at=aware))
    assert item.retrieved_at == aware


def test_gq10_immutable_and_extra_forbidden() -> None:
    """Read models reject unknown fields and mutation."""
    item = InvestigationGeolocationItem(**_item_kwargs())
    with pytest.raises(ValidationError):
        InvestigationGeolocationItem(**_item_kwargs(surprise=True))
    with pytest.raises(ValidationError):
        item.ip_address = "203.0.113.11"
    with pytest.raises(ValidationError):
        InvestigationGeolocationResult.model_validate(
            {"items": (), "truncated": False, "extra": 1}
        )


# --- Pure persisted-facts mapping (G-M01..G-M10) --------------------------


def test_gm01_approved_facts_map_correctly() -> None:
    """Every approved normalized fact maps to its typed field."""
    item = _mapped(_city_facts())
    assert item.country_code == "US"
    assert item.region == "Washington"
    assert item.city == "Seattle"
    assert item.latitude == 47.6062
    assert item.longitude == -122.3321
    assert item.provider == PROVIDER
    assert item.precision is GeoPrecision.CITY


def test_gm02_unknown_extra_facts_ignored() -> None:
    """Unknown extra normalized facts are ignored, never leaked."""
    facts = _city_facts()
    facts["venom_score"] = 100
    facts["raw_path"] = "/var/lib/ati/datasets/dbip-city-lite/city-lite.mmdb"
    item = _mapped(facts)
    assert item.model_extra is None
    assert not any(field in item.model_dump() for field in ("venom_score", "raw_path"))


def test_gm03_missing_optional_context_accepted() -> None:
    """Missing city/region/country are accepted optional location fields."""
    item = _mapped(
        {
            "country_code": "US",
            "provider": PROVIDER,
            "precision": "country",
        }
    )
    assert item.country_code == "US"
    assert item.region is None
    assert item.city is None
    assert item.latitude is None
    assert item.longitude is None
    assert item.precision is GeoPrecision.COUNTRY


def test_gm04_missing_required_provider_rejected() -> None:
    """A provider-less persisted geolocation row fails the read closed."""
    with pytest.raises(GeolocationFactsError):
        _mapped({"precision": "city", "country_code": "US"})


def test_gm05_missing_required_precision_rejected() -> None:
    """A precision-less persisted geolocation row fails the read closed."""
    with pytest.raises(GeolocationFactsError):
        _mapped({"provider": PROVIDER, "country_code": "US"})


@pytest.mark.parametrize("value", ["47.6", "north", [], {}])
def test_gm06_non_numeric_coordinate_rejected(value: object) -> None:
    """Non-numeric coordinate facts are never coerced into coordinates."""
    facts = _city_facts()
    facts["latitude"] = value
    with pytest.raises(GeolocationFactsError):
        _mapped(facts)


@pytest.mark.parametrize("value", [True, False])
def test_gm07_boolean_coordinate_rejected(value: bool) -> None:
    """Boolean coordinate facts fail the read closed."""
    facts = _city_facts()
    facts["latitude"] = value
    with pytest.raises(GeolocationFactsError):
        _mapped(facts)


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_gm08_nan_and_infinity_rejected(value: float) -> None:
    """NaN and infinity coordinate facts fail the read closed."""
    facts = _city_facts()
    facts["longitude"] = value
    with pytest.raises(GeolocationFactsError):
        _mapped(facts)


def test_gm09_partial_coordinate_pair_rejected() -> None:
    """A persisted partial pair fails closed rather than plotting one side."""
    facts = _city_facts()
    facts["longitude"] = None
    with pytest.raises(GeolocationFactsError):
        _mapped(facts)


def test_gm10_no_provider_arbitrary_facts_escape() -> None:
    """Only the approved fields can ever appear on the read item."""
    item = _mapped(_city_facts())
    assert set(item.model_dump()) == {
        "evidence_id",
        "entity_id",
        "ip_address",
        "country_code",
        "region",
        "city",
        "latitude",
        "longitude",
        "precision",
        "provider",
        "observed_at",
        "retrieved_at",
    }


def test_gm10_invalid_precision_vocabulary_rejected() -> None:
    """A precision value outside the existing vocabulary fails closed."""
    with pytest.raises(GeolocationFactsError):
        _mapped({"provider": PROVIDER, "precision": "town"})


def test_gm10_invalid_country_code_rejected() -> None:
    """A non-two-letter country code fails closed."""
    with pytest.raises(GeolocationFactsError):
        _mapped({**_city_facts(), "country_code": "United States"})
    with pytest.raises(GeolocationFactsError):
        _mapped({**_city_facts(), "country_code": "us"})
