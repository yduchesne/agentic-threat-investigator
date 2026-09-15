# SPDX-License-Identifier: AGPL-3.0-only
"""PR 25A API contract tests for the geolocation projection (G-A01..G-A10).

Pure HTTP contracts with injected application fakes: authentication and
authorization behave like every analytical read, the response DTO is an
explicit allowlist (no facts/raw payload/artifact paths), the empty and
truncated projections transport exactly, and malformed persisted data maps
to a safe 500 without leaking internals. A lower-privilege authenticated
role does not exist in the v0.1 UserRole vocabulary, so the 403 branch is
covered at the shared ``require_analyst`` dependency rather than here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from agentic_threat_investigator.api.app import create_app
from agentic_threat_investigator.app.query.geolocation import (
    GeolocationFactsError,
    InvestigationGeolocationItem,
    InvestigationGeolocationResult,
)
from agentic_threat_investigator.config import Settings
from agentic_threat_investigator.domain.geolocation import GeoPrecision
from agentic_threat_investigator.domain.identity import UserRole

from .conftest import (
    FakeAuthenticationService,
    FakeQueryBundle,
    build_test_app,
    login_client,
    make_user,
)

FIXED = datetime(2026, 1, 1, tzinfo=UTC)
INVESTIGATION = UUID("11111111-1111-1111-1111-111111111111")
PROVIDER = "urn:ati:source:dbip_city_lite"


def _city_item(*, city: str = "Seattle") -> InvestigationGeolocationItem:
    """Build one fully mappable projection item fixture."""
    return InvestigationGeolocationItem(
        evidence_id=uuid4(),
        entity_id=uuid4(),
        ip_address="203.0.113.10",
        country_code="US",
        region="Washington",
        city=city,
        latitude=47.6062,
        longitude=-122.3321,
        precision=GeoPrecision.CITY,
        provider=PROVIDER,
        observed_at=None,
        retrieved_at=FIXED,
    )


def test_ga01_authentication_required() -> None:
    """Unauthenticated access returns 401 authentication_required."""
    with build_test_app() as client:
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/geolocations")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"


def test_ga02_analyst_allowed() -> None:
    """An ANALYST reads the projection with 200."""
    bundle = FakeQueryBundle()
    marker = _city_item()
    bundle.geolocations.result = InvestigationGeolocationResult(
        items=(marker,), truncated=False
    )
    auth = FakeAuthenticationService(user=make_user(role=UserRole.ANALYST))
    with build_test_app(bundle=bundle, authentication=auth) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/geolocations")

    assert response.status_code == 200
    assert bundle.geolocations.investigation_ids == [INVESTIGATION]


def test_ga03_admin_allowed() -> None:
    """An ADMIN reads the projection with 200."""
    bundle = FakeQueryBundle()
    auth = FakeAuthenticationService(user=make_user(role=UserRole.ADMIN))
    with build_test_app(bundle=bundle, authentication=auth) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/geolocations")

    assert response.status_code == 200
    assert response.json() == {"items": [], "truncated": False}


def test_ga05_exact_response_dto() -> None:
    """The response carries exactly the allowlisted typed fields."""
    bundle = FakeQueryBundle()
    marker = _city_item()
    bundle.geolocations.result = InvestigationGeolocationResult(
        items=(marker,), truncated=False
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/geolocations")

    assert response.status_code == 200
    body = response.json()
    assert list(body) == ["items", "truncated"]
    assert body["truncated"] is False
    (item,) = body["items"]
    assert set(item) == {
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
    assert item["evidence_id"] == str(marker.evidence_id)
    assert item["entity_id"] == str(marker.entity_id)
    assert item["ip_address"] == "203.0.113.10"
    assert item["country_code"] == "US"
    assert item["region"] == "Washington"
    assert item["city"] == "Seattle"
    assert item["latitude"] == 47.6062
    assert item["longitude"] == -122.3321
    assert item["precision"] == "city"
    assert item["provider"] == PROVIDER
    assert item["observed_at"] is None
    assert item["retrieved_at"] == "2026-01-01T00:00:00Z"


def test_ga06_raw_facts_not_exposed() -> None:
    """No facts, raw payloads, record ids, or artifact paths are exposed."""
    bundle = FakeQueryBundle()
    bundle.geolocations.result = InvestigationGeolocationResult(
        items=(_city_item(),), truncated=False
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/geolocations")

    assert response.status_code == 200
    text = response.text
    for forbidden in (
        "facts",
        "raw_payload",
        "source_record_id",
        "mmdb",
        "artifact",
        "datasets",
        "/var/lib/ati",
    ):
        assert forbidden not in text


def test_ga07_empty_collection() -> None:
    """An existing Investigation without location data yields an empty 200."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/geolocations")

    assert response.status_code == 200
    assert response.json() == {"items": [], "truncated": False}


def test_ga08_truncation_transport() -> None:
    """truncated=true transports the server-owned bound exactly."""
    bundle = FakeQueryBundle()
    bundle.geolocations.result = InvestigationGeolocationResult(
        items=(_city_item(), _city_item(city="Renton")), truncated=True
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/geolocations")

    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 2
    assert body["truncated"] is True


def test_ga09_malformed_persisted_projection_is_safe_500() -> None:
    """Malformed persisted data surfaces a safe 500 internal contract error."""
    bundle = FakeQueryBundle()
    bundle.geolocations.errors.append(
        GeolocationFactsError("persisted geolocation facts are malformed")
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/geolocations")

    assert response.status_code == 500
    body = response.json()["error"]
    assert body["code"] == "internal_error"
    assert "malformed" not in response.text
    assert "Seattle" not in response.text


def test_ga10_openapi_operation_declared() -> None:
    """OpenAPI declares the geolocation GET with cookie security."""
    schema = create_app(Settings(public_base_url="http://testserver")).openapi()
    operation = schema["paths"][
        "/api/v1/investigations/{investigation_id}/geolocations"
    ]["get"]
    assert operation["operationId"] == "list_investigation_geolocations"
    assert operation["security"] == [{"cookieSession": []}]
    assert operation["tags"] == ["geolocation"]
    response_schema = operation["responses"]["200"]["content"]["application/json"][
        "schema"
    ]
    assert response_schema["$ref"].endswith(
        "/InvestigationGeolocationCollectionResponse"
    )
    schemas = schema["components"]["schemas"]
    collection = schemas["InvestigationGeolocationCollectionResponse"]
    assert list(collection["properties"]) == ["items", "truncated"]
    item_schema = schemas["InvestigationGeolocationResponse"]
    assert "raw_payload" not in item_schema["properties"]
    assert "facts" not in item_schema["properties"]
