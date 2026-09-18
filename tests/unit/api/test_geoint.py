# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26D API contract tests for the GEOINT read routes (G26D-A01..A15).

Pure HTTP contracts with injected application fakes: authentication and
authorization behave like every analytical read, every endpoint is
Investigation-scoped and 404s cross-scope detail lookups without disclosing
existence elsewhere, location collections transport the containment flag
exactly, and no GEOINT route mutates state or needs CSRF. The v0.1
UserRole vocabulary has exactly ANALYST and ADMIN, so the 403 branch is
covered at the shared ``require_analyst`` dependency (as for every other
analytical route).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from agentic_threat_investigator.app.query.geoint import (
    GeointEntityLocationItem,
    GeointLocationPage,
    GeointLocationRef,
    GeointObservationDetail,
    GeointObservationItem,
    GeointPrecisionCounts,
    GeointSummary,
    GeointTopLocation,
)
from agentic_threat_investigator.app.query.models import QueryPage
from agentic_threat_investigator.app.query.pagination import InvalidCursorError
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.geoint import (
    LocationPrecision,
    LocationType,
)

from .conftest import (
    FakeGeointService,
    FakeQueryBundle,
    build_test_app,
    login_client,
)

FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
INVESTIGATION = UUID("11111111-1111-1111-1111-111111111111")
ENTITY = UUID("22222222-2222-2222-2222-222222222222")
LOCATION = UUID("33333333-3333-3333-3333-333333333333")
OBSERVATION = UUID("44444444-4444-4444-4444-444444444444")
EVIDENCE = UUID("55555555-5555-5555-5555-555555555555")


def location_ref() -> GeointLocationRef:
    """Build one deterministic Location reference fixture."""
    return GeointLocationRef(
        location_id=LOCATION,
        location_type=LocationType.COUNTRY,
        canonical_name="United States",
        country_code="US",
        latitude=39.8283,
        longitude=-98.5795,
    )


def observation_item() -> GeointObservationItem:
    """Build one deterministic observation read item fixture."""
    return GeointObservationItem(
        observation_id=OBSERVATION,
        entity_id=ENTITY,
        location=location_ref(),
        evidence_observation_id=EVIDENCE,
        precision=LocationPrecision.CITY,
        resolution_method="canonical_geography_v1",
        observed_at=None,
        retrieved_at=FIXED,
        resolved_at=FIXED,
    )


def entity_item() -> GeointEntityLocationItem:
    """Build one deterministic Investigation-relative Entity item fixture."""
    return GeointEntityLocationItem(
        entity_id=ENTITY,
        entity_type=EntityType.IP_ADDRESS,
        entity_value="203.0.113.10",
        display_name=None,
        current_observation=observation_item(),
    )


def observation_detail() -> GeointObservationDetail:
    """Build one deterministic observation detail fixture."""
    return GeointObservationDetail(
        observation=observation_item(),
        entity_type=EntityType.IP_ADDRESS,
        entity_value="203.0.113.10",
        display_name=None,
    )


def summary_result() -> GeointSummary:
    """Build one deterministic bounded summary fixture."""
    return GeointSummary(
        entity_count_with_location=2,
        observation_count=3,
        location_count=2,
        country_count=1,
        administrative_area_count=1,
        city_count=0,
        precision_counts=GeointPrecisionCounts(
            country=1, administrative_area=1, city=1
        ),
        top_locations=(
            GeointTopLocation(location=location_ref(), scoped_entity_count=2),
        ),
        truncated=False,
    )


def _geoint_url(path: str) -> str:
    """Build the /api/v1 GEOINT URL for one path fragment."""
    return f"/api/v1/investigations/{INVESTIGATION}/geoint/{path}"


# ---------------------------------------------------------------------------
# Authentication / authorization (G26D-A01..A02)
# ---------------------------------------------------------------------------


def test_a01_unauthenticated_returns_401() -> None:
    """G26D-A01 unauthenticated GEOINT reads return 401."""
    with build_test_app() as client:
        response = client.get(_geoint_url("summary"))

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"


def test_a02_non_analyst_role_is_forbidden() -> None:
    """G26D-A02 an actor without ANALYST/ADMIN is rejected by the shared gate.

    The v0.1 ``UserRole`` vocabulary has exactly ANALYST and ADMIN, so the
    forbidden branch is proven at the shared ``require_analyst`` dependency
    with an unsupported actor stub, exactly like the other analytical reads.
    """
    from typing import Any, cast

    import pytest

    from agentic_threat_investigator.api.dependencies import require_analyst
    from agentic_threat_investigator.api.errors import ApiError
    from agentic_threat_investigator.domain.identity import User

    class UnsupportedActor:
        """Actor stub carrying an unsupported role value."""

        role = "observer"

    with pytest.raises(ApiError) as error:
        require_analyst(cast(User, cast(Any, UnsupportedActor())))

    assert error.value.status_code == 403
    assert error.value.code == "forbidden"


# ---------------------------------------------------------------------------
# Detail endpoints (G26D-A04, A05, A10, A11)
# ---------------------------------------------------------------------------


def test_a04_entity_detail_typed_200() -> None:
    """G26D-A04 the entity detail returns a typed 200 with exact provenance."""

    bundle = FakeQueryBundle()
    bundle.geoint.entity_results[(INVESTIGATION, ENTITY)] = entity_item()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_geoint_url(f"entities/{ENTITY}"))

    assert response.status_code == 200
    body = response.json()
    assert body["entity_id"] == str(ENTITY)
    assert body["entity_type"] == "ip_address"
    assert body["entity_value"] == "203.0.113.10"
    current = body["current_observation"]
    assert current["observation_id"] == str(OBSERVATION)
    assert current["evidence_id"] == str(EVIDENCE)
    assert current["location"]["location_id"] == str(LOCATION)
    assert current["location"]["latitude"] == 39.8283
    assert current["location"]["longitude"] == -98.5795
    for forbidden in ("facts", "raw_payload", "geometry", "boundary"):
        assert forbidden not in response.text


def test_a05_entity_absent_in_scope_404() -> None:
    """G26D-A05 an Entity with no scoped data maps to 404, never a leak."""
    bundle = FakeQueryBundle()
    bundle.geoint.entity_results[(INVESTIGATION, ENTITY)] = None
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_geoint_url(f"entities/{ENTITY}"))

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "geoint_entity_not_found"


def test_a10_observation_detail_exact_evidence_id() -> None:
    """G26D-A10 the observation detail returns the exact evidence_id."""
    bundle = FakeQueryBundle()
    bundle.geoint.observation_results[(INVESTIGATION, OBSERVATION)] = (
        observation_detail()
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_geoint_url(f"observations/{OBSERVATION}"))

    assert response.status_code == 200
    body = response.json()
    observation = body["observation"]
    assert observation["observation_id"] == str(OBSERVATION)
    assert observation["evidence_id"] == str(EVIDENCE)
    assert body["entity_type"] == "ip_address"
    assert body["entity_value"] == "203.0.113.10"
    assert observation["location"]["canonical_name"] == "United States"


def test_a11_cross_scope_observation_404() -> None:
    """G26D-A11 a cross-Investigation observation maps to 404."""
    bundle = FakeQueryBundle()
    bundle.geoint.observation_results[(INVESTIGATION, OBSERVATION)] = None
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_geoint_url(f"observations/{OBSERVATION}"))

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "geoint_observation_not_found"


# ---------------------------------------------------------------------------
# Collections (G26D-A03, A06, A07, A08, A09)
# ---------------------------------------------------------------------------


def test_a03_summary_typed_200() -> None:
    """G26D-A03 the summary returns a typed bounded 200."""
    bundle = FakeQueryBundle(geoint=FakeGeointService())
    bundle.geoint.summary_result = summary_result()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_geoint_url("summary"))

    assert response.status_code == 200
    body = response.json()
    assert body["observation_count"] == 3
    assert body["truncated"] is False
    (top,) = body["top_locations"]
    assert top["scoped_entity_count"] == 2
    assert top["location"]["location_id"] == str(LOCATION)
    assert body["precision_counts"] == {
        "country": 1,
        "administrative_area": 1,
        "city": 1,
    }
    for forbidden in ("risk", "concentration", "geometry"):
        assert forbidden not in response.text.lower() or "geometry" not in response.text


def test_a06_entity_history_is_page_response() -> None:
    """G26D-A06 the entity history returns a PageResponse-shaped 200."""
    bundle = FakeQueryBundle()
    bundle.geoint.page = QueryPage(
        items=(observation_item(),), next_cursor="continuation"
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_geoint_url(f"entities/{ENTITY}/observations"))

    assert response.status_code == 200
    body = response.json()
    assert list(body) == ["items", "next_cursor"]
    assert body["next_cursor"] == "continuation"
    (item,) = body["items"]
    assert item["evidence_id"] == str(EVIDENCE)


def test_a07_location_entities_typed_page() -> None:
    """G26D-A07 the Location-Entity collection returns a typed page."""
    bundle = FakeQueryBundle()
    bundle.geoint.location_page = GeointLocationPage(
        items=(entity_item(),), next_cursor=None, containment_applied=False
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            _geoint_url(f"locations/{LOCATION}/entities"), params={"limit": 10}
        )

    assert response.status_code == 200
    body = response.json()
    assert list(body) == ["items", "next_cursor", "containment_applied"]
    assert body["containment_applied"] is False
    (item,) = body["items"]
    assert item["entity_id"] == str(ENTITY)
    query = bundle.geoint.location_entity_lists[-1]
    assert query.include_contained is False
    assert query.limit == 10


def test_a08_containment_flag_mapped_exactly() -> None:
    """G26D-A08 the containment flag is carried through the Location-Entity page."""
    bundle = FakeQueryBundle()
    bundle.geoint.location_page = GeointLocationPage(
        items=(), next_cursor=None, containment_applied=True
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            _geoint_url(f"locations/{LOCATION}/entities"),
            params={"include_contained": "true"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["containment_applied"] is True
    query = bundle.geoint.location_entity_lists[-1]
    assert query.include_contained is True


def test_a09_location_observations_typed_page() -> None:
    """G26D-A09 the Location-observation collection returns a typed page."""
    bundle = FakeQueryBundle()
    bundle.geoint.location_page = GeointLocationPage(
        items=(observation_item(),), next_cursor="next", containment_applied=False
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_geoint_url(f"locations/{LOCATION}/observations"))

    assert response.status_code == 200
    body = response.json()
    assert list(body) == ["items", "next_cursor", "containment_applied"]
    assert body["next_cursor"] == "next"
    (item,) = body["items"]
    assert item["observation_id"] == str(OBSERVATION)
    assert item["location"]["location_id"] == str(LOCATION)


# ---------------------------------------------------------------------------
# Cursor / bound failures (G26D-A12..A14)
# ---------------------------------------------------------------------------


def test_a12_invalid_cursor_stable_error() -> None:
    """G26D-A12 a malformed cursor maps to the stable invalid_cursor error."""
    bundle = FakeQueryBundle()
    bundle.geoint.errors = [InvalidCursorError("cursor is not valid base64")]
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            _geoint_url(f"entities/{ENTITY}/observations"), params={"cursor": "!!!"}
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_cursor"


def test_a13_oversized_cursor_bounded_validation() -> None:
    """G26D-A13 an oversized cursor is rejected by bounded parameter validation."""
    with build_test_app() as client:
        login_client(client)
        response = client.get(
            _geoint_url(f"entities/{ENTITY}/observations"),
            params={"cursor": "x" * 4096},
        )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_a14_oversized_limit_forwarded_to_existing_bound() -> None:
    """G26D-A14 an oversized limit is forwarded to the shared query bound.

    The ceiling itself is validated by the PR 23A query services through
    :class:`QueryLimits` (proven at the service level and on the real
    stack); the route forwards the caller-supplied value unchanged exactly
    like every other PR 23A collection route.
    """
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            _geoint_url(f"locations/{LOCATION}/observations"), params={"limit": 9999}
        )

    assert response.status_code == 200
    query = bundle.geoint.location_observation_lists[-1]
    assert query.limit == 9999


# ---------------------------------------------------------------------------
# PR 25 compatibility (G26D-A15)
# ---------------------------------------------------------------------------


def test_a16_malformed_persisted_read_is_safe_500() -> None:
    """Malformed persisted GEOINT state surfaces a safe 500 contract error."""
    from agentic_threat_investigator.app.query.geoint import GeointReadError

    bundle = FakeQueryBundle()
    bundle.geoint.errors.append(
        GeointReadError("persisted geoint precision is outside the vocabulary")
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_geoint_url("summary"))

    assert response.status_code == 500
    body = response.json()["error"]
    assert body["code"] == "internal_error"
    assert "precision" not in response.text
    assert "vocabulary" not in response.text


def test_a15_pr25_geolocations_unchanged() -> None:
    """G26D-A15 the PR 25 geolocation projection still serves unchanged."""
    bundle = FakeQueryBundle()
    from agentic_threat_investigator.app.query.geolocation import (
        InvestigationGeolocationItem,
        InvestigationGeolocationResult,
    )
    from agentic_threat_investigator.domain.geolocation import GeoPrecision

    bundle.geolocations.result = InvestigationGeolocationResult(
        items=(
            InvestigationGeolocationItem(
                evidence_observation_id=EVIDENCE,
                entity_id=ENTITY,
                ip_address="203.0.113.10",
                country_code="US",
                region="Washington",
                city="Seattle",
                latitude=47.6062,
                longitude=-122.3321,
                precision=GeoPrecision.CITY,
                provider="urn:ati:source:dbip_city_lite",
                observed_at=None,
                retrieved_at=FIXED,
            ),
        ),
        truncated=False,
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(f"/api/v1/investigations/{INVESTIGATION}/geolocations")

    assert response.status_code == 200
    assert list(response.json()) == ["items", "truncated"]
    (item,) = response.json()["items"]
    assert item["ip_address"] == "203.0.113.10"
    assert "containment_applied" not in response.json()
