# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic canonical claim -> canonical Location resolution (PR 26B).

PR 26B introduces the deterministic application-level primitive
:class:`CanonicalGeographyResolver` (the name is deliberately distinct from
PR 26C's asynchronous ``LocationResolver``). It owns canonical matching only:
no GeoResolution lifecycle, no Entity/Evidence mutation, no nearest-city or
fuzzy geocoding. Normal outcomes are :class:`CanonicalLocationResolution`
results (resolved/ambiguous/unresolvable); malformed claims raise
:class:`InvalidGeographicClaimError` (exposed by the claim validator).

Resolution precedence (documented contract):

1. validate the claim;
2. restrict by ``country_code`` when supplied;
3. resolve the explicit administrative code when supplied;
4. resolve the normalized administrative name only inside the country;
5. resolve the normalized city name only inside the already-resolved
   country/admin context;
6. use coordinates only as a deterministic disambiguation signal among
   equally-valued candidates (boundary-inclusive ``ST_Covers`` against the
   candidate's own polygon for admins and the candidate's admin-parent
   polygon for cities), never to invent precision or select outside the
   semantic narrowing;
7. return ambiguity rather than guessing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from uuid import UUID

from pydantic import ValidationError

from agentic_threat_investigator.app.persistence.repositories import (
    InvalidGeographicClaimError,
)
from agentic_threat_investigator.domain.geoint import (
    AMBIGUOUS_REASON_CODES,
    RESOLVED_REASON_CODES,
    UNRESOLVABLE_REASON_CODES,
    CanonicalLocationResolution,
    CanonicalLocationResolutionStatus,
    GeographicClaim,
    Location,
    LocationCandidate,
)

# Equally-valued candidate cap so every resolution path stays bounded; a
# corpus with more matches than this is definitionally ambiguous.
CANDIDATE_LIMIT = 100


def ensure_valid_claim(claim: GeographicClaim) -> None:
    """Re-validate a claim fail-closed before deterministic resolution.

    Construction already enforces the claim contract; this defensive pass
    also rejects ``model_construct``-built instances so malformed input is
    never silently resolved. Raises
    :class:`InvalidGeographicClaimError` with the pydantic detail.
    """
    try:
        GeographicClaim.model_validate(claim.model_dump())
    except ValidationError as error:
        raise InvalidGeographicClaimError(str(error)) from error


def resolved_result(
    location: Location, *, reason_code: str, matched_fields: tuple[str, ...]
) -> CanonicalLocationResolution:
    """Build and validate a RESOLVED resolution for one exact location."""
    if reason_code not in RESOLVED_REASON_CODES:
        raise ValueError(f"unknown resolved reason code: {reason_code}")
    return CanonicalLocationResolution(
        status=CanonicalLocationResolutionStatus.RESOLVED,
        location=location,
        candidates=(
            LocationCandidate(location=location, matched_fields=matched_fields),
        ),
        reason_code=reason_code,
    )


def ambiguous_result(
    candidates: Sequence[LocationCandidate], *, reason_code: str
) -> CanonicalLocationResolution:
    """Build and validate an AMBIGUOUS resolution over equally-valued candidates.

    Candidates must already be in deterministic canonical order
    ``(country_code, admin1_code, admin2_code, canonical_name, id)``.
    """
    if reason_code not in AMBIGUOUS_REASON_CODES:
        raise ValueError(f"unknown ambiguous reason code: {reason_code}")
    return CanonicalLocationResolution(
        status=CanonicalLocationResolutionStatus.AMBIGUOUS,
        candidates=tuple(candidates),
        reason_code=reason_code,
    )


def unresolvable_result(reason_code: str) -> CanonicalLocationResolution:
    """Build and validate an UNRESOLVABLE resolution with a typed reason."""
    if reason_code not in UNRESOLVABLE_REASON_CODES:
        raise ValueError(f"unknown unresolvable reason code: {reason_code}")
    return CanonicalLocationResolution(
        status=CanonicalLocationResolutionStatus.UNRESOLVABLE,
        reason_code=reason_code,
    )


def matched_fields_for_claim(claim: GeographicClaim) -> tuple[str, ...]:
    """Return the semantic claim fields that participated in narrowing."""
    fields: list[str] = []
    if claim.country_code is not None:
        fields.append("country_code")
    if claim.administrative_area is not None:
        fields.append("administrative_area_name")
    elif claim.administrative_area_code is not None:
        fields.append("administrative_area_code")
    if claim.city is not None:
        fields.append("city_name")
    return tuple(fields)


def candidate_sort_key(location: Location) -> tuple[str, str, str, str, UUID]:
    """Return the deterministic canonical candidate ordering key.

    Ordering is ``(country_code, admin1_code, admin2_code, canonical_name,
    id)`` with null admin codes normalized to the empty string, matching the
    canonical identity normalization.
    """
    return (
        location.country_code,
        location.admin1_code or "",
        location.admin2_code or "",
        location.canonical_name,
        location.id or UUID(int=0),
    )


class CanonicalGeographyResolver(ABC):
    """Deterministic application-level claim -> canonical Location resolver.

    The concrete PostgreSQL implementation (PR 26B) uses purpose-built
    bounded read SQL/PostGIS directly; this is a read/canonicalization
    service, not ad-hoc domain mutation. PR 26C's asynchronous
    ``LocationResolver`` composes this primitive instead of duplicating
    canonical matching.
    """

    @abstractmethod
    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Resolve a bounded geographic claim deterministically.

        Raised :class:`InvalidGeographicClaimError` on malformed input;
        every valid claim yields a resolved/ambiguous/unresolvable result.
        This method never mutates Entities, Relationships, Evidence,
        GeoResolution, or any persisted state.
        """
