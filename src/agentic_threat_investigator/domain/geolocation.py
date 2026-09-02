# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Approximate geolocation context.

Geolocation is approximate contextual information. It does not identify the
physical location of an attacker or device, and it is never maliciousness
evidence.
"""

from enum import Enum

from pydantic import BaseModel


class GeoPrecision(str, Enum):
    """How precisely a geolocation result locates its subject."""

    COUNTRY = "country"
    REGION = "region"
    CITY = "city"
    UNKNOWN = "unknown"


class GeoLocation(BaseModel):
    """Approximate geographic context for an entity from one provider."""

    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    provider: str
    precision: GeoPrecision
