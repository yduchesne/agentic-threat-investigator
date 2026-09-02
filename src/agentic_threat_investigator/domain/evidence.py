# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable evidence observations.

Evidence is an immutable observation from a source about one primary subject.
A new provider retrieval creates a new observation rather than overwriting a
prior one. Provider-specific scores remain normalized facts; analytical
confidence belongs to the Assessment.
"""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from agentic_threat_investigator.domain.entities import EntityType


class EvidenceType(str, Enum):
    """Stable ATI evidence type URNs."""

    DNS = "urn:ati:evidence:dns"
    REGISTRATION = "urn:ati:evidence:registration"
    NETWORK = "urn:ati:evidence:network"
    GEOLOCATION = "urn:ati:evidence:geolocation"
    REPUTATION = "urn:ati:evidence:reputation"
    THREAT_INTELLIGENCE = "urn:ati:evidence:threat_intelligence"
    VULNERABILITY = "urn:ati:evidence:vulnerability"
    THREAT_RESEARCH = "urn:ati:evidence:threat_research"


class EntityRef(BaseModel):
    """A lightweight reference to an entity by identity or raw value."""

    id: UUID | None = None
    type: EntityType
    value: str


class Evidence(BaseModel):
    """An immutable observation from a source about one primary subject.

    ``observed_at`` is the time represented by the source when known;
    ``retrieved_at`` is when ATI retrieved the information.
    """

    id: UUID | None = None
    investigation_id: UUID
    type: EvidenceType
    subject: EntityRef
    source: str
    source_record_id: str | None = None
    source_url: str | None = None
    observed_at: datetime | None = None
    retrieved_at: datetime
    facts: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] | None = None
