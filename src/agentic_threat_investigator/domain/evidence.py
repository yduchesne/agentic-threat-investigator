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

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.immutable_json import FrozenDict, freeze_mapping


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
    """A lightweight immutable reference to an entity by identity or raw value."""

    model_config = ConfigDict(frozen=True)

    id: UUID | None = None
    type: EntityType
    value: str


class Evidence(BaseModel):
    """An immutable observation from a source about one primary subject.

    ``observed_at`` is the time represented by the source when known;
    ``retrieved_at`` is when ATI retrieved the information.
    """

    model_config = ConfigDict(frozen=True)

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

    @field_validator("facts", mode="after")
    @classmethod
    def freeze_facts(cls, value: dict[str, Any]) -> FrozenDict:
        """Store normalized facts as a deeply immutable JSON object."""
        return freeze_mapping(value)

    @field_validator("raw_payload", mode="after")
    @classmethod
    def freeze_raw_payload(cls, value: dict[str, Any] | None) -> FrozenDict | None:
        """Store raw source data as a deeply immutable JSON object."""
        return None if value is None else freeze_mapping(value)
