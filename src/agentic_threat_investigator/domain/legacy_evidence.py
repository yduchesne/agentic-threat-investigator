# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Transitional v0.1 runtime Evidence shape (PR 28A compatibility seam).

PR 28A replaced the v0.1 Investigation-owned single-subject ``Evidence``
contract with the stable global ``Evidence`` in
``agentic_threat_investigator.domain.evidence``. The v0.1 runtime still needs
the old shape until PR 28B migrates persistence: the PostgreSQL evidence
tables, the Investigation executor/extraction pipeline, GEOINT/API/report/RAG
consumers, and the legacy provider suites all construct and read the old
Investigation/subject-bound observation.

:class:`LegacyEvidence` is therefore the **explicit, transitional** v0.1
runtime observation shape. It is deprecated by contract: it exists only to
keep the current build and tests coherent while PR 28B owns the persistence
and query cutover, and must be removed together with the v0.1 persistence
boundary. No new code outside that boundary should construct it, and it must
never regain a first-class domain role. :class:`EntityRef` is the v0.1
privileged-subject reference that accompanies it; PR 28A removes the
concept of a privileged Evidence subject from the domain.

Do not add fields to these models; the shape is fixed by the v0.1 database
schema and runtime contracts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.immutable_json import FrozenDict, freeze_mapping


class EntityRef(BaseModel):
    """A lightweight immutable reference to an entity by identity or raw value.

    Transitional v0.1 helper: the v0.1 runtime uses it as the single subject
    binding of a :class:`LegacyEvidence`. The v0.2 domain has no privileged
    Evidence subject; this class is retained only for the v0.1 runtime
    boundary and is removed with it.
    """

    model_config = ConfigDict(frozen=True)

    id: UUID | None = None
    type: EntityType
    value: str


class LegacyEvidence(BaseModel):
    """Transitional v0.1 Investigation-bound, single-subject evidence observation.

    Deprecated by contract (PR 28A): the stable global domain model is
    :class:`Evidence`. This shape is retained unchanged only until PR 28B
    migrates the v0.1 persistence/query boundary that constructs and reads
    it. ``observed_at`` is the time represented by the source when known;
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

    @field_validator("observed_at", "retrieved_at")
    @classmethod
    def validate_utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware timestamps, normalized to UTC."""
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evidence timestamps must be timezone-aware")
        return value.astimezone(UTC)

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
