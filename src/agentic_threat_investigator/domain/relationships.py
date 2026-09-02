# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Durable relationships and their historical observations.

A :class:`Relationship` is the durable semantic edge between two canonical
entities. Repeated source observations of the same assertion create new
:class:`RelationshipObservation` rows rather than mutating the relationship.
Historical relationships are not deleted merely because a later lookup no
longer observes them; currentness is a query/view concept based on
observations.
"""

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel


class RelationshipType(str, Enum):
    """Stable ATI relationship type URNs."""

    RESOLVES_TO = "urn:ati:relationship:dns:resolves_to"
    CNAME_OF = "urn:ati:relationship:dns:cname_of"
    USES_NAME_SERVER = "urn:ati:relationship:dns:uses_name_server"
    USES_MAIL_SERVER = "urn:ati:relationship:dns:uses_mail_server"
    BELONGS_TO = "urn:ati:relationship:network:belongs_to"
    ANNOUNCED_BY = "urn:ati:relationship:routing:announced_by"
    REGISTERED_TO = "urn:ati:relationship:registration:registered_to"
    OPERATED_BY = "urn:ati:relationship:organization:operated_by"
    ASSOCIATED_WITH = "urn:ati:relationship:threat:associated_with"
    USES_TECHNIQUE = "urn:ati:relationship:attack:uses_technique"
    EXPLOITS = "urn:ati:relationship:vulnerability:exploits"


class Relationship(BaseModel):
    """The durable semantic edge between a source and a target entity.

    Relationship identity is unique by source entity, relationship type URN,
    and target entity.
    """

    id: UUID
    source_entity_id: UUID
    target_entity_id: UUID
    type: RelationshipType


class RelationshipObservation(BaseModel):
    """A historical, append-oriented record of when/why a relationship was observed."""

    id: UUID
    relationship_id: UUID
    evidence_id: UUID
    investigation_id: UUID | None = None
    observed_at: datetime | None = None
    retrieved_at: datetime
    source: str
    confidence: float | None = None
