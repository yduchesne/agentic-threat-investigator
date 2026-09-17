# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Typed datasource vocabulary and immutable datasource definitions.

A configured datasource is described by five independent dimensions: the
datasource-instance identity, the external source/provider identity, the
acquisition protocol, the physical serialization format, and the semantic
format. No dimension is inferred from another: future semantic conversion is
selected by ``semantic_format``, never by provider, protocol, serialization,
or datasource instance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)

DATASOURCE_ID_MAX_LENGTH = 64
"""Bounded length of one canonical datasource-instance identifier."""

_DATASOURCE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
"""Canonical lowercase kebab form of a datasource-instance identifier."""


def validate_datasource_id(value: str) -> str:
    """Validate a canonical datasource-instance identifier and return it.

    Rejects blank, whitespace-only, padded, over-bound, and non-canonical
    values so a datasource ID is a stable configuration identity.
    """
    if not value.strip():
        raise ValueError("datasource_id must not be blank")
    if value != value.strip():
        raise ValueError("datasource_id must not have leading or trailing whitespace")
    if len(value) > DATASOURCE_ID_MAX_LENGTH:
        raise ValueError(
            f"datasource_id must not exceed {DATASOURCE_ID_MAX_LENGTH} characters"
        )
    if _DATASOURCE_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("datasource_id must use the canonical lowercase kebab form")
    return value


@dataclass(frozen=True)
class DatasourceId:
    """Typed identifier of one configured datasource definition.

    Identifies configuration, not provider and not execution: multiple
    datasource instances may share the same :class:`SourceId`.
    """

    value: str

    def __post_init__(self) -> None:
        """Validate the canonical identifier form."""
        validate_datasource_id(self.value)

    def __str__(self) -> str:
        """Return the canonical identifier text."""
        return self.value


class DatasourceProtocol(StrEnum):
    """Typed acquisition protocol vocabulary.

    Protocol identifies how ATI obtains the source material and determines
    acquisition mechanics, never the meaning of records. It is never a
    semantic format.
    """

    HTTPS = "https"
    FILE = "file"


class SerializationFormat(StrEnum):
    """Typed physical serialization vocabulary.

    Serialization answers how bytes/records are encoded, not what they mean.
    STIX, ThreatFox, MISP, and TAXII are semantic or protocol concepts and
    are never classified as serialization formats.
    """

    JSON = "json"


class DatasourceDefinition(BaseModel):
    """Immutable typed description of one configured datasource.

    All five classification dimensions are explicit: datasource instance,
    source/provider identity, acquisition protocol, serialization format,
    and semantic format. None is inferred from another; unknown typed values
    fail closed at construction.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    datasource_id: DatasourceId
    source_id: SourceId
    protocol: DatasourceProtocol
    serialization_format: SerializationFormat
    semantic_format: SemanticFormatId

    @field_validator("datasource_id", mode="before")
    @classmethod
    def _coerce_datasource_id(cls, value: object) -> DatasourceId:
        """Accept a plain string and validate it into the typed identifier."""
        if isinstance(value, DatasourceId):
            return value
        if not isinstance(value, str):
            raise ValueError("datasource_id must be a string or DatasourceId")
        return DatasourceId(value)


REPRESENTATIVE_DATASOURCE_DEFINITIONS: tuple[DatasourceDefinition, ...] = (
    DatasourceDefinition(
        datasource_id=DatasourceId("threatfox-live"),
        source_id=SourceId.THREATFOX,
        protocol=DatasourceProtocol.HTTPS,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.THREATFOX,
    ),
    DatasourceDefinition(
        datasource_id=DatasourceId("mitre-attack-enterprise"),
        source_id=SourceId.MITRE_ATTACK,
        protocol=DatasourceProtocol.FILE,
        serialization_format=SerializationFormat.JSON,
        semantic_format=SemanticFormatId.STIX_21,
    ),
)
"""Repository-owned representative datasource definitions (PR 27A).

Proves the architectural separation without migrating runtime ingestion:
ThreatFox is HTTPS + JSON with its own proprietary semantic format, while
MITRE ATT&CK is FILE + JSON with the shared STIX 2.1 semantic format.
"""
