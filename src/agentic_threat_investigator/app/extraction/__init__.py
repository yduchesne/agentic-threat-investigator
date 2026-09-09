# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic entity and relationship extraction (PR 18B).

A pure, database-free layer converting persisted normalized Evidence into
canonical discovered entity identities and evidence-backed relationship
assertions. The package performs no I/O, persistence, provider calls, SQL,
LangGraph, LLM calls, ``RelationshipObservation`` creation, or database-ID
allocation, and depends only on domain models, source identifiers, Pydantic,
and the standard library.
"""

from .dns import extract_dns
from .extractor import extract, extract_empty
from .ipinfo import extract_ipinfo
from .models import (
    EntityIdentity,
    EvidenceExtractionError,
    ExtractedEntity,
    ExtractionErrorReason,
    ExtractionResult,
    RelationshipAssertion,
    deduplicate_assertions,
    deduplicate_entities,
)
from .rdap import extract_rdap
from .threatfox import extract_threatfox
from .urlhaus import extract_urlhaus

__all__ = [
    "extract",
    "extract_dns",
    "extract_empty",
    "extract_ipinfo",
    "extract_rdap",
    "extract_threatfox",
    "extract_urlhaus",
    "EntityIdentity",
    "RelationshipAssertion",
    "ExtractionResult",
    "ExtractedEntity",
    "ExtractionErrorReason",
    "EvidenceExtractionError",
    "deduplicate_entities",
    "deduplicate_assertions",
]
