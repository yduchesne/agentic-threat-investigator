# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure domain model for Agentic Threat Investigator.

This package contains typed domain models and enums only. It must not import
FastAPI, SQLAlchemy, HTTP clients, LangChain, LangGraph, or persistence
implementations.
"""

from agentic_threat_investigator.domain.assessment import (
    Assessment,
    AssessmentConfidence,
    EvidenceReference,
    Verdict,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType, canonicalize
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.geolocation import GeoLocation, GeoPrecision
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    AnalysisDisposition,
    InvestigationBudget,
    InvestigationError,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    PivotClass,
    PivotRequest,
    PivotStatus,
    StopReason,
    default_investigation_budget,
    pivot_class,
)
from agentic_threat_investigator.domain.preferences import UiTheme, UserPreferences
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)

__all__ = [
    "AnalysisDisposition",
    "Assessment",
    "AssessmentConfidence",
    "Entity",
    "EntityRef",
    "EntityType",
    "Evidence",
    "EvidenceReference",
    "EvidenceType",
    "GeoLocation",
    "GeoPrecision",
    "InvestigationBudget",
    "InvestigationError",
    "InvestigationState",
    "InvestigationStatus",
    "InvestigationTriggerType",
    "PivotClass",
    "PivotRequest",
    "PivotStatus",
    "Relationship",
    "RelationshipObservation",
    "RelationshipType",
    "SourceId",
    "StopReason",
    "UiTheme",
    "UserPreferences",
    "Verdict",
    "canonicalize",
    "default_investigation_budget",
    "pivot_class",
]
