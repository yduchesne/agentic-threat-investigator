# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation state, budgets, pivots, and stopping semantics.

:class:`InvestigationState` carries identifiers, queues, budgets, status, and
outcomes rather than copies of all domain objects. The persisted domain
objects remain authoritative.
"""

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field

from agentic_threat_investigator.domain.entities import EntityType

DEFAULT_MAX_DEPTH = 2
"""Initial configurable default maximum pivot depth."""

DEFAULT_MAX_ENTITIES = 10
"""Initial configurable default maximum discovered entities."""

DEFAULT_MAX_PROVIDER_CALLS = 40
"""Initial configurable default maximum provider calls."""

DEFAULT_MAX_REPLANS = 3
"""Initial configurable default maximum coordinator replans."""


class InvestigationStatus(str, Enum):
    """Lifecycle statuses of an investigation."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class InvestigationTriggerType(str, Enum):
    """How an investigation was initiated."""

    MANUAL = "manual"
    MONITOR = "monitor"
    API = "api"


class PivotStatus(str, Enum):
    """Lifecycle statuses of an individual pivot."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"


class PivotRequest(BaseModel):
    """A requested pivot onto an existing root or evidence-discovered entity.

    A pivot target must already exist as a root or discovered entity; the
    Coordinator cannot manufacture an arbitrary target. ``reason`` records
    the concise evidence-backed rationale for the action.
    """

    entity_id: UUID
    reason: str
    depth: int
    status: PivotStatus = PivotStatus.PENDING


class InvestigationBudget(BaseModel):
    """Deterministic resource budgets for one investigation.

    LLM call limits and counters are added with the agent implementations.
    """

    max_depth: int
    max_entities: int
    max_provider_calls: int
    max_replans: int
    provider_calls_used: int = 0
    replans_used: int = 0


class InvestigationError(BaseModel):
    """A structured error recorded during investigation execution."""

    source: str | None = None
    code: str
    message: str
    recoverable: bool


class InvestigationState(BaseModel):
    """Operational workflow state for one investigation.

    Contains IDs and workflow information only: no raw provider payloads,
    complete document chunks, prompts, database clients, repositories, HTTP
    clients, or hidden reasoning.
    """

    investigation_id: UUID
    status: InvestigationStatus
    trigger_type: InvestigationTriggerType
    trigger_id: UUID | None = None
    root_entity_ids: list[UUID]
    objective: str
    discovered_entity_ids: list[UUID] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    relationship_ids: list[UUID] = Field(default_factory=list)
    pending_pivots: list[PivotRequest] = Field(default_factory=list)
    investigated_entity_ids: list[UUID] = Field(default_factory=list)
    research_required_for_entity_ids: list[UUID] = Field(default_factory=list)
    research_result_ids: list[UUID] = Field(default_factory=list)
    assessment_id: UUID | None = None
    report_id: UUID | None = None
    budget: InvestigationBudget
    stop_reason: str | None = None
    errors: list[InvestigationError] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime | None = None


class StopReason(str, Enum):
    """Stable reasons why an investigation stopped."""

    SUFFICIENT_EVIDENCE = "sufficient_evidence"
    NO_ELIGIBLE_PIVOTS = "no_eligible_pivots"
    DEPTH_LIMIT_REACHED = "depth_limit_reached"
    ENTITY_BUDGET_EXHAUSTED = "entity_budget_exhausted"
    PROVIDER_BUDGET_EXHAUSTED = "provider_budget_exhausted"
    REPLAN_LIMIT_REACHED = "replan_limit_reached"
    FATAL_ERROR = "fatal_error"


class AnalysisDisposition(str, Enum):
    """The Evidence Analyst's disposition of the collected evidence."""

    SUFFICIENT = "sufficient"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    EXHAUSTED = "exhausted"


class PivotClass(str, Enum):
    """How an entity type participates in investigative pivots."""

    PIVOTABLE = "pivotable"
    ENRICHABLE = "enrichable"
    RESEARCHABLE = "researchable"


_PIVOT_CLASSES: dict[EntityType, PivotClass] = {
    EntityType.DOMAIN: PivotClass.PIVOTABLE,
    EntityType.IP_ADDRESS: PivotClass.PIVOTABLE,
    EntityType.URL: PivotClass.PIVOTABLE,
    EntityType.NETWORK_PREFIX: PivotClass.ENRICHABLE,
    EntityType.ASN: PivotClass.ENRICHABLE,
    EntityType.ORGANIZATION: PivotClass.ENRICHABLE,
    EntityType.MALWARE: PivotClass.RESEARCHABLE,
    EntityType.ATTACK_TECHNIQUE: PivotClass.RESEARCHABLE,
    EntityType.VULNERABILITY: PivotClass.RESEARCHABLE,
}


def pivot_class(entity_type: EntityType) -> PivotClass:
    """Return the fixed pivot classification of an entity type.

    Classification is a stable domain fact. Eligibility of a concrete pivot
    (relevance, evidence support, budgets, cycles, information gain) is
    decided by the deterministic pivot policy, not here.
    """

    return _PIVOT_CLASSES[entity_type]


def default_investigation_budget() -> InvestigationBudget:
    """Return a fresh budget using the initial configurable defaults.

    Returns a new instance on every call so callers may mutate counters
    without affecting other investigations.
    """

    return InvestigationBudget(
        max_depth=DEFAULT_MAX_DEPTH,
        max_entities=DEFAULT_MAX_ENTITIES,
        max_provider_calls=DEFAULT_MAX_PROVIDER_CALLS,
        max_replans=DEFAULT_MAX_REPLANS,
    )
