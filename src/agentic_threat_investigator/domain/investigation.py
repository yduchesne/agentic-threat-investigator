# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation state, budgets, pivots, and stopping semantics.

:class:`InvestigationState` carries identifiers, queues, budgets, status, and
outcomes rather than copies of all domain objects. The persisted domain
objects remain authoritative.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.identifiers import SourceId

DEFAULT_MAX_DEPTH = 2
"""Initial configurable default maximum pivot depth."""

DEFAULT_MAX_ENTITIES = 10
"""Initial configurable default maximum unique admitted investigation entities."""

DEFAULT_MAX_PROVIDER_CALLS = 40
"""Initial configurable default maximum provider calls."""

DEFAULT_MAX_REPLANS = 3
"""Initial configurable default maximum coordinator replans."""

DEFAULT_MAX_LLM_CALLS = 10
"""Initial configurable default maximum LLM calls per investigation.

The limit covers every actual model invocation, including structured-output
repair attempts, and is enforced by the Evidence Analyst through the
persisted Investigation budget (PR 20B).
"""


def _unique_execution_strings(value: tuple[str, ...]) -> tuple[str, ...]:
    """Strip and stably deduplicate a tuple of research filter values."""
    result: list[str] = []
    for item in value:
        stripped = item.strip()
        if not stripped:
            raise ValueError("research filter values must not be blank")
        if stripped not in result:
            result.append(stripped)
    return tuple(result)


def _unique_execution_uuids(value: tuple[UUID, ...]) -> tuple[UUID, ...]:
    """Stably deduplicate research context entity identifiers."""
    return tuple(dict.fromkeys(value))


class InvalidInvestigationStatusTransitionError(ValueError):
    """Raised when a status change violates the investigation lifecycle."""


class InvestigationBudgetExhaustedError(ValueError):
    """Raised when an LLM call would exceed the investigation's LLM budget.

    The counter is incremented only when the call is actually attempted, and
    the durable reservation is persisted through Investigation version/history
    semantics rather than a transient in-memory mutation.
    """


class InvestigationStatus(str, Enum):
    """Lifecycle statuses of an investigation."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


INVESTIGATION_STATUS_TRANSITIONS: dict[
    InvestigationStatus, frozenset[InvestigationStatus]
] = {
    InvestigationStatus.PENDING: frozenset(
        {InvestigationStatus.RUNNING, InvestigationStatus.FAILED}
    ),
    InvestigationStatus.RUNNING: frozenset(
        {
            InvestigationStatus.COMPLETED,
            InvestigationStatus.PARTIAL,
            InvestigationStatus.FAILED,
        }
    ),
    InvestigationStatus.COMPLETED: frozenset(),
    InvestigationStatus.PARTIAL: frozenset(),
    InvestigationStatus.FAILED: frozenset(),
}
"""The confirmed investigation lifecycle.

``PENDING`` investigations start running or fail before execution begins.
``RUNNING`` investigations complete, complete partially, or fail. Terminal
statuses admit no further transitions. An identical target status is not a
transition and is handled as a semantic no-op by the persistence layer.
"""


_TERMINAL_STATUSES: frozenset[InvestigationStatus] = frozenset(
    {
        InvestigationStatus.COMPLETED,
        InvestigationStatus.PARTIAL,
        InvestigationStatus.FAILED,
    }
)


def is_terminal_status(status: InvestigationStatus) -> bool:
    """Return whether an investigation status admits no further transitions."""

    return status in _TERMINAL_STATUSES


def can_transition_status(
    current: InvestigationStatus, target: InvestigationStatus
) -> bool:
    """Return whether the lifecycle permits changing one status to another.

    An identical target status is not a transition; callers that want the
    confirmed lifecycle rule only must compare statuses first.
    """

    if current is target:
        return True
    return target in INVESTIGATION_STATUS_TRANSITIONS[current]


def require_status_transition(
    current: InvestigationStatus, target: InvestigationStatus
) -> None:
    """Validate a status change against the lifecycle or raise a typed error."""

    if not can_transition_status(current, target):
        raise InvalidInvestigationStatusTransitionError(
            f"investigation status transition {current.value} -> {target.value} "
            "is not permitted"
        )


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


class ProviderWorkItem(BaseModel):
    """One approved provider-work unit queued for deterministic execution.

    The work identity is exactly ``(provider, entity_id, depth)`` and is used
    for deterministic queue duplicate suppression only. It carries
    operational identifiers, never entity values, provider instances, or
    infrastructure objects.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: SourceId
    entity_id: UUID
    depth: int = Field(ge=0)


class InvestigationBudget(BaseModel):
    """Deterministic resource budgets for one investigation.

    LLM call accounting (PR 20B) counts every actual model invocation,
    including structured-output repair attempts. Input-loading and
    persistence failures never increment the counter; an exhausted budget
    raises a typed error before another model call is attempted.

    Transient budget documents are validated before persistence: every
    consumed counter is a nonnegative integer within its maximum, and every
    maximum is nonnegative. Monotonicity across coordinator transitions is
    enforced by the stored function (a counter may never decrease, and only
    the owning transition may change it).
    """

    max_depth: int
    max_entities: int
    max_provider_calls: int
    max_replans: int
    max_llm_calls: int = Field(default=DEFAULT_MAX_LLM_CALLS, ge=0)
    provider_calls_used: int = 0
    replans_used: int = 0
    llm_calls_used: int = Field(default=0, ge=0)

    @field_validator("max_depth", "max_entities", "max_provider_calls", "max_replans")
    @classmethod
    def maxima_nonnegative(cls, value: int) -> int:
        """Reject negative maximum values."""
        if value < 0:
            raise ValueError("budget maxima must be nonnegative")
        return value

    @field_validator("provider_calls_used", "replans_used")
    @classmethod
    def counters_nonnegative(cls, value: int) -> int:
        """Reject negative consumed counters."""
        if value < 0:
            raise ValueError("budget consumed counters must be nonnegative")
        return value

    @model_validator(mode="after")
    def counters_within_maxima(self) -> "InvestigationBudget":
        """Reject any consumed counter above its maximum."""
        if self.provider_calls_used > self.max_provider_calls:
            raise ValueError("provider_calls_used exceeds max_provider_calls")
        if self.replans_used > self.max_replans:
            raise ValueError("replans_used exceeds max_replans")
        if self.llm_calls_used > self.max_llm_calls:
            raise ValueError("llm_calls_used exceeds max_llm_calls")
        return self

    @property
    def llm_calls_remaining(self) -> int:
        """Return how many model invocations remain before the limit."""
        return self.max_llm_calls - self.llm_calls_used

    def record_llm_call(self) -> None:
        """Reserve one model invocation or raise a typed exhausted error.

        The reservation becomes durable only after the caller persists the
        budget through Investigation version/history semantics; callers must
        never treat this in-memory mutation alone as authoritative accounting.
        """
        if self.llm_calls_used >= self.max_llm_calls:
            raise InvestigationBudgetExhaustedError(
                "investigation LLM budget exhausted "
                f"(max_llm_calls={self.max_llm_calls})"
            )
        self.llm_calls_used += 1


class InvestigationError(BaseModel):
    """A structured error recorded during investigation execution."""

    source: str | None = None
    code: str
    message: str
    recoverable: bool


MAX_RESEARCH_EXECUTION_ATTEMPTS = 2
"""The v0.1 hard orchestration bound on research execution attempts.

One exact research context may be requested at most twice: attempt 1, then at
most one later retry after a recoverable execution failure. The bound is a
workflow-execution counter, never an LLM-call counter: the Research Agent's
internal structured-output repair is separately bounded and separately
accounted.
"""


class ResearchExecutionStatus(str, Enum):
    """Durable lifecycle of one exact research context (PR 22C).

    ``REQUESTED`` means the durable attempt was authorized before external
    execution began; ``COMPLETED`` means an authoritative ResearchResult was
    adopted/linked; ``EXHAUSTED`` means the final allowed orchestration
    attempt failed recoverably (or crashed) with no durable result, so the
    unchanged context is no longer due. There is deliberately no RUNNING or
    FAILED status: external execution happens only after the durable
    REQUESTED transition, and a recoverable failure keeps the context
    REQUESTED until the final attempt resolves it.
    """

    REQUESTED = "requested"
    COMPLETED = "completed"
    EXHAUSTED = "exhausted"


class ResearchExecutionState(BaseModel):
    """Durable orchestration lifecycle state for one exact research context.

    The context identity is ``(subject_entity_id, context_fingerprint)``: the
    fingerprint is a deterministic, schema-versioned hash of the planned
    request, so an unchanged context never re-executes while a changed
    context becomes due again. The state preserves the exact planned request
    fields needed to re-validate equivalence and carries the workflow
    attempt count and result linkage. It is Investigation workflow state, not
    a ResearchResult domain object: claim/citation content lives only in the
    immutable ResearchResult.

    Invariants:

    - ``REQUESTED``: ``result_id`` is ``None``.
    - ``COMPLETED``: ``result_id`` is required.
    - ``EXHAUSTED``: ``result_id`` is ``None`` and ``attempts`` equals the
      hard orchestration bound (:data:`MAX_RESEARCH_EXECUTION_ATTEMPTS`).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_entity_id: UUID
    context_fingerprint: str
    query: str
    entity_ids: tuple[UUID, ...] = ()
    source_ids: tuple[str, ...] = ()
    document_types: tuple[str, ...] = ()
    max_results: int = Field(default=8, ge=1, le=100)

    status: ResearchExecutionStatus
    attempts: int = Field(default=1, ge=1, le=MAX_RESEARCH_EXECUTION_ATTEMPTS)
    result_id: UUID | None = None

    @field_validator("query", "context_fingerprint")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        """Reject blank query and fingerprint values."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("research execution query/fingerprint must not be blank")
        return stripped

    _validate_string_filters = field_validator("source_ids", "document_types")(
        _unique_execution_strings
    )
    _validate_entity_filters = field_validator("entity_ids")(_unique_execution_uuids)

    @model_validator(mode="after")
    def status_result_invariants(self) -> "ResearchExecutionState":
        """Enforce the status/result/attempt lifecycle invariants."""
        if (
            self.status is ResearchExecutionStatus.REQUESTED
            and self.result_id is not None
        ):
            raise ValueError("requested research execution must not carry a result_id")
        if self.status is ResearchExecutionStatus.COMPLETED and self.result_id is None:
            raise ValueError("completed research execution requires a result_id")
        if self.status is ResearchExecutionStatus.EXHAUSTED:
            if self.result_id is not None:
                raise ValueError(
                    "exhausted research execution must not carry a result_id"
                )
            if self.attempts != MAX_RESEARCH_EXECUTION_ATTEMPTS:
                raise ValueError(
                    "exhausted research execution requires the maximum attempt count"
                )
        return self


class ProviderExecutionStatus(str, Enum):
    """Outcome status of one fake/deterministic provider work execution."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ProviderExecutionOutcome(BaseModel):
    """Typed operational result of executing one :class:`ProviderWorkItem`.

    Contains operational identifiers only: no evidence objects, provider
    payloads, relationship objects, assessments, or hidden reasoning.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    work_item: ProviderWorkItem
    status: ProviderExecutionStatus
    evidence_ids: tuple[UUID, ...] = ()
    discovered_entity_ids: tuple[UUID, ...] = ()
    relationship_ids: tuple[UUID, ...] = ()
    error: InvestigationError | None = None


class EntityTraversalState(BaseModel):
    """Durable discovery metadata for one entity in an investigation.

    Tracks the deterministic first-discovery order and the minimum depth at
    which the entity was discovered, so pivot policy can order candidates and
    suppress same-or-worse-depth replay without relying on set/dict ordering
    or on ``investigated_entity_ids`` (which cannot encode depth).

    ``first_discovery_ordinal`` is the 0-based position in discovery order;
    roots occupy the leading ordinals in ``root_entity_ids`` order before any
    provider discovery is recorded. ``minimum_depth`` is 0 for root entities
    and ``parent work depth + 1`` for provider-discovered entities; a
    rediscovery may lower it but never raises it.

    ``best_investigated_depth`` retains the shallowest depth at which the
    entity was actually investigated (its pivot entered execution). It is
    independent of ``minimum_depth``: an entity investigated at depth 3 and
    later rediscovered at depth 1 has ``best_investigated_depth == 3`` and
    ``minimum_depth == 1``, so the shallower rediscovery is not suppressed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    first_discovery_ordinal: int = Field(ge=0)
    minimum_depth: int = Field(ge=0)
    best_investigated_depth: int | None = Field(default=None, ge=0)

    def record_investigation(self, depth: int) -> "EntityTraversalState":
        """Return a copy with the shallowest executed investigation depth."""
        current = self.best_investigated_depth
        if current is None or depth < current:
            return self.model_copy(update={"best_investigated_depth": depth})
        return self


class EntityTraversalStateBuilder:
    """Deterministic builder for :class:`EntityTraversalState` entries.

    Keeps the first-discovery ordinal of every known entity (roots first in
    ``root_entity_ids`` order, then provider discoveries in provider-result
    order) and the minimum known depth. Duplicate ordinals are rejected.
    """

    def __init__(self, root_entity_ids: list[UUID]) -> None:
        """Seed the builder with root entities at depth zero."""
        self._entries: list[EntityTraversalState] = []
        self._depth_by_id: dict[UUID, int] = {}
        self._ordinal_by_id: dict[UUID, int] = {}
        ordinal = 0
        for entity_id in root_entity_ids:
            if entity_id not in self._ordinal_by_id:
                self._ordinal_by_id[entity_id] = ordinal
                self._depth_by_id[entity_id] = 0
                self._entries.append(
                    EntityTraversalState(
                        entity_id=entity_id,
                        first_discovery_ordinal=ordinal,
                        minimum_depth=0,
                    )
                )
                ordinal += 1

    def record_discovery(self, entity_id: UUID, parent_depth: int) -> None:
        """Record one provider discovery at ``parent_depth + 1``.

        A new entity receives the next ordinal and depth ``parent_depth + 1``.
        A rediscovery keeps the first ordinal and lowers the minimum depth only
        when the proposed depth is shallower.
        """
        proposed_depth = parent_depth + 1
        if entity_id not in self._ordinal_by_id:
            ordinal = len(self._entries)
            self._ordinal_by_id[entity_id] = ordinal
            self._depth_by_id[entity_id] = proposed_depth
            self._entries.append(
                EntityTraversalState(
                    entity_id=entity_id,
                    first_discovery_ordinal=ordinal,
                    minimum_depth=proposed_depth,
                )
            )
            return
        current_depth = self._depth_by_id[entity_id]
        if proposed_depth < current_depth:
            self._depth_by_id[entity_id] = proposed_depth
            self._update_depth(entity_id, proposed_depth)

    def record_discovery_at_ordinal(
        self,
        entity_id: UUID,
        ordinal: int,
        depth: int,
        *,
        best_depth: int | None = None,
    ) -> None:
        """Replay one already-known traversal entry into the builder.

        Used to rebuild traversal state from persisted entries without
        re-ordering roots or discoveries. Duplicate entities are rejected so
        a malformed persisted traversal cannot be silently repaired. The
        optional ``best_depth`` replays the historic investigated depth.
        """
        if entity_id in self._ordinal_by_id:
            raise ValueError(f"traversal entry duplicated for entity {entity_id}")
        if ordinal != len(self._entries):
            raise ValueError("traversal ordinals must be contiguous from zero")
        self._ordinal_by_id[entity_id] = ordinal
        self._depth_by_id[entity_id] = depth
        self._entries.append(
            EntityTraversalState(
                entity_id=entity_id,
                first_discovery_ordinal=ordinal,
                minimum_depth=depth,
                best_investigated_depth=best_depth,
            )
        )

    def _update_depth(self, entity_id: UUID, depth: int) -> None:
        """Rewrite one entry's minimum depth, preserving execution history.

        A shallower rediscovery lowers only ``minimum_depth``; the recorded
        ``best_investigated_depth`` is always carried over so historical
        execution depth is never erased by rediscovery.
        """
        for index, entry in enumerate(self._entries):
            if entry.entity_id == entity_id:
                self._entries[index] = EntityTraversalState(
                    entity_id=entry.entity_id,
                    first_discovery_ordinal=entry.first_discovery_ordinal,
                    minimum_depth=depth,
                    best_investigated_depth=entry.best_investigated_depth,
                )
                return

    def entries(self) -> tuple[EntityTraversalState, ...]:
        """Return the ordered traversal entries."""
        return tuple(self._entries)

    def minimum_depth(self, entity_id: UUID) -> int | None:
        """Return the minimum depth of an entity, or ``None`` when unknown."""
        return self._depth_by_id.get(entity_id)


class InvestigationState(BaseModel):
    """Operational workflow state for one investigation.

    Contains IDs and workflow information only: no raw provider payloads,
    complete document chunks, prompts, database clients, repositories, HTTP
    clients, or hidden reasoning.

    The trailing ``version``/timestamp/deletion fields are database-owned
    persistence output. Callers must not supply them; the persistence layer
    never serializes them back into ``budget`` or ``operational_state`` and
    never lets caller values override the authoritative database columns.
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
    pending_provider_work: list[ProviderWorkItem] = Field(default_factory=list)
    completed_provider_work: list[ProviderWorkItem] = Field(default_factory=list)
    current_provider_work: ProviderWorkItem | None = None
    last_provider_outcome: ProviderExecutionOutcome | None = None
    investigated_entity_ids: list[UUID] = Field(default_factory=list)
    research_required_for_entity_ids: list[UUID] = Field(default_factory=list)
    research_executions: list[ResearchExecutionState] = Field(default_factory=list)
    analyzed_evidence_ids: list[UUID] = Field(default_factory=list)
    analysis_disposition: AnalysisDisposition | None = None
    traversal: list[EntityTraversalState] = Field(default_factory=list)
    research_result_ids: list[UUID] = Field(default_factory=list)
    assessment_id: UUID | None = None
    report_id: UUID | None = None
    budget: InvestigationBudget
    stop_reason: str | None = None
    errors: list[InvestigationError] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime | None = None
    version: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    deleted_at: datetime | None = None
    deleted_by_actor_id: UUID | None = None

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware timestamps, normalized to UTC."""
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("investigation timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("traversal")
    @classmethod
    def traversal_entries_valid(
        cls, value: list[EntityTraversalState]
    ) -> list[EntityTraversalState]:
        """Reject malformed traversal entries.

        Entries must have unique entity IDs and unique ordinal values, and
        must be ordered by ordinal. An entry may reference a root or a
        discovered entity; cross-field coherence with
        ``root_entity_ids``/``discovered_entity_ids`` is validated by
        :meth:`traversal_coherent_with_discoveries`.
        """
        seen_ids: set[UUID] = set()
        seen_ordinals: set[int] = set()
        previous_ordinal = -1
        for expected_ordinal, entry in enumerate(value):
            if entry.entity_id in seen_ids:
                raise ValueError(
                    f"traversal entry duplicated for entity {entry.entity_id}"
                )
            seen_ids.add(entry.entity_id)
            if entry.first_discovery_ordinal in seen_ordinals:
                raise ValueError(
                    "traversal first_discovery_ordinal values must be unique"
                )
            seen_ordinals.add(entry.first_discovery_ordinal)
            if entry.first_discovery_ordinal <= previous_ordinal:
                raise ValueError("traversal entries must be ordered by ordinal")
            if entry.first_discovery_ordinal != expected_ordinal:
                raise ValueError("traversal ordinals must be contiguous from zero")
            previous_ordinal = entry.first_discovery_ordinal
        return value

    @field_validator("analyzed_evidence_ids")
    @classmethod
    def analyzed_evidence_ids_unique(cls, value: list[UUID]) -> list[UUID]:
        """Reject duplicate analyzed Evidence identities."""
        if len(value) != len(set(value)):
            raise ValueError("analyzed_evidence_ids must not contain duplicates")
        return value

    @field_validator("research_executions")
    @classmethod
    def research_executions_valid(
        cls, value: list[ResearchExecutionState]
    ) -> list[ResearchExecutionState]:
        """Reject duplicate exact research contexts and duplicate result links.

        One exact context (``subject_entity_id`` + ``context_fingerprint``)
        has exactly one durable orchestration state; a COMPLETED result ID
        may never be linked by more than one execution.
        """
        contexts: set[tuple[UUID, str]] = set()
        completed_result_ids: set[UUID] = set()
        for execution in value:
            context = (execution.subject_entity_id, execution.context_fingerprint)
            if context in contexts:
                raise ValueError(
                    "research execution contexts must be unique per subject/fingerprint"
                )
            contexts.add(context)
            if execution.result_id is not None:
                if execution.result_id in completed_result_ids:
                    raise ValueError(
                        "research execution result_ids must not repeat across executions"
                    )
                completed_result_ids.add(execution.result_id)
        return value

    @model_validator(mode="after")
    def research_executions_coherent(self) -> "InvestigationState":
        """Require research result linkage to be coherent with executions.

        Every COMPLETED execution's ``result_id`` must appear in
        ``research_result_ids`` exactly once, and every ``research_result_ids``
        entry must correspond to one COMPLETED execution once executions have
        been recorded. A pre-22C investigation that carries result identities
        without execution state (``research_executions`` empty) remains
        valid so legacy persisted rows are never rejected.
        """
        if not self.research_executions:
            return self
        linked = set(self.research_result_ids)
        completed_ids = [
            execution.result_id
            for execution in self.research_executions
            if execution.status is ResearchExecutionStatus.COMPLETED
        ]
        for result_id in completed_ids:
            if result_id is None:
                continue
            if result_id not in linked:
                raise ValueError(
                    "completed research execution result is not linked in "
                    "research_result_ids"
                )
        for result_id in self.research_result_ids:
            if result_id not in completed_ids:
                raise ValueError(
                    "research_result_ids entry lacks a completed execution"
                )
        return self

    @model_validator(mode="after")
    def traversal_coherent_with_discoveries(self) -> "InvestigationState":
        """Reject traversal metadata that contradicts root/discovery lists.

        Every traversal entry must name a root or a discovered entity; every
        discovered entity recorded by provider execution must have an entry
        when the traversal has been populated. Roots are validated to have
        depth zero when represented.
        """
        if (
            self.status is InvestigationStatus.RUNNING
            and self.version is not None
            and self.discovered_entity_ids
            and not self.traversal
        ):
            raise ValueError(
                "persisted running investigation discoveries require traversal metadata"
            )
        known = set(self.root_entity_ids) | set(self.discovered_entity_ids)
        traversal_ids = {entry.entity_id for entry in self.traversal}
        unknown = traversal_ids - known
        if unknown:
            raise ValueError(
                "traversal references an entity absent from roots/discoveries"
            )
        if self.traversal:
            unique_roots = list(dict.fromkeys(self.root_entity_ids))
            root_prefix = [
                entry.entity_id for entry in self.traversal[: len(unique_roots)]
            ]
            if root_prefix != unique_roots:
                raise ValueError(
                    "root traversal entries must be the leading root order"
                )
        for entry in self.traversal:
            if entry.entity_id in self.root_entity_ids and entry.minimum_depth != 0:
                raise ValueError("root traversal entries must have minimum_depth 0")
        # A discovered entity missing traversal metadata is only a hard error
        # when the traversal has been populated at all (i.e. provider
        # execution already recorded discoveries).
        if self.traversal:
            missing = set(self.discovered_entity_ids) - traversal_ids
            if missing:
                raise ValueError(
                    "discovered entity lacks traversal metadata after discovery"
                )
        return self


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


class CoordinatorTransitionKind(str, Enum):
    """Bounded coordinator persistence transitions (PR 21).

    Each transition kind restricts which operational fields and budget
    counters may change in one versioned write, so a repository-bypassing
    caller cannot reuse budgets, lower counters, change limits, spoof
    references, or replace unrelated workflow state.
    """

    SELECT_PROVIDER_WORK = "select_provider_work"
    RECORD_PROVIDER_OUTCOME = "record_provider_outcome"
    AUTHORIZE_PIVOT = "authorize_pivot"
    MARK_RESEARCH_REQUIRED = "mark_research_required"
    REQUEST_RESEARCH = "request_research"
    RECORD_RESEARCH_OUTCOME = "record_research_outcome"
    FINALIZE_STOP = "finalize_stop"


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
        max_llm_calls=DEFAULT_MAX_LLM_CALLS,
    )
