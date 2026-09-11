# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Analyst-facing investigation workflow timeline events.

The timeline is a distinct, append-only record of safe observable workflow
actions. It is separate from audit events, domain-object history, application
logs, and distributed tracing, and it never carries prose reasoning, raw
provider payloads, secrets, or chain-of-thought.
"""

import re
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from agentic_threat_investigator.domain.identifiers import SourceId

_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
"""Stable bounded error-code grammar: lowercase snake-case, at most 64 chars."""


class InvestigationTimelineEventType(str, Enum):
    """Safe observable workflow actions recorded on an investigation timeline."""

    INVESTIGATION_STARTED = "investigation_started"
    PROVIDER_WORK_STARTED = "provider_work_started"
    PROVIDER_WORK_COMPLETED = "provider_work_completed"
    PROVIDER_WORK_FAILED = "provider_work_failed"
    EVIDENCE_PERSISTED = "evidence_persisted"
    ENTITIES_DISCOVERED = "entities_discovered"
    PIVOT_ENQUEUED = "pivot_enqueued"
    PIVOT_EXECUTED = "pivot_executed"
    PIVOT_SKIPPED = "pivot_skipped"
    ASSESSMENT_REQUESTED = "assessment_requested"
    INVESTIGATION_STOPPED = "investigation_stopped"


class InvestigationTimelineEvent(BaseModel):
    """One append-only, analyst-facing workflow timeline event.

    Events carry typed identifiers and a stable event type only: no free-form
    reason text, raw payloads, stack traces, prompts, or hidden reasoning.
    Presentation prose, where required later, is derived deterministically
    from the event type and fields.

    Event-shape contract (enforced by ``_validate_shape``):

    - ``INVESTIGATION_STARTED``: provider, target_entity_id, and error_code
      are ``None``; all ID tuples are empty.
    - ``PROVIDER_WORK_STARTED``: provider and target_entity_id are required;
      error_code is ``None``; all ID tuples are empty.
    - ``EVIDENCE_PERSISTED``: provider and target_entity_id are required;
      exactly one Evidence ID is required; Entity/Relationship ID tuples may
      be empty; error_code is ``None``.
    - ``PROVIDER_WORK_COMPLETED``: provider and target_entity_id are required;
      aggregate ID tuples may be empty; error_code may carry the retained
      first provider error for a mixed partial result.
    - ``PROVIDER_WORK_FAILED``: provider, target_entity_id, and error_code are
      required; all ID tuples are empty because committed IDs live in the
      operational outcome and prior ``EVIDENCE_PERSISTED`` events.
    - ``ENTITIES_DISCOVERED``: at least one Entity ID is required; error_code
      is ``None``.
    - ``PIVOT_ENQUEUED``: at least one Entity ID is required; no
      provider/target/error_code/reason_code; pivot_depth and counters
      permitted.
    - ``PIVOT_EXECUTED``: exactly one Entity ID and a required pivot_depth; no
      provider/target/error_code/reason_code; counters permitted.
    - ``PIVOT_SKIPPED``: at least one Entity ID and a required bounded
      reason_code; no provider/target/error_code.
    - ``ASSESSMENT_REQUESTED``: no identifier tuples, reason_code, or
      pivot_depth; counters permitted.
    - ``INVESTIGATION_STOPPED``: no identifier tuples or pivot_depth; the
      stable stop reason is carried as reason_code; counters permitted.

    ``error_code`` is bounded to 64 ASCII characters matching
    ``^[a-z][a-z0-9_]{0,63}$``; leading/trailing whitespace is rejected, never
    stripped or normalized.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    investigation_id: UUID
    type: InvestigationTimelineEventType
    occurred_at: datetime
    provider: SourceId | None = None
    target_entity_id: UUID | None = None
    evidence_ids: tuple[UUID, ...] = ()
    entity_ids: tuple[UUID, ...] = ()
    relationship_ids: tuple[UUID, ...] = ()
    error_code: str | None = None
    pivot_depth: int | None = None
    reason_code: str | None = None
    provider_calls_used: int | None = None
    replans_used: int | None = None
    entity_count: int | None = None

    @field_validator(
        "pivot_depth", "provider_calls_used", "replans_used", "entity_count"
    )
    @classmethod
    def nonnegative_counters(cls, value: int | None) -> int | None:
        """Reject negative bounded coordinator fields."""
        if value is not None and value < 0:
            raise ValueError("coordinator timeline counters must be nonnegative")
        return value

    @field_validator("reason_code")
    @classmethod
    def validate_reason_code(cls, value: str | None) -> str | None:
        """Reject reason codes outside the stable bounded snake-case grammar.

        Whitespace is not stripped or normalized: a padded code is a contract
        failure, never a silent repair.
        """
        if value is None:
            return None
        if not _ERROR_CODE_RE.fullmatch(value):
            raise ValueError(
                "timeline reason_code must match ^[a-z][a-z0-9_]{0,63}$ "
                "with no surrounding whitespace"
            )
        return value

    @field_validator("occurred_at")
    @classmethod
    def validate_utc(cls, value: datetime) -> datetime:
        """Require a timezone-aware timestamp, normalized to UTC."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timeline timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("error_code")
    @classmethod
    def validate_error_code(cls, value: str | None) -> str | None:
        """Reject error codes outside the stable bounded snake-case grammar.

        Whitespace is not stripped or normalized: a padded code is a contract
        failure, never a silent repair.
        """
        if value is None:
            return None
        if not _ERROR_CODE_RE.fullmatch(value):
            raise ValueError(
                "timeline error_code must match ^[a-z][a-z0-9_]{0,63}$ "
                "with no surrounding whitespace"
            )
        return value

    @model_validator(mode="after")
    def _validate_shape(self) -> "InvestigationTimelineEvent":
        """Enforce the per-event-type field-shape contract deterministically.

        Provider-work events are validated by the later provider/target
        requirement; coordinator-only events (pivots, assessments, stops) are
        validated here before that requirement so they never need a provider
        or target. The branch count is intrinsic to the distinct documented
        event shapes; the narrow disable follows repository convention.
        """
        event_type = self.type
        has_provider = self.provider is not None
        has_target = self.target_entity_id is not None
        if event_type is InvestigationTimelineEventType.INVESTIGATION_STARTED:
            if has_provider or has_target or self.error_code is not None:
                raise ValueError(
                    "investigation_started events carry no provider, target, "
                    "error_code, or identifier tuples"
                )
            if self.evidence_ids or self.entity_ids or self.relationship_ids:
                raise ValueError(
                    "investigation_started events carry no identifier tuples"
                )
            return self
        if event_type is InvestigationTimelineEventType.ENTITIES_DISCOVERED:
            if not self.entity_ids:
                raise ValueError("entities_discovered events require entity IDs")
            if self.error_code is not None:
                raise ValueError("entities_discovered events carry no error_code")
            return self
        # Coordinator-only events never require a provider or target. Each
        # permits only the bounded fields relevant to evaluation.
        if event_type is InvestigationTimelineEventType.PIVOT_ENQUEUED:
            if has_provider or has_target or self.error_code is not None:
                raise ValueError(
                    "pivot_enqueued events carry no provider, target, or error_code"
                )
            if not self.entity_ids:
                raise ValueError("pivot_enqueued events require entity IDs")
            if self.reason_code is not None:
                raise ValueError("pivot_enqueued events carry no reason_code")
            return self
        if event_type is InvestigationTimelineEventType.PIVOT_EXECUTED:
            if has_provider or has_target or self.error_code is not None:
                raise ValueError(
                    "pivot_executed events carry no provider, target, or error_code"
                )
            if len(self.entity_ids) != 1:
                raise ValueError("pivot_executed events require exactly one entity ID")
            if self.pivot_depth is None:
                raise ValueError("pivot_executed events require pivot_depth")
            if self.reason_code is not None:
                raise ValueError("pivot_executed events carry no reason_code")
            return self
        if event_type is InvestigationTimelineEventType.PIVOT_SKIPPED:
            if has_provider or has_target or self.error_code is not None:
                raise ValueError(
                    "pivot_skipped events carry no provider, target, or error_code"
                )
            if not self.entity_ids:
                raise ValueError("pivot_skipped events require entity IDs")
            if self.reason_code is None:
                raise ValueError("pivot_skipped events require a reason_code")
            return self
        if event_type is InvestigationTimelineEventType.ASSESSMENT_REQUESTED:
            if has_provider or has_target or self.error_code is not None:
                raise ValueError(
                    "assessment_requested events carry no provider, target, "
                    "or error_code"
                )
            if self.evidence_ids or self.entity_ids or self.relationship_ids:
                raise ValueError(
                    "assessment_requested events carry no identifier tuples"
                )
            if self.reason_code is not None or self.pivot_depth is not None:
                raise ValueError(
                    "assessment_requested events carry no reason_code or pivot_depth"
                )
            return self
        if event_type is InvestigationTimelineEventType.INVESTIGATION_STOPPED:
            if has_provider or has_target or self.error_code is not None:
                raise ValueError(
                    "investigation_stopped events carry no provider, target, "
                    "or error_code"
                )
            if self.evidence_ids or self.entity_ids or self.relationship_ids:
                raise ValueError(
                    "investigation_stopped events carry no identifier tuples"
                )
            if self.pivot_depth is not None:
                raise ValueError("investigation_stopped events carry no pivot_depth")
            if self.reason_code is None:
                raise ValueError(
                    "investigation_stopped events require a reason_code "
                    "(the stable stop reason value)"
                )
            return self
        # Every remaining event type requires provider and target.
        if not has_provider or not has_target:
            raise ValueError(
                f"{event_type.value} events require provider and target_entity_id"
            )
        if event_type is InvestigationTimelineEventType.PROVIDER_WORK_STARTED:
            if self.error_code is not None:
                raise ValueError("provider_work_started events carry no error_code")
            if self.evidence_ids or self.entity_ids or self.relationship_ids:
                raise ValueError(
                    "provider_work_started events carry no identifier tuples"
                )
            # pivot_depth carries the provider work depth (root=0, pivots>0)
            # needed for coordinator trajectory evaluation.
            return self
        if event_type is InvestigationTimelineEventType.EVIDENCE_PERSISTED:
            if len(self.evidence_ids) != 1:
                raise ValueError(
                    "evidence_persisted events require exactly one Evidence ID"
                )
            if self.error_code is not None:
                raise ValueError("evidence_persisted events carry no error_code")
            return self
        if event_type is InvestigationTimelineEventType.PROVIDER_WORK_FAILED:
            if self.error_code is None:
                raise ValueError("provider_work_failed events require an error_code")
            if self.evidence_ids or self.entity_ids or self.relationship_ids:
                raise ValueError(
                    "provider_work_failed events carry no identifier tuples; "
                    "committed IDs live in the operational outcome and prior "
                    "evidence_persisted events"
                )
            return self
        # PROVIDER_WORK_COMPLETED: aggregate tuples may be empty; error_code
        # may carry the retained first provider error (mixed partial result).
        if event_type is InvestigationTimelineEventType.PROVIDER_WORK_COMPLETED:
            return self
        # Unknown event type reaches here and is accepted only if it is a
        # provider-work family event; new event types must be handled
        # explicitly above.
        return self
