# SPDX-License-Identifier: AGPL-3.0-only
"""Generic history public allowlist and redaction (PR 23C).

Raw ``domain_object_history.state``/``diff`` JSONB snapshots are never
exposed wholesale. Each allowlisted public object type maps through a safe
per-type key allowlist; private operational fields (queues, provider work,
research execution state, traversal metadata, credentials, sessions, jobs)
never cross the HTTP boundary. RelationshipObservation remains outside
generic history by design.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

PUBLIC_HISTORY_OBJECT_TYPES: frozenset[str] = frozenset(
    {
        "investigation",
        "entity",
        "relationship",
        "assessment",
        "investigation_report",
    }
)
"""The allowlisted public history object types (v0.1)."""


class HistoryObjectTypeForbiddenError(ValueError):
    """Raised when a history browse targets a non-allowlisted object type."""


_INVESTIGATION_COLUMNS = frozenset(
    {
        "id",
        "status",
        "trigger_type",
        "objective",
        "version",
        "created_at",
        "updated_at",
        "started_at",
        "completed_at",
        "deleted_at",
        "deleted_by_actor_id",
        "assessment_id",
        "report_id",
        "stop_reason",
        "root_entity_ids",
        "discovered_entity_ids",
        "evidence_ids",
        "relationship_ids",
        "budget",
    }
)
"""Public Investigation row columns plus public operational-state keys.

Deliberately excluded: pending_pivots, pending/completed provider work,
current_provider_work, last_provider_outcome, investigated_entity_ids,
research_required_for_entity_ids, research_executions, research_result_ids,
analyzed_evidence_ids, analysis_disposition, traversal, errors, trigger_id.
"""

_ENTITY_COLUMNS = frozenset(
    {
        "id",
        "entity_type",
        "canonical_value",
        "display_name",
        "attributes",
        "version",
        "created_at",
        "updated_at",
        "deleted_at",
        "deleted_by_actor_id",
    }
)
"""Public Entity row columns; ``content_hash`` is deliberately excluded."""

_RELATIONSHIP_COLUMNS = frozenset(
    {
        "id",
        "source_entity_id",
        "target_entity_id",
        "relationship_type_urn",
        "version",
        "created_at",
        "updated_at",
        "deleted_at",
        "deleted_by_actor_id",
    }
)

_ASSESSMENT_COLUMNS = frozenset(
    {
        "id",
        "investigation_id",
        "verdict",
        "confidence",
        "summary",
        "analyzed_evidence_ids",
        "limitations",
        "unresolved_questions",
        "recommended_next_steps",
        "version",
        "created_at",
        "deleted_at",
        "deleted_by_actor_id",
    }
)

_REPORT_COLUMNS = frozenset(
    {
        "id",
        "investigation_id",
        "assessment_id",
        "verdict",
        "confidence",
        "title",
        "executive_summary",
        "findings",
        "research_context",
        "limitations",
        "unresolved_questions",
        "recommended_next_steps",
        "source_evidence_ids",
        "source_relationship_observation_ids",
        "source_research_result_ids",
        "version",
        "created_at",
        "deleted_at",
        "deleted_by_actor_id",
    }
)

_TYPE_ALLOWLISTS: dict[str, frozenset[str]] = {
    "investigation": _INVESTIGATION_COLUMNS,
    "entity": _ENTITY_COLUMNS,
    "relationship": _RELATIONSHIP_COLUMNS,
    "assessment": _ASSESSMENT_COLUMNS,
    "investigation_report": _REPORT_COLUMNS,
}


def require_public_history_object_type(object_type: str) -> str:
    """Validate one history object type against the public allowlist.

    Raises :class:`HistoryObjectTypeForbiddenError` for credential/session/
    job/internal types and for any unlisted type, so auth material can never
    be browsed through generic history.
    """
    if object_type not in PUBLIC_HISTORY_OBJECT_TYPES:
        raise HistoryObjectTypeForbiddenError(
            f"history object type is not public: {object_type}"
        )
    return object_type


def redact_history_snapshot(
    object_type: str, snapshot: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Return the allowlisted public projection of one history snapshot.

    ``snapshot`` is the raw JSONB ``state`` or ``diff`` mapping. Only keys in
    the per-type allowlist are copied; values are returned unchanged (they
    are already validated JSON-compatible scalars/objects).
    """
    allowlist = _TYPE_ALLOWLISTS.get(object_type)
    if allowlist is None:
        raise HistoryObjectTypeForbiddenError(
            f"history object type is not public: {object_type}"
        )
    if snapshot is None:
        return {}
    return {key: value for key, value in snapshot.items() if key in allowlist}
