# SPDX-License-Identifier: AGPL-3.0-only
"""PR 22B Research Agent typed contracts: bounded request and semantic output.

These are ATI-owned Pydantic contracts only. They carry no repository,
provider, LangChain, LangGraph, or persistence dependency, and they do not
subclass the PR 22A retrieval ``ResearchQuery``: the retrieval contract and
the agent-execution request are distinct responsibilities.

``ResearchAgentRequest`` is one explicitly authorized, bounded contextual
research execution. It owns the authoritative result persistence context
(investigation, subject entity, normalized query) plus the retrieval-context
filters; it deliberately carries no orchestration, depth, tool, or authority
fields.

``ResearchAgentClaim`` and ``ResearchAgentDecision`` are the semantic-only
outputs of the model invocation. They reference stable ``citation_id``
values supplied in the prompt and carry no persistence-owned identity,
timestamp, verdict, confidence, disposition, pivot, or tool fields: the
application stamps authoritative fields when it constructs the immutable
``ResearchResult``.
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = ["ResearchAgentRequest", "ResearchAgentClaim", "ResearchAgentDecision"]


def _unique_strings(value: tuple[str, ...]) -> tuple[str, ...]:
    """Strip and stably deduplicate a tuple of filter values."""
    result: list[str] = []
    for item in value:
        stripped = item.strip()
        if not stripped:
            raise ValueError("filter values must not be blank")
        if stripped not in result:
            result.append(stripped)
    return tuple(result)


def _unique_uuids(value: tuple[UUID, ...]) -> tuple[UUID, ...]:
    """Stably deduplicate contextual entity identifiers."""
    return tuple(dict.fromkeys(value))


class ResearchAgentRequest(BaseModel):
    """One explicitly authorized bounded research execution.

    ``investigation_id`` and ``subject_entity_id`` locate the durable
    ``ResearchResult``; ``query`` is the exact normalized research question
    persisted on the result; ``entity_ids``, ``source_ids``, and
    ``document_types`` are retrieval-context filters/hints only and never
    authorize pivots or orchestration work; ``max_results`` remains within
    the existing bounded retrieval contract (1..100).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    investigation_id: UUID
    subject_entity_id: UUID
    query: str
    entity_ids: tuple[UUID, ...] = ()
    source_ids: tuple[str, ...] = ()
    document_types: tuple[str, ...] = ()
    max_results: int = Field(default=8, ge=1, le=100)

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        """Reject blank queries and retain their trimmed representation."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("query must not be blank")
        return stripped

    _validate_string_filters = field_validator("source_ids", "document_types")(
        _unique_strings
    )
    _validate_entity_filters = field_validator("entity_ids")(_unique_uuids)


class ResearchAgentClaim(BaseModel):
    """One semantic research claim the model proposes against supplied context.

    The model returns no claim UUID: the application assigns the durable
    ``ResearchClaim.id`` after output validation. Every non-empty claim must
    cite at least one unique stable ``citation_id`` from the exact chunks
    supplied to this model invocation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str
    citation_ids: tuple[UUID, ...]

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        """Trim and reject blank claim text."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("claim text must not be blank")
        return stripped

    @field_validator("citation_ids")
    @classmethod
    def validate_citation_ids(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        """Require at least one citation and reject duplicates within a claim."""
        if not value:
            raise ValueError("a research claim must cite at least one chunk")
        if len(set(value)) != len(value):
            raise ValueError("claim citation_ids must be unique")
        return value


class ResearchAgentDecision(BaseModel):
    """The semantic-only structured output the model returns.

    ``claims=()`` is valid: the model can deterministically express that no
    supplied context is relevant or sufficient to substantiate a factual
    claim. The contract contains no persistence-owned identifiers, no
    timestamps, no verdict/confidence, and no pivot/tool/retrieval request.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    claims: tuple[ResearchAgentClaim, ...] = ()
