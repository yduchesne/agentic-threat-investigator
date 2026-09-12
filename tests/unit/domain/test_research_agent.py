# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PR 22B Research Agent immutable request/output contracts."""

from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
    ResearchAgentRequest,
)


def _request(**overrides: object) -> ResearchAgentRequest:
    """Build a valid deterministic execution request."""
    values: dict[str, object] = {
        "investigation_id": uuid4(),
        "subject_entity_id": uuid4(),
        "query": "  What is T1059.003?  ",
    }
    values.update(overrides)
    return ResearchAgentRequest.model_validate(values)


def test_valid_request_is_immutable_normalized_and_dedicated() -> None:
    """RA-U01: a valid request is accepted, frozen, and normalized."""
    request = _request()

    assert request.query == "What is T1059.003?"
    assert request.max_results == 8
    assert request.entity_ids == ()
    assert request.source_ids == ()
    assert request.document_types == ()
    assert request.investigation_id is not None
    assert request.subject_entity_id is not None


def test_blank_query_is_rejected() -> None:
    """RA-U02: a blank or whitespace-only query fails validation."""
    for query in ("", "   "):
        with pytest.raises(ValidationError):
            _request(query=query)


def test_max_results_boundaries_are_accepted() -> None:
    """RA-U03/RA-U04: the bounded retrieval limits are accepted."""
    assert _request(max_results=1).max_results == 1
    assert _request(max_results=100).max_results == 100


def test_max_results_outside_bounds_is_rejected() -> None:
    """RA-U05: values outside 1..100 fail validation."""
    for value in (0, 101):
        with pytest.raises(ValidationError):
            _request(max_results=value)


def test_duplicate_filter_values_are_deduplicated() -> None:
    """RA-U06: repeated filters collapse to one stable occurrence."""
    first_id, second_id = uuid4(), uuid4()
    request = _request(
        entity_ids=[second_id, first_id, second_id],
        source_ids=["urn:src:b", "urn:src:a", "urn:src:b"],
        document_types=["technique", "technique", "advisory"],
    )

    assert request.entity_ids == (second_id, first_id)
    assert request.source_ids == ("urn:src:b", "urn:src:a")
    assert request.document_types == ("technique", "advisory")


def test_blank_source_and_document_filters_are_rejected() -> None:
    """RA-U07: blank filter entries fail validation."""
    with pytest.raises(ValidationError):
        _request(source_ids=["urn:src:a", "   "])
    with pytest.raises(ValidationError):
        _request(document_types=["", "advisory"])


def test_extra_request_fields_are_forbidden() -> None:
    """Extra request fields (authority/orchestration) fail closed."""
    with pytest.raises(ValidationError):
        _request(depth=3, pivot_authorized=True)


def _claim(**overrides: object) -> ResearchAgentClaim:
    """Build one deterministic semantic claim from override values."""
    values: dict[str, object] = {
        "text": "The technique enables persistence.",
        "citation_ids": (uuid4(),),
    }
    values.update(overrides)
    return ResearchAgentClaim.model_validate(values)


def test_claim_with_one_citation_is_accepted() -> None:
    """RA-U08: a semantic claim citing one stable citation ID is accepted."""
    citation_id = uuid4()
    claim = ResearchAgentClaim(
        text="  Contextual statement.  ", citation_ids=(citation_id,)
    )

    assert claim.text == "Contextual statement."
    assert claim.citation_ids == (citation_id,)


def test_claim_without_citation_is_rejected() -> None:
    """RA-U09: an empty claim citation list fails validation."""
    with pytest.raises(ValidationError):
        ResearchAgentClaim(text="Unsupported statement.", citation_ids=())


def test_claim_duplicate_citation_ids_are_rejected() -> None:
    """RA-U10: repeating one citation ID inside a claim fails validation."""
    citation_id = uuid4()
    with pytest.raises(ValidationError):
        ResearchAgentClaim(
            text="Duplicate citation.", citation_ids=(citation_id, citation_id)
        )


def test_claim_blank_text_is_rejected() -> None:
    """RA-U40: blank or whitespace-only claim text fails validation."""
    for text in ("", "   "):
        with pytest.raises(ValidationError):
            ResearchAgentClaim(text=text, citation_ids=(uuid4(),))


def test_claim_extra_output_fields_are_forbidden() -> None:
    """RA-U38/U39: verdict/confidence/pivot/tool fields fail closed."""
    with pytest.raises(ValidationError):
        _claim(verdict="malicious", call_tool="search")


def test_empty_decision_is_valid() -> None:
    """RA-U11: a decision with zero claims represents irrelevant context."""
    decision = ResearchAgentDecision()

    assert decision.claims == ()


def test_decision_accepts_ordered_claims() -> None:
    """A non-empty decision preserves the model's claim order."""
    first_id, second_id = uuid4(), uuid4()
    decision = ResearchAgentDecision(
        claims=(
            ResearchAgentClaim(text="First claim.", citation_ids=(first_id,)),
            ResearchAgentClaim(text="Second claim.", citation_ids=(second_id,)),
        )
    )

    assert [claim.text for claim in decision.claims] == [
        "First claim.",
        "Second claim.",
    ]


def test_decision_extra_fields_are_forbidden() -> None:
    """The decision contract owns no orchestration/identity fields."""
    with pytest.raises(ValidationError):
        ResearchAgentDecision.model_validate(
            {
                "claims": [],
                "investigation_id": str(uuid4()),
                "result_uuid": str(uuid4()),
                "created_at": "2026-01-01T00:00:00Z",
                "disposition": "sufficient",
            }
        )


def test_decision_model_never_carries_durable_identity_fields() -> None:
    """The semantic output surface is exactly (text, citation_ids) per claim."""
    decision = ResearchAgentDecision.model_validate(
        {"claims": [{"text": "Statement.", "citation_ids": [str(uuid4())]}]}
    )
    [claim] = decision.claims
    assert (
        {"text", "citation_ids"}
        == set(ResearchAgentClaim.model_fields)
        == set(claim.model_dump())
    )
    assert set(ResearchAgentDecision.model_fields) == {"claims"}
    assert isinstance(claim.citation_ids[0], UUID)
