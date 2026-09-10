# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the bounded PostgreSQL Assessment persistence adapter."""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    AssessmentSizeLimitExceededError,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    Assessment,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql import (
    assessment_repositories,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _assessment(
    *,
    findings: tuple[AnalyticalFinding, ...] = (),
    analyzed: tuple[UUID, ...] = (uuid4(),),
    limitations: tuple[str, ...] = (),
    unresolved: tuple[str, ...] = (),
    next_steps: tuple[str, ...] = (),
) -> Assessment:
    """Build a deterministic candidate Assessment."""
    return Assessment(
        investigation_id=uuid4(),
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="bounded candidate",
        analyzed_evidence_ids=analyzed,
        findings=findings,
        limitations=limitations,
        unresolved_questions=unresolved,
        recommended_next_steps=next_steps,
    )


def _finding(supports: int = 1) -> AnalyticalFinding:
    """Build one Finding with the requested number of distinct support references."""
    return AnalyticalFinding(
        category=FindingCategory.NETWORK,
        disposition=FindingDisposition.SUPPORTING,
        statement="A bounded finding.",
        confidence=AssessmentConfidence.MEDIUM,
        support=tuple(
            EvidenceSupport(kind="evidence", evidence_id=uuid4())
            for _ in range(supports)
        ),
    )


def _session() -> SimpleNamespace:
    """Return a recording session that answers one insert result."""
    return SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(one=lambda: (uuid4(), 1, _RETRIEVED_AT))
        )
    )


def test_repository_rejects_nonpositive_batch_size() -> None:
    """The batch limit must be a positive integer."""
    with pytest.raises(ValueError, match="positive"):
        assessment_repositories.PostgresAssessmentRepository(
            cast(AsyncSession, _session()), batch_size=0
        )
    with pytest.raises(ValueError, match="positive"):
        assessment_repositories.PostgresAssessmentRepository(
            cast(AsyncSession, _session()), batch_size=-3
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "candidate",
    [
        _assessment(analyzed=(uuid4(), uuid4(), uuid4())),
        _assessment(findings=(_finding(), _finding(), _finding())),
        _assessment(findings=(_finding(supports=3),)),
        _assessment(limitations=("a", "b", "c")),
        _assessment(unresolved=("a", "b", "c")),
        _assessment(next_steps=("a", "b", "c")),
    ],
)
async def test_oversized_collection_rejected_before_sql(candidate: Assessment) -> None:
    """The repository rejects oversized input before any SQL executes."""
    session = _session()
    repository = assessment_repositories.PostgresAssessmentRepository(
        cast(AsyncSession, session), batch_size=2
    )

    with pytest.raises(AssessmentSizeLimitExceededError):
        await repository.insert(candidate)

    session.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_at_limit_candidate_serializes_and_executes_once() -> None:
    """A candidate exactly at the limit reaches the stored function once."""
    session = _session()
    repository = assessment_repositories.PostgresAssessmentRepository(
        cast(AsyncSession, session), batch_size=2
    )
    candidate = _assessment(
        analyzed=(uuid4(), uuid4()),
        findings=(_finding(), _finding()),
    )

    persisted = await repository.insert(candidate)

    session.execute.assert_awaited_once()
    assert persisted.id is not None
    assert persisted.version == 1
    parameters = session.execute.await_args.args[1]
    assert parameters["verdict"] == "suspicious"
    assert len(parameters["analyzed"]) == 2
    assert len(parameters["findings"]) == 2
    assert len(parameters["supports"]) == 2
    assert parameters["limitations"] == []
