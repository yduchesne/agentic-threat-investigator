# SPDX-License-Identifier: AGPL-3.0-only
"""Application-level bundle of every PR 23A read contract.

The HTTP layer depends on this abstract bundle rather than on any concrete
PostgreSQL query service, so routes never import persistence internals.
Each bundle instance is bound to exactly one short-lived read session;
callers must close it after use.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from agentic_threat_investigator.app.query.assessments import AssessmentQueryService
from agentic_threat_investigator.app.query.evidence import EvidenceQueryService
from agentic_threat_investigator.app.query.history import DomainHistoryQueryService
from agentic_threat_investigator.app.query.investigations import (
    InvestigationQueryService,
)
from agentic_threat_investigator.app.query.relationships import (
    RelationshipObservationQueryService,
    RelationshipQueryService,
)
from agentic_threat_investigator.app.query.reports import ReportQueryService
from agentic_threat_investigator.app.query.research import ResearchResultQueryService
from agentic_threat_investigator.app.query.timeline import TimelineQueryService


class QueryServiceBundle(ABC):
    """One read-session bundle exposing every collection contract (PR 23A).

    A bundle is a composition of narrow single-collection query services
    bound to one short-lived read session. It owns no query policy: each
    collection keeps exactly one canonical ordering, opaque versioned
    cursors, bounded filters, and half-open UTC date ranges.
    """

    investigations: InvestigationQueryService
    evidence: EvidenceQueryService
    relationships: RelationshipQueryService
    relationship_observations: RelationshipObservationQueryService
    research_results: ResearchResultQueryService
    assessments: AssessmentQueryService
    reports: ReportQueryService
    timeline_events: TimelineQueryService
    domain_history: DomainHistoryQueryService

    @abstractmethod
    async def close(self) -> None:
        """Release the bound read session.

        Implementations must be safe to call once per bundle; the session is
        never shared across HTTP requests.
        """
