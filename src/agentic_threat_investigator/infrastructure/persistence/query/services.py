# SPDX-License-Identifier: AGPL-3.0-only
"""Bundle of the PR 23A PostgreSQL read query services.

One :class:`PostgresQueryServices` instance shares a single read session and
the configured page-size limits across every collection contract. Callers
open short read-only UnitOfWork/session scopes; queries never hold locks and
never span an HTTP lifetime in the future API.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.assessments import AssessmentQueryService
from agentic_threat_investigator.app.query.evidence import EvidenceQueryService
from agentic_threat_investigator.app.query.history import DomainHistoryQueryService
from agentic_threat_investigator.app.query.investigations import (
    InvestigationQueryService,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.query.relationships import (
    RelationshipObservationQueryService,
    RelationshipQueryService,
)
from agentic_threat_investigator.app.query.reports import ReportQueryService
from agentic_threat_investigator.app.query.research import ResearchResultQueryService
from agentic_threat_investigator.app.query.timeline import TimelineQueryService

from .assessments import PostgresAssessmentQueryService
from .evidence import PostgresEvidenceQueryService
from .history import PostgresDomainHistoryQueryService
from .investigations import PostgresInvestigationQueryService
from .relationships import (
    PostgresRelationshipObservationQueryService,
    PostgresRelationshipQueryService,
)
from .reports import PostgresReportQueryService
from .research import PostgresResearchResultQueryService
from .timeline import PostgresTimelineQueryService


class PostgresQueryServices:
    """Expose every PR 23A read contract bound to one session."""

    def __init__(
        self, session: AsyncSession, limits: QueryLimits | None = None
    ) -> None:
        """Bind the session; defaults to the module-standard page limits."""
        self.investigations: InvestigationQueryService = (
            PostgresInvestigationQueryService(session, limits or QueryLimits())
        )
        self.evidence: EvidenceQueryService = PostgresEvidenceQueryService(
            session, limits or QueryLimits()
        )
        self.relationships: RelationshipQueryService = PostgresRelationshipQueryService(
            session, limits or QueryLimits()
        )
        self.relationship_observations: RelationshipObservationQueryService = (
            PostgresRelationshipObservationQueryService(
                session, limits or QueryLimits()
            )
        )
        self.research_results: ResearchResultQueryService = (
            PostgresResearchResultQueryService(session, limits or QueryLimits())
        )
        self.assessments: AssessmentQueryService = PostgresAssessmentQueryService(
            session, limits or QueryLimits()
        )
        self.reports: ReportQueryService = PostgresReportQueryService(
            session, limits or QueryLimits()
        )
        self.timeline_events: TimelineQueryService = PostgresTimelineQueryService(
            session, limits or QueryLimits()
        )
        self.domain_history: DomainHistoryQueryService = (
            PostgresDomainHistoryQueryService(session, limits or QueryLimits())
        )
