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
from agentic_threat_investigator.app.query.geoint import (
    DEFAULT_GEONT_SUMMARY_TOP_LOCATIONS,
    GeointQueryService,
)
from agentic_threat_investigator.app.query.geolocation import (
    DEFAULT_MAX_MAP_GEOLOCATION_ITEMS,
    InvestigationGeolocationQueryService,
)
from agentic_threat_investigator.app.query.graph import GraphQueryService
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
from agentic_threat_investigator.app.query.services import QueryServiceBundle
from agentic_threat_investigator.app.query.timeline import TimelineQueryService

from .assessments import PostgresAssessmentQueryService
from .evidence import PostgresEvidenceQueryService
from .geoint import PostgresGeointQueryService
from .geolocation import PostgresInvestigationGeolocationQueryService
from .graph import PostgresGraphQueryService
from .history import PostgresDomainHistoryQueryService
from .investigations import PostgresInvestigationQueryService
from .relationships import (
    PostgresRelationshipObservationQueryService,
    PostgresRelationshipQueryService,
)
from .reports import PostgresReportQueryService
from .research import PostgresResearchResultQueryService
from .timeline import PostgresTimelineQueryService


class PostgresQueryServices(QueryServiceBundle):
    """Expose every PR 23A read contract bound to one session."""

    def __init__(
        self,
        session: AsyncSession,
        limits: QueryLimits | None = None,
        geolocation_max_items: int | None = None,
        geoint_summary_top_locations: int | None = None,
    ) -> None:
        """Bind the session; defaults to the module-standard limits.

        ``geolocation_max_items`` is the server-owned hard bound of the
        PR 25A geolocation projection, semantically separate from pageable
        collection sizes; it defaults to the module-standard map bound.
        ``geoint_summary_top_locations`` is the server-owned hard bound of
        the PR 26D summary top-location groups; it defaults to the
        module-standard summary bound.
        """
        self._session = session
        query_limits = limits or QueryLimits()
        self.investigations: InvestigationQueryService = (
            PostgresInvestigationQueryService(session, query_limits)
        )
        self.evidence: EvidenceQueryService = PostgresEvidenceQueryService(
            session, query_limits
        )
        self.geolocations: InvestigationGeolocationQueryService = (
            PostgresInvestigationGeolocationQueryService(
                session,
                geolocation_max_items
                if geolocation_max_items is not None
                else DEFAULT_MAX_MAP_GEOLOCATION_ITEMS,
            )
        )
        self.geoint: GeointQueryService = PostgresGeointQueryService(
            session,
            query_limits,
            geoint_summary_top_locations
            if geoint_summary_top_locations is not None
            else DEFAULT_GEONT_SUMMARY_TOP_LOCATIONS,
        )
        self.graph: GraphQueryService = PostgresGraphQueryService(session, query_limits)
        self.relationships: RelationshipQueryService = PostgresRelationshipQueryService(
            session, query_limits
        )
        self.relationship_observations: RelationshipObservationQueryService = (
            PostgresRelationshipObservationQueryService(session, query_limits)
        )
        self.research_results: ResearchResultQueryService = (
            PostgresResearchResultQueryService(session, query_limits)
        )
        self.assessments: AssessmentQueryService = PostgresAssessmentQueryService(
            session, query_limits
        )
        self.reports: ReportQueryService = PostgresReportQueryService(
            session, query_limits
        )
        self.timeline_events: TimelineQueryService = PostgresTimelineQueryService(
            session, query_limits
        )
        self.domain_history: DomainHistoryQueryService = (
            PostgresDomainHistoryQueryService(session, query_limits)
        )

    async def close(self) -> None:
        """Release the bound read session."""
        await self._session.close()
