// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Route topology (PR 24A / PR 24B / PR 24C / PR 24D / PR 24E).
//
//   /login             authenticated -> /investigations; else sign-in form
//   /                  authenticated -> /investigations
//   /investigations    real cursor-based list (24B)
//   /investigations/new                       create form (24B)
//   /investigations/:id                        workspace (24B)
//     -> /investigations/:id/overview          substantive Overview
//     -> /investigations/:id/overview/report   full persisted Report
//     -> /investigations/:id/evidence          analyst tables (24C)
//     -> /investigations/:id/relationships
//     -> /investigations/:id/relationships/observations
//     -> /investigations/:id/relationships/evolution   (24E; entity_id
//        query param required, view=evolution|graph)
//     -> /investigations/:id/map                Investigation Map (25B)
//     -> /investigations/:id/research
//     -> /investigations/:id/timeline
//     -> /investigations/:id/history           secondary (24C)
//   *                  safe 404
//
// The same route array backs the production Browser Router and the memory
// route tables used by component tests.

import type { ReactElement } from "react";
import type { RouteObject } from "react-router";
import { Navigate } from "react-router";

import { LoginRoute } from "../auth/LoginPage";
import { RequireAuth } from "../auth/RequireAuth";
import { NotFoundPage } from "../pages/NotFoundPage";
import { AnalystShell } from "../shell/AnalystShell";
import { CreateInvestigationPage } from "../investigations/CreateInvestigationPage";
import { InvestigationsPage } from "../investigations/InvestigationsPage";
import { InvestigationWorkspace, WorkspaceIndexRedirect } from "../investigations/InvestigationWorkspace";
import { OverviewPage } from "../investigations/OverviewPage";
import { ReportPage } from "../investigations/ReportPage";
import { EvidencePage } from "../evidence/EvidencePage";
import { EvidenceDetailPage } from "../evidence/EvidenceDetailPage";
import { HistoryPage } from "../history/HistoryPage";
import { RelationshipsPage } from "../relationships/RelationshipsPage";
import { RelationshipDetailPage } from "../relationships/RelationshipDetailPage";
import { RelationshipObservationsPage } from "../relationships/RelationshipObservationsPage";
import { ObservationDetailPage } from "../relationships/ObservationDetailPage";
import { RelationshipEvolutionPage } from "../relationship-evolution/RelationshipEvolutionPage";
import { InvestigationMapPage } from "../geolocation/InvestigationMapPage";
import { GeointPage } from "../geoint/GeointPage";
import { EntityGeointPage } from "../geoint/EntityGeointPage";
import { LocationEntitiesPage } from "../geoint/LocationEntitiesPage";
import { LocationObservationsPage } from "../geoint/LocationObservationsPage";
import { GeointObservationDetailPage } from "../geoint/GeointObservationDetailPage";
import { ResearchPage } from "../research/ResearchPage";
import { TimelinePage } from "../timeline/TimelinePage";

/** Redirects the authenticated `/` route to the Investigations module. */
function RootHome(): ReactElement {
  return <Navigate to="/investigations" replace />;
}

/** Build the shared route table used by Browser and Memory routers. */
export function createAppRoutes(): RouteObject[] {
  return [
    {
      path: "/login",
      Component: LoginRoute,
    },
    {
      // Pathless guard layout: renders the authenticated shell subtree only
      // after `/auth/me` resolves.
      Component: RequireAuth,
      children: [
        {
          Component: AnalystShell,
          children: [
            { index: true, Component: RootHome },
            { path: "investigations", Component: InvestigationsPage },
            { path: "investigations/new", Component: CreateInvestigationPage },
            {
              path: "investigations/:investigationId",
              Component: InvestigationWorkspace,
              children: [
                {
                  index: true,
                  Component: WorkspaceIndexRedirect,
                },
                { path: "overview", Component: OverviewPage },
                { path: "overview/report", Component: ReportPage },
                { path: "evidence", Component: EvidencePage },
                // PR 31F-8: exact Evidence detail is a routed surface.
                {
                  path: "evidence/:evidenceId",
                  Component: EvidenceDetailPage,
                },
                { path: "relationships", Component: RelationshipsPage },
                // PR 31F-8: exact Relationship detail is a routed surface.
                {
                  path: "relationships/:relationshipId",
                  Component: RelationshipDetailPage,
                },
                {
                  path: "relationships/observations",
                  Component: RelationshipObservationsPage,
                },
                // PR 31F-8: exact observation detail is a routed surface.
                {
                  path: "relationships/observations/:observationId",
                  Component: ObservationDetailPage,
                },
                {
                  path: "relationships/evolution",
                  Component: RelationshipEvolutionPage,
                },
                { path: "research", Component: ResearchPage },
                { path: "map", Component: InvestigationMapPage },
                { path: "geoint", Component: GeointPage },
                // PR 31F-8: GEOINT resources mount as explicit routed
                // surfaces (canonical IDs as path identity).
                {
                  path: "geoint/entities/:entityId",
                  Component: EntityGeointPage,
                },
                {
                  path: "geoint/locations/:locationId/entities",
                  Component: LocationEntitiesPage,
                },
                {
                  path: "geoint/locations/:locationId/observations",
                  Component: LocationObservationsPage,
                },
                {
                  path: "geoint/observations/:observationId",
                  Component: GeointObservationDetailPage,
                },
                { path: "timeline", Component: TimelinePage },
                { path: "history", Component: HistoryPage },
              ],
            },
          ],
        },
      ],
    },
    {
      path: "*",
      Component: NotFoundPage,
    },
  ];
}
