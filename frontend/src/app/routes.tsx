// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Route topology (PR 24A / PR 24B).
//
//   /login             authenticated -> /investigations; else sign-in form
//   /                  authenticated -> /investigations
//   /investigations    real cursor-based list (24B)
//   /investigations/new                       create form (24B)
//   /investigations/:id                        workspace (24B)
//     -> /investigations/:id/overview          substantive Overview
//     -> /investigations/:id/overview/report   full persisted Report
//     -> evidence/relationships/research/timeline bounded placeholders
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
import { InvestigationWorkspace } from "../investigations/InvestigationWorkspace";
import { OverviewPage } from "../investigations/OverviewPage";
import { ReportPage } from "../investigations/ReportPage";
import {
  WorkspacePlaceholderPage,
  type WorkspacePlaceholderKind,
} from "../investigations/WorkspacePlaceholderPage";

/** Redirects the authenticated `/` route to the Investigations module. */
function RootHome(): ReactElement {
  return <Navigate to="/investigations" replace />;
}

/** One bounded PR 24C placeholder route. */
function PlaceholderRoute({ kind }: { kind: WorkspacePlaceholderKind }): ReactElement {
  return <WorkspacePlaceholderPage kind={kind} />;
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
                  element: <Navigate to="overview" replace />,
                },
                { path: "overview", Component: OverviewPage },
                { path: "overview/report", Component: ReportPage },
                {
                  path: "evidence",
                  element: <PlaceholderRoute kind="evidence" />,
                },
                {
                  path: "relationships",
                  element: <PlaceholderRoute kind="relationships" />,
                },
                {
                  path: "research",
                  element: <PlaceholderRoute kind="research" />,
                },
                {
                  path: "timeline",
                  element: <PlaceholderRoute kind="timeline" />,
                },
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