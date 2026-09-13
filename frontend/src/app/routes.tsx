// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Route topology (PR 24A).
//
//   /login             authenticated -> /investigations; else sign-in form
//   /                  authenticated -> /investigations
//   /investigations    authenticated placeholder (24A)
//   *                  safe 404
//
// The same route array backs the production Browser Router and the memory
// route tables used by component tests.

import type { ReactElement } from "react";
import type { RouteObject } from "react-router";
import { Navigate } from "react-router";

import { LoginRoute } from "../auth/LoginPage";
import { RequireAuth } from "../auth/RequireAuth";
import { InvestigationsPlaceholderPage } from "../pages/InvestigationsPlaceholderPage";
import { NotFoundPage } from "../pages/NotFoundPage";
import { AnalystShell } from "../shell/AnalystShell";

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
            { path: "investigations", Component: InvestigationsPlaceholderPage },
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