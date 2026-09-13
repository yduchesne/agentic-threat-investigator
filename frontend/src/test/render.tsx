// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared render helpers (PR 24A).
//
// Each test builds its own QueryClient (no shared Query cache) and, when
// routing is needed, its own Memory Router over the real application route
// table. i18n is initialized once from the global setup.

import { render, type RenderResult } from "@testing-library/react";
import { QueryClient } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { createMemoryRouter, RouterProvider } from "react-router";

import { AppProviders } from "../app/AppProviders";
import { createAppQueryClient } from "../app/queryClient";
import { createAppRoutes } from "../app/routes";

/** Build an isolated QueryClient for one test (zero retry backoff). */
export function freshQueryClient(): QueryClient {
  return createAppQueryClient({ retryDelay: 0 });
}

export interface RenderProvidersOptions {
  queryClient?: QueryClient;
}

/** Render arbitrary children under the production providers. */
export function renderProviders(
  children: ReactElement,
  options: RenderProvidersOptions = {},
): { result: RenderResult; queryClient: QueryClient } {
  const queryClient = options.queryClient ?? freshQueryClient();
  return {
    result: render(<AppProviders queryClient={queryClient}>{children}</AppProviders>),
    queryClient,
  };
}

/** Render the real route table starting at `path` in an isolated Memory Router. */
export function renderAtPath(
  path: string | object,
  options: RenderProvidersOptions = {},
): { result: RenderResult; queryClient: QueryClient } {
  const queryClient = options.queryClient ?? freshQueryClient();
  const routeTable = createMemoryRouter(createAppRoutes(), { initialEntries: [path] });
  return {
    result: render(
      <AppProviders queryClient={queryClient}>
        <RouterProvider router={routeTable} />
      </AppProviders>,
    ),
    queryClient,
  };
}