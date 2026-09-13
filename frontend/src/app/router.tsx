// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// The single application Browser Router (PR 24A).
//
// Created once outside the React component tree; URL/history state is
// owned by React Router, never by a global store.

import { createBrowserRouter } from "react-router";

import { createAppRoutes } from "./routes";

/** Application-wide browser router (Data mode). */
export const router = createBrowserRouter(createAppRoutes());