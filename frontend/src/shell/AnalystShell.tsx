// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Responsive authenticated analyst shell (PR 24A).

import { Box } from "@mui/material";
import type { ReactElement } from "react";
import { Outlet } from "react-router";

import { FakeDataBanner } from "./FakeDataBanner";
import { AppHeader } from "./AppHeader";
import { useMeQuery } from "../auth/auth-queries";

/**
 * The authenticated application shell: header, runtime-mode indicator and
 * the routed main outlet. Server state comes from TanStack Query and
 * navigation state from React Router — no global store is introduced.
 */
export function AnalystShell(): ReactElement {
  const me = useMeQuery();
  if (me.state !== "authenticated" || me.user === null) {
    // RequireAuth gates this route; render nothing defensively.
    return <Box aria-hidden="true" sx={{ display: "none" }} />;
  }
  return (
    <Box sx={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <AppHeader user={me.user} />
      <FakeDataBanner />
      <Box component="main" role="main" sx={{ flexGrow: 1, px: 2, py: 2 }}>
        <Outlet />
      </Box>
    </Box>
  );
}