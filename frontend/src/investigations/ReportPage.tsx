// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Legacy Report URL compatibility (PR 35-5 amendment).
//
// `/investigations/:id/overview/report` is no longer a second live Report
// implementation. It is a bounded ``replace`` redirect to the canonical
// REPORT surface at `/investigations/:id/overview`, preserving any stable
// `#finding-N` fragment so direct deep links keep working. No second report
// query or renderer exists.

import type { ReactElement } from "react";
import { Navigate, useLocation, useParams } from "react-router";

/** Compatibility-only redirect from the legacy Report URL to REPORT. */
export function ReportPage(): ReactElement {
  const { investigationId = "" } = useParams();
  const location = useLocation();
  return (
    <Navigate
      to={`/investigations/${investigationId}/overview${location.hash}`}
      replace
    />
  );
}
