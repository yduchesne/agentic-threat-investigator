// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Legacy Report URL compatibility tests (PR 35-5 amendment).
//
// `/overview/report` is no longer a second live Report implementation; it is
// a bounded ``replace`` redirect to the canonical REPORT surface at
// `/overview`, preserving the stable `#finding-N` fragment.

import { waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import {
  authMeSuccess,
  buildReport,
  completedInvestigationFixture,
  investigationLifecycleHandler,
  reportCurrentHandler,
  resolveSupportPresentationsHandler,
  runtimeFake,
} from "../test/handlers";
import { CSRF_COOKIE_NAME } from "../api/csrf";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";

useHttp();

beforeEach(() => {
  document.cookie = `${CSRF_COOKIE_NAME}=test-csrf-token`;
});

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";

function installReportHandlers(): void {
  setHttpHandlers(
    ...AUTH,
    investigationLifecycleHandler([completedInvestigationFixture()]),
    reportCurrentHandler(buildReport({ investigation_id: INVESTIGATION_ID })),
    resolveSupportPresentationsHandler(),
  );
}

describe("legacy /overview/report compatibility", () => {
  it("replace-redirects to the canonical /overview REPORT surface", async () => {
    installReportHandlers();
    const { router } = renderAtPath(
      `/investigations/${INVESTIGATION_ID}/overview/report`,
    );
    await waitFor(() =>
      expect(router.state.location.pathname).toBe(
        `/investigations/${INVESTIGATION_ID}/overview`,
      ),
    );
    expect(router.state.location.hash).toBe("");
  });

  it("preserves the #finding-N fragment through the redirect", async () => {
    installReportHandlers();
    const { router } = renderAtPath(
      `/investigations/${INVESTIGATION_ID}/overview/report#finding-1`,
    );
    await waitFor(() =>
      expect(router.state.location.pathname).toBe(
        `/investigations/${INVESTIGATION_ID}/overview`,
      ),
    );
    expect(router.state.location.hash).toBe("#finding-1");
    await waitFor(() =>
      expect(document.querySelector("#finding-1")).not.toBeNull(),
    );
  });
});
