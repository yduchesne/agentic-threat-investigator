// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Route topology tests through the real route table (PR 24A U20-U22, U30).

import { screen, waitFor } from "@testing-library/react";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  ANALYST_USER,
  authMe401,
  authMeSuccess,
  buildGeointSummary,
  buildInvestigation,
  geointSummaryHandler,
  investigationDetailHandler,
  investigationsListHandler,
  jsonResponse,
  runtimeFake,
} from "../test/handlers";

useHttp();

describe("route topology", () => {
  it("redirects protected /investigations to /login when unauthenticated (U20)", async () => {
    setHttpHandlers(authMe401);
    renderAtPath("/investigations");
    await screen.findByRole("heading", { name: "Sign in" });
    expect(screen.queryByText("FAKE DATA")).not.toBeInTheDocument();
    expect(screen.queryByText(ANALYST_USER.alias)).not.toBeInTheDocument();
  });

  it("renders the authenticated shell for a real /auth/me user (U21)", async () => {
    setHttpHandlers(authMeSuccess, runtimeFake, investigationsListHandler([]));
    renderAtPath("/investigations");
    expect(
      await screen.findByRole("heading", { name: /A T I.*Agentic Threat Investigator/ }),
    ).toBeInTheDocument();
    expect(await screen.findByText(ANALYST_USER.alias)).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Investigations" })).toBeInTheDocument();
  });

  it("redirects the authenticated / route to /investigations", async () => {
    setHttpHandlers(authMeSuccess, runtimeFake, investigationsListHandler([]));
    renderAtPath("/");
    expect(
      await screen.findByRole("heading", { name: "Investigations" }),
    ).toBeInTheDocument();
  });

  it("redirects authenticated /login to /investigations (U22)", async () => {
    setHttpHandlers(authMeSuccess, runtimeFake, investigationsListHandler([]));
    renderAtPath("/login");
    expect(
      await screen.findByRole("heading", { name: "Investigations" }),
    ).toBeInTheDocument();
  });

  it("renders a safe 404 for unknown paths (U30)", async () => {
    // NotFoundPage performs no API request.
    setHttpHandlers();
    renderAtPath("/definitely-not-a-route");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
    expect(await screen.findByText("The requested page does not exist.")).toBeInTheDocument();
  });
});

describe("PR 35-2 GEOINT route topology (U05/U06)", () => {
  const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";

  function geointHandlers() {
    return [
      authMeSuccess,
      runtimeFake,
      investigationDetailHandler(
        buildInvestigation({ id: INVESTIGATION_ID, status: "completed" }),
      ),
      http.get("*/api/v1/investigations/:id/geolocations", () =>
        jsonResponse({ items: [], truncated: false }),
      ),
      geointSummaryHandler(buildGeointSummary({ observation_count: 0 })),
    ];
  }

  it("U05: /geoint deterministically redirects (replace) to canonical MAP", async () => {
    setHttpHandlers(...geointHandlers());
    const { router } = renderAtPath(`/investigations/${INVESTIGATION_ID}/geoint`);
    await waitFor(() =>
      expect(router.state.location.pathname).toBe(
        `/investigations/${INVESTIGATION_ID}/geoint/map`,
      ),
    );
    expect(await screen.findByRole("heading", { name: "GEOINT" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "MAP" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });

  it("U06: legacy /map replaces to canonical /geoint/map", async () => {
    setHttpHandlers(...geointHandlers());
    const { router } = renderAtPath(`/investigations/${INVESTIGATION_ID}/map`);
    await waitFor(() =>
      expect(router.state.location.pathname).toBe(
        `/investigations/${INVESTIGATION_ID}/geoint/map`,
      ),
    );
    expect(await screen.findByRole("heading", { name: "GEOINT" })).toBeInTheDocument();
  });

  it("/geoint/table renders the TABLE presentation at its canonical URL", async () => {
    setHttpHandlers(...geointHandlers());
    const { router } = renderAtPath(
      `/investigations/${INVESTIGATION_ID}/geoint/table`,
    );
    expect(await screen.findByRole("heading", { name: "GEOINT" })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe(
      `/investigations/${INVESTIGATION_ID}/geoint/table`,
    );
    expect(screen.getByRole("tab", { name: "TABLE" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });
});
