// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT MAP/TABLE sub-navigation tests (PR 35-2 U07/U08/U18/U20).
//
// Sub-tab selection is URL-owned: refresh/deep links reconstruct it, the
// active destination is inert (no same-URL navigation), and the inactive
// destination is a semantic React Router link inside an accessible
// navigation region.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import {
  authMeSuccess,
  buildGeointSummary,
  buildInvestigation,
  geointSummaryHandler,
  investigationDetailHandler,
  jsonResponse,
  runtimeFake,
} from "../test/handlers";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}/geoint`;

function handlers() {
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

describe("GEOINT MAP/TABLE sub-tabs", () => {
  it("U07/U20: MAP is inert-selected on /geoint/map and TABLE is a semantic link", async () => {
    setHttpHandlers(...handlers());
    renderAtPath(`${BASE}/map`);
    await screen.findByRole("heading", { name: "GEOINT" });
    const nav = screen.getByRole("navigation", { name: "GEOINT view" });
    const mapTab = screen.getByRole("tab", { name: "MAP" });
    const tableTab = screen.getByRole("tab", { name: "TABLE" });
    expect(nav).toBeInTheDocument();
    expect(mapTab).toHaveAttribute("aria-selected", "true");
    expect(mapTab.closest("a")).toBeNull();
    expect(tableTab).toHaveAttribute("aria-selected", "false");
    expect(tableTab.closest("a")).toHaveAttribute("href", `${BASE}/table`);
  });

  it("U08: TABLE is inert-selected on /geoint/table and MAP is a semantic link", async () => {
    setHttpHandlers(...handlers());
    renderAtPath(`${BASE}/table`);
    await screen.findByRole("heading", { name: "GEOINT" });
    const mapTab = screen.getByRole("tab", { name: "MAP" });
    const tableTab = screen.getByRole("tab", { name: "TABLE" });
    expect(tableTab).toHaveAttribute("aria-selected", "true");
    expect(tableTab.closest("a")).toBeNull();
    expect(mapTab.closest("a")).toHaveAttribute("href", `${BASE}/map`);
  });

  it("U18: activating the already-active sub-tab performs no same-URL navigation", async () => {
    setHttpHandlers(...handlers());
    const { router } = renderAtPath(`${BASE}/map`);
    await screen.findByRole("heading", { name: "GEOINT" });
    const before = router.state.location.key;
    await userEvent.click(screen.getByRole("tab", { name: "MAP" }));
    expect(router.state.location.pathname).toBe(`${BASE}/map`);
    expect(router.state.location.key).toBe(before);
  });
});
