// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 25B Investigation Map principal workflow (E24).
//
// Runs against the production-path stack created by the repository E2E
// harness (scripts/e2e.sh): built/static React + Nginx -> real FastAPI ->
// real PostgreSQL -> real durable Investigation worker with the
// deterministic offline LLM boundary, over the packaged PR 23D fake world.
// No live Internet, no live threat-intelligence provider, and no live
// LLM; `FAKE DATA` remains visible throughout. The PR 25A endpoint is
// real — no geolocation interception, no MSW, no mocked fetch.
//
// E24 DATA PREREQUISITE (PR 25B STOP condition, docs/PR_PLAN.md PR 25B):
//
//   The current fake world (scenarios F01..F05) contains no DB-IP City
//   Lite provider and persists no ``urn:ati:evidence:geolocation`` rows:
//   GEOLOCATION evidence is produced only by the DbIpCityLiteProvider,
//   which is composed solely when ``dbip_city_lite_artifact_uri`` is
//   configured. Therefore a completed fake-world Investigation currently
//   returns an honest empty geolocation projection, and the marker/plotted
//   assertions below cannot pass until a deterministic real-stack seeding
//   seam exists (see the PR 25B delivered summary / STOP report).
//
//   This spec therefore implements the exact PR 25B §52 path and, when the
//   completed Investigation's Map shows the honest empty state (no
//   persisted mappable GEOLOCATION context), records the STOP condition
//   and skips precisely — it never asserts a false pass and never depends
//   on external basemap tile delivery. When the deterministic seeding lands,
//   the same spec proves the full path: geolocation data through the real
//   stack -> visible disclaimer -> exact IP in the non-map representation
//   -> at least one real marker -> exact Evidence provenance -> safe return
//   -> `FAKE DATA` -> clean console.
//
// The spec file is named ``zz-*`` so it runs after the PR 24A/24B specs
// and reuses the authenticated session captured by the PR 24C suite
// (zz-analyst-tables.spec.ts -> test-results/analyst-session.json); the
// backend login rate limit is therefore never exceeded.
//
// Interaction notes: while a detail drawer (a full-viewport fixed layer)
// is open, the Chromium composite locator hit-test path can wedge the
// browser main thread on this stack; raw pointer events are not affected.
// Overlay controls therefore use the same direct click-event dispatch used
// by zz-relationship-evolution.spec.ts; page-level controls use normal
// clicks.

import { expect, test, type Locator, type Page } from "@playwright/test";

const OBJECTIVE = "PR 25B investigate geolocation map context";
const ROOT_DOMAIN = "update-package.test";
const SHARED_SESSION_STATE = "test-results/analyst-session.json";

/** Recorded PR 25B E24 data STOP (docs/PR_PLAN.md PR 25B). */
const E24_DATA_STOP =
  "E24 data STOP: the current PR 23D fake world persists no mappable " +
  "GEOLOCATION Evidence (no DB-IP provider); the Map honestly reports " +
  "empty context. Deterministic real-stack geolocation seeding is a " +
  "documented prerequisite for the marker assertions.";

/** Activate an overlay control through a direct click-event dispatch. */
async function activate(page: Page, target: Locator): Promise<void> {
  await expect(target).toBeVisible({ timeout: 30_000 });
  await target.dispatchEvent("click");
}

/** Create and complete one deterministic fake-world Investigation. */
async function completeInvestigation(
  page: Page,
  objective: string,
  rootDomain: string,
): Promise<string> {
  await page.getByRole("link", { name: "New Investigation" }).click();
  await expect(
    page.getByRole("heading", { name: "Create Investigation" }),
  ).toBeVisible();
  await page.getByLabel(/^Objective/).fill(objective);
  await page.getByLabel("Indicator value 1").fill(rootDomain);
  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
  const url = page.url();
  const investigationId = url.match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
  expect(investigationId).not.toBeUndefined();
  await expect(
    page.getByRole("heading", { name: objective }),
  ).toBeVisible({ timeout: 20_000 });
  await expect(page.getByLabel("Status: Completed").first()).toBeVisible({
    timeout: 240_000,
  });
  return investigationId ?? "";
}

test.describe("PR 25B real-stack Investigation Map", () => {
  test.describe.configure({ timeout: 300_000 });
  test.use({ storageState: SHARED_SESSION_STATE });

  test("E24 principal Map workflow (data prerequisite required)", async ({
    page,
  }) => {
    const consoleErrors: string[] = [];
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${String(error)}`));
    page.on("console", (message) => {
      if (message.type === "error") {
        consoleErrors.push(`console: ${message.text}`);
      }
    });

    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const investigationId = await completeInvestigation(page, OBJECTIVE, ROOT_DOMAIN);
    expect(investigationId).not.toBe("");

    // Open the Map primary tab.
    await page.getByRole("tab", { name: "Map" }).click();
    await expect(
      page.getByRole("heading", { name: "Investigation Map" }),
    ).toBeVisible({ timeout: 30_000 });

    // The persistent approximation disclaimer is visible normal text.
    await expect(
      page.getByText(/IP geolocation is approximate network-address context/i),
    ).toBeVisible({ timeout: 30_000 });

    // E24 data prerequisite: a completed fake-world Investigation currently
    // persists no GEOLOCATION Evidence, so the honest empty state appears.
    const emptyState = page.getByText(
      "No geolocation context is available for this Investigation.",
    );
    const emptyVisible = await emptyState.isVisible().catch(() => false);
    if (emptyVisible) {
      console.log(`E24-DATA-STOP ${E24_DATA_STOP}`);
      test.skip(true, E24_DATA_STOP);
      return;
    }

    // --- Data-present path (exercised once deterministic seeding exists) ---

    // Exact IP of a persisted mappable item in the non-map representation.
    const rows = page.getByRole("table", { name: "All returned geolocation items" });
    await expect(rows).toBeVisible({ timeout: 30_000 });
    const ipCell = rows.locator("tbody tr").first().locator("th").first();
    await expect(ipCell).toHaveText(/^\d{1,3}(\.\d{1,3}){3}$/);

    // At least one real Leaflet marker renders for persisted mappable data.
    await expect(page.locator(".leaflet-marker-icon").first()).toBeVisible({
      timeout: 30_000,
    });
    expect(await page.locator(".leaflet-marker-icon").count()).toBeGreaterThan(0);

    // Exact Evidence provenance through the non-map row action.
    const evidenceButton = rows
      .locator("tbody tr")
      .first()
      .getByRole("button", { name: "View Evidence" });
    await evidenceButton.click();
    const drawer = page.getByRole("dialog", { name: "Evidence" });
    await expect(drawer).toBeVisible({ timeout: 30_000 });
    // The exact persisted Evidence subject is shown (never an IP lookup).
    await expect(drawer.getByText("Subject").first()).toBeVisible();
    // Return safely to the Map.
    await activate(page, page.getByRole("button", { name: "Close detail" }));
    await expect(page.getByRole("dialog", { name: "Evidence" })).not.toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Investigation Map" }),
    ).toBeVisible();

    // The existing global fake-data indicator remains visible; the browser
    // console stayed clean. Correctness never depended on external tile
    // delivery (ATI data assertions use the list and markers, not tiles).
    expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });
});