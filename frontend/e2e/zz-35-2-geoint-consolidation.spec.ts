// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 35-2 GEOINT UI consolidation (Chromium + Firefox).
//
// Runs the focused consolidation journey against the authoritative
// repository harness (scripts/e2e.sh), on the production-path topology
// (built frontend -> real FastAPI -> real PostgreSQL -> deterministic Fake
// World):
//
//   primary navigation exposes GEOINT and no separate Map/Geographic context
//   -> legacy /map replaces to canonical /geoint/map
//   -> GEOINT MAP selected with bounded geolocation content
//   -> TABLE selected with bounded summary + Top Locations
//   -> TABLE refresh reconstructs the selected sub-tab
//   -> TABLE Explore Location -> routed GEOINT resource -> Back to TABLE
//   -> MAP exact Evidence -> Back to MAP
//   -> 10 stable MAP <-> TABLE cycles (no URL churn, no wedge, clean console)
//
// Every activation is a normal locator click with bounded `expect`
// timeouts. No `force`, dispatchEvent, sleep, reload-as-workaround, or
// retry-based hiding is used.

import { execSync } from "node:child_process";
import { expect, test, type Page } from "@playwright/test";

const ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 35-2 GEOINT consolidation acceptance";

const SEED_SCRIPT = process.env.E2E_SEED_SCRIPT ?? "";
const GEOINT_SEED_SCRIPT = process.env.E2E_GEOINT_SEED_SCRIPT ?? "";
const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";

/** Invoke the harness-only geolocation seeder; any failure fails the test. */
function seedGeolocation(investigationId: string, scenario: string): void {
  if (SEED_SCRIPT === "") {
    throw new Error(
      "E2E_SEED_SCRIPT is not exported: the E2E harness (scripts/e2e.sh) " +
        "must define it before running Playwright",
    );
  }
  execSync(`"${SEED_SCRIPT}" "${investigationId}" "${scenario}"`, {
    timeout: 180_000,
  });
}

/** Invoke the harness-only GEOINT seeder; any failure fails the test. */
function seedGeoint(investigationId: string, scenario: string): void {
  if (GEOINT_SEED_SCRIPT === "") {
    throw new Error(
      "E2E_GEOINT_SEED_SCRIPT is not exported: the E2E harness " +
        "(scripts/e2e.sh) must define it before running Playwright",
    );
  }
  execSync(`"${GEOINT_SEED_SCRIPT}" "${investigationId}" "${scenario}"`, {
    timeout: 180_000,
  });
}

/** Collect product console/page errors; asserted clean at the end. */
function trackConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(`pageerror: ${String(error)}`));
  page.on("console", (message) => {
    if (message.type() === "error") {
      errors.push(`console: ${message.text()}`);
    }
  });
  return errors;
}

/** Prove the page is alive with a bounded heartbeat after a transition. */
async function heartbeat(page: Page, label: string): Promise<void> {
  await page.evaluate("1+1", undefined, { timeout: 3000 });
  console.log(`35-2-OK ${label}`);
}

async function login(page: Page): Promise<void> {
  await page.goto(`${BASE_URL}/login`);
  await page.getByLabel("Username").fill(process.env.E2E_ADMIN_USERNAME ?? "admin");
  await page.getByLabel("Password").fill(process.env.E2E_ADMIN_PASSWORD ?? "admin");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByText("FAKE DATA").waitFor();
}

/** Create and complete one deterministic fake-world Investigation. */
async function completeInvestigation(page: Page): Promise<string> {
  await page.getByRole("link", { name: "New Investigation" }).click();
  await expect(
    page.getByRole("heading", { name: "Create Investigation" }),
  ).toBeVisible({ timeout: 30_000 });
  await page.getByLabel(/^Objective/).fill(OBJECTIVE);
  await page.getByLabel("Indicator value 1").fill(ROOT_DOMAIN);
  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
  const investigationId = page.url().match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
  expect(investigationId).not.toBeUndefined();
  await expect(page.getByRole("heading", { name: OBJECTIVE })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByLabel("Status: Completed").first()).toBeVisible({
    timeout: 240_000,
  });
  return investigationId ?? "";
}

test.describe("PR 35-2 GEOINT consolidation", () => {
  test.describe.configure({ timeout: 600_000, retries: 0 });
  test.use({ storageState: { cookies: [], origins: [] } });

  test("consolidated GEOINT MAP/TABLE journey + stability", async ({ page }) => {
    await login(page);
    // Register console/pageerror tracking AFTER the sign-in navigation: the
    // login page's unauthenticated `/auth/me` probe is an expected 401, not
    // a product error. The authenticated journey below must stay clean.
    const consoleErrors = trackConsoleErrors(page);
    const investigationId = await completeInvestigation(page);
    seedGeolocation(investigationId, "multi_ioc");
    seedGeoint(investigationId, "entity_history");
    const base = `/investigations/${investigationId}`;

    // Primary navigation: exactly one consolidated GEOINT primary tab and
    // no separate Map/Geographic context tabs.
    const majorTabs = await page.getByRole("tab").allTextContents();
    expect(majorTabs).toEqual([
      "Overview",
      "Evidence",
      "Graph",
      "GEOINT",
      "Research",
      "Timeline",
    ]);
    expect(await page.getByRole("tab", { name: "Map", exact: true }).count()).toBe(0);
    expect(
      await page.getByRole("tab", { name: "Geographic context", exact: true }).count(),
    ).toBe(0);

    // Legacy /map deterministically replaces to canonical GEOINT MAP.
    await page.goto(`${base}/map`);
    await expect(page).toHaveURL(`${base}/geoint/map`);
    await expect(page.getByRole("heading", { name: "GEOINT" })).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByRole("tab", { name: "MAP" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    // MAP keeps the bounded IP-geolocation projection with its disclaimer
    // and the always-available non-map list.
    await expect(
      page.getByText(/IP geolocation is approximate network-address context/i),
    ).toBeVisible({ timeout: 30_000 });
    const mapRows = page
      .getByRole("table", { name: "All returned geolocation items" })
      .locator("tbody tr");
    await expect(mapRows.first()).toBeVisible({ timeout: 30_000 });
    // The seeded bounded IP-geolocation rows are rendered (the Fake World
    // pipeline may contribute further rows).
    await expect(mapRows.filter({ hasText: "203.0.113.10" })).toHaveCount(1);
    await expect(mapRows.filter({ hasText: "203.0.113.20" })).toHaveCount(1);
    expect(await page.locator(".leaflet-marker-icon").count()).toBeGreaterThan(0);

    // TABLE is a URL-owned sibling sub-tab.
    await page.getByRole("tab", { name: "TABLE" }).click();
    await expect(page).toHaveURL(`${base}/geoint/table`);
    await expect(page.getByRole("tab", { name: "TABLE" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    const topLocations = page.getByRole("table", {
      name: "Top canonical Locations in this Investigation",
    });
    await expect(topLocations).toBeVisible({ timeout: 30_000 });
    await expect(topLocations.getByText("Seattle")).toBeVisible();
    await expect(topLocations.getByText("Dallas")).toBeVisible();
    await expect(page.getByText("Bounded summary")).toBeVisible();
    // TABLE is the non-map presentation.
    expect(await page.locator(".leaflet-marker-icon").count()).toBe(0);

    // Deep-link/refresh reconstructs the selected TABLE sub-tab.
    await page.reload();
    await expect(page).toHaveURL(`${base}/geoint/table`);
    await expect(page.getByRole("tab", { name: "TABLE" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(topLocations.getByText("Seattle")).toBeVisible({ timeout: 30_000 });

    // TABLE Explore Location -> routed GEOINT resource -> Back to TABLE.
    const seattleRow = topLocations.locator("tbody tr", { hasText: "Seattle" });
    await seattleRow.getByRole("button", { name: /Explore/ }).click();
    await page.getByRole("link", { name: "Entities at this location" }).click();
    await expect(page).toHaveURL(/\/geoint\/locations\/[0-9a-f-]+\/entities$/);
    await expect(
      page.getByRole("table", { name: "Entities observed at this Location" }),
    ).toBeVisible({ timeout: 30_000 });
    await page.goBack();
    await expect(page).toHaveURL(`${base}/geoint/table`);
    await expect(page.getByRole("tab", { name: "TABLE" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await heartbeat(page, "back-to-table");

    // MAP exact Evidence -> routed in-page detail -> Back to MAP origin.
    await page.getByRole("tab", { name: "MAP" }).click();
    await expect(page).toHaveURL(`${base}/geoint/map`);
    const viewButton = page
      .getByRole("table", { name: "All returned geolocation items" })
      .locator("tbody tr")
      .first()
      .getByRole("button", { name: "View Evidence" });
    await viewButton.click();
    await expect(page.getByRole("heading", { name: "Evidence" })).toBeVisible({
      timeout: 30_000,
    });
    await page.getByRole("button", { name: "Back to Evidence" }).click();
    await expect(page).toHaveURL(`${base}/geoint/map`);
    await expect(page.getByRole("tab", { name: "MAP" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await heartbeat(page, "back-to-map");

    // 10 stable MAP <-> TABLE cycles: correct URL/selection, no URL churn
    // after settling, and no input/main-thread wedge.
    for (let cycle = 0; cycle < 10; cycle += 1) {
      await page.getByRole("tab", { name: "TABLE" }).click();
      await expect(page).toHaveURL(`${base}/geoint/table`);
      await expect(page.getByRole("tab", { name: "TABLE" })).toHaveAttribute(
        "aria-selected",
        "true",
      );
      await heartbeat(page, `table-${cycle}`);
      await expect(page).toHaveURL(`${base}/geoint/table`);

      await page.getByRole("tab", { name: "MAP" }).click();
      await expect(page).toHaveURL(`${base}/geoint/map`);
      await expect(page.getByRole("tab", { name: "MAP" })).toHaveAttribute(
        "aria-selected",
        "true",
      );
      await heartbeat(page, `map-${cycle}`);
      await expect(page).toHaveURL(`${base}/geoint/map`);
    }

    expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });
});
