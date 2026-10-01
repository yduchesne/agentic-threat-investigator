// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack native-pointer GEOINT stress acceptance (PR 31F-8 §16).
//
// The canonical routed acceptance journey repeated AT LEAST 20 consecutive
// cycles in ONE page process/session:
//
//   Geographic context
//   -> Location Explore (semantic link)
//   -> Location Entities route
//   -> Entity Explore (semantic link)
//   -> Entity GEOINT route
//   -> View Evidence (semantic link)
//   -> Evidence route
//   -> browser Back  -> Entity GEOINT
//   -> browser Back  -> Location Entities
//   -> browser Forward -> Entity GEOINT
//   -> browser Forward -> Evidence
//   -> semantic parent/back -> Geographic context
//
// Every activation is a NORMAL locator click (never dispatchEvent/force/
// coordinate/sleep). Each cycle proves: target visible, native click
// completes, canonical URL (no ``pivot=``, no ``pivot-workbench``),
// content renders, Back/Forward restore the expected route, the returned
// resource stays interactive, the browser stays responsive (heartbeat),
// and no product console error accumulates. The suite runs in Chromium AND
// Firefox (`inspector-firefox` project) with workers=1/retries=0.

import { execSync } from "node:child_process";
import { expect, test, type Page } from "@playwright/test";

const CYCLES = parseInt(process.env.ATI_31F8_STRESS_CYCLES ?? "20", 10);

const GEOINT_SEED_SCRIPT = process.env.E2E_GEOINT_SEED_SCRIPT ?? "";
const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";

/** Login once (the local E2E profile raises the in-process rate limit). */
async function login(page: Page): Promise<void> {
  await page.goto(`${BASE_URL}/login`);
  await page.getByLabel("Username").fill(process.env.E2E_ADMIN_USERNAME ?? "admin");
  await page.getByLabel("Password").fill(process.env.E2E_ADMIN_PASSWORD ?? "admin");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByText("FAKE DATA").waitFor();
}

/** Invoke the harness-only GEOINT seeder (entity_history scenario). */
function seedGeoint(investigationId: string): void {
  if (GEOINT_SEED_SCRIPT === "") {
    throw new Error("E2E_GEOINT_SEED_SCRIPT is not exported by the harness");
  }
  execSync(`"${GEOINT_SEED_SCRIPT}" "${investigationId}" entity_history`, {
    timeout: 180_000,
  });
}

/** Collect product console/page errors; asserted clean at the end. */
function trackConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(`pageerror: ${String(error)}`));
  page.on("console", (message) => {
    if (message.type === "error") {
      errors.push(`console: ${message.text}`);
    }
  });
  return errors;
}

/** Prove the page is alive with a bounded heartbeat after a transition. */
async function heartbeat(page: Page, label: string): Promise<void> {
  await page.evaluate("1+1", undefined, { timeout: 3000 });
  console.log(`31F8-OK ${label}`);
}

async function createInvestigation(page: Page, objective: string): Promise<string> {
  await page.getByRole("link", { name: "New Investigation" }).click();
  await expect(
    page.getByRole("heading", { name: "Create Investigation" }),
  ).toBeVisible({ timeout: 30_000 });
  await page.getByLabel(/^Objective/).fill(objective);
  await page.getByLabel("Indicator value 1").fill("update-package.test");
  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/(overview|geoint)/);
  const url = page.url();
  const investigationId = url.match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
  expect(investigationId).not.toBeUndefined();
  return investigationId ?? "";
}

test.describe("PR 31F-8 routed GEOINT native-pointer stress", () => {
  test.describe.configure({ timeout: 900_000, retries: 0 });

  test(`${CYCLES} consecutive routed cycles in one page process`, async ({ page }) => {
    const consoleErrors = trackConsoleErrors(page);
    await login(page);
    const investigationId = await createInvestigation(page, "PR 31F-8 stress");
    seedGeoint(investigationId);
    const base = `/investigations/${investigationId}`;

    // Start on the canonical GEOINT surface.
    await page.getByRole("tab", { name: "Geographic context" }).click();
    await expect(
      page.getByRole("heading", { name: "Geographic context" }),
    ).toBeVisible({ timeout: 30_000 });

    const topLocations = () =>
      page.getByRole("table", { name: "Top canonical Locations in this Investigation" });
    const locationEntitiesTable = () =>
      page.getByRole("table", { name: "Entities observed at this Location" });
    const entityHistory = () =>
      page.getByRole("table", { name: "Entity geographic observation history" });

    for (let cycle = 0; cycle < CYCLES; cycle += 1) {
      const C = `c${cycle}`;

      // ---- Geographic context -> Location Explore -> Entities route ----
      const locationRow = topLocations().locator("tbody tr", { hasText: "Seattle" });
      await expect(locationRow.getByRole("button", { name: /Explore/ })).toBeVisible(
        { timeout: 30_000 },
      );
      await locationRow.getByRole("button", { name: /Explore/ }).click();
      await page.getByRole("link", { name: "Entities at this location" }).click();
      await expect(page).toHaveURL(
        new RegExp(`${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/geoint/locations/[0-9a-f-]+/entities$`),
      );
      await expect(locationEntitiesTable()).toBeVisible({ timeout: 30_000 });
      await expect(page.getByText("203.0.113.10")).toBeVisible();
      expect(page.url()).not.toContain("pivot=");
      expect(await page.getByTestId("pivot-workbench").count()).toBe(0);
      await heartbeat(page, `${C}-location-entities`);

      // ---- Entity Explore -> Entity GEOINT route ----
      const entityRow = locationEntitiesTable().locator("tbody tr", { hasText: "203.0.113.10" });
      await entityRow.getByRole("button", { name: /Explore/ }).click();
      await page.getByRole("link", { name: "Geographic context for this entity" }).click();
      await expect(page).toHaveURL(
        new RegExp(`${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/geoint/entities/[0-9a-f-]+$`),
      );
      await expect(page.getByText("Current in this Investigation")).toBeVisible({
        timeout: 30_000,
      });
      await heartbeat(page, `${C}-entity-geoint`);

      // ---- View Evidence -> Evidence route ----
      await entityHistory()
        .locator("tbody tr")
        .getByRole("link", { name: "View Evidence" })
        .first()
        .click();
      await expect(page).toHaveURL(
        new RegExp(`${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/evidence/[0-9a-f-]+$`),
      );
      await expect(
        page.getByRole("heading", { name: "Evidence details" }),
      ).toBeVisible({ timeout: 30_000 });
      await heartbeat(page, `${C}-evidence`);

      // ---- browser Back -> Entity GEOINT ----
      await page.goBack();
      await expect(page).toHaveURL(
        new RegExp(`${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/geoint/entities/[0-9a-f-]+$`),
      );
      await expect(page.getByText("Current in this Investigation")).toBeVisible({
        timeout: 30_000,
      });
      // The returned surface is interactive: the history table is live.
      await expect(
        entityHistory().locator("tbody tr").first().getByRole("link", { name: "View Evidence" }),
      ).toBeVisible({ timeout: 30_000 });
      await heartbeat(page, `${C}-back-entity`);

      // ---- browser Back -> Location Entities ----
      await page.goBack();
      await expect(page).toHaveURL(
        new RegExp(`${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/geoint/locations/[0-9a-f-]+/entities$`),
      );
      await expect(locationEntitiesTable()).toBeVisible({ timeout: 30_000 });
      await heartbeat(page, `${C}-back-location`);

      // ---- browser Forward -> Entity GEOINT ----
      await page.goForward();
      await expect(page).toHaveURL(
        new RegExp(`${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/geoint/entities/[0-9a-f-]+$`),
      );
      await expect(page.getByText("Current in this Investigation")).toBeVisible({
        timeout: 30_000,
      });
      await heartbeat(page, `${C}-forward-entity`);

      // ---- browser Forward -> Evidence ----
      await page.goForward();
      await expect(page).toHaveURL(
        new RegExp(`${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/evidence/[0-9a-f-]+$`),
      );
      await expect(
        page.getByRole("heading", { name: "Evidence details" }),
      ).toBeVisible({ timeout: 30_000 });
      await heartbeat(page, `${C}-forward-evidence`);

      // ---- semantic parent/back: Back to Entity, then the GEOINT
      // breadcrumb root link -> Geographic context (next cycle start) ----
      await page.goBack();
      await expect(page).toHaveURL(
        new RegExp(`${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/geoint/entities/[0-9a-f-]+$`),
      );
      await page.getByRole("link", { name: "Geographic context" }).click();
      await expect(page).toHaveURL(`${base}/geoint`);
      await expect(
        page.getByRole("heading", { name: "Geographic context" }),
      ).toBeVisible({ timeout: 30_000 });
      await heartbeat(page, `${C}-back-to-context`);

      // Canonical invariants hold at the end of every cycle.
      expect(page.url()).not.toContain("pivot=");
      expect(await page.getByTestId("pivot-workbench").count()).toBe(0);
      console.log(`31F8-CYCLE-DONE ${cycle + 1}/${CYCLES}`);
    }

    expect(consoleErrors).toEqual([]);
  });
});
