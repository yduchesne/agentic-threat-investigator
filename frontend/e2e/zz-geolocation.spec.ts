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
// PR 25C: E24's data prerequisite is closed by the deterministic real-stack
// seeding seam. After the browser completes the exact Investigation, this
// spec invokes the harness-only seeder (scripts/e2e-seed-geolocation.sh,
// exported as E2E_SEED_SCRIPT) for the exact browser-created Investigation
// UUID with the allowlisted ``single_mappable`` scenario. The seeder
// persists ordinary canonical IP Entity + GEOLOCATION Evidence rows through
// the normal application repositories into the isolated E2E PostgreSQL; the
// browser then consumes those rows exclusively through the real PR 25A
// endpoint. Seed failure is test failure; there is no data-path skip.
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

import { execSync } from "node:child_process";
import { expect, test, type Locator, type Page } from "@playwright/test";

const OBJECTIVE = "PR 25B investigate geolocation map context";
const ROOT_DOMAIN = "update-package.test";
const SHARED_SESSION_STATE = "test-results/analyst-session.json";

/** The harness-exported absolute path of the seeding helper script. */
const SEED_SCRIPT = process.env.E2E_SEED_SCRIPT ?? "";

/** Invoke the harness-only seeder; any failure fails the test. */
function seedGeolocation(investigationId: string, scenario: string): void {
  if (SEED_SCRIPT === "") {
    throw new Error(
      "E2E_SEED_SCRIPT is not exported: the E2E harness (scripts/e2e.sh) must " +
        "define it before running Playwright",
    );
  }
  try {
    execSync(`"${SEED_SCRIPT}" "${investigationId}" "${scenario}"`, {
      timeout: 120_000,
    });
  } catch (error) {
    const detail = error instanceof Error ? String(error) : String(error);
    throw new Error(
      `geolocation seeding failed for investigation ${investigationId} ` +
        `scenario ${scenario}: ${detail}`,
    );
  }
}

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

  test("E24 principal Map workflow with seeded deterministic geolocation", async ({
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

    // Deterministic real-stack seeding (PR 25C seam): attach the allowlisted
    // single mappable scenario to the exact browser-created Investigation.
    seedGeolocation(investigationId, "single_mappable");

    // Open the Map primary tab.
    await page.getByRole("tab", { name: "Map" }).click();
    await expect(
      page.getByRole("heading", { name: "Investigation Map" }),
    ).toBeVisible({ timeout: 30_000 });

    // The persistent approximation disclaimer is visible normal text.
    await expect(
      page.getByText(/IP geolocation is approximate network-address context/i),
    ).toBeVisible({ timeout: 30_000 });

    // Exact IP of the persisted mappable item in the non-map representation.
    const rows = page.getByRole("table", { name: "All returned geolocation items" });
    await expect(rows).toBeVisible({ timeout: 30_000 });
    await expect(rows.locator("tbody tr")).toHaveCount(1);
    const ipCell = rows.locator("tbody tr").first().locator("th").first();
    await expect(ipCell).toHaveText(/^\d{1,3}(\.\d{1,3}){3}$/);

    // At least one real Leaflet marker renders for persisted mappable data.
    await expect(page.locator(".leaflet-marker-icon").first()).toBeVisible({
      timeout: 30_000,
    });
    expect(await page.locator(".leaflet-marker-icon").count()).toBeGreaterThan(0);

    // Exact Evidence provenance through the non-map row action: the drawer
    // resolves the exact persisted GEOLOCATION Evidence (subject IP + type +
    // source) — never an IP lookup or a substitute row. The provider appears
    // both in the source row and inside the normalized facts section.
    const evidenceButton = rows
      .locator("tbody tr")
      .first()
      .getByRole("button", { name: "View Evidence" });
    await evidenceButton.click();
    const drawer = page.getByRole("dialog", { name: "Evidence" });
    await expect(drawer).toBeVisible({ timeout: 30_000 });
    await expect(drawer.getByText("Subject").first()).toBeVisible();
    await expect(drawer.getByText("203.0.113.10")).toBeVisible();
    await expect(drawer.getByText("Geolocation")).toBeVisible();
    await expect(
      drawer.getByText("urn:ati:source:dbip_city_lite").first(),
    ).toBeVisible();
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