// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 26E canonical GEOINT workspace matrix (G1-G6).
//
// Same production-path topology and interaction conventions as the
// PR 25C/E24-E28 specs: built/static React + Nginx -> real FastAPI ->
// real PostgreSQL 18 + PostGIS, deterministic offline LLM boundary, and
// no interception or injected state. Deterministic canonical geographic
// context is attached through the harness-only GEOINT seeder to the exact
// browser-created Investigation UUID; the seeder creates ordinary
// GEOLOCATION Evidence rows and drives the *production*
// GeoResolutionWorker + canonical resolver to completion — the canonical
// Location / EntityLocationObservation rows are never inserted directly.
// Reference geography is loaded through the normal PR 26B build/import
// work by the harness. Every read goes through the real PR 26D API.
//
// G1  entity history: two Locations/times, correct Investigation-relative
//     current, both history rows, distinct timestamps, exact Evidence
//     drill-down, no movement path.
// G2  same-Location entities stay individually inspectable; no
//     relationship/coordination language.
// G3  containment: exact vs included, server-owned, honest status.
// G4  cross-Investigation: I1 sees only I1; the I2 observation is a safe
//     404 under I1; no current leak.
// G5  non-mappable: valid observation without coordinates stays usable.
// G6  Chromium pivot stability: GEOINT row -> Location -> Entity ->
//     Evidence -> Back -> Close completes without a hang.

import { execSync } from "node:child_process";
import { expect, test, type Locator, type Page } from "@playwright/test";

const SHARED_SESSION_STATE = "test-results/analyst-session.json";

/** The harness-exported absolute path of the GEOINT seeding helper. */
const GEOINT_SEED_SCRIPT = process.env.E2E_GEOINT_SEED_SCRIPT ?? "";

/** Invoke the harness-only GEOINT seeder; any failure fails the test. */
function seedGeoint(
  investigationId: string,
  scenario: string,
  otherInvestigationId = "",
): string {
  if (GEOINT_SEED_SCRIPT === "") {
    throw new Error(
      "E2E_GEOINT_SEED_SCRIPT is not exported: the E2E harness " +
        "(scripts/e2e.sh) must define it before running Playwright",
    );
  }
  try {
    const args = [investigationId, scenario];
    if (otherInvestigationId !== "") {
      args.push(otherInvestigationId);
    }
    return execSync(
      `"${GEOINT_SEED_SCRIPT}" ${args.map((value) => `"${value}"`).join(" ")}`,
      { timeout: 180_000 },
    ).toString();
  } catch (error) {
    const detail = error instanceof Error ? String(error) : String(error);
    throw new Error(
      `geoint seeding failed for investigation ${investigationId} ` +
        `scenario ${scenario}: ${detail}`,
    );
  }
}

/** Collect page errors and console errors; assert clean at the end. */
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

/** Click a target inside a fixed overlay via the raw pointer path. */
async function clickForce(page: Page, target: Locator): Promise<void> {
  await expect(target).toBeVisible({ timeout: 30_000 });
  let box: { x: number; y: number; width: number; height: number } | null = null;
  for (let attempt = 0; attempt < 5 && box === null; attempt += 1) {
    box = await target.boundingBox();
    if (box === null) {
      await page.waitForTimeout(300);
    }
  }
  if (box === null) {
    throw new Error(`no bounding box for ${target}`);
  }
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2, { delay: 40 });
}

/**
 * Create one browser-created Investigation and return its UUID.
 *
 * The GEOINT workspace is functional for any Investigation status, so the
 * spec only waits for the 202 navigation (never the full fake-world
 * pipeline completion); the canonical geography is then seeded through the
 * harness seeder.
 */
async function createInvestigation(
  page: Page,
  objective: string,
  rootDomain = "update-package.test",
): Promise<string> {
  await page.getByRole("link", { name: "New Investigation" }).click();
  await expect(
    page.getByRole("heading", { name: "Create Investigation" }),
  ).toBeVisible({ timeout: 30_000 });
  await page.getByLabel(/^Objective/).fill(objective);
  await page.getByLabel("Indicator value 1").fill(rootDomain);
  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/(overview|geoint)/);
  const url = page.url();
  const investigationId = url.match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
  expect(investigationId).not.toBeUndefined();
  return investigationId ?? "";
}

/** Open the GEOINT tab and wait for its authoritative surface. */
async function openGeoint(page: Page): Promise<void> {
  await page.getByRole("tab", { name: "Geographic context" }).click();
  await expect(
    page.getByRole("heading", { name: "Geographic context" }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(
    page.getByText(
      /do not establish a cyber relationship, common ownership, coordination, targeting, or attribution/i,
    ),
  ).toBeVisible({ timeout: 30_000 });
}

/** The always-available top-Locations table. */
function topLocationsTable(page: Page): Locator {
  return page.getByRole("table", { name: "Top canonical Locations in this Investigation" });
}

/**
 * Explore one top Location row into the Location-Entities pivot surface.
 */
async function exploreLocation(page: Page, name: string): Promise<Locator> {
  const row = topLocationsTable(page).locator("tbody tr", { hasText: name });
  await row.scrollIntoViewIfNeeded();
  await row.getByRole("button", { name: /Explore/ }).click();
  await page.getByRole("menuitem", { name: "Entities at this location" }).dispatchEvent("click");
  const workspace = page.getByRole("dialog", { name: "Entities by location pivot workspace" });
  await expect(workspace).toBeVisible({ timeout: 30_000 });
  return workspace;
}

/** Explore a row inside one workspace into the Entity GEOINT surface. */
async function exploreEntityGeoint(page: Page, workspace: Locator, entityValue: string): Promise<Locator> {
  const row = workspace
    .getByRole("table", { name: "Entities observed at this Location" })
    .locator("tbody tr", { hasText: entityValue });
  await row.scrollIntoViewIfNeeded();
  await row.getByRole("button", { name: /Explore/ }).click();
  await page
    .getByRole("menuitem", { name: "Geographic context for this entity" })
    .dispatchEvent("click");
  const entityWorkspace = page.getByRole("dialog", {
    name: "Entity geographic context pivot workspace",
  });
  await expect(entityWorkspace).toBeVisible({ timeout: 30_000 });
  return entityWorkspace;
}

test.describe("PR 26E real-stack GEOINT matrix", () => {
  test.describe.configure({ timeout: 300_000 });
  test.use({ storageState: SHARED_SESSION_STATE });

  test("G1 entity history: current + both rows + exact Evidence, no path", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const investigationId = await createInvestigation(
      page,
      "PR 26E entity history",
    );
    seedGeoint(investigationId, "entity_history");
    await openGeoint(page);

    // The bounded summary shows two observations across two Locations.
    await expect(topLocationsTable(page)).toBeVisible({ timeout: 30_000 });
    await expect(topLocationsTable(page).getByText("Seattle")).toBeVisible();
    await expect(topLocationsTable(page).getByText("Dallas")).toBeVisible();

    // Seattle -> Entities at this location -> the entity's GEOINT surface.
    const locationWorkspace = await exploreLocation(page, "Seattle");
    await expect(locationWorkspace.getByText("203.0.113.10")).toBeVisible();
    const entityWorkspace = await exploreEntityGeoint(
      page,
      locationWorkspace,
      "203.0.113.10",
    );

    // Investigation-relative current is the newer Location (Dallas), and
    // the history table lists both immutable rows in server order.
    const current = entityWorkspace.getByText("Current in this Investigation");
    await expect(current).toBeVisible({ timeout: 30_000 });
    await expect(entityWorkspace.getByText("Dallas")).toBeVisible();
    const history = entityWorkspace.getByRole("table", {
      name: "Entity geographic observation history",
    });
    await expect(history).toBeVisible({ timeout: 30_000 });
    expect(await history.locator("tbody tr").count()).toBe(2);
    const rowTexts = await history
      .locator("tbody tr")
      .evaluateAll((rows) => rows.map((row) => row.textContent ?? ""));
    expect(rowTexts.join(" ")).toContain("Seattle");
    expect(rowTexts.join(" ")).toContain("Dallas");
    // Distinct timestamps are asserted by the three distinct columns.
    expect(
      await history
        .getByRole("columnheader", { name: "Observed" })
        .count(),
    ).toBe(1);
    expect(
      await history
        .getByRole("columnheader", { name: "Retrieved" })
        .count(),
    ).toBe(1);
    expect(await history.getByRole("columnheader", { name: "Resolved" }).count()).toBe(1);

    // No movement path / route language is ever rendered.
    for (const forbidden of ["moved from", "route of", "between point"]) {
      expect(entityWorkspace.getByText(forbidden, { exact: false })).toHaveCount(0);
    }

    // Exact Evidence drill-down: the row's View Evidence opens the exact
    // Evidence for the exact persisted evidence_id.
    const evidenceButton = history
      .locator("tbody tr", { hasText: "Seattle" })
      .getByRole("button", { name: "View Evidence" })
      .first();
    await evidenceButton.click();
    const drawer = page.getByRole("dialog", { name: "Evidence" });
    await expect(drawer).toBeVisible({ timeout: 30_000 });
    await expect(drawer.getByText("203.0.113.10")).toBeVisible();
    await expect(drawer.getByText("Geolocation")).toBeVisible();
    await page.getByRole("button", { name: "Close detail" }).dispatchEvent("click");
    await expect(page.getByRole("dialog", { name: "Evidence" })).not.toBeVisible();

    // Safe close of the whole pivot workspace.
    await clickForce(
      page,
      entityWorkspace.getByRole("button", { name: "Close pivot workspace" }),
    );
    await expect(
      page.getByRole("heading", { name: "Geographic context" }),
    ).toBeVisible();
    expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("G2 same-Location entities stay individually inspectable and unlinked", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const investigationId = await createInvestigation(
      page,
      "PR 26E same-location neutrality",
    );
    seedGeoint(investigationId, "same_location");
    await openGeoint(page);

    // Seattle groups exactly two distinct Entities.
    const locationWorkspace = await exploreLocation(page, "Seattle");
    const table = locationWorkspace.getByRole("table", {
      name: "Entities observed at this Location",
    });
    await expect(table).toBeVisible({ timeout: 30_000 });
    expect(await table.locator("tbody tr").count()).toBe(2);
    await expect(table.getByText("203.0.113.20")).toBeVisible();
    await expect(table.getByText("203.0.113.30")).toBeVisible();

    // The visible neutral disclaimer is always present.
    await expect(
      locationWorkspace.getByText(/not implied to be related/i),
    ).toBeVisible();

    // No association/coordination language is ever produced.
    for (const forbidden of ["related infra", "coordinated", "shared infrastructure"]) {
      expect(locationWorkspace.getByText(forbidden, { exact: false })).toHaveCount(0);
    }

    // Each Entity keeps its own exact Evidence drill-down.
    for (const value of ["203.0.113.20", "203.0.113.30"]) {
      const row = table.locator("tbody tr", { hasText: value });
      await row.getByRole("button", { name: "View Evidence" }).first().click();
      const drawer = page.getByRole("dialog", { name: "Evidence" });
      await expect(drawer).toBeVisible({ timeout: 30_000 });
      await expect(drawer.getByText(value)).toBeVisible();
      await page.getByRole("button", { name: "Close detail" }).dispatchEvent("click");
      await expect(page.getByRole("dialog", { name: "Evidence" })).not.toBeVisible();
    }

    await clickForce(
      page,
      locationWorkspace.getByRole("button", { name: "Close pivot workspace" }),
    );
    await expect(
      page.getByRole("heading", { name: "Geographic context" }),
    ).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("G3 containment: exact default, server expansion, honest status", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const investigationId = await createInvestigation(
      page,
      "PR 26E containment",
    );
    seedGeoint(investigationId, "containment");
    await openGeoint(page);

    // Washington groups the admin-precision Entity exactly.
    const locationWorkspace = await exploreLocation(page, "Washington");
    const table = locationWorkspace.getByRole("table", {
      name: "Entities observed at this Location",
    });
    await expect(table).toBeVisible({ timeout: 30_000 });
    await expect(
      locationWorkspace.getByText("Exact results are shown"),
    ).toBeVisible({ timeout: 30_000 });
    expect(await table.locator("tbody tr").count()).toBe(1);
    await expect(table.getByText("203.0.113.50")).toBeVisible();
    await expect(table.getByText("203.0.113.40")).not.toBeVisible();

    // Include contained Locations: the server expands to the city child.
    await locationWorkspace
      .getByRole("button", { name: "Include contained Locations" })
      .click();
    await expect(
      locationWorkspace.getByText("Contained Locations are included"),
    ).toBeVisible({ timeout: 30_000 });
    expect(await table.locator("tbody tr").count()).toBe(2);
    await expect(table.getByText("203.0.113.50")).toBeVisible();
    await expect(table.getByText("203.0.113.40")).toBeVisible();

    // The URL carries only the pivot-step identity state (base64 envelope);
    // refreshing restores the contained surface (URL-owned state).
    await page.reload();
    const restored = page.getByRole("dialog", {
      name: "Entities by location pivot workspace",
    });
    await expect(restored).toBeVisible({ timeout: 30_000 });
    await expect(
      restored.getByText("Contained Locations are included"),
    ).toBeVisible({ timeout: 30_000 });

    await clickForce(
      page,
      restored.getByRole("button", { name: "Close pivot workspace" }),
    );
    await expect(
      page.getByRole("heading", { name: "Geographic context" }),
    ).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("G4 cross-Investigation: I1 sees only I1; I2 observation is safe 404", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const investigationA = await createInvestigation(
      page,
      "PR 26E cross-investigation A",
    );
    // A second browser-created Investigation hosts the other observation.
    const investigationB = await createInvestigation(
      page,
      "PR 26E cross-investigation B",
    );
    const output = seedGeoint(investigationA, "cross_investigation", investigationB);
    const observationLine = output
      .split("\n")
      .find((line) => line.includes("E2E-GEOINT-SEED"));
    expect(observationLine).not.toBeUndefined();
    const observationIds = (
      observationLine!.match(/observation_ids=([0-9a-f-]+(?:,[0-9a-f-]+)*)/)?.[1] ?? ""
    ).split(",");
    expect(observationIds.length).toBeGreaterThanOrEqual(2);
    const otherObservationId = observationIds[observationIds.length - 1];

    await openGeoint(page);
    // I1's summary shows only Seattle: the Dallas/Later observation belongs
    // to I2 and never leaks into I1 (even as a map marker or top Location).
    await expect(topLocationsTable(page)).toBeVisible({ timeout: 30_000 });
    await expect(topLocationsTable(page).getByText("Seattle")).toBeVisible();
    expect(topLocationsTable(page).getByText("Dallas")).toHaveCount(0);
    expect(page.getByText("Dallas", { exact: true })).toHaveCount(0);

    // The I2 observation detail is a safe 404 under I1 (real API boundary).
    const response = await page.request.get(
      `/api/v1/investigations/${investigationA}/geoint/observations/${otherObservationId}`,
    );
    expect(response.status).toBe(404);
    const body = await response.json();
    expect(body.error.code).toBe("geoint_observation_not_found");

    // The current within I1 is Investigation-relative Seattle.
    const locationWorkspace = await exploreLocation(page, "Seattle");
    await expect(locationWorkspace.getByText("203.0.113.60")).toBeVisible();
    const entityWorkspace = await exploreEntityGeoint(
      page,
      locationWorkspace,
      "203.0.113.60",
    );
    await expect(
      entityWorkspace.getByText("Current in this Investigation"),
    ).toBeVisible({ timeout: 30_000 });
    await expect(entityWorkspace.getByText("Seattle").first()).toBeVisible();
    expect(entityWorkspace.getByText("Dallas")).toHaveCount(0);

    await clickForce(
      page,
      entityWorkspace.getByRole("button", { name: "Close pivot workspace" }),
    );
    await expect(
      page.getByRole("heading", { name: "Geographic context" }),
    ).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("G5 non-mappable: valid observation without coordinates stays usable", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const investigationId = await createInvestigation(
      page,
      "PR 26E non-mappable",
    );
    seedGeoint(investigationId, "non_mappable");
    await openGeoint(page);

    // No marker exists: EdgeLand has no representative coordinates.
    await expect(topLocationsTable(page)).toBeVisible({ timeout: 30_000 });
    await expect(topLocationsTable(page).getByText("EdgeLand")).toBeVisible();
    expect(await page.locator(".leaflet-marker-icon").count()).toBe(0);
    await expect(topLocationsTable(page).getByText("Not plotted")).toBeVisible();
    await expect(
      page.getByText(/no plottable coordinates/i),
    ).toBeVisible();

    // The row stays actionable through the pivot/table workflow.
    const locationWorkspace = await exploreLocation(page, "EdgeLand");
    await expect(locationWorkspace.getByText("203.0.113.70")).toBeVisible({
      timeout: 30_000,
    });
    const entityWorkspace = await exploreEntityGeoint(
      page,
      locationWorkspace,
      "203.0.113.70",
    );
    await expect(
      entityWorkspace.getByText("Current in this Investigation"),
    ).toBeVisible({ timeout: 30_000 });
    await expect(entityWorkspace.getByText("EdgeLand")).toBeVisible();
    const history = entityWorkspace.getByRole("table", {
      name: "Entity geographic observation history",
    });
    expect(await history.locator("tbody tr").count()).toBe(1);
    await history
      .locator("tbody tr")
      .getByRole("button", { name: "View Evidence" })
      .first()
      .click();
    const drawer = page.getByRole("dialog", { name: "Evidence" });
    await expect(drawer).toBeVisible({ timeout: 30_000 });
    await expect(drawer.getByText("203.0.113.70")).toBeVisible();
    await page.getByRole("button", { name: "Close detail" }).dispatchEvent("click");

    await clickForce(
      page,
      entityWorkspace.getByRole("button", { name: "Close pivot workspace" }),
    );
    await expect(
      page.getByRole("heading", { name: "Geographic context" }),
    ).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("G6 Chromium stability: GEOINT row -> Location -> Entity -> Evidence -> Back -> Close", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const investigationId = await createInvestigation(
      page,
      "PR 26E pivot stability",
    );
    seedGeoint(investigationId, "entity_history");
    await openGeoint(page);

    // Location pivot.
    const locationWorkspace = await exploreLocation(page, "Seattle");
    await expect(locationWorkspace.getByText("203.0.113.10")).toBeVisible();

    // Entity pivot.
    const entityWorkspace = await exploreEntityGeoint(
      page,
      locationWorkspace,
      "203.0.113.10",
    );
    await expect(
      entityWorkspace.getByText("Current in this Investigation"),
    ).toBeVisible({ timeout: 30_000 });

    // Evidence drawer.
    const history = entityWorkspace.getByRole("table", {
      name: "Entity geographic observation history",
    });
    await expect(history).toBeVisible({ timeout: 30_000 });
    await history
      .locator("tbody tr")
      .getByRole("button", { name: "View Evidence" })
      .first()
      .click();
    const drawer = page.getByRole("dialog", { name: "Evidence" });
    await expect(drawer).toBeVisible({ timeout: 30_000 });
    await page.getByRole("button", { name: "Close detail" }).dispatchEvent("click");
    await expect(page.getByRole("dialog", { name: "Evidence" })).not.toBeVisible();

    // Browser Back walks the URL-backed stack to the Location step.
    await page.goBack();
    await expect(
      page.getByRole("dialog", { name: "Entities by location pivot workspace" }),
    ).toBeVisible({ timeout: 30_000 });
    await page.goBack();
    await expect(
      page.getByRole("heading", { name: "Geographic context" }),
    ).toBeVisible({ timeout: 30_000 });

    // Close (or re-open) completes without a hang; the page is responsive.
    await openGeoint(page);
    await expect(
      page.getByRole("heading", { name: "Geographic context" }),
    ).toBeVisible();
    await page.getByRole("tab", { name: "Evidence" }).click();
    await expect(page.getByRole("heading", { name: "Evidence" })).toBeVisible({
      timeout: 30_000,
    });
    expect(consoleErrors).toEqual([]);
  });
});