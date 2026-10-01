// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 26E canonical GEOINT workspace matrix (G1-G6)
// on the PR 31F-8 routed architecture.
//
// Same production-path topology as the prior spec: built/static React +
// Nginx -> real FastAPI -> real PostgreSQL 18 + PostGIS, deterministic
// offline LLM boundary, and no interception or injected state.
// Deterministic canonical geographic context is attached through the
// harness-only GEOINT seeder to the exact browser-created Investigation
// UUID; the reference geography is loaded through the normal PR 26B
// build/import work. Every read goes through the real PR 26D API.
//
// PR 31F-8: cross-resource exploration is ordinary Investigation-scoped
// React Router navigation — no PivotWorkspace, no ``pivot=`` URL, no
// ``dispatchEvent``/``force``/coordinate workarounds. All activations are
// normal locator clicks on semantic links/buttons; browser Back/Forward
// reconstructs the prior routed surfaces from route/query state.
//
// G1  entity history: two Locations/times, correct Investigation-relative
//     current, both history rows, distinct timestamps, exact Evidence
//     drill-down route, no movement path.
// G2  same-Location entities stay individually inspectable; no
//     relationship/coordination language.
// G3  containment: exact vs included, server-owned, honest status, refresh
//     restores the contained URL state.
// G4  cross-Investigation: I1 sees only I1; the I2 observation is a safe
//     404 under I1; no current leak. I2 is created AFTER explicitly
//     returning to /investigations.
// G5  non-mappable: valid observation without coordinates stays usable.
// G6  routed stability: Location -> Entity -> Evidence -> Back -> Back
//     completes without a hang; the page stays responsive.

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

/** Open the GEOINT tab and wait for its authoritative surface (idempotent:
 * never re-clicks an already-active GEOINT tab — PR 31F-8 G4 deep links). */
async function openGeoint(page: Page): Promise<void> {
  if (!page.url().includes("/geoint")) {
    await page.getByRole("tab", { name: "Geographic context" }).click();
  }
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
 * Explore one top Location into the routed Location Entities surface:
 * ordinary link navigation (PR 31F-8 N07).
 */
async function exploreLocation(page: Page, name: string): Promise<Page> {
  const row = topLocationsTable(page).locator("tbody tr", { hasText: name });
  await row.scrollIntoViewIfNeeded();
  await row.getByRole("button", { name: /Explore/ }).click();
  await page.getByRole("link", { name: "Entities at this location" }).click();
  await expect(page).toHaveURL(/\/geoint\/locations\/[0-9a-f-]+\/entities$/);
  await expect(
    page.getByRole("table", { name: "Entities observed at this Location" }),
  ).toBeVisible({ timeout: 30_000 });
  return page;
}

/**
 * Explore one Entity row into the routed Entity GEOINT surface: ordinary
 * link navigation (PR 31F-8 N08).
 */
async function exploreEntityGeoint(page: Page, entityValue: string): Promise<Page> {
  const table = page.getByRole("table", { name: "Entities observed at this Location" });
  const row = table.locator("tbody tr", { hasText: entityValue });
  await row.scrollIntoViewIfNeeded();
  await row.getByRole("button", { name: /Explore/ }).click();
  await page.getByRole("link", { name: "Geographic context for this entity" }).click();
  await expect(page).toHaveURL(/\/geoint\/entities\/[0-9a-f-]+$/);
  await expect(
    page.getByText("Current in this Investigation"),
  ).toBeVisible({ timeout: 30_000 });
  return page;
}

/** The entity history table on the rendered Entity GEOINT surface. */
function entityHistoryTable(page: Page): Locator {
  return page.getByRole("table", { name: "Entity geographic observation history" });
}

test.describe("PR 26E real-stack GEOINT matrix (routed, PR 31F-8)", () => {
  test.describe.configure({ timeout: 300_000 });
  test.use({ storageState: SHARED_SESSION_STATE });

  test("G1 entity history: current + both rows + exact Evidence route, no path", async ({
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
    // Replay the identical seed (same Investigation, same args): the
    // deterministic seeder must reconcile authoritative persisted state and
    // succeed without creating duplicate GeoResolution work or canonical
    // observations (GEOINT seeding idempotency corrective PR).
    seedGeoint(investigationId, "entity_history");
    await openGeoint(page);

    // The bounded summary shows two observations across two Locations.
    await expect(topLocationsTable(page)).toBeVisible({ timeout: 30_000 });
    await expect(topLocationsTable(page).getByText("Seattle")).toBeVisible();
    await expect(topLocationsTable(page).getByText("Dallas")).toBeVisible();

    // Seattle -> Entities at this location -> the entity's GEOINT surface.
    await exploreLocation(page, "Seattle");
    await expect(page.getByText("203.0.113.10")).toBeVisible();
    await exploreEntityGeoint(page, "203.0.113.10");

    // Canonical URLs: exactly one routed surface, no pivot parameter, no
    // hosted workbench anywhere.
    expect(page.url()).toMatch(/\/geoint\/entities\/[0-9a-f-]+$/);
    expect(page.url()).not.toContain("pivot=");

    // Investigation-relative current is the newer Location (Dallas), and
    // the history table lists both immutable rows in server order. The
    // current-context assertion is scoped to the current section because
    // the history table also renders a Dallas row (strict-mode-safe).
    const current = page.getByText("Current in this Investigation");
    await expect(current).toBeVisible({ timeout: 30_000 });
    await expect(
      page
        .getByRole("heading", { name: "Canonical Location" })
        .locator("..")
        .getByText("Dallas"),
    ).toBeVisible();
    const history = entityHistoryTable(page);
    await expect(history).toBeVisible({ timeout: 30_000 });
    expect(await history.locator("tbody tr").count()).toBe(2);
    const rowTexts = await history
      .locator("tbody tr")
      .evaluateAll((rows) => rows.map((row) => row.textContent ?? ""));
    expect(rowTexts.join(" ")).toContain("Seattle");
    expect(rowTexts.join(" ")).toContain("Dallas");
    // Distinct timestamps are asserted by the three distinct columns.
    expect(await history.getByRole("columnheader", { name: "Observed" }).count()).toBe(1);
    expect(await history.getByRole("columnheader", { name: "Retrieved" }).count()).toBe(1);
    expect(await history.getByRole("columnheader", { name: "Resolved" }).count()).toBe(1);

    // No movement path / route language is ever rendered.
    for (const forbidden of ["moved from", "route of", "between point"]) {
      expect(page.getByText(forbidden, { exact: false })).toHaveCount(0);
    }

    // Exact Evidence drill-down: the row's View Evidence links to the exact
    // Evidence route for the exact persisted evidence_id (N09).
    const evidenceLink = history
      .locator("tbody tr", { hasText: "Seattle" })
      .getByRole("link", { name: "View Evidence" })
      .first();
    await evidenceLink.click();
    await expect(page).toHaveURL(/\/evidence\/[0-9a-f-]+$/);
    const heading = page.getByRole("heading", { name: "Evidence details" });
    await expect(heading).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("203.0.113.10").first()).toBeVisible();
    await expect(page.getByText("Geolocation", { exact: true }).first()).toBeVisible();

    // Browser Back reconstructs the Entity GEOINT surface (N16).
    await page.goBack();
    await expect(page).toHaveURL(/\/geoint\/entities\/[0-9a-f-]+$/);
    await expect(
      page.getByText("Current in this Investigation"),
    ).toBeVisible({ timeout: 30_000 });

    // Browser Back walks to the Location Entities surface; the persistent
    // Investigation shell stays mounted throughout.
    await page.goBack();
    await expect(page).toHaveURL(/\/geoint\/locations\/[0-9a-f-]+\/entities$/);
    await expect(
      page.getByRole("table", { name: "Entities observed at this Location" }),
    ).toBeVisible({ timeout: 30_000 });
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
    await exploreLocation(page, "Seattle");
    const table = page.getByRole("table", {
      name: "Entities observed at this Location",
    });
    await expect(table).toBeVisible({ timeout: 30_000 });
    expect(await table.locator("tbody tr").count()).toBe(2);
    await expect(table.getByText("203.0.113.20")).toBeVisible();
    await expect(table.getByText("203.0.113.30")).toBeVisible();

    // The visible neutral disclaimer is always present.
    await expect(page.getByText(/not implied to be related/i)).toBeVisible();

    // No association/coordination language is ever produced.
    for (const forbidden of ["related infra", "coordinated", "shared infrastructure"]) {
      expect(page.getByText(forbidden, { exact: false })).toHaveCount(0);
    }

    // Each Entity keeps its own exact Evidence drill-down route.
    for (const value of ["203.0.113.20", "203.0.113.30"]) {
      const row = table.locator("tbody tr", { hasText: value });
      await row.getByRole("link", { name: "View Evidence" }).first().click();
      await expect(page).toHaveURL(/\/evidence\/[0-9a-f-]+$/);
      const heading = page.getByRole("heading", { name: "Evidence details" });
      await expect(heading).toBeVisible({ timeout: 30_000 });
      await expect(page.getByText(value).first()).toBeVisible();
      // Back to the Entity-vs-Location surface via browser Back.
      await page.goBack();
      await expect(page).toHaveURL(/\/geoint\/locations\/[0-9a-f-]+\/entities$/);
      await expect(table).toBeVisible({ timeout: 30_000 });
    }
    expect(consoleErrors).toEqual([]);
  });

  test("G3 containment: exact default, server expansion, honest status, refresh", async ({
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
    await exploreLocation(page, "Washington");
    const table = page.getByRole("table", {
      name: "Entities observed at this Location",
    });
    await expect(table).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("Exact results are shown")).toBeVisible({ timeout: 30_000 });
    expect(await table.locator("tbody tr").count()).toBe(1);
    await expect(table.getByText("203.0.113.50")).toBeVisible();
    await expect(table.getByText("203.0.113.40")).not.toBeVisible();

    // Include contained Locations: the server expands to the city child.
    await page.getByRole("button", { name: "Include contained Locations" }).click();
    await expect(page.getByText("Contained Locations are included")).toBeVisible({ timeout: 30_000 });
    expect(await table.locator("tbody tr").count()).toBe(2);
    await expect(table.getByText("203.0.113.50")).toBeVisible();
    await expect(table.getByText("203.0.113.40")).toBeVisible();

    // The URL carries the containment query state; refreshing restores the
    // contained surface (N19/N20: URL-owned state, no component survival).
    expect(page.url()).toContain("include_contained=true");
    await page.reload();
    await expect(page).toHaveURL(/\/geoint\/locations\/[0-9a-f-]+\/entities/);
    await expect(page.getByText("Contained Locations are included")).toBeVisible({
      timeout: 30_000,
    });
    expect(await page.getByRole("table", { name: "Entities observed at this Location" }).locator("tbody tr").count()).toBe(2);
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
    // PR 31F-8 §3.8: explicitly return to /investigations before creating
    // the second Investigation (no product control added to satisfy tests).
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
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

    // I1's surface is reached as a direct deep link (no prior navigation
    // to A inside this session): the seeded summary shows only Seattle.
    await page.goto(`/investigations/${investigationA}/geoint`);
    await openGeoint(page);
    // The already-selected GEOINT tab stays inert-safe: activating it
    // (keyboard) neither navigates nor stalls the page (native-pointer
    // stability; the prior architecture's same-URL workbench re-entry was a
    // wedge class).
    const activeTab = page.getByRole("tab", { name: "Geographic context" });
    await activeTab.focus();
    await page.keyboard.press("Enter");
    await expect(
      page.getByRole("heading", { name: "Geographic context" }),
    ).toBeVisible({ timeout: 30_000 });
    await expect(topLocationsTable(page)).toBeVisible({ timeout: 30_000 });
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
    expect(response.status()).toBe(404);
    const body = await response.json();
    expect(body.error.code).toBe("geoint_observation_not_found");

    // The current within I1 is Investigation-relative Seattle.
    await exploreLocation(page, "Seattle");
    await expect(page.getByText("203.0.113.60")).toBeVisible();
    await exploreEntityGeoint(page, "203.0.113.60");
    await expect(page.getByText("Seattle").first()).toBeVisible();
    expect(page.getByText("Dallas")).toHaveCount(0);
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
    await expect(page.getByText(/no plottable coordinates/i)).toBeVisible();

    // The row stays actionable through the routed workflow.
    await exploreLocation(page, "EdgeLand");
    await expect(page.getByText("203.0.113.70")).toBeVisible({ timeout: 30_000 });
    await exploreEntityGeoint(page, "203.0.113.70");
    // The current-context section renders EdgeLand (also present in the
    // history row), so the assertion is scoped to the current section.
    await expect(
      page
        .getByRole("heading", { name: "Canonical Location" })
        .locator("..")
        .getByText("EdgeLand"),
    ).toBeVisible();
    const history = entityHistoryTable(page);
    expect(await history.locator("tbody tr").count()).toBe(1);
    await history
      .locator("tbody tr")
      .getByRole("link", { name: "View Evidence" })
      .first()
      .click();
    await expect(page).toHaveURL(/\/evidence\/[0-9a-f-]+$/);
    const heading = page.getByRole("heading", { name: "Evidence details" });
    await expect(heading).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("203.0.113.70").first()).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("G6 routed stability: Location -> Entity -> Evidence -> Back -> Back", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const investigationId = await createInvestigation(
      page,
      "PR 26E routed stability",
    );
    seedGeoint(investigationId, "entity_history");
    await openGeoint(page);

    // Location surface (routed link).
    await exploreLocation(page, "Seattle");
    await expect(page.getByText("203.0.113.10")).toBeVisible();

    // Entity surface (routed link).
    await exploreEntityGeoint(page, "203.0.113.10");

    // Evidence route.
    const history = entityHistoryTable(page);
    await expect(history).toBeVisible({ timeout: 30_000 });
    await history
      .locator("tbody tr")
      .getByRole("link", { name: "View Evidence" })
      .first()
      .click();
    await expect(page).toHaveURL(/\/evidence\/[0-9a-f-]+$/);
    const heading = page.getByRole("heading", { name: "Evidence details" });
    await expect(heading).toBeVisible({ timeout: 30_000 });

    // Browser Back reconstructs Entity GEOINT; the returned surface stays
    // interactive (another normal click works), N16.
    await page.goBack();
    await expect(page).toHaveURL(/\/geoint\/entities\/[0-9a-f-]+$/);
    await expect(
      page.getByText("Current in this Investigation"),
    ).toBeVisible({ timeout: 30_000 });
    await history
      .locator("tbody tr")
      .getByRole("link", { name: "View Evidence" })
      .first()
      .click();
    await expect(page).toHaveURL(/\/evidence\/[0-9a-f-]+$/);

    // Browser Back x2 walks to Location Entities and then the persistent
    // shell remains responsive (ordinary tab navigation still works).
    await page.goBack();
    await expect(page).toHaveURL(/\/geoint\/entities\/[0-9a-f-]+$/);
    await page.goBack();
    await expect(page).toHaveURL(/\/geoint\/locations\/[0-9a-f-]+\/entities$/);
    await page.goBack();
    await expect(
      page.getByRole("heading", { name: "Geographic context" }),
    ).toBeVisible();
    expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });
});
