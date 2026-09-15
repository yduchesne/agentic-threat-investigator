// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 25C Map workflow matrix (E25-E28).
//
// Same production-path topology and interaction conventions as E24
// (zz-geolocation.spec.ts): built/static React + Nginx -> real FastAPI ->
// real PostgreSQL, deterministic offline LLM boundary, packaged fake
// world, and the real PR 25A endpoint. Deterministic geolocation data is
// attached through the harness-only seeder to the exact browser-created
// Investigation UUID before the Map is opened; every read goes through the
// real endpoint — no interception, no MSW, no injected state.
//
// E25  multi-IOC exploration with typed pivots (list, markers, breadcrumb,
//      server-filtered Evidence target, legal Relationship dead-end).
// E26  same-coordinate indicators stay individually inspectable; no
//      cluster/co-location claim is invented.
// E27  coordinate-less item stays fully actionable without a marker.
// E28  an unseeded fake-world Investigation proves the honest empty Map and
//      that no other Investigation's seeded rows leak across (isolation).
//
// Interaction notes: inside the pivot workspace overlay (fixed layer) the
// Chromium composite hit-test can wedge the main thread; raw pointer input
// via ``page.mouse`` (clickForce, as in zz-pivots.spec.ts) is used there.
// Page-level controls use normal clicks.

import { execSync } from "node:child_process";
import { expect, test, type Locator, type Page } from "@playwright/test";

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
  await page.mouse.click(
    box.x + box.width / 2,
    box.y + box.height / 2,
    { delay: 40 },
  );
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

/** Open the Map tab and wait for its authoritative projection rendering. */
async function openMap(page: Page): Promise<void> {
  await page.getByRole("tab", { name: "Map" }).click();
  await expect(
    page.getByRole("heading", { name: "Investigation Map" }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(
    page.getByText(/IP geolocation is approximate network-address context/i),
  ).toBeVisible({ timeout: 30_000 });
}

/** The always-available non-map representation table. */
function geolocationRows(page: Page): Locator {
  return page
    .getByRole("table", { name: "All returned geolocation items" })
    .locator("tbody tr");
}

/**
 * Bring one row's Explore trigger comfortably inside the viewport.
 *
 * The action menu opens in a fixed portal below the trigger; if the
 * trigger sits at the bottom edge of a 720px-tall headless viewport the
 * menu renders below the fold and Playwright cannot click the item. The
 * row scrolls so its trigger lands near the top of the viewport first.
 */
async function scrollTriggerIntoView(page: Page, row: Locator): Promise<void> {
  await row.scrollIntoViewIfNeeded();
  const box = await row.boundingBox();
  expect(box).not.toBeNull();
  if (box !== null) {
    await page.evaluate((offset) => window.scrollBy(0, offset), box.y - 140);
  }
  await expect(row.getByRole("button", { name: /Explore/ })).toBeVisible({
    timeout: 30_000,
  });
}

test.describe("PR 25C real-stack Map workflow matrix", () => {
  test.describe.configure({ timeout: 300_000 });
  test.use({ storageState: SHARED_SESSION_STATE });

  test("E25 multi-IOC Map exploration and typed pivots", async ({ page }) => {
    const consoleErrors = trackConsoleErrors(page);
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const investigationId = await completeInvestigation(
      page,
      "PR 25C multi-IOC map exploration",
      "update-package.test",
    );
    seedGeolocation(investigationId, "multi_ioc");
    await openMap(page);

    // Two distinct IPs, two markers, server order preserved.
    const rows = geolocationRows(page);
    await expect(rows).toHaveCount(2, { timeout: 30_000 });
    expect(await rows.nth(0).locator("th").first().textContent()).toContain(
      "203.0.113.10",
    );
    expect(await rows.nth(1).locator("th").first().textContent()).toContain(
      "203.0.113.20",
    );
    await expect(page.locator(".leaflet-marker-icon").first()).toBeVisible({
      timeout: 30_000,
    });
    expect(await page.locator(".leaflet-marker-icon").count()).toBe(2);

    // Explore IP A -> Evidence for the exact Entity through the typed
    // PivotWorkspace. Breadcrumb carries the IP identity.
    const rowA = page
      .getByRole("table", { name: "All returned geolocation items" })
      .locator("tbody tr", { hasText: "203.0.113.10" });
    await scrollTriggerIntoView(page, rowA);
    await rowA.getByRole("button", { name: /Explore/ }).click();
    await page
      .getByRole("menuitem", { name: "Evidence for this entity" })
      .dispatchEvent("click");
    const workspace = page.getByRole("dialog", {
      name: "Evidence pivot workspace",
    });
    await expect(workspace).toBeVisible({ timeout: 30_000 });
    await expect(workspace.getByText("203.0.113.10").first()).toBeVisible();
    // Server-filtered target: the seeded GEOLOCATION Evidence row resolves.
    await expect(
      workspace.getByRole("table").getByText("urn:ati:source:dbip_city_lite").first(),
    ).toBeVisible({ timeout: 30_000 });

    // Close/back to Map safely; disclaimer remains.
    await clickForce(
      page,
      workspace.getByRole("button", { name: "Close pivot workspace" }),
    );
    await expect(workspace).not.toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Investigation Map" }),
    ).toBeVisible();
    await expect(
      page.getByText(/IP geolocation is approximate network-address context/i),
    ).toBeVisible();

    // Explore IP B -> a legal Relationship target with an honest
    // empty/dead-end state (no fabricated edges for unrelated IPs).
    const rowB = page
      .getByRole("table", { name: "All returned geolocation items" })
      .locator("tbody tr", { hasText: "203.0.113.20" });
    await scrollTriggerIntoView(page, rowB);
    await rowB.getByRole("button", { name: /Explore/ }).click();
    await page
      .getByRole("menuitem", { name: "Relationships where source" })
      .dispatchEvent("click");
    const relationshipsWorkspace = page.getByRole("dialog", {
      name: "Relationships pivot workspace",
    });
    await expect(relationshipsWorkspace).toBeVisible({ timeout: 30_000 });
    await expect(
      relationshipsWorkspace.getByText("203.0.113.20").first(),
    ).toBeVisible();
    await expect(
      relationshipsWorkspace.getByText("No relationships match these filters"),
    ).toBeVisible({ timeout: 30_000 });
    await clickForce(
      page,
      relationshipsWorkspace.getByRole("button", {
        name: "Close pivot workspace",
      }),
    );
    await expect(
      page.getByRole("heading", { name: "Investigation Map" }),
    ).toBeVisible();

    // Exact Evidence drill-down still works through the non-map row.
    const evidenceButton = rowA.getByRole("button", { name: "View Evidence" });
    await evidenceButton.click();
    const drawer = page.getByRole("dialog", { name: "Evidence" });
    await expect(drawer).toBeVisible({ timeout: 30_000 });
    await expect(drawer.getByText("203.0.113.10")).toBeVisible();
    await expect(drawer.getByText("Geolocation")).toBeVisible();
    await page.getByRole("button", { name: "Close detail" }).dispatchEvent("click");
    await expect(page.getByRole("dialog", { name: "Evidence" })).not.toBeVisible();

    expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("E26 same-coordinate items stay individually inspectable", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const investigationId = await completeInvestigation(
      page,
      "PR 25C same-coordinate inspectability",
      "update-package.test",
    );
    seedGeolocation(investigationId, "same_location");
    await openMap(page);

    // Two distinct rows and two markers at identical coordinates. The
    // server orders by canonical IP string, so matching is by exact IP
    // text, never by row position.
    const rows = geolocationRows(page);
    await expect(rows).toHaveCount(2, { timeout: 30_000 });
    await expect(page.locator(".leaflet-marker-icon").first()).toBeVisible({
      timeout: 30_000,
    });
    expect(await page.locator(".leaflet-marker-icon").count()).toBe(2);

    // No co-location/cluster/related claim is ever rendered.
    for (const forbidden of ["co-located", "cluster", "related infra"]) {
      expect(page.getByText(forbidden, { exact: false })).toHaveCount(0);
    }

    // Each row has its own View Evidence and Explore actions.
    const rowA = page
      .getByRole("table", { name: "All returned geolocation items" })
      .locator("tbody tr", { hasText: "203.0.113.10" });
    const rowB = page
      .getByRole("table", { name: "All returned geolocation items" })
      .locator("tbody tr", { hasText: "198.51.100.30" });
    await expect(rowA).toBeVisible({ timeout: 30_000 });
    expect(await rowA.locator("th").first().textContent()).toContain("203.0.113.10");
    await expect(rowB).toBeVisible();
    expect(await rowB.locator("th").first().textContent()).toContain("198.51.100.30");
    await scrollTriggerIntoView(page, rowA);
    await expect(rowA.getByRole("button", { name: /Explore/ })).toBeVisible();
    await scrollTriggerIntoView(page, rowB);
    await expect(rowB.getByRole("button", { name: /Explore/ })).toBeVisible();

    // Exact Evidence actions are distinct per row.
    await rowA.getByRole("button", { name: "View Evidence" }).click();
    const drawerA = page.getByRole("dialog", { name: "Evidence" });
    await expect(drawerA).toBeVisible({ timeout: 30_000 });
    await expect(drawerA.getByText("203.0.113.10")).toBeVisible();
    await page.getByRole("button", { name: "Close detail" }).dispatchEvent("click");
    await expect(page.getByRole("dialog", { name: "Evidence" })).not.toBeVisible();

    await rowB.getByRole("button", { name: "View Evidence" }).click();
    const drawerB = page.getByRole("dialog", { name: "Evidence" });
    await expect(drawerB).toBeVisible({ timeout: 30_000 });
    await expect(drawerB.getByText("198.51.100.30")).toBeVisible();
    await page.getByRole("button", { name: "Close detail" }).dispatchEvent("click");
    await expect(page.getByRole("dialog", { name: "Evidence" })).not.toBeVisible();

    // Both Explore triggers open the identical menu of entity actions
    // (keyboard operable trigger with an accessible IP context).
    await rowA.getByRole("button", { name: /Explore/ }).click();
    const menu = page.getByRole("menu");
    await expect(menu).toBeVisible({ timeout: 30_000 });
    await expect(
      page.getByRole("menuitem", { name: "Evidence for this entity" }),
    ).toBeVisible();
    // Escape on the focused item closes the menu (keyboard operability).
    await page
      .getByRole("menuitem", { name: "Evidence for this entity" })
      .focus();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("menu")).not.toBeVisible({ timeout: 30_000 });

    expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("E27 coordinate-less context stays fully actionable", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const investigationId = await completeInvestigation(
      page,
      "PR 25C coordinate-less context",
      "update-package.test",
    );
    seedGeolocation(investigationId, "non_mappable");
    await openMap(page);

    // No marker exists for the coordinate-less item.
    const rows = geolocationRows(page);
    await expect(rows).toHaveCount(1, { timeout: 30_000 });
    expect(await page.locator(".leaflet-marker-icon").count()).toBe(0);

    // Provider/precision/location context remains visible on the row.
    const row = page
      .getByRole("table", { name: "All returned geolocation items" })
      .locator("tbody tr", { hasText: "192.0.2.40" });
    await expect(row).toBeVisible();
    await expect(row.getByText("Region-level approximation")).toBeVisible();
    await expect(row.getByText("DB-IP City Lite")).toBeVisible();
    await expect(row.getByText(/Oregon, US/)).toBeVisible();
    await expect(row.getByText("Not plotted")).toBeVisible();

    // Exact Evidence drill-down works for the coordinate-less item.
    await row.getByRole("button", { name: "View Evidence" }).click();
    const drawer = page.getByRole("dialog", { name: "Evidence" });
    await expect(drawer).toBeVisible({ timeout: 30_000 });
    await expect(drawer.getByText("192.0.2.40")).toBeVisible();
    await expect(drawer.getByText("Geolocation")).toBeVisible();
    await page.getByRole("button", { name: "Close detail" }).dispatchEvent("click");
    await expect(page.getByRole("dialog", { name: "Evidence" })).not.toBeVisible();

    // A legal Explore action works; an empty target is honestly empty.
    await scrollTriggerIntoView(page, row);
    await row.getByRole("button", { name: /Explore/ }).click();
    await page
      .getByRole("menuitem", { name: "Research for this entity" })
      .dispatchEvent("click");
    const researchWorkspace = page.getByRole("dialog", {
      name: "Research pivot workspace",
    });
    await expect(researchWorkspace).toBeVisible({ timeout: 30_000 });
    await expect(researchWorkspace.getByText("192.0.2.40").first()).toBeVisible();
    await expect(
      researchWorkspace.getByText("No research results match these filters"),
    ).toBeVisible({ timeout: 30_000 });
    // Safe close/back to Map.
    await clickForce(
      page,
      researchWorkspace.getByRole("button", { name: "Close pivot workspace" }),
    );
    await expect(
      page.getByRole("heading", { name: "Investigation Map" }),
    ).toBeVisible();

    expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("E28 empty Map: unseeded Investigation stays empty and isolated", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    // A fresh unseeded fake-world Investigation: prior E24-E27 seeds must
    // never leak into it (cross-Investigation isolation through the real
    // endpoint).
    const investigationId = await completeInvestigation(
      page,
      "PR 25C empty map isolation",
      "update-package.test",
    );
    expect(investigationId).not.toBe("");
    await openMap(page);

    // Honest empty state; no marker; no fabricated rows/actions.
    await expect(
      page.getByText("No geolocation context is available for this Investigation."),
    ).toBeVisible({ timeout: 30_000 });
    expect(await page.locator(".leaflet-marker-icon").count()).toBe(0);
    const rows = geolocationRows(page);
    await expect(rows).toHaveCount(0);
    expect(await page.getByRole("button", { name: /Explore/ }).count()).toBe(0);
    expect(await page.getByRole("button", { name: /View Evidence/ }).count()).toBe(0);

    // Safe navigation away and back.
    await page.getByRole("tab", { name: "Evidence" }).click();
    await expect(
      page.getByRole("heading", { name: "Evidence" }),
    ).toBeVisible({ timeout: 30_000 });
    await page.getByRole("tab", { name: "Map" }).click();
    await expect(
      page.getByRole("heading", { name: "Investigation Map" }),
    ).toBeVisible({ timeout: 30_000 });

    expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });
});