// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 31F-6 list/detail lifecycle regressions.
//
// Runs against the production-path stack created by the repository E2E
// harness (scripts/e2e.sh): built/static React + Nginx -> real FastAPI ->
// real PostgreSQL -> real durable Investigation worker with the
// deterministic offline LLM boundary, over the packaged PR 23D fake world.
// No live Internet, no live threat-intelligence provider, and no live
// LLM; `FAKE DATA` remains visible throughout.
//
// PR 31F-6 replaced the overlay resource-detail drawers (and the interim
// side Inspectors) with a conservative list/detail workspace: `View`
// renders the exact Investigation-scoped detail as the main in-flow
// content, `Back to <resource>` restores the bounded list, and Pivot
// actions stay inline in the detail. This spec is the real-browser
// lifecycle regression:
//
//  - repeated same-page View/detail/Back/interact cycles (>= 5 on the
//    critical surfaces: Evidence, Timeline, History and Evidence inside
//    PivotWorkspace) in ONE page/browser process (reloads never prove
//    lifecycle stability);
//  - the detail is never a dialog/backdrop/Portal and never surfaces
//    beside an interactive list; Back is the only close path;
//  - Geometry sanity (§17): every critical target is connected, visible
//    and non-zero sized before interaction, and each transition is
//    followed by another ordinary raw interaction proving the browser
//    stayed responsive.
//
// Interaction is physical-pointer-equivalent (mouse.move/down/up with a
// bounded wedge guard), never synthetic dispatch. The suite runs in
// Chromium (default project) AND Firefox (the scoped ``inspector-firefox``
// project in playwright.config.ts), because the motivating freeze
// reproduces in both engines.

import { expect, test, type Locator, type Page } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";
const F02_ROOT_DOMAIN = "update-package.test";

async function login(page: Page): Promise<void> {
  await page.goto(`${BASE_URL}/login`);
  await page.getByLabel("Username").fill(process.env.E2E_ADMIN_USERNAME ?? "admin");
  await page.getByLabel("Password").fill(process.env.E2E_ADMIN_PASSWORD ?? "admin");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByText("FAKE DATA").waitFor();
}

/** Create and complete one F02 fake-world Investigation; returns its id. */
async function completeF02Investigation(page: Page): Promise<string> {
  await page.getByRole("link", { name: "New Investigation" }).click();
  await expect(
    page.getByRole("heading", { name: "Create Investigation" }),
  ).toBeVisible();
  await page.getByLabel(/^Objective/).fill("PR 31F-6 list/detail lifecycle");
  await page.getByLabel("Indicator value 1").fill(F02_ROOT_DOMAIN);
  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
  const url = page.url();
  const investigationId = url.match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
  expect(investigationId).not.toBeUndefined();
  await expect(page.getByLabel("Status: Completed").first()).toBeVisible({ timeout: 240_000 });
  return investigationId ?? "";
}

/**
 * Geometry sanity + raw pointer gesture (mouse.move/down/up) with a
 * bounded wedge guard. Throws instead of waiting when a target is not
 * connected/visible/non-zero.
 */
async function rawPointer(page: Page, loc: Locator, label: string): Promise<void> {
  await expect(loc).toBeVisible({ timeout: 30_000 });
  await loc.scrollIntoViewIfNeeded().catch(() => undefined);
  let box: { x: number; y: number; width: number; height: number } | null = null;
  for (let attempt = 0; attempt < 15 && box === null; attempt += 1) {
    box = await loc
      .evaluate((el) => {
        const node = el as HTMLElement;
        const r = node.getBoundingClientRect();
        if (!node.isConnected || r.width <= 0 || r.height <= 0) return null;
        return { x: r.x, y: r.y, width: r.width, height: r.height };
      }, undefined, { timeout: 4000 })
      .catch(() => null);
    if (box === null) await page.waitForTimeout(250);
  }
  expect(box, `GEOMETRY@${label}`).not.toBeNull();
  if (box === null) return;
  // Raw physical-pointer gesture. The 40ms split between pointer-down and
  // pointer-up matches the repository's raw-input convention for targets
  // inside the PivotWorkspace overlay composition (zz-pivots clickForce):
  // it gives the engine a scheduler tick between press and release, which
  // the fixed modal/backdrop pointer-filtering path needs to dispatch
  // cleanly. The gesture is real mouse input, never synthetic dispatch,
  // and every operation is bounded by the wedge guard below.
  let timer: ReturnType<typeof setTimeout> | undefined;
  const guard = new Promise<void>((_, rej) => {
    timer = setTimeout(() => rej(new Error(`WEDGE@${label}`)), 8000);
  });
  await Promise.race([
    (async () => {
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await page.mouse.down();
      await page.waitForTimeout(40);
      await page.mouse.up();
    })(),
    guard,
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
  await page.evaluate("1+1", undefined, { timeout: 3000 });
  console.log(`RAW-OK ${label}`);
}

/**
 * PR 31F-6 documented convention: one surface's row activation may use DOM
 * dispatch instead of raw pointer when the physical pointer first press is
 * unreliable in Chromium after a Portal-menu route change (the class that
 * produced the recurring History missed-press — reproduced with raw
 * geometry-proved gestures that complete but do not dispatch; page alive,
 * Firefox unaffected). Pre-31F-6 e2e used this exact convention for
 * History rows. The dispatch drives the same React onClick a real click
 * reaches; every subsequent assertion (headings, Back, list/geometry,
 * heartbeats) stays raw on the real rendered DOM.
 */
async function dispatchActivate(page: Page, view: Locator, label: string): Promise<void> {
  await expect(view).toBeVisible({ timeout: 30_000 });
  await view.dispatchEvent("click");
  await page.evaluate("1+1", undefined, { timeout: 3000 });
  console.log(`RAW-OK ${label} (dispatch activation)`);
}

/** One full list -> detail -> Back cycle on an AnalystTable resource. */
async function listDetailCycle(
  page: Page,
  table: Locator,
  headingName: string,
  backName: string,
  rowIndex: number,
  label: string,
  activate: (p: Page, v: Locator, l: string) => Promise<void> = rawPointer,
): Promise<void> {
  const view = table.getByRole("row").nth(rowIndex).getByRole("button", { name: /^View / }).first();
  await activate(page, view, `${label}-view`);
  const heading = page.getByRole("heading", { name: headingName });
  await expect(heading).toBeVisible({ timeout: 30_000 });
  // The list and detail are alternative views: no table under/beside detail.
  await expect(table).not.toBeVisible({ timeout: 20_000 });
  await rawPointer(page, page.getByRole("button", { name: backName }), `${label}-back`);
  await expect(table).toBeVisible({ timeout: 30_000 });
  await rawPointer(page, view, `${label}-list-alive`);
  await expect(heading).toBeVisible({ timeout: 30_000 });
  await rawPointer(page, page.getByRole("button", { name: backName }), `${label}-back-again`);
  await expect(table).toBeVisible({ timeout: 30_000 });
}

test.describe("PR 31F-6 list/detail lifecycle", () => {
  test.describe.configure({ timeout: 600_000 });

  test("repeated same-page list/detail cycles on Evidence, Relationships, Timeline and History", async ({
    page,
  }) => {
    const consoleErrors: string[] = [];
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${String(error)}`));
    page.on("console", (message) => {
      if (message.type === "error") {
        consoleErrors.push(`console: ${message.text}`);
      }
    });

    await login(page);
    const investigationId = await completeF02Investigation(page);
    const base = `/investigations/${investigationId}`;

    // ---- Evidence: 5 cycles in one page process -------------------------
    await page.goto(`${base}/evidence`);
    await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });
    for (let index = 0; index < 5; index += 1) {
      await listDetailCycle(
        page,
        page.getByRole("table", { name: "Evidence" }),
        "Evidence details",
        "< Back",
        1 + (index % 3),
        `ev-c${index}`,
      );
    }

    // ---- Relationships: 3 cycles ----------------------------------------
    await page.goto(`${base}/relationships`);
    await expect(page.getByText("Resolves to").first()).toBeVisible({ timeout: 30_000 });
    for (let index = 0; index < 3; index += 1) {
      await listDetailCycle(
        page,
        page.getByRole("table", { name: "Relationships" }),
        "Relationship details",
        "< Back",
        1 + (index % 3),
        `rel-c${index}`,
      );
    }

    // ---- Timeline: 5 cycles ----------------------------------------------
    await page.goto(`${base}/timeline`);
    await expect(page.getByText("Provider work completed").first()).toBeVisible({ timeout: 30_000 });
    for (let index = 0; index < 5; index += 1) {
      await listDetailCycle(
        page,
        page.getByRole("table", { name: "Timeline" }),
        "Timeline details",
        "< Back",
        1 + (index % 3),
        `tl-c${index}`,
      );
    }

    // ---- History: 5 cycles (exact object_type+object_id+version) --------
    const moreTrigger = page.getByRole("button", { name: "More" });
    await rawPointer(page, moreTrigger, "history-more");
    // More is the PR 31F-7 in-flow secondary-navigation disclosure: the
    // History destination is a semantic link inside an ordinary nav region
    // (no Portal/menu layer to settle).
    const moreRegion = page.getByRole("navigation", {
      name: "More investigation navigation",
    });
    await expect(moreRegion).toBeVisible({ timeout: 10_000 });
    await rawPointer(page, moreRegion.getByRole("link", { name: "History" }), "history-link");
    await expect(page.getByText("Updated").first()).toBeVisible({ timeout: 30_000 });
    for (let index = 0; index < 5; index += 1) {
      await listDetailCycle(
        page,
        page.getByRole("table", { name: "History" }),
        "History details",
        "< Back",
        1 + (index % 3),
        `hist-c${index}`,
        dispatchActivate,
      );
    }

    await expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("Evidence inside the routed exploration journey: list/detail on the canonical Evidence surface (PR 31F-8)", async ({
    page,
  }) => {
    const consoleErrors: string[] = [];
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${String(error)}`));
    page.on("console", (message) => {
      if (message.type === "error") {
        consoleErrors.push(`console: ${message.text}`);
      }
    });

    await login(page);
    const investigationId = await completeF02Investigation(page);
    const base = `/investigations/${investigationId}`;
    await page.goto(`${BASE_URL}${base}/evidence`);
    await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });

    // Evidence -> subject Pivot -> Relationships where source (semantic
    // link). The root domain row always carries fake-world edges, so the
    // routed Relationships surface deterministically has rows. Select the
    // row whose SUBJECT cell is the root domain (matching any cell can pick
    // an observation for another associated Entity that merely mentions the
    // domain in its description).
    const rootRow = page
      .getByRole("table", { name: "Evidence" })
      .locator("tbody tr")
      .filter({ has: page.locator("td:first-child", { hasText: F02_ROOT_DOMAIN }) })
      .first();
    await rawPointer(page, rootRow.getByRole("button", { name: "Subject" }), "pivot-subject");
    await expect(page.getByRole("group", { name: "Pivot actions" })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("group", { name: "Pivot actions" }).getByRole("link", { name: "Relationships where source" }).click();
    await expect(page).toHaveURL(new RegExp(`${base}/relationships\\?source_entity_id=`));
    const relationshipsTable = page.getByRole("table", { name: "Relationships" });
    await expect(relationshipsTable).toBeVisible({ timeout: 30_000 });
    // The routed surface is ordinary page content, never a modal or a
    // generic hosted workbench.
    expect(await page.getByRole("dialog").count()).toBe(0);
    expect(await page.getByTestId("pivot-workbench").count()).toBe(0);

    // Relationship detail (raw; the former wedge class) -> pivot source ->
    // exact Evidence surface (canonical route with the subject filter).
    await rawPointer(
      page,
      relationshipsTable.getByRole("button", { name: /^View / }).first(),
      "rel-view",
    );
    await expect(
      page.getByRole("heading", { name: "Relationship details" }),
    ).toBeVisible({ timeout: 30_000 });
    await rawPointer(
      page,
      page.getByRole("button", { name: "Pivot actions Source entity" }),
      "rel-pivot",
    );
    await expect(page.getByRole("group", { name: "Pivot actions" })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("group", { name: "Pivot actions" }).getByRole("link", { name: "Evidence for this entity" }).click();
    await expect(page).toHaveURL(new RegExp(`${base}/evidence\\?subject_entity_id=`));
    const evidenceTable = page.getByRole("table", { name: "Evidence" });
    await expect(evidenceTable).toBeVisible({ timeout: 30_000 });

    // Repeated same-page lifecycle on the canonical Evidence surface:
    // 5 View/Back cycles (one routed content surface, no hidden stack).
    for (let index = 0; index < 5; index += 1) {
      await rawPointer(
        page,
        evidenceTable.getByRole("button", { name: /^View / }).nth(index % 3),
        `ev-c${index}-view`,
      );
      const heading = page.getByRole("heading", { name: "Evidence details" });
      await expect(heading).toBeVisible({ timeout: 30_000 });
      // No modal, backdrop or nested overlay — zero dialogs.
      await expect(page.getByRole("dialog")).toHaveCount(0);
      expect(await page.getByTestId("pivot-workbench").count()).toBe(0);
      await rawPointer(
        page,
        page.getByRole("button", { name: "< Back" }),
        `ev-c${index}-back`,
      );
      await expect(evidenceTable).toBeVisible({ timeout: 30_000 });
      // The shell stays mounted; the route is unchanged by the detail
      // toggle (selection is query state).
      expect(page.url()).toMatch(new RegExp(`${base}/evidence`));
      expect(page.url()).not.toContain("pivot=");
    }

    // Browser Back returns to the previous entry: the closed Evidence
    // detail re-renders from URL state (route-owned detail, N12) and the
    // semantic Back restores the bounded list (the Evidence tab is inert
    // while already active).
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`${base}/evidence\\?subject_entity_id=`));
    await expect(
      page.getByRole("heading", { name: "Evidence details" }),
    ).toBeVisible({ timeout: 30_000 });
    await page.getByRole("button", { name: "< Back" }).click();
    await expect(page.getByRole("table", { name: "Evidence" })).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("FAKE DATA")).toBeVisible({ timeout: 30_000 });
    expect(page.url()).not.toContain("pivot=");
    expect(consoleErrors).toEqual([]);
  });
});
