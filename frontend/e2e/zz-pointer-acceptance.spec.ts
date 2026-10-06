// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31F-6 amendment 4: raw-pointer list/detail Evidence journey acceptance.
//
// The ordinary Evidence surface is a list/detail workspace: RAW View
// replaces the bounded list with the exact Investigation-scoped detail as
// the main in-flow content, the inline Pivot action bar sits inside the
// detail, and RAW Back to Evidence restores the list context. Every
// critical interaction is driven with physical-pointer-equivalent input
// (mouse.move/down/up) and each critical target is geometry-proved
// (connected, visible, width > 0, height > 0). Synthetic DOM click
// dispatch is NOT acceptance evidence for this journey.
//
// The journey repeats five times in ONE page/browser process (no reload)
// and performs another raw ordinary list interaction after every
// transition, proving responsiveness. Chromium runs the default project;
// Firefox runs the same journey via the scoped ``inspector-firefox``
// project (the motivating freeze reproduces in both engines).

import { expect, test, type Locator, type Page } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";
const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 31F-6 raw-pointer list/detail journey";

/** One raw pointer gesture (move/down/up) with a bounded wedge guard. */
async function rawPointer(page: Page, loc: Locator, label: string): Promise<void> {
  const box = await assertHealthy(page, loc, label);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const guard = new Promise<void>((_, rej) => {
    timer = setTimeout(() => rej(new Error(`WEDGE@${label}`)), 5000);
  });
  await Promise.race([
    (async () => {
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await page.mouse.down();
      await page.mouse.up();
    })(),
    guard,
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
  await assertResponsive(page, label);
}

/**
 * Geometry sanity (PR 31F-6 §17): connected, visible, width > 0,
 * height > 0. Returns the target center box for the raw gesture.
 */
async function assertHealthy(
  page: Page,
  loc: Locator,
  label: string,
): Promise<{ x: number; y: number; width: number; height: number }> {
  await expect(loc).toBeVisible({ timeout: 30_000 });
  await loc.scrollIntoViewIfNeeded().catch(() => undefined);
  let box: { x: number; y: number; width: number; height: number } | null = null;
  for (let attempt = 0; attempt < 15 && box === null; attempt += 1) {
    box = await loc
      .evaluate((el) => {
        const node = el as HTMLElement;
        if (!node.isConnected) return null;
        const r = node.getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) return null;
        return { x: r.x, y: r.y, width: r.width, height: r.height };
      }, undefined, { timeout: 4000 })
      .catch(() => null);
    if (box === null) await page.waitForTimeout(250);
  }
  if (box === null) throw new Error(`GEOMETRY@${label}: target not connected/visible/non-zero`);
  return box;
}

/** Prove the page is alive right after an interaction. */
async function assertResponsive(page: Page, label: string): Promise<void> {
  await page.evaluate("1+1", undefined, { timeout: 3000 });
  console.log(`RAW-OK ${label}`);
}

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
  await page.getByLabel(/^Objective/).fill(OBJECTIVE);
  await page.getByLabel("Indicator value 1").fill(F02_ROOT_DOMAIN);
  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
  const url = page.url();
  const investigationId = url.match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
  expect(investigationId).not.toBeUndefined();
  await expect(
    page.getByRole("heading", { name: OBJECTIVE }),
  ).toBeVisible({ timeout: 20_000 });
  await expect(page.getByLabel("Status: Completed").first()).toBeVisible({ timeout: 240_000 });
  return investigationId ?? "";
}

test.describe("PR 31F-6 raw-pointer list/detail Evidence journey", () => {
  test.describe.configure({ timeout: 420_000 });

  test("Evidence list -> RAW View -> detail -> RAW Pivot/Cancel -> RAW Back; five same-page cycles", async ({
    page,
  }) => {
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await page.goto(`${BASE_URL}/investigations/${investigationId}/evidence`);
    await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });

    const table = page.getByRole("table", { name: "Evidence" });

    for (let cycle = 0; cycle < 5; cycle += 1) {
      console.log(`RAW-CYCLE ${cycle + 1}`);

      // RAW View on the root-domain row -> full-width detail as main content.
      const view = table
        .getByRole("row")
        .filter({ hasText: F02_ROOT_DOMAIN })
        .first()
        .getByRole("button", { name: /^View / })
        .first();
      await rawPointer(page, view, `c${cycle}-view`);
      const detailHeading = page.getByRole("heading", { name: "Evidence details" });
      await expect(detailHeading).toBeVisible({ timeout: 30_000 });
      await assertHealthy(page, detailHeading, `c${cycle}-detail-heading`);
      // The list is an alternative view: not rendered under/beside the detail.
      await expect(table).not.toBeVisible({ timeout: 20_000 });
      await assertResponsive(page, `c${cycle}-detail-open`);

      // RAW Pivot trigger inside the detail expands only the inline bar.
      const pivotTrigger = page.getByRole("button", { name: "Pivot actions", exact: true });
      await rawPointer(page, pivotTrigger, `c${cycle}-pivot-trigger`);
      const actionBar = page.getByRole("group", { name: "Pivot actions" });
      await expect(actionBar).toBeVisible({ timeout: 20_000 });
      await assertResponsive(page, `c${cycle}-bar-expanded`);

      // RAW valid action or Hide: Hide collapses only the action bar.
      // (The valid-action path is covered by the PivotWorkspace journey.)
      await rawPointer(page, actionBar.getByRole("button", { name: "Hide" }), `c${cycle}-hide`);
      await expect(actionBar).not.toBeVisible({ timeout: 20_000 });
      await assertResponsive(page, `c${cycle}-bar-collapsed`);

      // RAW Back to Evidence restores the bounded list.
      await rawPointer(page, page.getByRole("button", { name: "Back to Evidence" }), `c${cycle}-back`);
      await expect(table).toBeVisible({ timeout: 30_000 });
      await assertHealthy(page, table, `c${cycle}-list-returned`);
      await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });
      await assertResponsive(page, `c${cycle}-list-restored`);

      // After every transition another raw ordinary list control proves the
      // browser stayed alive: open the detail again via RAW View.
      await rawPointer(page, view, `c${cycle}-view-again`);
      await expect(detailHeading).toBeVisible({ timeout: 30_000 });
      await assertResponsive(page, `c${cycle}-final`);
      await rawPointer(page, page.getByRole("button", { name: "Back to Evidence" }), `c${cycle}-back-again`);
      await expect(table).toBeVisible({ timeout: 30_000 });
      await assertResponsive(page, `c${cycle}-final-back`);
    }
  });
});
