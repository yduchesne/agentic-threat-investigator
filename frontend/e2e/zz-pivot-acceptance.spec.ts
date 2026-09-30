// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31F-6 amendment 5: raw-pointer acceptance of the in-flow Pivot
// workbench (replaces the former fixed-overlay PivotWorkspace).
//
// The forced relationship from the A5 checkpoint: the former in-workspace
// raw View press wedged the browser main thread inside the fixed overlay;
// in the in-flow Pivot workbench the same raw press completes cleanly
// (this spec is the regression gate for that exact former failure).
//
// Journey (repeated >= 5 times in ONE page process, per engine):
//   Evidence list
//    -> RAW action entering the Relationships Pivot step
//    -> in-flow Pivot workbench
//    -> RAW View -> Relationship detail
//    -> RAW Back -> Relationships list
//    -> RAW another Pivot/workbench control (expand inline Pivot -> Cancel)
//    -> RAW breadcrumb/truncate where applicable
//    -> RAW Close Pivot -> normal Investigation workbench
//    -> RAW ordinary Investigation control (Evidence row View/Back)
//    -> responsive heartbeat after each transition
//
// Every critical action is physical-pointer (mouse.move/down/up) over a
// geometry-proved target (connected/visible/width>0/height>0) with a
// bounded wedge guard. No synthetic dispatch, no evaluated click, no
// reload, workers=1, retries=0.

import { expect, test, type Locator, type Page } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";
const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 31F-6 A5 in-flow Pivot acceptance";
const CYCLES = 5;

async function login(page: Page): Promise<void> {
  await page.goto(`${BASE_URL}/login`);
  await page.getByLabel("Username").fill(process.env.E2E_ADMIN_USERNAME ?? "admin");
  await page.getByLabel("Password").fill(process.env.E2E_ADMIN_PASSWORD ?? "admin");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByText("FAKE DATA").waitFor();
}

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
  await expect(page.getByLabel("Status: Completed").first()).toBeVisible({ timeout: 240_000 });
  return investigationId ?? "";
}

/** Geometry-proof + raw pointer press (bounded wedge guard). */
async function rawPointer(page: Page, loc: Locator, label: string): Promise<void> {
  await expect(loc).toBeVisible({ timeout: 30_000 });
  await loc.scrollIntoViewIfNeeded().catch(() => undefined);
  let box: { x: number; y: number; width: number; height: number } | null = null;
  for (let attempt = 0; attempt < 15 && box === null; attempt += 1) {
    box = await loc
      .evaluate((el) => {
        const n = el as HTMLElement;
        const r = n.getBoundingClientRect();
        if (!n.isConnected || r.width <= 0 || r.height <= 0) return null;
        return { x: r.x, y: r.y, width: r.width, height: r.height };
      }, undefined, { timeout: 4000 })
      .catch(() => null);
    if (box === null) await page.waitForTimeout(250);
  }
  expect(box, `GEOMETRY@${label}`).not.toBeNull();
  if (box === null) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const guard = new Promise<void>((_, rej) => {
    timer = setTimeout(() => rej(new Error(`STALL@${label} (raw pointer froze)`)), 8000);
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
  await page.evaluate("1+1", undefined, { timeout: 3000 });
  console.log(`RAW-OK ${label}`);
}

test.describe("PR 31F-6 A5 in-flow Pivot workbench acceptance", () => {
  test.describe.configure({ timeout: 600_000 });

  test("raw-pointer journey: Evidence -> Pivot workbench -> View/Back -> Close; five same-page cycles", async ({
    page,
  }) => {
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await page.goto(`${BASE_URL}/investigations/${investigationId}/evidence`);
    await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });

    const pivotSubject = () =>
      page
        .getByRole("row")
        .filter({ hasText: F02_ROOT_DOMAIN })
        .first()
        .getByRole("button", { name: "Subject" });
    const relationshipsTable = () => page.getByRole("table", { name: "Relationships" });
    const wsView = () =>
      relationshipsTable()
        .getByRole("row")
        .filter({ hasText: F02_ROOT_DOMAIN })
        .first()
        .getByRole("button", { name: /^View / });

    for (let cycle = 0; cycle < CYCLES; cycle += 1) {
      console.log(`RAW-CYCLE ${cycle + 1}`);

      // RAW action entering the Relationships Pivot step.
      await rawPointer(page, pivotSubject(), `c${cycle}-pivot-subject`);
      await expect(page.getByRole("group", { name: "Pivot actions" })).toBeVisible({ timeout: 15_000 });
      await rawPointer(page, page.getByRole("button", { name: "Relationships where source" }), `c${cycle}-pivot-action`);

      // In-flow Pivot workbench is primary; no modal remains.
      const workbench = page.getByTestId("pivot-workbench");
      await expect(page.getByRole("heading", { name: "Relationships pivot workspace" })).toBeVisible({ timeout: 30_000 });
      await expect(workbench).toBeVisible({ timeout: 30_000 });
      expect(await page.getByRole("dialog").count()).toBe(0);
      // The normal Investigation workbench (tabs) is not mounted underneath.
      await expect(page.getByRole("tab", { name: "Evidence" })).not.toBeVisible({ timeout: 10_000 });

      // RAW View -> Relationship detail (the former wedge class).
      await rawPointer(page, wsView(), `c${cycle}-ws-view`);
      await expect(
        page.getByRole("heading", { name: "Relationships details" }),
      ).toBeVisible({ timeout: 30_000 });
      await expect(
        page.getByRole("button", { name: "Back to Relationships" }),
      ).toBeVisible({ timeout: 30_000 });

      // RAW Back -> same step's Relationships list.
      await rawPointer(page, page.getByRole("button", { name: "Back to Relationships" }), `c${cycle}-ws-back`);
      await expect(relationshipsTable()).toBeVisible({ timeout: 30_000 });

      // RAW another Pivot/workbench control: inline Pivot -> Cancel.
      const rowPivot = relationshipsTable()
        .getByRole("row")
        .filter({ hasText: F02_ROOT_DOMAIN })
        .first()
        .getByRole("button", { name: "Source entity" });
      await rawPointer(page, rowPivot, `c${cycle}-bar-trigger`);
      const bar = page.getByRole("group", { name: "Pivot actions" });
      await expect(bar).toBeVisible({ timeout: 15_000 });
      await rawPointer(page, bar.getByRole("button", { name: "Cancel" }), `c${cycle}-bar-cancel`);
      await expect(bar).not.toBeVisible({ timeout: 15_000 });

      // RAW Close Pivot -> normal Investigation workbench returns.
      await rawPointer(page, page.getByRole("button", { name: "Close pivot workspace" }), `c${cycle}-close`);
      await expect(page.getByTestId("pivot-workbench")).not.toBeVisible({ timeout: 20_000 });
      await expect(page.getByRole("tab", { name: "Evidence" })).toBeVisible({ timeout: 30_000 });

      // RAW ordinary Investigation control: the Evidence list's row View
      // (deferred-commit list/detail, the same control the A4 ordinary
      // acceptance exercises) proves the normal workbench is responsive
      // again after the pivot workbench closed.
      const rowView = page
        .getByRole("table", { name: "Evidence" })
        .getByRole("row")
        .filter({ hasText: F02_ROOT_DOMAIN })
        .first()
        .getByRole("button", { name: /^View / });
      await rawPointer(page, rowView, `c${cycle}-ordinary-view`);
      await expect(
        page.getByRole("heading", { name: "Evidence details" }),
      ).toBeVisible({ timeout: 30_000 });
      await rawPointer(page, page.getByRole("button", { name: "Back to Evidence" }), `c${cycle}-ordinary-back`);
      await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });
      await page.evaluate("1+1", undefined, { timeout: 3000 });
      console.log(`RAW-CYCLE-DONE ${cycle + 1}`);
    }
  });
});
