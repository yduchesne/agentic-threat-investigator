// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31F-7 critical real-stack acceptance (Chromium + Firefox).
//
// Two defect classes are closed by PR 31F-7 and are proven here with
// physical-pointer-equivalent input (mouse.move/down/up) over
// geometry-proved targets, `--retries=0`, `workers=1`, no recovery
// reload and no arbitrary sleeps:
//
// 1. More navigation is an ordinary in-flow secondary-navigation
//    disclosure (no MUI Menu/Popover/Modal/Portal, no backdrop, no body
//    lock, no document-global dismissal listener). The raw journey opens
//    and closes More and navigates More -> History five times in ONE
//    page/browser process, proving the page stays live after every
//    transition (heartbeat + another raw ordinary interaction).
// 2. Appearance live-preview lifecycle for EVERY supported appearance
//    (Light/Dark/Wargames/Control Room): selecting previews the rendered
//    surface before Save, Cancel restores the committed appearance,
//    Save persists across reload, and no theme-only change alters the
//    route. No appearance is special-cased: they all use the one generic
//    preview path.
//
// Chromium runs the default project; Firefox runs the same journey via
// the scoped ``inspector-firefox`` project (playwright.config.ts).
//
// The rendered-surface probe uses the shell header (AppBar) element via a
// CSS locator because the MUI Preferences dialog is a genuine modal and
// correctly marks the rest of the page ``aria-hidden`` while open — role/
// landmark locators resolve to nothing during the in-dialog preview steps.

import { expect, test, type Locator, type Page } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";
const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 31F-7 critical acceptance journey";

/** Surface tokens (theme.ts) used as end-to-end computed-style proofs. */
const LIGHT_PAPER_RGB = "rgb(255, 255, 255)";
const DARK_PAPER_RGB = "rgb(28, 32, 38)";
const WARGAMES_PAPER_RGB = "rgb(16, 21, 15)";
const CONTROL_ROOM_PAPER_RGB = "rgb(15, 26, 44)";

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

/**
 * Shell header (AppBar) computed background, resolved as DOM (CSS
 * locator) because the Preferences modal marks the rest of the page
 * ``aria-hidden`` while open (see file header).
 */
async function headerBackground(page: Page): Promise<string> {
  return page
    .locator("header.MuiAppBar-root")
    .evaluate((el) => getComputedStyle(el).backgroundColor);
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

test.describe("PR 31F-7 critical acceptance (More + appearance)", () => {
  test.describe.configure({ timeout: 480_000 });

  test("More in-flow disclosure five same-page raw cycles; every appearance live-previews, Cancel restores, Save persists", async ({
    page,
  }) => {
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await page.goto(`${BASE_URL}/investigations/${investigationId}/overview`);
    const overviewHeading = page.getByRole("heading", { name: OBJECTIVE });
    await expect(overviewHeading).toBeVisible({ timeout: 30_000 });

    const moreTrigger = page.getByRole("button", { name: "More" });
    const moreRegion = page.getByRole("navigation", {
      name: "More investigation navigation",
    });
    const historyLink = page.getByRole("link", { name: "History" });

    // ---- More: five same-page cycles (no reload) ------------------------
    for (let cycle = 0; cycle < 5; cycle += 1) {
      console.log(`MORE-CYCLE ${cycle + 1}`);

      // RAW open More: the in-flow region appears in normal layout and the
      // page stays live.
      await rawPointer(page, moreTrigger, `m${cycle}-open`);
      await expect(moreRegion).toBeVisible({ timeout: 20_000 });
      await assertHealthy(page, moreRegion, `m${cycle}-region`);
      // No ARIA menu / modal / body lock exists anywhere on the page.
      expect(await page.getByRole("menu").count()).toBe(0);
      const portalProbe = await page.evaluate(() => ({
        modal: document.querySelector('[aria-modal="true"]') !== null,
        bodyHidden: document.body.getAttribute("aria-hidden") !== null,
      }));
      expect(portalProbe).toEqual({ modal: false, bodyHidden: false });
      expect(await moreTrigger.getAttribute("aria-expanded")).toBe("true");
      await assertResponsive(page, `m${cycle}-region-open`);

      // RAW close via the trigger toggle; the region collapses in place.
      await rawPointer(page, moreTrigger, `m${cycle}-close`);
      await expect(moreRegion).not.toBeVisible({ timeout: 20_000 });
      await assertResponsive(page, `m${cycle}-region-closed`);

      // RAW open again, then RAW History -> exactly one navigation, and the
      // ordinary browser Back restores the workspace for the next cycle.
      await rawPointer(page, moreTrigger, `m${cycle}-open2`);
      await expect(moreRegion).toBeVisible({ timeout: 20_000 });
      await rawPointer(page, historyLink, `m${cycle}-history`);
      await expect(page).toHaveURL(/\/history$/, { timeout: 20_000 });
      await expect(page.getByRole("heading", { name: "History" })).toBeVisible({ timeout: 30_000 });
      await expect(page.getByText("Updated").first()).toBeVisible({ timeout: 30_000 });
      await assertResponsive(page, `m${cycle}-history-rendered`);

      await page.goBack();
      await expect(overviewHeading).toBeVisible({ timeout: 30_000 });
      await assertHealthy(page, overviewHeading, `m${cycle}-overview-back`);
      await assertResponsive(page, `m${cycle}-overview-restored`);
      // A raw ordinary workspace control proves the page stayed fully live.
      await rawPointer(page, moreTrigger, `m${cycle}-final-open`);
      await expect(moreRegion).toBeVisible({ timeout: 20_000 });
      await rawPointer(page, moreTrigger, `m${cycle}-final-close`);
      await expect(moreRegion).not.toBeVisible({ timeout: 20_000 });
      await assertResponsive(page, `m${cycle}-final`);
    }

    // ---- Appearance: every supported appearance, one generic path -------
    const urlBefore = page.url();

    // Baseline Light (canonical default).
    await expect.poll(headerBackground.bind(null, page)).toBe(LIGHT_PAPER_RGB);

    // Preview Dark (rendered surface BEFORE Save), then Save.
    await page.getByRole("button", { name: "Preferences" }).click();
    const dialog = page.getByRole("dialog", { name: "Preferences" });
    await expect(dialog).toBeVisible({ timeout: 20_000 });
    await dialog.getByRole("radio", { name: "Dark" }).click();
    await expect.poll(headerBackground.bind(null, page)).toBe(DARK_PAPER_RGB);
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).not.toBeVisible();
    await expect.poll(headerBackground.bind(null, page)).toBe(DARK_PAPER_RGB);

    // Reload: Dark is committed.
    await page.reload();
    await expect(overviewHeading).toBeVisible({ timeout: 30_000 });
    await expect.poll(headerBackground.bind(null, page)).toBe(DARK_PAPER_RGB);

    // Reopen: Wargames previews BEFORE Save, Cancel restores Dark.
    await page.getByRole("button", { name: "Preferences" }).click();
    const dialog2 = page.getByRole("dialog", { name: "Preferences" });
    await expect(dialog2).toBeVisible({ timeout: 20_000 });
    await expect(dialog2.getByRole("radio", { name: "Dark" })).toBeChecked();
    await dialog2.getByRole("radio", { name: "Wargames" }).click();
    await expect.poll(headerBackground.bind(null, page)).toBe(WARGAMES_PAPER_RGB);
    await dialog2.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog2).not.toBeVisible();
    await expect.poll(headerBackground.bind(null, page)).toBe(DARK_PAPER_RGB);

    // Reopen: Control Room previews, Save commits, route unchanged, reload persists.
    await page.getByRole("button", { name: "Preferences" }).click();
    const dialog3 = page.getByRole("dialog", { name: "Preferences" });
    await expect(dialog3).toBeVisible({ timeout: 20_000 });
    await dialog3.getByRole("radio", { name: "Control Room" }).click();
    await expect.poll(headerBackground.bind(null, page)).toBe(CONTROL_ROOM_PAPER_RGB);
    await dialog3.getByRole("button", { name: "Save" }).click();
    await expect(dialog3).not.toBeVisible();
    await expect(page).toHaveURL(urlBefore);
    await expect.poll(headerBackground.bind(null, page)).toBe(CONTROL_ROOM_PAPER_RGB);
    await page.reload();
    await expect(overviewHeading).toBeVisible({ timeout: 30_000 });
    await expect.poll(headerBackground.bind(null, page)).toBe(CONTROL_ROOM_PAPER_RGB);

    // Reopen: Light (fourth supported appearance) previews, Cancel restores.
    await page.getByRole("button", { name: "Preferences" }).click();
    const dialog4 = page.getByRole("dialog", { name: "Preferences" });
    await expect(dialog4).toBeVisible({ timeout: 20_000 });
    await expect(dialog4.getByRole("radio", { name: "Control Room" })).toBeChecked();
    await dialog4.getByRole("radio", { name: "Light" }).click();
    await expect.poll(headerBackground.bind(null, page)).toBe(LIGHT_PAPER_RGB);
    await dialog4.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog4).not.toBeVisible();
    await expect.poll(headerBackground.bind(null, page)).toBe(CONTROL_ROOM_PAPER_RGB);
  });
});
