// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31F-8: routed cross-resource navigation acceptance (replaces the
// former in-flow Pivot workbench acceptance).
//
// Cross-resource exploration is ordinary Investigation-scoped React Router
// navigation: semantic links for route-known targets, buttons for local
// actions, browser Back/Forward for the reverse journey. This spec runs
// the same navigation cycle at least 5 times in ONE page process per
// engine and proves each transition with a canonical URL, rendered
// content, a responsive heartbeat and zero product console errors. Every
// activation is a NORMAL locator click — no dispatch, no force, no
// coordinate clicks, no sleeps, no reload.

import { expect, test, type Page } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";
const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 31F-8 routed cross-resource acceptance";
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

/** Prove the page is alive right after an interaction. */
async function assertResponsive(page: Page, label: string): Promise<void> {
  await page.evaluate("1+1", undefined, { timeout: 3000 });
  console.log(`31F8-OK ${label}`);
}

test.describe("PR 31F-8 routed cross-resource navigation acceptance", () => {
  test.describe.configure({ timeout: 600_000, retries: 0 });

  test("Evidence -> routed Relationships -> detail -> Back -> observations; five same-page cycles", async ({
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

    for (let cycle = 0; cycle < CYCLES; cycle += 1) {
      console.log(`31F8-RAW-CYCLE ${cycle + 1}`);

      // Routed capability activation: Evidence subject -> Relationships
      // where source (semantic link in the in-flow action bar).
      // Select the row whose SUBJECT cell is the root domain. Matching any
      // cell is ambiguous: a ThreatFox observation for another associated
      // Entity can mention the domain in its description while its subject
      // is not the domain, which would pivot to an unrelated Entity.
      const rootRow = page
        .getByRole("table", { name: "Evidence" })
        .locator("tbody tr")
        .filter({
          has: page.locator("td:first-child", { hasText: F02_ROOT_DOMAIN }),
        })
        .first();
      await rootRow.getByRole("button", { name: "Subject" }).click();
      const bar = page.getByRole("group", { name: "Pivot actions" });
      await expect(bar).toBeVisible({ timeout: 15_000 });
      await bar.getByRole("link", { name: "Relationships where source" }).click();

      // Canonical Relationships route with the exact filter query; one
      // routed surface, no pivot parameter, no hosted workbench.
      await expect(page).toHaveURL(new RegExp(`${base}/relationships\\?source_entity_id=`));
      const relationshipsTable = page.getByRole("table", { name: "Relationships" });
      await expect(relationshipsTable).toBeVisible({ timeout: 60_000 });
      expect(page.url()).not.toContain("pivot=");
      expect(await page.getByTestId("pivot-workbench").count()).toBe(0);
      await assertResponsive(page, `c${cycle}-relationships-route`);

      // Detail -> list cycle on the relationships surface (ordinary
      // list/detail View/Back, the routed shell stays mounted).
      await relationshipsTable
        .getByRole("row")
        .filter({ hasText: F02_ROOT_DOMAIN })
        .first()
        .getByRole("button", { name: /^View / })
        .click();
      await expect(
        page.getByRole("heading", { name: "Relationship details" }),
      ).toBeVisible({ timeout: 30_000 });
      await assertResponsive(page, `c${cycle}-detail`);
      await page.getByRole("button", { name: "Back to Relationships" }).click();
      await expect(relationshipsTable).toBeVisible({ timeout: 30_000 });
      await assertResponsive(page, `c${cycle}-back`);

      // Local inline actions: expand a row's Pivot bar and Cancel.
      const rowPivot = relationshipsTable
        .getByRole("row")
        .filter({ hasText: F02_ROOT_DOMAIN })
        .first()
        .getByRole("button", { name: "Source entity" });
      await rowPivot.click();
      const inlineBar = page.getByRole("group", { name: "Pivot actions" });
      await expect(inlineBar).toBeVisible({ timeout: 15_000 });
      await inlineBar.getByRole("button", { name: "Hide" }).click();
      await expect(inlineBar).not.toBeVisible({ timeout: 15_000 });
      await assertResponsive(page, `c${cycle}-cancel`);

      // Routed capability: the relationship detail's "View all
      // observations" semantic link -> the observations route with the
      // exact relationship filter.
      await relationshipsTable
        .getByRole("row")
        .filter({ hasText: F02_ROOT_DOMAIN })
        .first()
        .getByRole("button", { name: /^View / })
        .click();
      await expect(
        page.getByRole("heading", { name: "Relationship details" }),
      ).toBeVisible({ timeout: 30_000 });
      await expect(page.getByText(/Confidence/).first()).toBeVisible({ timeout: 30_000 });
      await page.getByRole("link", { name: "View all history" }).click();
      await page.waitForURL(
        new RegExp(`${base}/relationships/observations\\?relationship_id=`),
        { timeout: 5_000 },
      );
      await expect(
        page.getByRole("textbox", { name: "Relationship ID" }),
      ).toBeVisible({ timeout: 30_000 });
      await assertResponsive(page, `c${cycle}-observations-route`);

      // Browser Back returns to the Relationship detail entry (the
      // observations link was followed from the detail); ordinary
      // workbench tabs stay responsive from anywhere.
      await page.goBack();
      await expect(page).toHaveURL(new RegExp(`${base}/relationships\\?source_entity_id=`));
      await expect(
        page.getByRole("heading", { name: "Relationship details" }),
      ).toBeVisible({ timeout: 30_000 });
      await assertResponsive(page, `c${cycle}-back-detail`);
      // The semantic Back control closes the detail (the Relationships tab
      // is inert while the detail route is active).
      await page.getByRole("button", { name: "Back to Relationships" }).click();
      await expect(relationshipsTable).toBeVisible({ timeout: 30_000 });
      await assertResponsive(page, `c${cycle}-detail-closed`);

      // Enter the next cycle from the Evidence tab (normal workbench).
      await page.getByRole("tab", { name: "Evidence" }).click();
      await expect(
        page.getByRole("table", { name: "Evidence" }),
      ).toBeVisible({ timeout: 30_000 });
      await assertResponsive(page, `c${cycle}-evidence-tab`);
      console.log(`31F8-RAW-CYCLE-DONE ${cycle + 1}`);
    }

    expect(consoleErrors).toEqual([]);
  });
});
