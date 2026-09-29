// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 31F-4 Appearance Preferences (E30).
//
// Runs against the production-path stack created by the repository E2E
// harness (scripts/e2e.sh) after the PR 24A/24B/24C suites, reusing the
// authenticated session captured by zz-analyst-tables.spec.ts
// (test-results/analyst-session.json) so the backend login rate limit is
// never exceeded. `FAKE DATA` stays visible throughout; no live Internet,
// no live threat-intelligence provider, and no live LLM.
//
// Canonical slice:
//   login (shared session) -> create F03 fake-world Investigation ->
//   Relationship Evolution -> Graph view -> Preferences: select Dark ->
//   Save -> route unchanged -> reload -> Dark restored (persistence) ->
//   graph still usable -> preview Wargames -> Cancel -> Dark restored ->
//   Save Control Room -> graph remains usable with no theme-only request.

import { expect, test, type Page } from "@playwright/test";

const OBJECTIVE = "PR 31F-4 assess appearance workbench";
const F03_ROOT_DOMAIN = "logistics-corp.test";
const SHARED_SESSION_STATE = "test-results/analyst-session.json";

/** Dark surface token (theme.ts) used as an end-to-end computed-style proof. */
const DARK_PAPER_RGB = "rgb(28, 32, 38)";
/** Wargames surface token (theme.ts). */
const WARGAMES_PAPER_RGB = "rgb(16, 21, 15)";
/** Control Room surface token (theme.ts). */
const CONTROL_ROOM_PAPER_RGB = "rgb(15, 26, 44)";

/** Resolve the AppBar (header) computed background color. */
async function headerBackground(page: Page): Promise<string> {
  return page.getByRole("banner").evaluate((el) => getComputedStyle(el).backgroundColor);
}

test.describe("PR 31F-4 real-stack appearance preference workflow", () => {
  test.describe.configure({ timeout: 300_000 });
  test.use({ storageState: SHARED_SESSION_STATE });

  test("E30 login -> Investigation -> Dark saves locally and survives reload; Cancel restores; Control Room keeps the graph usable", async ({
    page,
  }) => {
    const consoleErrors: string[] = [];
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${String(error)}`));
    page.on("console", (message) => {
      if (message.type === "error") {
        consoleErrors.push(`console: ${message.text}`);
      }
    });

    // Create one F03 fake-world Investigation (no live anything).
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    await page.getByRole("link", { name: "New Investigation" }).click();
    await expect(page.getByRole("heading", { name: "Create Investigation" })).toBeVisible();
    await page.getByLabel(/^Objective/).fill(OBJECTIVE);
    await page.getByLabel("Indicator value 1").fill(F03_ROOT_DOMAIN);
    await page.getByRole("button", { name: "Submit" }).click();
    await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
    const investigationUrl = page.url();
    const investigationId = investigationUrl.match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
    expect(investigationId).not.toBeUndefined();
    await expect(page.getByRole("heading", { name: OBJECTIVE })).toBeVisible({ timeout: 20_000 });
    await expect(page.getByLabel("Status: Completed").first()).toBeVisible({ timeout: 240_000 });

    // Relationships -> first source entity -> Relationship Evolution -> Graph.
    await page.goto(`/investigations/${investigationId}/relationships`);
    const firstRow = page.getByRole("table", { name: "Relationships" }).getByRole("row").nth(1);
    await expect(firstRow).toBeVisible({ timeout: 20_000 });
    await firstRow
      .getByRole("link", { name: "View relationship evolution for source entity" })
      .first()
      .click();
    await expect(page).toHaveURL(/\/relationships\/evolution\?entity_id=/);
    await page.getByRole("button", { name: "Graph" }).click();
    await expect(page).toHaveURL(/view=graph/);

    // Request observer registered before any appearance step: switching
    // themes must never cause a graph refetch.
    let graphNeighborhoodRequests = 0;
    page.on("request", (request) => {
      if (request.url().includes("/api/v1/") && request.url().includes("/graph/entities/")) {
        graphNeighborhoodRequests += 1;
      }
    });

    const graphCanvas = page.getByRole("group", { name: "Relationship graph (one-hop)" });
    const graphList = page.getByRole("table", { name: "Relationship list (this page)" });
    await expect(graphCanvas).toBeVisible({ timeout: 20_000 });
    await expect(graphList).toBeVisible({ timeout: 20_000 });
    const graphRequestsAtOpen = graphNeighborhoodRequests;

    // Preferences gear -> select Dark -> Save: route and URL stay stable.
    const urlBeforeSave = page.url();
    await page.getByRole("button", { name: "Preferences" }).click();
    const dialog = page.getByRole("dialog", { name: "Preferences" });
    await expect(dialog).toBeVisible({ timeout: 20_000 });
    await dialog.getByRole("radio", { name: "Dark" }).click();
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).not.toBeVisible();
    await expect(page).toHaveURL(urlBeforeSave);
    expect(graphNeighborhoodRequests).toBe(graphRequestsAtOpen);

    // The theme is actually applied (semantic surface token -> computed style).
    await expect.poll(headerBackground.bind(null, page)).toBe(DARK_PAPER_RGB);

    // Reload: the committed appearance survives browser-local persistence.
    await page.reload();
    await expect(page).toHaveURL(/view=graph/);
    await expect(graphCanvas).toBeVisible({ timeout: 30_000 });
    await page.getByRole("button", { name: "Preferences" }).click();
    const dialogAfterReload = page.getByRole("dialog", { name: "Preferences" });
    await expect(dialogAfterReload).toBeVisible({ timeout: 20_000 });
    await expect(dialogAfterReload.getByRole("radio", { name: "Dark" })).toBeChecked();

    // Preview Wargames then Cancel: the committed Dark is restored.
    await dialogAfterReload.getByRole("radio", { name: "Wargames" }).click();
    // Live preview applies while the dialog is still open.
    await expect.poll(headerBackground.bind(null, page)).toBe(WARGAMES_PAPER_RGB);
    await dialogAfterReload.getByRole("button", { name: "Cancel" }).click();
    await expect(dialogAfterReload).not.toBeVisible();
    await expect.poll(headerBackground.bind(null, page)).toBe(DARK_PAPER_RGB);

    // Save Control Room: graph stays fully usable with no theme-only request.
    const graphRequestsBeforeControlRoom = graphNeighborhoodRequests;
    await page.getByRole("button", { name: "Preferences" }).click();
    const dialog3 = page.getByRole("dialog", { name: "Preferences" });
    await expect(dialog3).toBeVisible({ timeout: 20_000 });
    await dialog3.getByRole("radio", { name: "Control Room" }).click();
    await dialog3.getByRole("button", { name: "Save" }).click();
    await expect(dialog3).not.toBeVisible();
    await expect(page).toHaveURL(/view=graph/);
    await expect.poll(headerBackground.bind(null, page)).toBe(CONTROL_ROOM_PAPER_RGB);
    await expect(graphCanvas).toBeVisible({ timeout: 20_000 });
    await expect(graphList).toBeVisible({ timeout: 20_000 });
    expect(graphNeighborhoodRequests).toBe(graphRequestsBeforeControlRoom);

    // No console errors across the whole real-stack workflow.
    expect(consoleErrors, consoleErrors.join("\n")).toEqual([]);
  });
});
