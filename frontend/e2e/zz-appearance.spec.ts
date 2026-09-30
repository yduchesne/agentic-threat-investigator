// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 31F-4 Appearance Preferences (E30)
// + PR 31F-7 generic appearance-preview lifecycle.
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
//
// PR 31F-7 lifecycle guarantees, through ONE generic preview path and with
// every supported appearance (Light/Dark/Wargames/Control Room):
//   1. selecting an appearance live-previews the rendered application
//      surface BEFORE Save;
//   2. Cancel restores the previously committed appearance;
//   3. Save commits and stays active;
//   4. reload restores the committed appearance;
//   5. route/URL and graph topology are untouched by theme-only changes.
// The appearance engine itself is unchanged by PR 31F-7: the stable
// prebuilt registry (theme.ts), the single provider and the existing
// preview/commit/cancel state flow were verified present and correct. The
// former "Wargames preview never applies after Save/reload/reopen"
// E30-A6 failure was a browser-assertion artifact: the MUI Preferences
// dialog is a genuine modal and correctly marks the rest of the page
// ``aria-hidden`` while open, so the old ``getByRole("banner")`` poll
// matched nothing during the in-dialog preview step. The rendered surface
// is now resolved through the shell header element itself (CSS locator,
// unaffected by the modal accessibility mask); the assertion contract
// (rendered surface/token, never just the radio value) is unchanged.

import { expect, test, type Page } from "@playwright/test";

const OBJECTIVE = "PR 31F-4 assess appearance workbench";
const F03_ROOT_DOMAIN = "logistics-corp.test";
const SHARED_SESSION_STATE = "test-results/analyst-session.json";

/** Surface tokens (theme.ts) used as end-to-end computed-style proofs. */
const LIGHT_PAPER_RGB = "rgb(255, 255, 255)";
const DARK_PAPER_RGB = "rgb(28, 32, 38)";
const WARGAMES_PAPER_RGB = "rgb(16, 21, 15)";
const CONTROL_ROOM_PAPER_RGB = "rgb(15, 26, 44)";

/**
 * Resolve the shell header (AppBar) computed background color.
 *
 * PR 31F-7: the MUI Preferences dialog is a real modal and correctly sets
 * ``aria-hidden`` on the rest of the page while it is open (the a11y-
 * correct MUI Modal behavior), which excludes the header landmark from
 * the accessibility tree — ``getByRole("banner")`` resolves to nothing
 * during the live-preview steps. The rendered surface is therefore
 * resolved through the AppBar element as DOM (CSS locator), which is
 * unaffected by the modal mask while asserting the exact same semantic
 * surface token.
 */
async function headerBackground(page: Page): Promise<string> {
  return page
    .locator("header.MuiAppBar-root")
    .evaluate((el) => getComputedStyle(el).backgroundColor);
}

test.describe("PR 31F-4/31F-7 real-stack appearance preference workflow", () => {
  test.describe.configure({ timeout: 300_000 });
  test.use({ storageState: SHARED_SESSION_STATE });

  test("every supported appearance live-previews before Save, Cancel restores, Save persists across reload, route/graph untouched", async ({
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

    // The committed baseline is Light (canonical default).
    await expect.poll(headerBackground.bind(null, page)).toBe(LIGHT_PAPER_RGB);

    // 1. Select Dark -> the rendered surface previews it BEFORE Save.
    const urlBeforeSave = page.url();
    await page.getByRole("button", { name: "Preferences" }).click();
    const dialog = page.getByRole("dialog", { name: "Preferences" });
    await expect(dialog).toBeVisible({ timeout: 20_000 });
    await expect(dialog.getByRole("radio", { name: "Light" })).toBeChecked();
    await dialog.getByRole("radio", { name: "Dark" }).click();
    await expect.poll(headerBackground.bind(null, page)).toBe(DARK_PAPER_RGB);
    // Save: the preview becomes the committed appearance and the dialog closes.
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect(dialog).not.toBeVisible();
    await expect(page).toHaveURL(urlBeforeSave);
    expect(graphNeighborhoodRequests).toBe(graphRequestsAtOpen);
    await expect.poll(headerBackground.bind(null, page)).toBe(DARK_PAPER_RGB);

    // Reload: the committed appearance survives browser-local persistence.
    await page.reload();
    await expect(page).toHaveURL(/view=graph/);
    await expect(graphCanvas).toBeVisible({ timeout: 30_000 });
    await expect.poll(headerBackground.bind(null, page)).toBe(DARK_PAPER_RGB);
    await page.getByRole("button", { name: "Preferences" }).click();
    const dialogAfterReload = page.getByRole("dialog", { name: "Preferences" });
    await expect(dialogAfterReload).toBeVisible({ timeout: 20_000 });
    await expect(dialogAfterReload.getByRole("radio", { name: "Dark" })).toBeChecked();

    // 2. Preview Wargames BEFORE Save, then Cancel: committed Dark restored.
    await dialogAfterReload.getByRole("radio", { name: "Wargames" }).click();
    await expect.poll(headerBackground.bind(null, page)).toBe(WARGAMES_PAPER_RGB);
    await dialogAfterReload.getByRole("button", { name: "Cancel" }).click();
    await expect(dialogAfterReload).not.toBeVisible();
    await expect.poll(headerBackground.bind(null, page)).toBe(DARK_PAPER_RGB);

    // 3. Save Control Room: graph stays fully usable with no theme-only request.
    const graphRequestsBeforeControlRoom = graphNeighborhoodRequests;
    await page.getByRole("button", { name: "Preferences" }).click();
    const dialog3 = page.getByRole("dialog", { name: "Preferences" });
    await expect(dialog3).toBeVisible({ timeout: 20_000 });
    await dialog3.getByRole("radio", { name: "Control Room" }).click();
    await expect.poll(headerBackground.bind(null, page)).toBe(CONTROL_ROOM_PAPER_RGB);
    await dialog3.getByRole("button", { name: "Save" }).click();
    await expect(dialog3).not.toBeVisible();
    await expect(page).toHaveURL(/view=graph/);
    await expect.poll(headerBackground.bind(null, page)).toBe(CONTROL_ROOM_PAPER_RGB);
    await expect(graphCanvas).toBeVisible({ timeout: 20_000 });
    await expect(graphList).toBeVisible({ timeout: 20_000 });
    expect(graphNeighborhoodRequests).toBe(graphRequestsBeforeControlRoom);

    // Reload: Control Room persists.
    await page.reload();
    await expect(page).toHaveURL(/view=graph/);
    await expect(graphCanvas).toBeVisible({ timeout: 30_000 });
    await expect.poll(headerBackground.bind(null, page)).toBe(CONTROL_ROOM_PAPER_RGB);

    // 4. Reopen and preview Light (the fourth supported appearance) before
    // Save, then Cancel: Control Room restored. Every supported appearance
    // uses the SAME generic preview path (no Wargames-only or per-theme
    // branch anywhere in the engine).
    await page.getByRole("button", { name: "Preferences" }).click();
    const dialog4 = page.getByRole("dialog", { name: "Preferences" });
    await expect(dialog4).toBeVisible({ timeout: 20_000 });
    await expect(dialog4.getByRole("radio", { name: "Control Room" })).toBeChecked();
    await dialog4.getByRole("radio", { name: "Light" }).click();
    await expect.poll(headerBackground.bind(null, page)).toBe(LIGHT_PAPER_RGB);
    await dialog4.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog4).not.toBeVisible();
    await expect.poll(headerBackground.bind(null, page)).toBe(CONTROL_ROOM_PAPER_RGB);

    // No console errors across the whole real-stack workflow.
    expect(consoleErrors, consoleErrors.join("\n")).toEqual([]);
  });
});
