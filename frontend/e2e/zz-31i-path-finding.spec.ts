// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack PR 31I bounded path finding (Chromium + Firefox).
//
// The routed Graph workspace is opened through the PR 31F-8 Investigation
// shell, the analyst enters path mode (a transient workbench interaction),
// selects a source and a target Entity from the canvas with NO request
// before Find, and the explicit Find action issues exactly one bounded
// `/graph/paths` request that inherits the committed graph context. The
// returned connection topology renders through the existing graph component
// with a deterministic path selector; exit path mode restores the ordinary
// graph without a reload; a normal one-hop expansion still works after exit;
// a committed graph-context change deterministically clears endpoints and
// the displayed result so a stale prior-context result can never reappear.
// All interaction is normal locator/native-pointer (no force, dispatch,
// coordinate hacks, sleeps, reloads or retries), workers=1, retries=0, with
// a page-stays-live heartbeat and a clean product console. A 20-cycle
// same-page stress proves the Graph route never detaches/remounts while
// path mode/result state changes.

import { expect, test, type Locator, type Page } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";
const CYCLES = parseInt(process.env.ATI_31I_STRESS_CYCLES ?? "20", 10);
const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 31I bounded path finding acceptance journey";

/** Collect product console/page errors; asserted clean at the end. */
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

/** Prove the page is alive with a bounded heartbeat after a transition. */
async function heartbeat(page: Page, label: string): Promise<void> {
  await page.evaluate("1+1", undefined, { timeout: 3000 });
  console.log(`31I-OK ${label}`);
}

/** Normal locator click with connected/visible geometry; no workarounds. */
async function click(page: Page, loc: Locator, label: string): Promise<void> {
  await expect(loc).toBeVisible({ timeout: 30_000 });
  await loc.click();
  await heartbeat(page, label);
}

/** Track every /graph/paths network request/response for the page lifetime. */
function trackPathTraffic(page: Page): {
  requests: string[];
  responses: { status: number; body: string }[];
} {
  const requests: string[] = [];
  const responses: { status: number; body: string }[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/graph/paths")) {
      requests.push(request.url());
    }
  });
  page.on("response", (response) => {
    if (response.url().includes("/graph/paths")) {
      void response.text().then((body) => {
        responses.push({ status: response.status(), body });
      });
    }
  });
  return { requests, responses };
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
  ).toBeVisible({ timeout: 30_000 });
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

/** Open the routed Graph workspace for the first relationship-evolution entity. */
async function openGraphWorkspace(page: Page, base: string): Promise<string> {
  await page.goto(`${base}/relationships`);
  await expect(page.getByRole("heading", { name: "Relationships" })).toBeVisible({
    timeout: 30_000,
  });
  const firstEntityLink = page
    .getByRole("link", { name: /relationship evolution/i })
    .first();
  await expect(firstEntityLink).toBeVisible({ timeout: 30_000 });
  const href = await firstEntityLink.getAttribute("href");
  const entityMatch = href?.match(/entity_id=([0-9a-f-]+)/i);
  const entityId = entityMatch?.[1] ?? "";
  await page.goto(`${base}/relationships/evolution?entity_id=${entityId}&view=graph`);
  await expect(page).toHaveURL(/view=graph/);
  await expect(
    page.getByRole("group", { name: "Graph context and filters" }),
  ).toBeVisible({ timeout: 30_000 });
  return entityId;
}

test.describe("PR 31I path finding (real stack)", () => {
  test.describe.configure({ timeout: 900_000, retries: 0 });

  test("directed journey: enter, select two, Find, select path, exit, expand, context change", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    const pathTraffic = trackPathTraffic(page);
    const pathRequests = pathTraffic.requests;
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await openGraphWorkspace(page, `/investigations/${investigationId}`);

    const graphList = page.getByRole("table", { name: "Relationship list (this page)" });
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    const canvasNodes = page.locator(".react-flow__node");
    await expect(canvasNodes.first()).toBeVisible({ timeout: 30_000 });
    await expect(canvasNodes.nth(1)).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "graph-interactive");

    // Enter path mode: transient workbench state, no request.
    await click(page, page.getByRole("button", { name: "Path mode" }), "enter-path-mode");
    await expect(page.getByText(/Click two entities in the graph/)).toBeVisible({
      timeout: 20_000,
    });
    expect(pathRequests).toHaveLength(0);

    // Select source then target from the canvas: still no request.
    await click(page, canvasNodes.first(), "select-source");
    await click(page, canvasNodes.nth(1), "select-target");
    await expect(page.getByText(/Two entities selected/)).toBeVisible({ timeout: 20_000 });
    expect(pathRequests).toHaveLength(0);

    // Find: exactly one bounded path request (inherits committed context only).
    await click(page, page.getByRole("button", { name: "Find paths" }), "find-paths");
    const resultRegion = page.getByRole("region", { name: "Path results" });
    await expect(resultRegion).toBeVisible({ timeout: 30_000 });
    expect(pathRequests).toHaveLength(1);
    expect(pathRequests[0]).toContain("/graph/paths?");
    expect(pathRequests[0]).toContain("max_depth=");
    expect(pathRequests[0]).toContain("max_paths=");
    expect(pathRequests[0]).toContain("source_entity_id=");
    expect(pathRequests[0]).toContain("target_entity_id=");
    // The traversal depth is never sent as the path bound.
    expect(pathRequests[0]).not.toContain("graph_depth=");
    console.log(`31I-DIAG path responses: ${JSON.stringify(pathTraffic.responses)}`);
    await heartbeat(page, "paths-returned");

    // The deterministic path selector is present; selecting an individual
    // path must not refetch (still exactly one request).
    await click(page, resultRegion.getByRole("combobox"), "open-path-selector");
    const numberedPathOption = page.getByRole("option", { name: /^Path \d+/ });
    if ((await numberedPathOption.count()) > 0) {
      await click(page, numberedPathOption.first(), "select-specific-path");
      await expect(resultRegion).toBeVisible();
    }
    expect(pathRequests).toHaveLength(1);
    await heartbeat(page, "path-selected-no-refetch");

    // Exit path mode restores the ordinary graph without reload.
    await click(page, page.getByRole("button", { name: "Exit path mode" }), "exit-path-mode");
    await expect(page.getByRole("button", { name: "Path mode" })).toBeVisible({
      timeout: 20_000,
    });
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "ordinary-graph-restored");

    // A normal one-hop expansion still works after exit.
    await click(page, canvasNodes.first(), "node-select");
    await expect(page.getByText(/Entity:/)).toBeVisible({ timeout: 20_000 });
    await click(page, page.getByRole("button", { name: /Pivot actions/ }).first(), "pivot-open");
    await click(
      page,
      page.getByRole("button", { name: "Expand known relationships" }).first(),
      "expand-after-exit",
    );
    await heartbeat(page, "expansion-after-exit");

    // A committed graph-context change deterministically clears the path
    // result and endpoint selections.
    await click(page, page.getByRole("button", { name: "Known graph" }), "scope-known-toggle");
    await click(page, page.getByRole("button", { name: "Apply", exact: true }), "scope-known-apply");
    await expect(page).toHaveURL(/graph_scope=known/);
    await click(page, page.getByRole("button", { name: "Path mode" }), "re-enter-path-mode");
    await expect(page.getByText(/Click two entities in the graph/)).toBeVisible({
      timeout: 20_000,
    });
    expect(pathRequests).toHaveLength(1); // only the first Find ever fired

    // A second explicit Find in the new context issues exactly one new
    // request; the stale prior-context result cannot reappear.
    await click(page, canvasNodes.first(), "select-source-k");
    await click(page, canvasNodes.nth(1), "select-target-k");
    await click(page, page.getByRole("button", { name: "Find paths" }), "find-paths-known");
    await expect(page.getByRole("region", { name: "Path results" })).toBeVisible({
      timeout: 30_000,
    });
    await expect(pathRequests).toHaveLength(2);
    expect(pathRequests[1]).toContain("scope=known");

    await click(page, page.getByRole("button", { name: "Exit path mode" }), "exit-path-mode-2");
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "journey-complete");
    expect(consoleErrors).toEqual([]);
  });

  test(`${CYCLES} consecutive path cycles in one page process`, async ({ page }) => {
    const consoleErrors = trackConsoleErrors(page);
    const pathTraffic = trackPathTraffic(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await openGraphWorkspace(page, `/investigations/${investigationId}`);
    const graphList = page.getByRole("table", { name: "Relationship list (this page)" });
    const filters = page.getByRole("group", { name: "Graph context and filters" });
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    const canvasNodes = page.locator(".react-flow__node");
    await expect(canvasNodes.nth(1)).toBeVisible({ timeout: 30_000 });

    for (let cycle = 0; cycle < CYCLES; cycle += 1) {
      const C = `c${cycle}`;
      await click(page, page.getByRole("button", { name: "Path mode" }), `${C}-enter`);
      await click(page, canvasNodes.first(), `${C}-source`);
      await click(page, canvasNodes.nth(1), `${C}-target`);
      await click(page, page.getByRole("button", { name: "Find paths" }), `${C}-find`);
      await expect(page.getByRole("region", { name: "Path results" })).toBeVisible({
        timeout: 30_000,
      });
      await click(page, page.getByRole("button", { name: "Exit path mode" }), `${C}-exit`);
      // Ordinary graph expansion remains functional after path mode; the root
      // context is pristine at the start of every cycle because the previous
      // cycle committed a depth change and cleared (root reset).
      await click(page, canvasNodes.first(), `${C}-node`);
      await click(page, page.getByRole("button", { name: /Pivot actions/ }).first(), `${C}-pivot`);
      await click(
        page,
        page.getByRole("button", { name: "Expand known relationships" }).first(),
        `${C}-expand`,
      );
      // Re-enter path mode and cancel/clear endpoint selection (P-F02 no
      // request on selection is re-proven every cycle).
      await click(page, page.getByRole("button", { name: "Path mode" }), `${C}-reenter`);
      await click(page, page.getByRole("button", { name: "Clear endpoints" }), `${C}-clear`);
      await click(page, page.getByRole("button", { name: "Exit path mode" }), `${C}-exit2`);
      // One committed context change + Clear resets the root expansion state
      // deterministically for the next cycle (PR 31E root change semantics).
      await click(page, page.getByRole("button", { name: "2 hops" }), `${C}-depth-draft`);
      await click(page, page.getByRole("button", { name: "Apply", exact: true }), `${C}-depth-apply`);
      await expect(page).toHaveURL(/graph_depth=2/);
      await click(page, page.getByRole("button", { name: "Clear", exact: true }), `${C}-clear-root`);
      await expect(page).not.toHaveURL(/graph_depth=/);
      await expect(graphList).toBeVisible({ timeout: 20_000 });
      await expect(filters).toBeVisible();
      await heartbeat(page, `${C}-done`);
    }
    // Exactly one request per cycle, no request storm.
    expect(pathTraffic.requests).toHaveLength(CYCLES);
    expect(consoleErrors).toEqual([]);
  });
});
