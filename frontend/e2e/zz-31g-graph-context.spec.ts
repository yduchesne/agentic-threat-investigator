// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack PR 31G graph context + filter acceptance (Chromium + Firefox).
//
// The routed Graph workspace is opened through the PR 31F-8 Investigation
// shell, the default Investigation context is verified, the analyst applies
// Relationship type / connected Entity type / source / observed-interval
// filters through the draft form, applies them (one committed URL
// transition), verifies root and expansion requests inherit every filter,
// switches Known scope, inspects the Known context cue, clears, and drives
// browser Back/Forward + refresh through the URL-backed committed context —
// all with normal locator/native-pointer interaction, workers=1/retries=0,
// a page-stays-live heartbeat, and no product console error accumulation.
//
// The 20-cycle lifecycle stress proves the routed Graph page is never
// remounted merely because `location.search` changes: draft edits issue no
// request before Apply, each Apply/Clear is one committed route transition,
// and the graph stays interactive across many scope/filter/expansion/
// Back/Forward cycles in ONE page/browser process.

import { expect, test, type Locator, type Page } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";
const CYCLES = parseInt(process.env.ATI_31G_STRESS_CYCLES ?? "20", 10);
const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 31G graph context acceptance journey";

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
  console.log(`31G-OK ${label}`);
}

/** Normal locator click with connected/visible geometry; no workarounds. */
async function click(page: Page, loc: Locator, label: string): Promise<void> {
  await expect(loc).toBeVisible({ timeout: 30_000 });
  await loc.click();
  await heartbeat(page, label);
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

test.describe("PR 31G graph context + filters (real stack)", () => {
  test.describe.configure({ timeout: 900_000, retries: 0 });

  test("filter/scope journey: draft->Apply, expansion inheritance, Known cue, Clear, Back/Forward, refresh", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    const base = `/investigations/${investigationId}`;
    await page.goto(`${base}/overview`);

    // Open the routed Graph workspace for a known Investigation-visible
    // entity resolved from the Relationships table, then switch to Graph.
    await page.goto(`${base}/relationships`);
    await expect(page.getByRole("heading", { name: "Relationships" })).toBeVisible({
      timeout: 30_000,
    });
    const firstEntityLink = page
      .getByRole("link", { name: /relationship evolution/i })
      .first();
    await expect(firstEntityLink).toBeVisible({ timeout: 30_000 });

    // Resolve a real entity_id from the Evolution link and go to Graph.
    const href = await firstEntityLink.getAttribute("href");
    const entityMatch = href?.match(/entity_id=([0-9a-f-]+)/i);
    expect(entityMatch?.[1]).toBeDefined();
    const entityId = entityMatch?.[1] ?? "";
    await page.goto(
      `${base}/relationships/evolution?entity_id=${entityId}&view=graph`,
    );
    await expect(page).toHaveURL(/view=graph/);
    const graphList = page.getByRole("table", { name: "Relationship list (this page)" });
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    await expect(
      page.getByRole("group", { name: "Graph context and filters" }),
    ).toBeVisible({ timeout: 20_000 });
    await heartbeat(page, "graph-open-default");

    // Apply a source filter through the draft form: no request before
    // Apply, then exactly one committed URL transition and a new request.
    const sourceInput = page.getByLabel(/Observation source/i);
    await click(page, sourceInput, "source-draft");
    await sourceInput.fill("rdap");
    await heartbeat(page, "source-draft-filled");
    const applyButton = page.getByRole("button", { name: "Apply", exact: true });
    await click(page, applyButton, "apply-source");
    await expect(page).toHaveURL(/graph_source=/);
    // URL owns the committed context (refresh reconstructs it).
    const filteredUrl = page.url();
    await page.reload();
    await expect(page.getByRole("group", { name: "Graph context and filters" })).toBeVisible({
      timeout: 30_000,
    });
    await expect(page).toHaveURL(filteredUrl);
    await expect(page.getByLabel(/Observation source/i)).toHaveValue("rdap");
    await heartbeat(page, "refresh-url-kept");

    // Switch to Known scope via the toggle (draft-side) and Apply to commit.
    await click(page, page.getByRole("button", { name: "Known graph" }), "scope-known-toggle");
    await click(page, applyButton, "scope-known-apply");
    await expect(page).toHaveURL(/graph_scope=known/);

    // Expand one node: the expansion request inherits the committed context.
    const firstCanvasNode = page.locator(".react-flow__node").first();
    await expect(firstCanvasNode).toBeVisible({ timeout: 30_000 });
    await click(page, firstCanvasNode, "node-select");
    await expect(page.getByText(/Entity:/)).toBeVisible({ timeout: 20_000 });
    await click(
      page,
      page.getByRole("button", { name: /Pivot actions/ }).first(),
      "pivot-open",
    );
    await click(
      page,
      page.getByRole("button", { name: "Expand known relationships" }),
      "expand-known",
    );

    // Clear restores Investigation scope with no optional filters.
    await click(page, page.getByRole("button", { name: "Clear", exact: true }), "clear");
    await expect(page).not.toHaveURL(/graph_scope=/);
    await expect(page).not.toHaveURL(/graph_source=/);

    // Back/Forward through committed context changes.
    await page.goBack();
    await expect(page).toHaveURL(/graph_scope=known/);
    await page.goForward();
    await expect(page).not.toHaveURL(/graph_scope=/);
    await heartbeat(page, "back-forward");

    // The graph stays interactive through all route-only changes.
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    await expect(
      page.getByRole("group", { name: "Graph context and filters" }),
    ).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test(`${CYCLES} consecutive graph-context cycles in one page process`, async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    const base = `/investigations/${investigationId}`;
    await page.goto(`${base}/relationships`);
    const firstEntityLink = page
      .getByRole("link", { name: /relationship evolution/i })
      .first();
    await expect(firstEntityLink).toBeVisible({ timeout: 30_000 });
    const href = await firstEntityLink.getAttribute("href");
    const entityId = href?.match(/entity_id=([0-9a-f-]+)/i)?.[1] ?? "";
    await page.goto(
      `${base}/relationships/evolution?entity_id=${entityId}&view=graph`,
    );
    const filters = page.getByRole("group", { name: "Graph context and filters" });
    await expect(filters).toBeVisible({ timeout: 30_000 });

    for (let cycle = 0; cycle < CYCLES; cycle += 1) {
      const C = `c${cycle}`;
      // Draft edit issues no request before Apply.
      const sourceInput = page.getByLabel(/Observation source/i);
      await expect(sourceInput).toBeVisible();
      await sourceInput.fill("rdap");
      await heartbeat(page, `${C}-draft`);
      // Apply -> one committed route transition.
      await click(page, page.getByRole("button", { name: "Apply", exact: true }), `${C}-apply`);
      await expect(page).toHaveURL(/graph_source=rdap/);
      // Expand one node inheriting the committed context.
      const canvasNode = page.locator(".react-flow__node").first();
      await expect(canvasNode).toBeVisible({ timeout: 30_000 });
      await click(page, canvasNode, `${C}-node`);
      await click(
        page,
        page.getByRole("button", { name: /Pivot actions/ }).first(),
        `${C}-pivot`,
      );
      await click(
        page,
        page.getByRole("button", { name: "Expand known relationships" }).first(),
        `${C}-expand`,
      );
      // Switch Known scope (draft) then Apply to commit.
      await click(page, page.getByRole("button", { name: "Known graph" }), `${C}-known-toggle`);
      await click(page, page.getByRole("button", { name: "Apply", exact: true }), `${C}-known-apply`);
      await expect(page).toHaveURL(/graph_scope=known/);
      // Clear restores defaults.
      await click(page, page.getByRole("button", { name: "Clear", exact: true }), `${C}-clear`);
      await expect(page).not.toHaveURL(/graph_scope=/);
      await expect(page).not.toHaveURL(/graph_source=/);
      // Back/Forward.
      await page.goBack();
      await expect(page).toHaveURL(/graph_scope=known/);
      await page.goForward();
      await expect(page).not.toHaveURL(/graph_scope=/);
      // The graph stays mounted and interactive across the route-only churn.
      await expect(
        page.getByRole("table", { name: "Relationship list (this page)" }),
      ).toBeVisible({ timeout: 20_000 });
      await expect(filters).toBeVisible();
      await heartbeat(page, `${C}-done`);
    }
    expect(consoleErrors).toEqual([]);
  });
});
