// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 24D cross-resource pivots, provenance
// navigation, and breadcrumb workspaces (E22).
//
// Runs against the production-path stack created by the repository E2E
// harness (scripts/e2e.sh): built/static React + Nginx -> real FastAPI ->
// real PostgreSQL -> real durable Investigation worker with the
// deterministic offline LLM boundary, over the packaged PR 23D fake world.
// No live Internet, no live threat-intelligence provider, and no live
// LLM; `FAKE DATA` remains visible throughout.
//
// The spec file is named ``zz-*`` so it runs after the PR 24A/24B specs
// and reuses the authenticated session captured by the PR 24C suite
// (zz-analyst-tables.spec.ts and its ``test-results/analyst-session.json``
// storageState) — the backend login rate limit is 5 attempts per 60s
// window and the PR 24C suite already performed the single login.
//
// Interaction notes:
// - While a detail drawer (a full-viewport ``position: fixed`` layer) is
//   open, Playwright/Chromium's composite locator hit-test path can hang
//   the browser main thread; raw pointer input is not affected (DIAG
//   probes against both the minimal browser-level repro and the real
//   stack: mouse.down/up dispatch events and the page stays responsive).
//   Real analyst input follows the raw path and is not affected; the
//   spec therefore resolves each target's box and clicks it through
//   ``page.mouse`` inside the pivot workspace (dialog + drawers + menus +
//   breadcrumbs), waiting for visibility first.
// - The fake world's per-run entity/relationship identities and edge
//   analyst labels vary between Investigation seeds; assertions match
//   structural text (titles, "Observed at", support labels) and regex
//   shapes, never specific ids or edge-type labels.
//
// Canonical slice (PR 24D §29):
//   completed Investigation Overview
//     -> finding support -> supporting Evidence pivot workspace
//     -> pivot Evidence subject -> Relationships where source
//     -> open Relationship -> RelationshipObservations
//     -> pivot observation Evidence -> Evidence
//     -> breadcrumb path, Back/Forward, truncation, refresh, Close
//
// Assertions: the breadcrumb path mirrors the exploration sequence,
// Back/Forward traverse pivot states, truncation restores a prior step,
// refresh restores the active modal, Close restores the underlying
// Overview route, `FAKE DATA` stays visible, and no browser console
// errors occur.

import { expect, test, type Locator, type Page } from "@playwright/test";

const OBJECTIVE = "PR 24D cross-resource pivots via provenance";
const F02_ROOT_DOMAIN = "update-package.test";
const SHARED_SESSION_STATE = "test-results/analyst-session.json";

/** Progress markers printed when E22 ends pin the exact stall point. */
const stepTags: Array<{ tag: string; at: number }> = [];
function step(tag: string): void {
  stepTags.push({ tag, at: Date.now() });
  console.log(`E22-STEP ${tag}`);
}

/**
 * Click a target inside the pivot overlay via the raw pointer path.
 *
 * Playwright/Chromium's composite locator hit-test path can hang the
 * browser main thread while a full-viewport ``position: fixed`` layer
 * (detail drawer) is open; raw CDP pointer input (what a real analyst's
 * mouse produces) is not affected and demonstrably keeps the page
 * responsive (DIAG probes against both the minimal browser-level repro
 * and the real stack). The locator resolves the target's box (with a
 * bounded retry for any in-flight render), then ``page.mouse`` dispatches
 * the gesture at its center.
 */
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

test.describe("PR 24D real-stack pivot exploration", () => {
  test.describe.configure({ timeout: 240_000 });
  test.use({ storageState: SHARED_SESSION_STATE });

  test("E22 provenance -> nested pivots -> breadcrumbs -> Back/Forward -> refresh -> Close", async ({
    page,
  }) => {
    const consoleErrors: string[] = [];
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${String(error)}`));
    page.on("console", (message) => {
      if (message.type === "error") {
        consoleErrors.push(`console: ${message.text}`);
      }
    });

    step("start");
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    await completeF02Investigation(page);
    step("overview ready");

    // The completed Overview shows the persisted Report with finding
    // support references (provenance stays visible).
    await expect(page.getByText("Supports").first()).toBeVisible({ timeout: 30_000 });
    step("supports visible");

    // Evidence support -> exact scoped Evidence pivot workspace.
    await page.getByRole("button", { name: "Open evidence" }).first().click();
    const evidenceDialog = page.getByRole("dialog", { name: /Evidence pivot workspace/i });
    await expect(evidenceDialog).toBeVisible({ timeout: 30_000 });
    // The exact supporting Evidence opens its detail drawer in the modal.
    const evidenceDrawer = page.getByRole("dialog", { name: /^Evidence$/ });
    await expect(evidenceDrawer).toBeVisible({ timeout: 30_000 });
    await expect(evidenceDrawer.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });
    // Breadcrumb anchors the exploration: Investigation / value / Evidence.
    const breadcrumb = evidenceDialog.getByRole("navigation", { name: "Pivot breadcrumb" });
    await expect(breadcrumb.getByText("Investigation")).toBeVisible();
    await expect(
      breadcrumb.getByText(/^Evidence [0-9a-fA-F-]{4,12}$/).first(),
    ).toBeVisible();
    step("evidence workspace open");

    // Pivot the Evidence subject -> Relationships where source.
    await clickForce(page, evidenceDrawer.getByRole("button", { name: "Pivot actions" }));
    await clickForce(page, page.getByRole("menuitem", { name: "Relationships where source" }));
    const relationshipsDialog = page.getByRole("dialog", { name: /Relationships pivot workspace/i });
    await expect(relationshipsDialog).toBeVisible({ timeout: 30_000 });
    // Pre-applied source filter + a rendered edge row.
    await expect(
      relationshipsDialog.getByRole("textbox", { name: "Source entity ID" }),
    ).toHaveValue(/^[0-9a-f-]{36}$/);
    await expect(
      relationshipsDialog.getByRole("table", { name: "Relationships" }),
    ).toBeVisible({ timeout: 30_000 });
    step("relationships workspace open");

    // Open the Relationship draw, then pivot to its observations.
    await clickForce(
      page,
      relationshipsDialog.getByRole("button", { name: /^View / }).first(),
    );
    const relationshipDrawer = page.getByRole("dialog", { name: /^Relationships$/ });
    await expect(relationshipDrawer).toBeVisible({ timeout: 30_000 });
    step("relationship drawer open");
    await clickForce(
      page,
      relationshipDrawer.getByRole("button", { name: "Observations for this relationship" }),
    );
    const observationsDialog = page.getByRole("dialog", {
      name: /Relationship observations pivot workspace/i,
    });
    await expect(observationsDialog).toBeVisible({ timeout: 30_000 });
    await expect(
      observationsDialog.getByText("Observed at", { exact: true }).first(),
    ).toBeVisible({ timeout: 30_000 });
    step("observations workspace open");

    // Pivot an observation's Evidence identity -> exact Evidence step.
    await clickForce(
      page,
      observationsDialog.getByRole("button", { name: "Evidence" }).first(),
    );
    await clickForce(page, page.getByRole("menuitem", { name: "Open evidence" }));
    const nestedEvidenceDialog = page.getByRole("dialog", { name: /Evidence pivot workspace/i });
    await expect(nestedEvidenceDialog).toBeVisible({ timeout: 30_000 });
    await expect(
      nestedEvidenceDialog
        .getByRole("navigation", { name: "Pivot breadcrumb" })
        .getByText("Relationship observations"),
    ).toBeVisible();
    step("nested evidence step open");

    // Browser Back restores the observations stack; Forward restores
    // the Evidence step again.
    await page.goBack();
    await expect(
      page.getByRole("dialog", { name: /Relationship observations pivot workspace/i }),
    ).toBeVisible({ timeout: 20_000 });
    await page.goForward();
    await expect(
      page.getByRole("dialog", { name: /Evidence pivot workspace/i }),
    ).toBeVisible({ timeout: 20_000 });
    step("Back/Forward restored");

    // Breadcrumb truncation restores the Relationships step.
    const truncatedBreadcrumb = page
      .getByRole("dialog", { name: /Evidence pivot workspace/i })
      .getByRole("navigation", { name: "Pivot breadcrumb" });
    await clickForce(
      page,
      truncatedBreadcrumb.getByRole("button", { name: "Return to update-package.test" }),
    );
    await expect(
      page.getByRole("dialog", { name: /Relationships pivot workspace/i }),
    ).toBeVisible({ timeout: 20_000 });
    step("truncation restored relationships");

    // Refresh restores the active (truncated) modal from the URL state.
    await page.reload();
    await expect(
      page.getByRole("dialog", { name: /Relationships pivot workspace/i }),
    ).toBeVisible({ timeout: 20_000 });

    // Close restores the underlying Overview route with no modal.
    await clickForce(page, page.getByRole("button", { name: "Close pivot workspace" }));
    await expect(page.getByRole("dialog", { name: /pivot workspace/i })).not.toBeVisible();
    await expect(page.getByRole("heading", { name: OBJECTIVE })).toBeVisible();
    await expect(page.getByText("Supports").first()).toBeVisible();
    expect(page.getByText("FAKE DATA")).toBeVisible();

    // No arbitrary modal stack survived on the base route.
    expect(
      (await page.getByRole("banner").allTextContents()).join(" "),
    ).not.toContain("Pivot breadcrumb");

    // The browser console stayed clean.
    expect(consoleErrors).toEqual([]);
    for (const { tag, at } of stepTags) {
      console.log(`E22-MARK ${tag} +${(at - stepTags[0].at) / 1000}s`);
    }
  });
});