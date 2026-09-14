// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 24E Relationship Evolution and Graph (E23).
//
// Runs against the production-path stack created by the repository E2E
// harness (scripts/e2e.sh): built/static React + Nginx -> real FastAPI ->
// real PostgreSQL -> real durable Investigation worker with the
// deterministic offline LLM boundary, over the packaged PR 23D fake world
// (F03 logistics-corp.test temporal world). No live Internet, no live
// threat-intelligence provider, and no live LLM; `FAKE DATA` remains
// visible throughout.
//
// The spec file is named ``zz-*`` so it runs after the PR 24A/24B specs
// and reuses the authenticated session captured by the PR 24C suite
// (zz-analyst-tables.spec.ts -> test-results/analyst-session.json); the
// backend login rate limit is therefore never exceeded.
//
// Canonical slice (PR 24E §38):
//   completed Investigation -> Relationships -> source entity ->
//   Relationship Evolution -> temporal observations (observed_at drives
//   placement; retrieved_at distinct) -> activate observation ->
//   Evidence/provenance -> switch to Graph -> edge/table navigation ->
//   refresh preserves filters -> Back/Forward preserves entity identity.
//
// The fake world's per-run entity/relationship identities vary between
// seeds, so assertions match structural text (headings, "observed …",
// "retrieved …", type labels) and URL shapes, never specific UUIDs.

import { expect, test, type Locator, type Page } from "@playwright/test";

const OBJECTIVE = "PR 24E assess logistics relationship evolution";
const F03_ROOT_DOMAIN = "logistics-corp.test";
const SHARED_SESSION_STATE = "test-results/analyst-session.json";

/**
 * Activate one overlay control through a direct click-event dispatch.
 *
 * Raw pointer events inside open fixed-position overlays (detail drawers,
 * pivot modals) can intermittently wedge the Chromium pointer dispatch on
 * this stack (see zz-pivots.spec.ts), and keyboard activation races the
 * overlay autoFocus (a nested drawer's close button steals focus before
 * Enter lands). Dispatch of the DOM `click` event drives React's synthetic
 * onClick directly without pointer coordinates and without focus
 * dependence — robust on this stack and representative of an analyst
 * activating the control.
 */
async function activate(page: Page, target: Locator): Promise<void> {
  await expect(target).toBeVisible({ timeout: 30_000 });
  await target.dispatchEvent("click");
}

test.describe("PR 24E real-stack relationship evolution and graph", () => {
  test.describe.configure({ timeout: 300_000 });
  test.use({ storageState: SHARED_SESSION_STATE });

  test("E23 entity -> Evolution -> observation -> Evidence -> Graph -> Relationship/table", async ({
    page,
  }) => {
    const consoleErrors: string[] = [];
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${String(error)}`));
    page.on("console", (message) => {
      if (message.type === "error") {
        consoleErrors.push(`console: ${message.text}`);
      }
    });

    // Seed + complete one F03 fake-world Investigation (no live anything).
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    await page.getByRole("link", { name: "New Investigation" }).click();
    await expect(
      page.getByRole("heading", { name: "Create Investigation" }),
    ).toBeVisible();
    await page.getByLabel(/^Objective/).fill(OBJECTIVE);
    await page.getByLabel("Indicator value 1").fill(F03_ROOT_DOMAIN);
    await page.getByRole("button", { name: "Submit" }).click();
    await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
    const url = page.url();
    const investigationId = url.match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
    expect(investigationId).not.toBeUndefined();
    await expect(
      page.getByRole("heading", { name: OBJECTIVE }),
    ).toBeVisible({ timeout: 20_000 });
    await expect(page.getByLabel("Status: Completed").first()).toBeVisible({
      timeout: 240_000,
    });

    // Relationships -> first row's source entity -> Relationship Evolution.
    await page.goto(`/investigations/${investigationId}/relationships`);
    const firstRow = page.getByRole("table", { name: "Relationships" }).getByRole("row").nth(1);
    await expect(firstRow).toBeVisible({ timeout: 20_000 });
    await firstRow.getByRole("link", { name: "View relationship evolution for source entity" })
      .first()
      .click();
    await expect(page).toHaveURL(/\/relationships\/evolution\?entity_id=/);
    const evolutionUrl = page.url();
    const entityParam = new URL(evolutionUrl).searchParams.get("entity_id");
    expect(entityParam).toMatch(/^[0-9a-f-]{36}$/);

    // Temporal visualization: observed_at drives point placement/labels and
    // retrieved_at stays distinct tooltip metadata.
    await expect(
      page.getByRole("heading", { name: "Observed relationships over time" }),
    ).toBeVisible({ timeout: 20_000 });
    const points = page.getByRole("button", { name: /observed 2026-/ });
    const pointCount = await points.count();
    expect(pointCount).toBeGreaterThanOrEqual(2);
    // Retrieval time is secondary metadata on the same point, never merged.
    const firstPoint = points.first();
    await expect(firstPoint).toHaveAttribute(
      "title",
      /^retrieved \d{4}-\d{2}-\d{2}T/,
    );
    // Page-scoped deterministic label (never a global "First observed" claim).
    await expect(
      page.getByText("Earliest shown on this page", { exact: true }).first(),
    ).toBeVisible();

    // Activate one observation -> exact observation detail surface.
    await firstPoint.click();
    const observationDrawer = page.getByRole("dialog", { name: "Observation" });
    await expect(observationDrawer).toBeVisible({ timeout: 20_000 });
    await expect(observationDrawer.getByText("Relationship ID", { exact: true })).toBeVisible();
    await expect(observationDrawer.getByText("Observed at", { exact: true })).toBeVisible();
    await expect(observationDrawer.getByText("Retrieved at", { exact: true })).toBeVisible();

    // Observation -> Evidence exact navigation (PR 24D pivot workspace).
    await activate(
      page,
      observationDrawer.getByRole("button", { name: "Observation provenance actions" }),
    );
    await activate(page, page.getByRole("menuitem", { name: "Open evidence" }));
    const evidenceDialog = page.getByRole("dialog", { name: /Evidence pivot workspace/i });
    await expect(evidenceDialog).toBeVisible({ timeout: 20_000 });
    await expect(
      evidenceDialog.getByRole("dialog", { name: /^Evidence$/ }),
    ).toBeVisible({ timeout: 20_000 });
    // Close the pivot workspace through the modal's own Escape handler
    // (keydown dispatch on the dialog box: no pointer coordinates, no
    // focus/autoFocus races, and immune to the raw-pointer wedge).
    await evidenceDialog.dispatchEvent("keydown", { key: "Escape" });
    await expect(page).not.toHaveURL(/pivot=/);
    await expect(page.getByRole("dialog", { name: /pivot workspace/i })).not.toBeVisible();
    // Close the underlying observation drawer the same way.
    await page.getByRole("dialog", { name: "Observation" }).dispatchEvent("keydown", { key: "Escape" });
    await expect(page).not.toHaveURL(/selected=/);

    // Switch to the bounded one-hop Graph: stable edges + accessible list.
    await page.getByRole("button", { name: "Graph" }).click();
    await expect(page).toHaveURL(/view=graph/);
    await expect(
      page.getByRole("table", { name: "Relationship list (this page)" }),
    ).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText("Resolves to", { exact: true }).first()).toBeVisible({
      timeout: 20_000,
    });

    // Graph edge -> exact Relationship table context (bounded, no recursion).
    const graphList = page.getByRole("table", { name: "Relationship list (this page)" });
    const firstEdgeRow = graphList.getByRole("row").nth(1);
    const relationshipLink = firstEdgeRow.getByRole("link", { name: "View", exact: true });
    await relationshipLink.click();
    await expect(page).toHaveURL(/\/relationships\?selected=/);
    await expect(
      page.getByRole("dialog", { name: "Relationships" }),
    ).toBeVisible({ timeout: 20_000 });
    await page.getByRole("dialog", { name: "Relationships" }).dispatchEvent("keydown", { key: "Escape" });
    await expect(page).not.toHaveURL(/selected=/);

    // Refresh preserves the URL-backed Evolution filter/entity state.
    await page.goto(evolutionUrl);
    await expect(page).toHaveURL(/entity_id=/);
    await expect(
      page.getByRole("heading", { name: "Observed relationships over time" }),
    ).toBeVisible({ timeout: 20_000 });
    expect(new URL(page.url()).searchParams.get("entity_id")).toBe(entityParam);

    // Browser Back restores the Relationships list; Forward restores the
    // entity-centric Evolution workspace with the same focal identity.
    await page.goBack();
    await expect(page).toHaveURL(/\/relationships$/);
    await page.goForward();
    await expect(page).toHaveURL(/\/relationships\/evolution/);
    expect(new URL(page.url()).searchParams.get("entity_id")).toBe(entityParam);

    // FAKE DATA stays visible; console stays clean.
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });
});