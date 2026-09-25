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

    // Switch to the bounded one-hop Graph (G31D-E01/E02/E08): the canvas and
    // the accessible non-spatial list render from the canonical PR 31C graph
    // endpoint, and pan/zoom/fit controls are available. The request
    // observer is registered before the switch so the initial neighborhood
    // request is captured.
    const graphNeighborhoodRequests: string[] = [];
    const relationshipsListRequests: string[] = [];
    const observationRequests: string[] = [];
    page.on("request", (request) => {
      const url = request.url();
      if (url.includes("/api/v1/") && url.includes("/graph/entities/")) {
        graphNeighborhoodRequests.push(url);
      }
      if (url.includes("/api/v1/") && url.includes("/relationships?")) {
        relationshipsListRequests.push(url);
      }
      if (url.includes("/api/v1/") && url.includes("/relationship-observations")) {
        observationRequests.push(url);
      }
    });
    await page.getByRole("button", { name: "Graph" }).click();
    await expect(page).toHaveURL(/view=graph/);
    const graphCanvas = page.getByRole("group", {
      name: "Relationship graph (one-hop)",
    });
    await expect(graphCanvas).toBeVisible({ timeout: 20_000 });
    const graphList = page.getByRole("table", {
      name: "Relationship list (this page)",
    });
    await expect(graphList).toBeVisible({ timeout: 20_000 });
    await expect(page.getByTestId("rf__controls")).toBeVisible();
    await expect(page.getByRole("button", { name: "Zoom In" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Zoom Out" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Fit View" })).toBeVisible();

    // Node/edge semantics from the graph API (G31D-E02/E03): the focal node
    // carries its exact value and a visible non-color Entity-type cue, and
    // the canvas edge carries the translated Relationship label.
    await expect(
      graphCanvas.getByText("Domain", { exact: true }).first(),
    ).toBeVisible({ timeout: 20_000 });
    await expect(
      graphCanvas.getByText("Resolves to", { exact: true }).first(),
    ).toBeVisible({ timeout: 20_000 });
    const canvasNode = graphCanvas.locator(".react-flow__node").first();
    await expect(canvasNode).toBeVisible({ timeout: 20_000 });
    const canvasEdge = graphCanvas.locator(".react-flow__edge").first();
    await expect(canvasEdge).toBeVisible({ timeout: 20_000 });
    await expect.poll(() => graphNeighborhoodRequests.length).toBeGreaterThan(0);
    expect(relationshipsListRequests).toEqual([]);
    expect(observationRequests).toEqual([]);
    expect(new URL(graphNeighborhoodRequests[0]).pathname).toMatch(
      /\/api\/v1\/investigations\/[0-9a-f-]+\/graph\/entities\/[0-9a-f-]+\/neighborhood$/,
    );
    const graphRequestCount = graphNeighborhoodRequests.length;

    // Select the focal node (G31D-E06): canonical Entity identity/value/type
    // appear in the selection detail, and no second graph request happens
    // (read-only, no expansion — G31D-E07/E10). The Display-name row is
    // rendered only when the server supplies one (unit-covered); the fake
    // world's Entities carry values without display names.
    await canvasNode.click();
    const nodeDetail = page.getByText(/^Entity: .+/).first();
    await expect(nodeDetail).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText("Entity type", { exact: true })).toBeVisible();
    await expect(page.getByText("Value", { exact: true })).toBeVisible();
    await expect(page.getByText("Entity ID", { exact: true }).first()).toBeVisible();

    // Select the canvas edge (G31D-E04): exact Relationship type + observation
    // summary (count, first/last observed) render as observational metadata.
    // The first canvas edge's type label comes from the graph API, so the
    // heading is asserted structurally, never hard-coded to one fake-world
    // type.
    await canvasEdge.click();
    // The heading lives directly inside the edge-selection panel box; scope
    // the summary assertions to that box (the list below repeats the same
    // column headings).
    const edgePanelHeading = page.getByText(/^Relationship: /);
    await expect(edgePanelHeading).toBeVisible({
      timeout: 20_000,
    });
    const edgePanel = edgePanelHeading.locator("xpath=..");
    await expect(
      edgePanel.getByText("Supporting observations", { exact: true }),
    ).toBeVisible();
    await expect(
      edgePanel.getByText("First observed", { exact: true }),
    ).toBeVisible();
    await expect(
      edgePanel.getByText("Last observed", { exact: true }),
    ).toBeVisible();

    // Drag smoke (G31D-E09): the node really moves and nothing is persisted
    // or re-fetched.
    const nodeBox = await canvasNode.boundingBox();
    await page.mouse.move(
      (nodeBox?.x ?? 0) + (nodeBox?.width ?? 0) / 2,
      (nodeBox?.y ?? 0) + (nodeBox?.height ?? 0) / 2,
    );
    await page.mouse.down();
    await page.mouse.move(
      (nodeBox?.x ?? 0) + (nodeBox?.width ?? 0) / 2 + 140,
      (nodeBox?.y ?? 0) + (nodeBox?.height ?? 0) / 2 + 70,
      { steps: 6 },
    );
    await page.mouse.up();
    const movedBox = await canvasNode.boundingBox();
    expect(movedBox !== null && nodeBox !== null).toBe(true);
    expect(Math.abs((movedBox?.x ?? 0) - (nodeBox?.x ?? 0)) + Math.abs((movedBox?.y ?? 0) - (nodeBox?.y ?? 0))).toBeGreaterThan(60);
    expect(graphNeighborhoodRequests.length).toBe(graphRequestCount);
    expect(relationshipsListRequests).toEqual([]);
    // Selection/drag are presentation only: no investigation mutation.
    await expect(page.getByText("FAKE DATA")).toBeVisible();

    // Graph edge -> exact Relationship table context (bounded, no recursion).
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
