// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack PR 31K graph-driven investigation actions (Chromium + Firefox).
//
// The routed Graph workspace is opened through the PR 31F-8 Investigation
// shell; with path mode OFF the analyst clicks one canonical graph Entity,
// the in-flow action panel presents the canonical Entity (type/value/ID),
// and starting the action routes the selected Entity through the EXISTING
// durable Investigation create command (`POST /api/v1/investigations` with
// the exact canonical type/value, CSRF + Idempotency-Key). The browser
// never calls providers/ResearchAgent and never synchronously waits for the
// durable worker; navigation goes through the existing Investigation
// workflow and the new Investigation reaches a terminal status with normal
// persisted outputs visible through existing resource/graph surfaces.
//
// K-E2E02 re-proves PR 31I path-mode click precedence (no action POST in
// path mode, action selectable again after exit). K-E2E03 re-proves PR 31J
// temporal compatibility: the action target is the canonical Entity (never
// temporal metadata) and a frame transition that removes the node clears
// the selection so a stale one cannot be submitted. K-E2E04 proves exactly
// one durable command per semantic attempt on the real stack. The
// 20-cycle same-page stability scenario toggles selection/cancel and path
// mode around the selection without submitting durable work, then performs
// one real durable action at the end. All interaction is normal
// locator/native-pointer (no force, dispatch, coordinate hacks, sleeps,
// reloads or retries), workers=1, retries=0, with a page-stays-live
// heartbeat and a clean product console.

import { expect, test, type Locator, type Page } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";
const CYCLES = parseInt(process.env.ATI_31K_STRESS_CYCLES ?? "20", 10);
const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 31K graph-driven investigation actions acceptance journey";

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
  console.log(`31K-OK ${label}`);
}

/** Normal locator click with connected/visible geometry; no workarounds. */
async function click(page: Page, loc: Locator, label: string): Promise<void> {
  await expect(loc).toBeVisible({ timeout: 30_000 });
  await loc.click();
  await heartbeat(page, label);
}

/** Record every exact create-POST (body + status) after installation. */
function trackCreatePosts(page: Page): { posts: { body: unknown; status: number }[] } {
  const posts: { body: unknown; status: number }[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (request.method() === "POST" && url.pathname === "/api/v1/investigations") {
      let body: unknown = null;
      try {
        body = request.postDataJSON();
      } catch {
        body = null;
      }
      posts.push({ body, status: 0 });
    }
  });
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (
      response.request().method() === "POST" &&
      url.pathname === "/api/v1/investigations"
    ) {
      const last = posts.filter((post) => post.status === 0).at(-1);
      if (last !== undefined) {
        last.status = response.status();
      }
    }
  });
  return { posts };
}

/** Server truth of every canonical graph neighborhood response seen. */
function trackNeighborhoodResponses(page: Page): {
  nodes: { entity_id: string; entity_type: string; value: string }[];
} {
  const nodes: { entity_id: string; entity_type: string; value: string }[] = [];
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (
      url.pathname.includes("/graph/entities/") &&
      url.pathname.endsWith("/neighborhood")
    ) {
      void response
        .json()
        .then((payload: unknown) => {
          const list = (payload as { nodes?: unknown[] })?.nodes;
          if (Array.isArray(list)) {
            nodes.length = 0;
            nodes.push(...(list as { entity_id: string; entity_type: string; value: string }[]));
          }
        })
        .catch(() => {});
    }
  });
  return { nodes };
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

/** Wait for the graph canvas to be interactive. */
async function awaitGraphInteractive(page: Page): Promise<Locator> {
  const graphList = page.getByRole("table", { name: "Relationship list (this page)" });
  await expect(graphList).toBeVisible({ timeout: 30_000 });
  const canvasNodes = page.locator(".react-flow__node");
  await expect(canvasNodes.first()).toBeVisible({ timeout: 30_000 });
  await heartbeat(page, "graph-interactive");
  return canvasNodes;
}

/** The in-flow action panel region. */
function actionPanel(page: Page): Locator {
  return page.getByRole("region", { name: "Start investigation" });
}

/** The canonical Entity ID rendered by one canvas node. */
async function nodeEntityId(node: Locator): Promise<string> {
  const dataId = await node.getAttribute("data-id");
  expect(dataId).not.toBeNull();
  const entityId = dataId?.replace(/^n:/, "");
  expect(entityId).toMatch(/^[0-9a-f-]{36}$/i);
  return entityId ?? "";
}

/** Convert an ISO instant to the localized ``datetime-local`` input value. */
function toLocalInput(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number, width = 2): string => String(n).padStart(width, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(
    d.getHours(),
  )}:${pad(d.getMinutes())}`;
}

/** The temporal controls group (single bounded region above the graph). */
function temporalGroup(page: Page): Locator {
  return page.getByRole("group", { name: "Temporal exploration" });
}

/** Enable temporal exploration with the committed PR 31J acceptance range. */
async function applyTemporal(page: Page): Promise<void> {
  const group = temporalGroup(page);
  await click(page, group.getByRole("checkbox", { name: "Temporal exploration" }), "enable-temporal");
  await group.getByLabel("Range start").fill(toLocalInput("2026-05-01T00:00:00Z"));
  await group.getByLabel("Range end").fill(toLocalInput("2026-05-11T00:00:00Z"));
  // Canonical default is 8 frames; no combobox interaction needed.
  await click(page, group.getByRole("button", { name: "Apply temporal" }), "apply-temporal");
}

test.describe("PR 31K graph-driven investigation actions (real stack)", () => {
  test.describe.configure({ timeout: 900_000, retries: 0 });

  test("K-E2E01 directed journey: select canonical Entity -> existing command -> durable terminal Investigation", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    // The neighborhood tracker must see the graph response of the workspace
    // being opened, so it is installed before navigation into the graph.
    const graphTruth = trackNeighborhoodResponses(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await openGraphWorkspace(page, `/investigations/${investigationId}`);
    const canvasNodes = await awaitGraphInteractive(page);
    // The action tracker starts here: the source create happened before it.
    const actionPosts = trackCreatePosts(page);

    // Select the focal (canonical Entity) while path mode is off. The
    // canonical type/value of the clicked node comes from the GRAPH API
    // response (server truth), never from labels the test assumes.
    const focalNode = canvasNodes.first();
    const focalId = await nodeEntityId(focalNode);
    const focalServer = graphTruth.nodes.find((node) => node.entity_id === focalId);
    expect(focalServer).toBeDefined();
    await click(page, focalNode, "select-focal");
    const panel = actionPanel(page);
    await expect(panel).toBeVisible({ timeout: 20_000 });
    await expect(
      panel.getByText(/^Starts an ATI investigation for/),
    ).toBeVisible();
    await expect(
      panel.getByText(`Canonical Entity ID: ${focalId}`),
    ).toBeVisible({ timeout: 20_000 });
    // The editable objective is prefilled with the canonical value.
    const objective = await page.getByLabel(/^Objective/).inputValue();
    expect(objective.startsWith("Investigate ")).toBe(true);
    expect(objective).toContain(focalServer?.value ?? "");
    await heartbeat(page, "action-panel-canonical");

    // Start the action: exactly one accepted durable Investigation command.
    await click(page, panel.getByRole("button", { name: "Start investigation" }), "start-action");
    await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
    await expect
      .poll(() => actionPosts.posts.length, { timeout: 30_000 })
      .toBe(1);
    const post = actionPosts.posts[0];
    expect(post.status).toBe(202);
    const body = post.body as {
      objective: string;
      indicators: { type: string; value: string }[];
    };
    // The EXACT canonical type/value of the selected Entity seeded the new
    // Investigation (no label parsing, no free-form IOC text).
    expect(body.indicators).toEqual([
      { type: focalServer?.entity_type, value: focalServer?.value },
    ]);
    expect(body.objective.startsWith("Investigate ")).toBe(true);
    await heartbeat(page, "action-accepted");

    // Navigate through the existing workflow: the durable worker runs the
    // Investigation; the browser never waits inside the action.
    const url = page.url();
    const newId = url.match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
    expect(newId).not.toBeUndefined();
    await expect(
      page.getByRole("heading", { name: body.objective }),
    ).toBeVisible({ timeout: 20_000 });
    await expect(page.getByLabel("Status: Completed").first()).toBeVisible({ timeout: 240_000 });

    // Persisted outputs are visible through existing resource/graph surfaces.
    await openGraphWorkspace(page, `/investigations/${newId ?? ""}`);
    await expect(
      page.getByRole("table", { name: "Relationship list (this page)" }),
    ).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "new-investigation-graph-queryable");
    expect(consoleErrors).toEqual([]);
  });

  test("K-E2E02 path-mode precedence: path clicks never trigger a graph action", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await openGraphWorkspace(page, `/investigations/${investigationId}`);
    const canvasNodes = await awaitGraphInteractive(page);
    const actionPosts = trackCreatePosts(page);

    // Enter path mode: canvas clicks select endpoints, not actions.
    await click(page, page.getByRole("button", { name: "Path mode" }), "enter-path-mode");
    await expect(page.getByText(/Click two entities in the graph/)).toBeVisible({
      timeout: 20_000,
    });
    await click(page, canvasNodes.first(), "path-source");
    await click(page, canvasNodes.nth(1), "path-target");
    await expect(page.getByText(/Two entities selected/)).toBeVisible({ timeout: 20_000 });
    expect(actionPanel(page)).not.toBeVisible();
    expect(actionPosts.posts).toHaveLength(0);
    await heartbeat(page, "path-mode-no-action");

    // Exit path mode: a node click now selects the graph action.
    await click(page, page.getByRole("button", { name: "Exit path mode" }), "exit-path-mode");
    await click(page, canvasNodes.first(), "select-after-exit");
    await expect(actionPanel(page)).toBeVisible({ timeout: 20_000 });
    expect(actionPosts.posts).toHaveLength(0);
    await heartbeat(page, "action-available-after-path");
    expect(consoleErrors).toEqual([]);
  });

  test("K-E2E03 temporal compatibility: canonical target, stale selection not submittable", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await openGraphWorkspace(page, `/investigations/${investigationId}`);
    await awaitGraphInteractive(page);
    const actionPosts = trackCreatePosts(page);

    // Commit frame 1 (provably empty for the F02 focal) then move to frame 2.
    await applyTemporal(page);
    await expect(page).toHaveURL(/graph_temporal=1/);
    await click(page, page.getByRole("button", { name: "Next frame" }), "next-frame");
    await expect(page).toHaveURL(/graph_time_frame=1/);
    const canvasNodes = page.locator(".react-flow__node");
    await expect(canvasNodes.nth(1)).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "frame2-interactive");

    // Select a visible node: the action target is the canonical Entity.
    const counterparty = canvasNodes.nth(1);
    const entityId = await nodeEntityId(counterparty);
    await click(page, counterparty, "select-in-frame2");
    const panel = actionPanel(page);
    await expect(panel).toBeVisible({ timeout: 20_000 });
    await expect(panel.getByText(`Canonical Entity ID: ${entityId}`)).toBeVisible({
      timeout: 20_000,
    });
    // The objective carries the canonical value, never temporal metadata.
    const objectiveValue = await page.getByLabel(/^Objective/).inputValue();
    expect(objectiveValue).toMatch(/^Investigate /);
    expect(objectiveValue).not.toContain("Frame");
    await heartbeat(page, "temporal-canonical-target");

    // A frame transition that removes the node clears the selection; the
    // stale selection cannot be submitted.
    await click(page, page.getByRole("button", { name: "Previous frame" }), "previous-frame");
    await expect(page).not.toHaveURL(/graph_time_frame=1/);
    await expect(actionPanel(page)).not.toBeVisible({ timeout: 20_000 });
    expect(actionPosts.posts).toHaveLength(0);
    await heartbeat(page, "stale-selection-cleared");
    expect(consoleErrors).toEqual([]);
  });

  test("K-E2E04 duplicate submission: one semantic attempt -> exactly one durable Investigation", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await openGraphWorkspace(page, `/investigations/${investigationId}`);
    await awaitGraphInteractive(page);
    const actionPosts = trackCreatePosts(page);

    await click(page, page.locator(".react-flow__node").first(), "select-node");
    const panel = actionPanel(page);
    await expect(panel).toBeVisible({ timeout: 20_000 });
    const submit = panel.getByRole("button", { name: "Start investigation" });

    // One click plus a rapid probe click: the pending/disabled UI or the
    // busy guard must collapse the attempt to exactly one durable command.
    await submit.click();
    if (await submit.isVisible().catch(() => false)) {
      await submit.click({ timeout: 750 }).catch(() => {});
    }
    await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
    await expect
      .poll(() => actionPosts.posts.length, { timeout: 30_000 })
      .toBe(1);
    expect(actionPosts.posts[0].status).toBe(202);
    await heartbeat(page, "single-durable-command");
    expect(consoleErrors).toEqual([]);
  });

  test(`${CYCLES} same-page action-selection cycles in one page process, then one durable action`, async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await openGraphWorkspace(page, `/investigations/${investigationId}`);
    const canvasNodes = await awaitGraphInteractive(page);
    const actionPosts = trackCreatePosts(page);
    const panel = actionPanel(page);

    for (let cycle = 0; cycle < CYCLES; cycle += 1) {
      const C = `c${cycle}`;
      // Select a visible node -> panel opens with the canonical Entity.
      const node = canvasNodes.nth(cycle % 2 === 0 ? 0 : 1);
      await click(page, node, `${C}-select`);
      await expect(panel).toBeVisible({ timeout: 20_000 });
      const entityId = await nodeEntityId(node);
      await expect(
        panel.getByText(`Canonical Entity ID: ${entityId}`),
      ).toBeVisible({ timeout: 20_000 });
      // Enter path mode around the selection: the selection is cleared and
      // path clicks never submit an action.
      await click(page, page.getByRole("button", { name: "Path mode" }), `${C}-path`);
      await expect(panel).not.toBeVisible({ timeout: 20_000 });
      await click(page, page.getByRole("button", { name: "Exit path mode" }), `${C}-exit-path`);
      // Cancel/clear the selection.
      await click(page, node, `${C}-reselect`);
      await expect(panel).toBeVisible({ timeout: 20_000 });
      await click(page, panel.getByRole("button", { name: "Cancel" }), `${C}-cancel`);
      await expect(panel).not.toBeVisible({ timeout: 20_000 });
      expect(actionPosts.posts).toHaveLength(0);
      await heartbeat(page, `${C}-done`);
    }

    // One real durable action at the end of the stability journey.
    await click(page, canvasNodes.first(), "final-select");
    await expect(panel).toBeVisible({ timeout: 20_000 });
    await click(page, panel.getByRole("button", { name: "Start investigation" }), "final-action");
    await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
    await expect
      .poll(() => actionPosts.posts.length, { timeout: 30_000 })
      .toBe(1);
    expect(actionPosts.posts[0].status).toBe(202);
    await heartbeat(page, "stability-durable-action");
    expect(consoleErrors).toEqual([]);
  });
});
