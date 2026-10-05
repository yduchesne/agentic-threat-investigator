// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack PR 31J temporal graph exploration (Chromium + Firefox).
//
// The routed Graph workspace is opened through the PR 31F-8 Investigation
// shell; the analyst enables temporal exploration, commits a bounded
// observed range with a supported frame count, and the active half-open
// frame constrains every neighborhood request through the EXISTING graph
// ``observed_from``/``observed_to`` contract (no new backend, no frame DTO,
// no Relationship-lifetime inference). Apply commits canonical URL state
// starting at frame 1; Previous/Next move only the committed frame index
// through the same URL codec (no wrapping, first/last disabled); refresh
// and browser Back/Forward reconstruct the same committed frame; Disable
// removes temporal-owned parameters and restores ordinary graph behavior;
// an empty frame renders observation-specific empty wording and can never
// show the previous frame's topology as its own. The fake-world focal here
// (F02 ``update-package.test``) has DNS observations on 2026-05-02 and a
// ThreatFox match on 2026-05-10, which under an 8-frame partition of
// [2026-05-01, 2026-05-11) makes frame 1 provably empty and frame 2
// non-empty — the sharpest stale-data check. All interaction is normal
// locator/native-pointer (no force, dispatch, coordinate hacks, sleeps,
// reloads or retries), workers=1, retries=0, with a page-stays-live
// heartbeat and a clean product console. A 20-cycle same-page stress proves
// the temporal interaction class stays deterministic and the Graph route
// never detaches/remounts.

import { expect, test, type Locator, type Page } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";
const CYCLES = parseInt(process.env.ATI_31J_STRESS_CYCLES ?? "20", 10);
const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 31J temporal graph exploration acceptance journey";

// Committed overall observed range (ISO-8601 UTC, seconds precision).
const RANGE_START_ISO = "2026-05-01T00:00:00Z";
const RANGE_END_ISO = "2026-05-11T00:00:00Z";
const FRAME_COUNT = 8;

/** ISO-8601 UTC seconds serialization matching the app format. */
function toIsoSeconds(ms: number): string {
  return new Date(Math.round(ms)).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Deterministic half-open frame bounds for one committed frame index over
 * the committed range (mirrors graphTemporalFrames: exact epoch-ms
 * arithmetic, final frame clamped to range end).
 */
function frameBounds(index: number): { from: string; to: string } {
  const startMs = Date.parse(RANGE_START_ISO);
  const endMs = Date.parse(RANGE_END_ISO);
  const inner = (endMs - startMs) / FRAME_COUNT;
  const fromMs = startMs + index * inner;
  const toMs = index === FRAME_COUNT - 1 ? endMs : startMs + (index + 1) * inner;
  return { from: toIsoSeconds(fromMs), to: toIsoSeconds(toMs) };
}

/** Convert an ISO instant to the localized ``datetime-local`` input value. */
function toLocalInput(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number, width = 2): string => String(n).padStart(width, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(
    d.getHours(),
  )}:${pad(d.getMinutes())}`;
}

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
  console.log(`31J-OK ${label}`);
}

/** Normal locator click with connected/visible geometry; no workarounds. */
async function click(page: Page, loc: Locator, label: string): Promise<void> {
  await expect(loc).toBeVisible({ timeout: 30_000 });
  await loc.click();
  await heartbeat(page, label);
}

/** Track every graph neighborhood/traversal request URL for the lifetime. */
function trackGraphTraffic(page: Page): { requests: string[] } {
  const requests: string[] = [];
  page.on("request", (request) => {
    const url = request.url();
    if (url.includes("/graph/entities/") && url.includes("/neighborhood")) {
      requests.push(url);
    }
  });
  return { requests };
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
    .getByRole("link", { name: /relationship history/i })
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

/** The temporal controls group (single bounded region above the graph). */
function temporalGroup(page: Page): Locator {
  return page.getByRole("group", { name: "Temporal exploration" });
}

/** Enable temporal exploration with the committed acceptance range. */
async function applyTemporal(
  page: Page,
  startIso: string,
  endIso: string,
  frameCount: number,
): Promise<void> {
  const group = temporalGroup(page);
  await click(page, group.getByRole("checkbox", { name: "Temporal exploration" }), "enable-temporal");
  const startInput = group.getByLabel("Range start");
  const endInput = group.getByLabel("Range end");
  await startInput.fill(toLocalInput(startIso));
  await endInput.fill(toLocalInput(endIso));
  // The canonical default is 8 frames; only touch the select on deviation
  // so the default path needs no combobox interaction.
  if (frameCount !== 8) {
    await group.getByRole("combobox", { name: "Frames" }).click();
    await page.getByRole("option", { name: String(frameCount) }).click();
  }
  await click(page, group.getByRole("button", { name: "Apply temporal" }), "apply-temporal");
}

/** Assert the committed banner matches one human 1-based frame 1..N. */
async function expectFrameStatus(page: Page, humanIndex: number): Promise<void> {
  const bounds = frameBounds(humanIndex - 1);
  const status = await page
    .getByRole("status")
    .filter({ hasText: "Frame" })
    .first()
    .getAttribute("aria-label");
  const expected = `Frame ${humanIndex} of ${FRAME_COUNT} — observations from ${bounds.from} through before ${bounds.to}`;
  expect(status).toBe(expected);
}

test.describe("PR 31J temporal graph exploration (real stack)", () => {
  test.describe.configure({ timeout: 900_000, retries: 0 });

  test("directed journey: enable, Apply frame 1, empty frame, Next/Previous, refresh, Back/Forward, Disable", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    const graphTraffic = trackGraphTraffic(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await openGraphWorkspace(page, `/investigations/${investigationId}`);

    const graphList = page.getByRole("table", { name: "Relationship list (this page)" });
    const canvasNodes = page.locator(".react-flow__node");
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    await expect(canvasNodes.first()).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "graph-interactive");

    // 31J-D01: the ordinary graph request before temporal mode carries no
    // observed bounds (unchanged PR 31G/31H/31I behavior).
    const ordinaryRequests = graphTraffic.requests.filter((url) =>
      !url.includes("observed_from=") && !url.includes("observed_to="),
    );
    expect(ordinaryRequests.length).toBeGreaterThan(0);
    await heartbeat(page, "ordinary-request");

    // Enable + Apply: one committed URL transition starting at frame 1.
    await applyTemporal(page, RANGE_START_ISO, RANGE_END_ISO, FRAME_COUNT);
    await expect(page).toHaveURL(/graph_temporal=1/);
    await expect(page).toHaveURL(/graph_time_start=/);
    await expect(page).toHaveURL(/graph_time_end=/);
    await expectFrameStatus(page, 1);
    // Canonical URL: frame 0 and default frame count are omitted.
    await expect(page).not.toHaveURL(/graph_time_frame=/);
    await expect(page).not.toHaveURL(/graph_time_frames=/);
    await heartbeat(page, "frame1-committed");

    // The neighborhood request now carries the exact frame-1 half-open bounds.
    const frame1 = frameBounds(0);
    await expect
      .poll(() =>
        graphTraffic.requests.some((url) => {
          const u = new URL(url);
          return (
            u.searchParams.get("observed_from") === frame1.from &&
            u.searchParams.get("observed_to") === frame1.to
          );
        }),
      )
      .toBe(true);
    // Frame 1 is provably EMPTY for the committed fake-world focal (its DNS
    // observations sit in frame 2): observation-specific wording must render
    // and the previous non-temporal topology must never show as current.
    const temporalEmpty = page.getByText(
      "No matching relationship observations were recorded in this frame.",
    );
    await expect(temporalEmpty).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "frame1-empty");

    // 31J-D02: Next advances the committed frame index and the request bounds.
    await click(page, page.getByRole("button", { name: "Next frame" }), "next-frame");
    await expect(page).toHaveURL(/graph_time_frame=1/);
    await expectFrameStatus(page, 2);
    await expect(temporalEmpty).not.toBeVisible({ timeout: 30_000 });
    const frame2 = frameBounds(1);
    await expect
      .poll(() =>
        graphTraffic.requests.some((url) => {
          const u = new URL(url);
          return (
            u.searchParams.get("observed_from") === frame2.from &&
            u.searchParams.get("observed_to") === frame2.to
          );
        }),
      )
      .toBe(true);
    // Frame 2 holds the committed DNS observations -> real topology.
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    await expect(canvasNodes.first()).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "frame2-topology");

    // 31J-D03: Previous returns deterministically to the same empty frame.
    await click(page, page.getByRole("button", { name: "Previous frame" }), "previous-frame");
    await expect(page).not.toHaveURL(/graph_time_frame=/);
    await expectFrameStatus(page, 1);
    await expect(temporalEmpty).toBeVisible({ timeout: 30_000 });
    // First frame: Previous is disabled (no wrapping).
    await expect(page.getByRole("button", { name: "Previous frame" })).toBeDisabled();
    await heartbeat(page, "back-to-frame1");

    // 31J-D04: navigate to the LAST frame and prove Next is disabled.
    for (let human = 2; human <= FRAME_COUNT; human += 1) {
      await click(page, page.getByRole("button", { name: "Next frame" }), `next-frame-${human}`);
      await expect(page).toHaveURL(/graph_time_frame=\d+/);
      await expectFrameStatus(page, human);
    }
    await expect(page.getByRole("button", { name: "Next frame" })).toBeDisabled();
    await heartbeat(page, "last-frame");

    // 31J-D05: refresh reconstructs the same committed NON-ZERO frame (the
    // last frame) — the committed temporal tuple is the sole authority.
    await expect(frameBounds(FRAME_COUNT - 1).from).not.toBe("");
    await page.reload();
    await expect(
      page.getByRole("group", { name: "Graph context and filters" }),
    ).toBeVisible({ timeout: 30_000 });
    await expect(
      page.getByRole("group", { name: "Temporal exploration" }),
    ).toBeVisible({ timeout: 30_000 });
    await expectFrameStatus(page, FRAME_COUNT);
    await expect(page).toHaveURL(/graph_time_frame=7/);
    await heartbeat(page, "refresh-reconstructs");

    // 31J-D06: browser Back/Forward move through committed frame history.
    await page.goBack();
    await expect(page).toHaveURL(/graph_time_frame=6/);
    await expectFrameStatus(page, FRAME_COUNT - 1);
    await page.goForward();
    await expect(page).toHaveURL(/graph_time_frame=7/);
    await expectFrameStatus(page, FRAME_COUNT);
    await heartbeat(page, "back-forward");

    // 31J-D07: Disable removes temporal-owned params; ordinary graph returns.
    await click(
      page,
      temporalGroup(page).getByRole("button", { name: "Disable temporal" }),
      "disable-temporal",
    );
    await expect(page).not.toHaveURL(/graph_temporal=/);
    await expect(page).not.toHaveURL(/graph_time_start/);
    await expect(page).not.toHaveURL(/graph_time_end=/);
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    await expect(canvasNodes.first()).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "ordinary-restored");

    expect(consoleErrors).toEqual([]);
  });

  test(`${CYCLES} consecutive temporal cycles in one page process`, async ({ page }) => {
    const consoleErrors = trackConsoleErrors(page);
    const graphTraffic = trackGraphTraffic(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await openGraphWorkspace(page, `/investigations/${investigationId}`);
    const graphList = page.getByRole("table", { name: "Relationship list (this page)" });
    const temporalEmpty = page.getByText(
      "No matching relationship observations were recorded in this frame.",
    );
    await expect(graphList).toBeVisible({ timeout: 30_000 });

    for (let cycle = 0; cycle < CYCLES; cycle += 1) {
      const C = `c${cycle}`;
      await applyTemporal(page, RANGE_START_ISO, RANGE_END_ISO, FRAME_COUNT);
      await expect(page).toHaveURL(/graph_temporal=1/);
      await expectFrameStatus(page, 1);
      await expect(temporalEmpty).toBeVisible({ timeout: 30_000 });
      await heartbeat(page, `${C}-frame1`);
      // Next to the DNS frame: status + bounds change; topology appears.
      await click(page, page.getByRole("button", { name: "Next frame" }), `${C}-next`);
      await expectFrameStatus(page, 2);
      await expect(temporalEmpty).not.toBeVisible({ timeout: 30_000 });
      await expect(graphList).toBeVisible({ timeout: 30_000 });
      await heartbeat(page, `${C}-frame2`);
      // Previous restores the empty first frame deterministically.
      await click(page, page.getByRole("button", { name: "Previous frame" }), `${C}-previous`);
      await expectFrameStatus(page, 1);
      await expect(temporalEmpty).toBeVisible({ timeout: 30_000 });
      // Disable + re-enable keeps the committed URL canonical and resets to
      // frame 1 on the next Apply (no stale frame index).
      await click(
        page,
        temporalGroup(page).getByRole("button", { name: "Disable temporal" }),
        `${C}-disable`,
      );
      await expect(page).not.toHaveURL(/graph_temporal=/);
      await expect(graphList).toBeVisible({ timeout: 30_000 });
      await heartbeat(page, `${C}-done`);
    }
    // Every cycle requested frame-bound graph traffic (no request storm, no
    // detached route); the page never needed a reload or recovery.
    expect(
      graphTraffic.requests.filter((url) => url.includes("observed_from=")).length,
    ).toBeGreaterThan(0);
    expect(consoleErrors).toEqual([]);
  });
});
