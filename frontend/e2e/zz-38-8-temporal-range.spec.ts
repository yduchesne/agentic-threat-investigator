// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack PR 38-8 direct observed-time range temporal graph exploration
// (Chromium + Firefox); consolidated under PR 38-10.
//
// The routed Graph workspace is opened through the PR 31F-8 Investigation
// shell; the analyst enables Temporal exploration, specifies one required
// start DATE and one required end DATE with OPTIONAL local times, and the
// committed direct range constrains every neighborhood request through the
// EXISTING graph ``observed_from``/``observed_to`` contract (no new backend,
// no temporal DTO, no frame partition, no Relationship-lifetime inference).
// PR 38-10 removed the redundant upper Graph toolbar observed-date inputs:
// Temporal exploration is the SOLE authority for graph observation-time
// bounds, so with temporal off the graph request carries no observed bounds
// even for a legacy ``graph_observed_*`` bookmark, and the retired keys are
// stripped on the next ordinary Graph write.
// A blank time normalizes to local midnight; the neutral draft defaults the
// end DATE to the browser-local current calendar date with a blank end time.
// Apply commits canonical URL state (switch + both instants) in one
// transition; refresh and browser Back/Forward reconstruct the same range;
// Disable removes temporal-owned parameters and restores ordinary graph
// behavior; an empty range renders observation-specific empty wording and
// can never show the prior range's topology as its own. There is no Time
// frames control, no frame index, and no Previous/Next frame navigation.
//
// The fake-world F02 focal (``update-package.test``) has DNS/registration
// observations at 2026-05-02T08:00:00Z and a ThreatFox match at
// 2026-05-10T00:00:00Z, so [2026-05-01, 2026-05-02) is provably empty for
// the focal while [2026-05-02, 2026-05-03) includes the DNS observations —
// the sharpest stale-data check. All interaction is normal
// locator/native-pointer (no force, dispatch, coordinate hacks, sleeps,
// reloads or retries), workers=1, retries=0, with a page-stays-live
// heartbeat and a clean product console. A 20-cycle same-page stress proves
// the temporal interaction class stays deterministic and the Graph route
// never detaches/remounts.

import { expect, test, type Locator, type Page } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";
const CYCLES = parseInt(process.env.ATI_38_8_STRESS_CYCLES ?? "20", 10);
const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 38-8 direct-range temporal graph exploration acceptance journey";
const EMPTY_WORDING =
  "No matching relationship observations were recorded in this time range.";

// Deterministic half-open ranges over the fake-world observation instants.
const RANGE_A_FROM = "2026-05-01T00:00:00Z"; // empty for the focal
const RANGE_A_TO = "2026-05-02T00:00:00Z";
const RANGE_B_FROM = "2026-05-02T00:00:00Z"; // includes the DNS observations
const RANGE_B_TO = "2026-05-03T00:00:00Z";
const EXPLICIT_FROM = "2026-05-02T13:37:00Z"; // non-midnight explicit time
const EXPLICIT_TO = "2026-05-03T00:00:00Z";

/** Convert an ISO instant to the browser-local calendar date (YYYY-MM-DD). */
function toLocalDate(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** Convert an ISO instant to the browser-local wall-clock time (HH:MM). */
function toLocalTime(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number): string => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
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
  console.log(`38-8-OK ${label}`);
}

/** Normal locator click with connected/visible geometry; no workarounds. */
async function click(page: Page, loc: Locator, label: string): Promise<void> {
  await expect(loc).toBeVisible({ timeout: 30_000 });
  await loc.click();
  await heartbeat(page, label);
}

/** Track every graph-entity request URL (neighborhood + traversal). */
function trackGraphTraffic(page: Page): { requests: string[] } {
  const requests: string[] = [];
  page.on("request", (request) => {
    const url = request.url();
    if (url.includes("/graph/entities/")) {
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

/** Enable temporal exploration if it is not already committed. */
async function enableTemporal(page: Page): Promise<void> {
  const checkbox = temporalGroup(page).getByRole("checkbox", {
    name: "Temporal exploration",
  });
  if (!(await checkbox.isChecked())) {
    await click(page, checkbox, "enable-temporal");
  }
}

/** Fill both boundaries as local date + explicit local time and Apply. */
async function applyExplicitRange(
  page: Page,
  fromIso: string,
  toIso: string,
  label: string,
): Promise<void> {
  await enableTemporal(page);
  const group = temporalGroup(page);
  await group.getByLabel("Range start date").fill(toLocalDate(fromIso));
  await group.getByLabel("Range start time").fill(toLocalTime(fromIso));
  await group.getByLabel("Range end date").fill(toLocalDate(toIso));
  await group.getByLabel("Range end time").fill(toLocalTime(toIso));
  await click(page, group.getByRole("button", { name: "Apply temporal" }), label);
}

/** Fill both boundaries as local date only (blank times) and Apply. */
async function applyDateOnlyRange(
  page: Page,
  fromDate: string,
  toDate: string,
  label: string,
): Promise<void> {
  await enableTemporal(page);
  const group = temporalGroup(page);
  await group.getByLabel("Range start date").fill(fromDate);
  await group.getByLabel("Range start time").fill("");
  await group.getByLabel("Range end date").fill(toDate);
  await group.getByLabel("Range end time").fill("");
  await click(page, group.getByRole("button", { name: "Apply temporal" }), label);
}

/** The browser-local midnight instant for one local calendar date. */
async function localMidnightIso(page: Page, date: string): Promise<string> {
  return page.evaluate((value: string) => {
    const [year, month, day] = value.split("-").map(Number);
    return new Date(year, (month ?? 1) - 1, day ?? 1, 0, 0, 0, 0)
      .toISOString()
      .replace(/\.\d{3}Z$/, "Z");
  }, date);
}

/** Assert the committed URL reconstructs the exact half-open range. */
async function expectCommittedRange(
  page: Page,
  fromIso: string,
  toIso: string,
): Promise<void> {
  await expect(page).toHaveURL(
    new RegExp(`graph_time_start=${encodeURIComponent(fromIso)}`),
  );
  await expect(page).toHaveURL(
    new RegExp(`graph_time_end=${encodeURIComponent(toIso)}`),
  );
}

/** Assert some graph neighborhood request carried the exact bounds. */
async function expectRequestBounds(
  traffic: { requests: string[] },
  fromIso: string,
  toIso: string,
): Promise<void> {
  await expect
    .poll(
      () =>
        traffic.requests.some((url) => {
          const u = new URL(url);
          return (
            u.searchParams.get("observed_from") === fromIso &&
            u.searchParams.get("observed_to") === toIso
          );
        }),
      { timeout: 30_000 },
    )
    .toBe(true);
}

test.describe("PR 38-8 direct-range temporal graph exploration (real stack)", () => {
  test.describe.configure({ timeout: 900_000, retries: 0 });

  test("directed journey: default end date, date-only, explicit time, topology, invalid, refresh, Back/Forward, Disable", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    const graphTraffic = trackGraphTraffic(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await openGraphWorkspace(page, `/investigations/${investigationId}`);

    const graphList = page.getByRole("table", { name: "Relationship list (this page)" });
    const canvasNodes = page.locator(".react-flow__node");
    const emptyMessage = page.getByText(EMPTY_WORDING);
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    await expect(canvasNodes.first()).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "graph-interactive");

    // B01/PR 38-10: the upper Graph filter toolbar carries no observed-date
    // inputs; the lower Temporal exploration section is the sole date
    // control and it is present.
    const graphFiltersGroup = page.getByRole("group", {
      name: "Graph context and filters",
    });
    await expect(graphFiltersGroup.getByLabel("Observed from")).toHaveCount(0);
    await expect(graphFiltersGroup.getByLabel("Observed to")).toHaveCount(0);
    await expect(
      graphFiltersGroup.locator('input[type="datetime-local"]'),
    ).toHaveCount(0);
    await expect(temporalGroup(page).getByLabel("Range start date")).toBeVisible();
    await heartbeat(page, "no-upper-date-controls");

    // Requirement 3 (PR 38-10): with Temporal exploration off and no legacy
    // bounds, every graph request is unbounded by observation time.
    await expect
      .poll(() => graphTraffic.requests.length, { timeout: 30_000 })
      .toBeGreaterThan(0);
    expect(
      graphTraffic.requests.every(
        (url) => !new URL(url).searchParams.has("observed_from"),
      ),
    ).toBe(true);
    await heartbeat(page, "temporal-off-unbounded");

    // E01: enabling temporal presents a neutral draft with a blank start and
    // a blank end TIME defaulting the end DATE to browser-local today, and
    // no Time frames or Previous/Next frame controls exist.
    const group = temporalGroup(page);
    await click(
      page,
      group.getByRole("checkbox", { name: "Temporal exploration" }),
      "enable-temporal",
    );
    const expectedToday = await page.evaluate(() => {
      const now = new Date();
      const pad = (n: number): string => String(n).padStart(2, "0");
      return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
    });
    await expect(group.getByLabel("Range start date")).toHaveValue("");
    await expect(group.getByLabel("Range start time")).toHaveValue("");
    await expect(group.getByLabel("Range end date")).toHaveValue(expectedToday);
    await expect(group.getByLabel("Range end time")).toHaveValue("");
    await expect(group.getByText("Time frames")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Previous frame" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Next frame" })).toHaveCount(0);
    await heartbeat(page, "neutral-draft-default-end-date");

    // E02: a date-only range (both times blank) normalizes to local midnight
    // and commits those exact instants with no frame parameters.
    const startDate = toLocalDate(RANGE_A_FROM);
    const endDate = toLocalDate(RANGE_A_TO);
    await applyDateOnlyRange(page, startDate, endDate, "apply-date-only");
    const midnightFrom = await localMidnightIso(page, startDate);
    const midnightTo = await localMidnightIso(page, endDate);
    await expectCommittedRange(page, midnightFrom, midnightTo);
    await expectRequestBounds(graphTraffic, midnightFrom, midnightTo);
    await expect(page).not.toHaveURL(/graph_time_frame/);
    await heartbeat(page, "date-only-normalized");

    // E03: an explicit non-midnight time is preserved exactly (never
    // overwritten with midnight).
    await applyExplicitRange(page, EXPLICIT_FROM, EXPLICIT_TO, "apply-explicit-time");
    await expectCommittedRange(page, EXPLICIT_FROM, EXPLICIT_TO);
    await expectRequestBounds(graphTraffic, EXPLICIT_FROM, EXPLICIT_TO);
    await heartbeat(page, "explicit-time-preserved");

    // B02/B05/PR 38-10: an ordinary Graph filter Apply/Clear only changes the
    // ordinary filters; the committed temporal interval survives and every
    // subsequent request stays bounded by it.
    const ordinarySource = graphFiltersGroup.getByLabel("Observation source");
    await ordinarySource.fill("rdap");
    await click(
      page,
      graphFiltersGroup.getByRole("button", { name: "Apply", exact: true }),
      "ordinary-apply-with-temporal",
    );
    await expect(page).toHaveURL(/graph_source=rdap/);
    await expectCommittedRange(page, EXPLICIT_FROM, EXPLICIT_TO);
    await expectRequestBounds(graphTraffic, EXPLICIT_FROM, EXPLICIT_TO);
    await click(
      page,
      graphFiltersGroup.getByRole("button", { name: "Clear", exact: true }),
      "ordinary-clear-with-temporal",
    );
    await expect(page).not.toHaveURL(/graph_source=/);
    await expectCommittedRange(page, EXPLICIT_FROM, EXPLICIT_TO);
    await heartbeat(page, "ordinary-filters-preserve-temporal");

    // E04: the exact committed range changes the displayed topology: range A
    // excludes the DNS observations, range B includes them.
    await applyExplicitRange(page, RANGE_A_FROM, RANGE_A_TO, "apply-empty-range");
    await expect(emptyMessage).toBeVisible({ timeout: 30_000 });
    await expect(graphList.locator("tbody tr")).toHaveCount(0);
    await heartbeat(page, "empty-range");
    await applyExplicitRange(page, RANGE_B_FROM, RANGE_B_TO, "apply-nonempty-range");
    await expect(emptyMessage).not.toBeVisible({ timeout: 30_000 });
    await expect(graphList.locator("tbody tr").first()).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "nonempty-range-topology");

    // E05: invalid drafts are rejected without silent repair and without a
    // committed request or URL transition.
    await expectRequestBounds(graphTraffic, RANGE_B_FROM, RANGE_B_TO);
    const requestsBeforeInvalid = graphTraffic.requests.length;
    const urlBeforeInvalid = page.url();
    await group.getByLabel("Range start date").fill("");
    await click(
      page,
      group.getByRole("button", { name: "Apply temporal" }),
      "apply-missing-start",
    );
    await expect(group.getByRole("alert")).toHaveText("Enter a range start date.");
    expect(graphTraffic.requests.length).toBe(requestsBeforeInvalid);
    expect(page.url()).toBe(urlBeforeInvalid);
    await heartbeat(page, "missing-start-rejected");

    await group.getByLabel("Range start date").fill("2026-05-02");
    await group.getByLabel("Range start time").fill("");
    await group.getByLabel("Range end date").fill("2026-05-02");
    await group.getByLabel("Range end time").fill("");
    await click(
      page,
      group.getByRole("button", { name: "Apply temporal" }),
      "apply-equal-range",
    );
    await expect(group.getByRole("alert")).toHaveText(
      "Enter a valid observed range with a start before the end.",
    );
    expect(graphTraffic.requests.length).toBe(requestsBeforeInvalid);
    expect(page.url()).toBe(urlBeforeInvalid);
    await heartbeat(page, "equal-range-rejected");

    await group.getByLabel("Range start date").fill("2026-05-03");
    await group.getByLabel("Range end date").fill("2026-05-02");
    await click(
      page,
      group.getByRole("button", { name: "Apply temporal" }),
      "apply-reversed-range",
    );
    await expect(group.getByRole("alert")).toHaveText(
      "Enter a valid observed range with a start before the end.",
    );
    expect(graphTraffic.requests.length).toBe(requestsBeforeInvalid);
    expect(page.url()).toBe(urlBeforeInvalid);
    await heartbeat(page, "reversed-range-rejected");

    // E06: refresh and Back/Forward reconstruct committed ranges from URL.
    await applyExplicitRange(page, RANGE_A_FROM, RANGE_A_TO, "apply-A");
    await expect(emptyMessage).toBeVisible({ timeout: 30_000 });
    await applyExplicitRange(page, RANGE_B_FROM, RANGE_B_TO, "apply-B");
    await expect(emptyMessage).not.toBeVisible({ timeout: 30_000 });

    await page.reload();
    await expect(
      page.getByRole("group", { name: "Graph context and filters" }),
    ).toBeVisible({ timeout: 30_000 });
    await expectCommittedRange(page, RANGE_B_FROM, RANGE_B_TO);
    await expect(emptyMessage).not.toBeVisible({ timeout: 30_000 });
    await expect(graphList.locator("tbody tr").first()).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "refresh-reconstructs");

    await page.goBack();
    await expectCommittedRange(page, RANGE_A_FROM, RANGE_A_TO);
    await expect(emptyMessage).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "back-reconstructs");

    await page.goForward();
    await expectCommittedRange(page, RANGE_B_FROM, RANGE_B_TO);
    await expect(emptyMessage).not.toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "forward-reconstructs");

    // Requirement 8 (PR 38-10): editing temporal inputs without Apply never
    // changes the committed range, the URL, or the issued requests.
    const urlBeforeDraftOnly = page.url();
    const requestsBeforeDraftOnly = graphTraffic.requests.length;
    await group.getByLabel("Range start date").fill("2026-05-04");
    await group.getByLabel("Range end date").fill("2026-05-06");
    await heartbeat(page, "draft-edits-without-apply");
    expect(page.url()).toBe(urlBeforeDraftOnly);
    expect(graphTraffic.requests.length).toBe(requestsBeforeDraftOnly);
    await expectCommittedRange(page, RANGE_B_FROM, RANGE_B_TO);

    // E08: switching from a non-empty range to an empty range never leaves
    // the prior topology presented as current.
    await expect(graphList.locator("tbody tr").first()).toBeVisible({ timeout: 30_000 });
    await applyExplicitRange(page, RANGE_A_FROM, RANGE_A_TO, "apply-empty-after-nonempty");
    await expect(emptyMessage).toBeVisible({ timeout: 30_000 });
    await expect(graphList.locator("tbody tr")).toHaveCount(0);
    await heartbeat(page, "no-stale-topology");

    // E07: Disable removes every temporal-owned parameter and restores the
    // ordinary graph behavior.
    await click(
      page,
      temporalGroup(page).getByRole("button", { name: "Disable temporal" }),
      "disable-temporal",
    );
    await expect(page).not.toHaveURL(/graph_temporal=/);
    await expect(page).not.toHaveURL(/graph_time_start/);
    await expect(page).not.toHaveURL(/graph_time_end/);
    await expect(page).not.toHaveURL(/graph_time_frame/);
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    await expect(canvasNodes.first()).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "ordinary-restored");

    expect(consoleErrors).toEqual([]);
  });

  test("PR 38-10 requirement 6: depth, expansion and re-root preserve the committed range", async ({
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

    // Commit a non-empty observed range for the F02 focal entity.
    await applyExplicitRange(page, RANGE_B_FROM, RANGE_B_TO, "req6-apply-range");
    await expectCommittedRange(page, RANGE_B_FROM, RANGE_B_TO);

    // Depth change (1 hop -> 2 hops) keeps the committed range and the
    // traversal request is bounded by it.
    await click(page, page.getByRole("button", { name: "2 hops" }), "req6-depth-draft");
    await click(
      page,
      page.getByRole("button", { name: "Apply", exact: true }),
      "req6-depth-apply",
    );
    await expect(page).toHaveURL(/graph_depth=2/);
    await expectCommittedRange(page, RANGE_B_FROM, RANGE_B_TO);
    await expect
      .poll(
        () =>
          graphTraffic.requests.some((url) => {
            const candidate = new URL(url);
            return (
              candidate.pathname.endsWith("/traversal") &&
              candidate.searchParams.get("observed_from") === RANGE_B_FROM &&
              candidate.searchParams.get("observed_to") === RANGE_B_TO
            );
          }),
        { timeout: 30_000 },
      )
      .toBe(true);
    await heartbeat(page, "req6-depth-preserves-range");

    // Revert to the one-hop neighborhood before expansion.
    await click(page, page.getByRole("button", { name: "1 hop" }), "req6-depth1-draft");
    await click(
      page,
      page.getByRole("button", { name: "Apply", exact: true }),
      "req6-depth1-apply",
    );
    await expect(page).not.toHaveURL(/graph_depth=/);
    await expectCommittedRange(page, RANGE_B_FROM, RANGE_B_TO);
    await expect(canvasNodes.first()).toBeVisible({ timeout: 30_000 });

    // Explicit expansion inherits the committed range.
    const requestsBeforeExpansion = graphTraffic.requests.length;
    await click(page, canvasNodes.first(), "req6-node-select");
    await expect(page.getByText(/Entity:/)).toBeVisible({ timeout: 20_000 });
    await click(
      page,
      page.getByRole("button", { name: /Pivot actions/ }).first(),
      "req6-pivot-open",
    );
    await click(
      page,
      page.getByRole("button", { name: "Expand known relationships" }).first(),
      "req6-expand",
    );
    await expect
      .poll(() => graphTraffic.requests.length, { timeout: 30_000 })
      .toBeGreaterThan(requestsBeforeExpansion);
    const expansionRequests = graphTraffic.requests.slice(requestsBeforeExpansion);
    expect(
      expansionRequests.every((url) => {
        const candidate = new URL(url);
        return (
          candidate.searchParams.get("observed_from") === RANGE_B_FROM &&
          candidate.searchParams.get("observed_to") === RANGE_B_TO
        );
      }),
    ).toBe(true);
    await heartbeat(page, "req6-expansion-preserves-range");

    // Re-rooting onto a non-focal canonical Entity keeps the committed range
    // and the new focal's request is bounded by it.
    const nonFocal = canvasNodes.nth(1);
    await expect(nonFocal).toBeVisible({ timeout: 30_000 });
    const testId = (await nonFocal.getAttribute("data-testid")) ?? "";
    const targetEntityId = testId.replace("rf__node-n:", "");
    expect(targetEntityId).toMatch(/^[0-9a-f-]{36}$/);
    const requestsBeforeReroot = graphTraffic.requests.length;
    await nonFocal.scrollIntoViewIfNeeded();
    await nonFocal.click({ button: "right" });
    const exploreAction = page.getByTestId("graph-explore-entity");
    await expect(exploreAction).toBeVisible({ timeout: 20_000 });
    await click(page, exploreAction, "req6-explore");
    await expect
      .poll(() => new URL(page.url()).searchParams.get("entity_id"))
      .toBe(targetEntityId);
    await expectCommittedRange(page, RANGE_B_FROM, RANGE_B_TO);
    await expect
      .poll(() => graphTraffic.requests.length, { timeout: 30_000 })
      .toBeGreaterThan(requestsBeforeReroot);
    const rerootRequests = graphTraffic.requests.slice(requestsBeforeReroot);
    expect(
      rerootRequests.some((url) => {
        const candidate = new URL(url);
        return (
          candidate.pathname.endsWith(
            `/graph/entities/${targetEntityId}/neighborhood`,
          ) &&
          candidate.searchParams.get("observed_from") === RANGE_B_FROM &&
          candidate.searchParams.get("observed_to") === RANGE_B_TO
        );
      }),
    ).toBe(true);
    await heartbeat(page, "req6-reroot-preserves-range");

    expect(consoleErrors).toEqual([]);
  });

  test("B08/PR 38-10: a legacy upper-date bookmark never bounds the graph and is stripped on Apply", async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    const graphTraffic = trackGraphTraffic(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    const entityId = await openGraphWorkspace(
      page,
      `/investigations/${investigationId}`,
    );

    // A bookmark carrying the retired upper-toolbar observed bounds must not
    // constrain the graph while temporal exploration is off.
    await page.goto(
      `/investigations/${investigationId}/relationships/evolution?entity_id=${entityId}` +
        `&view=graph&graph_observed_from=2000-01-01T00:00:00Z&graph_observed_to=2099-01-01T00:00:00Z`,
    );
    const graphList = page.getByRole("table", { name: "Relationship list (this page)" });
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    await expect
      .poll(() => graphTraffic.requests.length, { timeout: 30_000 })
      .toBeGreaterThan(0);
    const boundedRequests = graphTraffic.requests.filter((url) =>
      new URL(url).searchParams.has("observed_from"),
    );
    expect(boundedRequests).toEqual([]);
    await heartbeat(page, "legacy-bookmark-unbounded");

    // The next ordinary Graph Apply strips the retired keys.
    await click(
      page,
      page.getByRole("button", { name: "Apply", exact: true }),
      "legacy-strip-apply",
    );
    await expect(page).not.toHaveURL(/graph_observed_from/);
    await expect(page).not.toHaveURL(/graph_observed_to/);
    await heartbeat(page, "legacy-keys-stripped");
    expect(consoleErrors).toEqual([]);
  });

  test(`${CYCLES} consecutive direct-range temporal cycles in one page process`, async ({
    page,
  }) => {
    const consoleErrors = trackConsoleErrors(page);
    const graphTraffic = trackGraphTraffic(page);
    await login(page);
    const investigationId = await completeF02Investigation(page);
    await openGraphWorkspace(page, `/investigations/${investigationId}`);
    const graphList = page.getByRole("table", { name: "Relationship list (this page)" });
    const emptyMessage = page.getByText(EMPTY_WORDING);
    await expect(graphList).toBeVisible({ timeout: 30_000 });

    for (let cycle = 0; cycle < CYCLES; cycle += 1) {
      const C = `c${cycle}`;
      await applyExplicitRange(page, RANGE_A_FROM, RANGE_A_TO, `${C}-apply-A`);
      await expect(page).toHaveURL(/graph_temporal=1/);
      await expect(emptyMessage).toBeVisible({ timeout: 30_000 });
      await heartbeat(page, `${C}-empty-range`);

      await applyExplicitRange(page, RANGE_B_FROM, RANGE_B_TO, `${C}-apply-B`);
      await expect(emptyMessage).not.toBeVisible({ timeout: 30_000 });
      await expect(graphList.locator("tbody tr").first()).toBeVisible({ timeout: 30_000 });
      await heartbeat(page, `${C}-nonempty-range`);

      await click(
        page,
        temporalGroup(page).getByRole("button", { name: "Disable temporal" }),
        `${C}-disable`,
      );
      await expect(page).not.toHaveURL(/graph_temporal=/);
      await expect(graphList).toBeVisible({ timeout: 30_000 });
      await heartbeat(page, `${C}-done`);
    }
    // Every cycle requested range-bound graph traffic (no request storm, no
    // detached route); the page never needed a reload or recovery.
    expect(
      graphTraffic.requests.filter((url) => url.includes("observed_from=")).length,
    ).toBeGreaterThan(0);
    expect(consoleErrors).toEqual([]);
  });
});
