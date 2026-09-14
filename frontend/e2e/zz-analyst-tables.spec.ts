// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 24C analyst resource tables and drill-down
// (E20-E21).
//
// Runs against the production-path stack created by the repository E2E
// harness (scripts/e2e.sh): built/static React + Nginx -> real FastAPI ->
// real PostgreSQL -> real durable Investigation worker with the
// deterministic offline LLM boundary, over the packaged PR 23D fake world.
// No live Internet, no live threat-intelligence provider, and no live
// LLM; `FAKE DATA` remains visible throughout.
//
// The spec file is named ``zz-*`` so it runs after the PR 24A/24B specs:
// the backend login rate limit (5 attempts per 60s window) is shared by
// every browser session, and the authenticated 24A/24B specs are allowed
// their own burst before PR 24C adds more.
//
// Two browser sessions (E20 creates/completes one F02 investigation, E21
// reuses its session via Playwright storageState from the real list) keep
// the login rate limit well within normal bounds: the PR 24C suite
// performs exactly ONE login.
//
// Canonical slice:
//   login -> create the F02 fake-world Investigation -> terminal ->
//   Evidence (URL-backed filter + reload + detail drawer) ->
//   Relationships (detail + bounded observations) -> Observations route
//   (Observed vs Retrieved) -> Research (contextual separation) ->
//   Timeline (URL-backed event filter) -> History (exact-version
//   detail) -> current-page CSV download.
//
// Filter application follows the PR 24C architectural contract: filters
// are URL search parameters owned by the backend. The visible toolbar
// controls and their Apply semantics are covered by component tests; the
// browser slice proves real server-backed filtering through the URL.

import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";

const ADMIN_USERNAME = process.env.E2E_ADMIN_USERNAME ?? "";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "";

const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 24C assess update-package delivery";

async function login(page: Page): Promise<void> {
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Username").fill(ADMIN_USERNAME);
  await page.getByLabel("Password").fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
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

// E21 reuses the session cookie captured by E20 (Playwright storageState).
// The backend login rate limit is 5 attempts per 60s window (shared by the
// auth spec), so the PR 24C suite performs exactly ONE login.
const SHARED_SESSION_STATE = "test-results/analyst-session.json";

async function captureSession(page: Page): Promise<void> {
  const state = await page.context().storageState();
  const { writeFileSync } = await import("node:fs");
  writeFileSync(SHARED_SESSION_STATE, JSON.stringify(state), "utf-8");
}

test.describe("PR 24C real-stack analyst browsing", () => {
  test.describe.configure({ timeout: 300_000 });

  test.beforeAll(() => {
    if (ADMIN_USERNAME.length === 0 || ADMIN_PASSWORD.length === 0) {
      throw new Error("E2E_ADMIN_USERNAME and E2E_ADMIN_PASSWORD are required.");
    }
  });

  test("E20 analyst tables, URL-backed filters, drawers and CSV export", async ({
    page,
  }) => {
    await login(page);
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    await captureSession(page);
    const investigationId = await completeF02Investigation(page);
    const base = `/investigations/${investigationId}`;

    // Evidence: bounded server table with the persisted rows.
    await page.getByRole("tab", { name: "Evidence" }).click();
    await expect(page.getByRole("heading", { name: "Evidence" })).toBeVisible();
    await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("Observed at", { exact: true }).first()).toBeVisible();

    // A real exact filter applied through the URL-backed contract; the
    // reload preserves it (URL is the filter state).
    const evidenceUrl = `${base}/evidence?type=${encodeURIComponent("urn:ati:evidence:dns")}`;
    await page.goto(evidenceUrl);
    await expect(page).toHaveURL(/type=urn%3Aati%3Aevidence%3Adns/);
    await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });
    await page.reload();
    await expect(page.getByText("DNS", { exact: true }).first()).toBeVisible({ timeout: 30_000 });

    // Row View opens the authoritative scoped detail drawer with distinct
    // Observed at / Retrieved at timestamps. The drawer is URL-addressable
    // (`selected=<uuid>`); navigating back to the same filtered URL closes
    // it while the filters and cursor stay intact.
    await page.getByRole("button", { name: /View / }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByText("Observed at").first()).toBeVisible();
    await expect(page.getByText("Retrieved at").first()).toBeVisible();
    await page.goto(evidenceUrl);
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 10_000 });

    // Relationships: stable edges with analyst labels.
    await page.getByRole("tab", { name: "Relationships" }).click();
    await expect(
      page.getByRole("heading", { name: "Relationships" }),
    ).toBeVisible();
    await expect(page.getByText("Resolves to").first()).toBeVisible({ timeout: 30_000 });

    // Detail: the stable edge plus a bounded observation preview.
    await page.getByRole("button", { name: /View / }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByText(/Observations \(first page\)/)).toBeVisible();
    await expect(page.getByText("Observed at").first()).toBeVisible();
    await expect(page.getByText("Retrieved at").first()).toBeVisible();
    await expect(page.getByText("View all observations").first()).toBeVisible();

    // First-class observations route with the relationship filter preset
    // (the in-drawer link is proven by component tests; closing the drawer
    // through its URL then deep-linking exercises addressability).
    await page.goto(`${base}/relationships`);
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 10_000 });
    await page.goto(`${base}/relationships/observations`);
    await expect(page).toHaveURL(/\/relationships\/observations/);
    await expect(
      page.getByRole("heading", { name: "Relationship observations" }),
    ).toBeVisible();
    await expect(page.getByText("Observed at", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("Retrieved at", { exact: true }).first()).toBeVisible();

    // Research: visibly contextual knowledge, never Evidence.
    await page.getByRole("tab", { name: "Research" }).click();
    await expect(
      page.getByRole("heading", { name: "Research context" }),
    ).toBeVisible();
    await expect(page.getByText(/not observed Evidence/)).toBeVisible();

    // Timeline: canonical observable workflow with a URL-backed event
    // filter that reloads.
    await page.getByRole("tab", { name: "Timeline" }).click();
    await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
    await expect(page.getByText("Provider work completed").first()).toBeVisible({
      timeout: 30_000,
    });
    const timelineUrl = `${base}/timeline?event_type=evidence_persisted`;
    await page.goto(timelineUrl);
    await expect(page).toHaveURL(/event_type=evidence_persisted/);
    await expect(page.getByText("Evidence persisted").first()).toBeVisible({ timeout: 30_000 });

    // History: secondary via More -> History, exact-version detail.
    await page.getByRole("button", { name: "More" }).click();
    await page.getByRole("menuitem", { name: "History" }).click();
    await expect(page.getByRole("heading", { name: "History" })).toBeVisible();
    await expect(page.getByText("Updated").first()).toBeVisible({ timeout: 30_000 });
    await page.getByRole("button", { name: /View / }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByText("State").first()).toBeVisible();
    await expect(page.getByText("Diff").first()).toBeVisible();
    await expect(page.getByText("View versions of this object")).toBeVisible();
    await page.goto(`${base}/history`);
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 10_000 });

    // Current-page CSV export: safe filename and bounded content.
    await page.getByRole("tab", { name: "Evidence" }).click();
    await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export current page" }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(
      /^ati-[0-9a-f]{8}-evidence-\d{14}\.csv$/,
    );
    const path = await download.path();
    const text = readFileSync(path ?? "", "utf-8");
    expect(text).toContain(F02_ROOT_DOMAIN);
    expect(text).not.toContain("Export all");
  });

  test.describe("PR 24C shared-session reuse", () => {
    test.use({ storageState: SHARED_SESSION_STATE });
    test("E21 the completed investigation browses with no pivot UI", async ({
      page,
    }) => {
      await page.goto("/investigations");
      await expect(page.getByText("FAKE DATA")).toBeVisible();

    // The created Investigation appears in the real list (the assertion of
    // exactly one duplicate-free entry is covered by the PR 24B suite on a
    // fresh stack; here multiple runs share one debug stack).
    const objective = page.getByRole("link", { name: OBJECTIVE }).first();
    await expect(objective).toBeVisible({ timeout: 30_000 });
    await objective.click();
    await expect(
      page.getByRole("heading", { name: OBJECTIVE }),
    ).toBeVisible({ timeout: 20_000 });
    expect(page.getByText("FAKE DATA")).toBeVisible();

    await page.getByRole("tab", { name: "Evidence" }).click();
    await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });

      // No PR 24D pivot modal workspace / breadcrumb chain exists.
      expect(
        (await page.getByRole("banner").allTextContents()).join(" "),
      ).not.toContain("Breadcrumb");
      await expect(page.getByRole("dialog")).not.toBeVisible();
    });
  });
});