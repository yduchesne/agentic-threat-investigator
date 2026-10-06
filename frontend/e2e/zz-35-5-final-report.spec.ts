// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 35-5 canonical Final Report (Chromium + Firefox).
//
// Runs against the production-path stack created by scripts/e2e.sh: built
// static React + Nginx -> real FastAPI -> real PostgreSQL -> the durable
// production worker executing the coordinator/runner/persistence with the
// deterministic offline LLM boundary over the packaged fake world.
//
// The journey proves the browser displays the *persisted Report Writer
// prose* (title/summary/description) rather than the canonical
// `AnalyticalFinding.statement`, that the Summary/Details are deterministic
// projections of one canonical ordered finding set, that Contents uses
// stable title-independent anchors, and that contextual drill-down returns
// with the normalized `< Back` label.

import { expect, test, type Page } from "@playwright/test";

const ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 35-5 final report acceptance";

/** Collect product console/page errors; asserted clean at the end. */
function trackConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(`pageerror: ${String(error)}`));
  page.on("console", (message) => {
    if (message.type() === "error") {
      errors.push(`console: ${message.text()}`);
    }
  });
  return errors;
}

async function login(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill(process.env.E2E_ADMIN_USERNAME ?? "admin");
  await page.getByLabel("Password").fill(process.env.E2E_ADMIN_PASSWORD ?? "admin");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByText("FAKE DATA").waitFor();
}

/** Create and complete one Investigation rooted at the deterministic domain. */
async function completeInvestigation(page: Page): Promise<string> {
  await page.getByRole("link", { name: "New Investigation" }).click();
  await expect(
    page.getByRole("heading", { name: "Create Investigation" }),
  ).toBeVisible({ timeout: 30_000 });
  await page.getByLabel(/^Objective/).fill(OBJECTIVE);
  await page.getByLabel("Indicator value 1").fill(ROOT_DOMAIN);
  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
  await expect(page.getByLabel("Status: Completed").first()).toBeVisible({
    timeout: 300_000,
  });
  const investigationId = page.url().match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
  expect(investigationId).toBeTruthy();
  return investigationId ?? "";
}

test.describe("PR 35-5 canonical Final Report", () => {
  test.describe.configure({ timeout: 600_000, retries: 0 });

  test("persisted prose, Contents, deep links, and < Back", async ({ page }) => {
    await login(page);
    const consoleErrors = trackConsoleErrors(page);
    const failedResponses: string[] = [];
    page.on("response", (response) => {
      const url = new URL(response.url());
      if (
        url.pathname.startsWith("/api/") &&
        response.status() >= 400 &&
        response.status() !== 401
      ) {
        failedResponses.push(`${response.status()} ${url.pathname}`);
      }
    });

    const investigationId = await completeInvestigation(page);
    const base = `/investigations/${investigationId}`;

    // Overview: one Final Report link; no abbreviated terminal report. The
    // report pointer is set just after the terminal status transition, so
    // the link is awaited with a bounded generous timeout.
    await expect(page.getByRole("link", { name: "View report" })).toBeVisible({
      timeout: 180_000,
    });
    expect(await page.getByText("Executive summary").count()).toBe(0);
    expect(await page.getByText("At a glance").count()).toBe(0);

    await page.getByRole("link", { name: "View report" }).click();
    await expect(page).toHaveURL(/\/overview\/report/);
    await expect(
      page.getByRole("heading", { name: "ATI deterministic investigation report" }),
    ).toBeVisible({ timeout: 30_000 });

    // Summary is finding-centric and never the old Executive Summary.
    await expect(page.getByText("Summary").first()).toBeVisible();
    expect(await page.getByText("Executive summary").count()).toBe(0);
    await expect(
      page.getByText(/Finding 1: Generated summary for canonical finding 1\./),
    ).toBeVisible();
    // The Summary now contains every canonical finding (including the LOW
    // finding 2); there is no conditional additional-findings note.
    await expect(
      page.getByText(/Finding 2: Generated summary for canonical finding 2\./),
    ).toBeVisible();
    expect(
      await page.getByText("Additional findings are detailed below.").count(),
    ).toBe(0);
    expect(await page.getByText(/Assessment 1/).count()).toBe(0);

    // Status replaces Lifecycle.
    await expect(page.getByText("Status").first()).toBeVisible();
    expect(await page.getByText("Lifecycle").count()).toBe(0);
    await expect(page.getByText(/Criticality:/).first()).toBeVisible();
    await expect(page.getByText(/Confidence:/).first()).toBeVisible();
    await expect(page.getByText(/Started at:/)).toBeVisible();
    await expect(page.getByText(/Ended at:/)).toBeVisible();
    await expect(page.getByText(/Duration:/)).toBeVisible();
    await expect(page.getByText(/Outcome \/ stop reason:/)).toBeVisible();

    // Contents + Details -> Findings.
    await expect(page.getByRole("heading", { name: "Contents" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Details" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();

    // Details renders the persisted Report Writer title and description, not
    // the canonical statement.
    await expect(
      page.getByText(/Finding 1 — Generated finding 1 heading/).first(),
    ).toBeVisible();
    await expect(
      page.getByText(/Generated reader-facing description for canonical finding 1\./),
    ).toBeVisible();
    // The canonical statement is not substituted for the description.
    expect(
      await page
        .getByText(/Threat-intelligence and reputation sources associate/)
        .count(),
    ).toBe(0);
    // The low finding is retained in Details.
    await expect(
      page.getByText(/Finding 2 — Generated finding 2 heading/).first(),
    ).toBeVisible();
    await expect(page.getByText("Corroboration").first()).toBeVisible();

    // Contents finding link uses a stable, title-independent anchor.
    await page.getByRole("link", { name: /Finding 2 —/ }).first().click();
    await expect(page).toHaveURL(/#finding-2/);
    await expect(page.locator("#finding-2")).toBeVisible();
    await page
      .locator("#finding-2")
      .getByRole("link", { name: "Back to contents" })
      .click();
    await expect(page).toHaveURL(/#contents/);

    // Direct deep link survives refresh and shows the same persisted prose.
    await page.goto(`${base}/overview/report#finding-1`);
    await expect(page.locator("#finding-1")).toBeVisible();
    await expect(
      page.getByText(/Generated reader-facing description for canonical finding 1\./),
    ).toBeVisible();

    // A corroborating routed Evidence action returns with `< Back`.
    await page
      .locator("#finding-1")
      .getByTestId("pivot-action-evidenceExact")
      .first()
      .click();
    await expect(page).toHaveURL(new RegExp(`${base}/evidence/`));
    await expect(page.getByRole("link", { name: "< Back" })).toBeVisible();
    await page.getByRole("link", { name: "< Back" }).click();
    await expect(page).toHaveURL(/\/overview\/report/);
    await expect(
      page.getByText(/Generated reader-facing description for canonical finding 1\./),
    ).toBeVisible();

    expect(failedResponses).toEqual([]);
    expect(consoleErrors).toEqual([]);
  });
});
