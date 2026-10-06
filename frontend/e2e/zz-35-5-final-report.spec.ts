// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 35-5 REPORT tab consolidation (Chromium).
//
// Runs against the production-path stack created by scripts/e2e.sh: built
// static React + Nginx -> real FastAPI -> real PostgreSQL -> the durable
// production worker executing the coordinator/runner/persistence with the
// deterministic offline LLM boundary over the packaged fake world.
//
// Amendment scope: the primary REPORT tab renders the one canonical persisted
// Final Report directly. This focused journey asserts the consolidated
// hierarchy (Status before Summary, Summary/Details closure, direct
// Evidence/Graph Analysis support, no Corroboration, no Details
// Back-to-contents), stable Contents anchors, and deep-link retention. It
// deliberately does not drill into resources, test Markdown, or run the
// broader E2E suite.

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

  test("REPORT tab renders the canonical Final Report hierarchy", async ({
    page,
  }) => {
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

    // The primary REPORT tab is the surface; the old Overview indirection is
    // gone. The report pointer is set just after the terminal status
    // transition, so the canonical Report is awaited with a bounded timeout.
    await expect(page.getByRole("tab", { name: "REPORT" })).toBeVisible();
    expect(
      await page.getByRole("tab", { name: "Overview" }).count(),
    ).toBe(0);
    expect(await page.getByRole("link", { name: "View report" }).count()).toBe(0);
    await expect(
      page.getByRole("heading", { name: "ATI deterministic investigation report" }),
    ).toBeVisible({ timeout: 240_000 });
    expect(await page.getByText("Lifecycle").count()).toBe(0);

    // Status precedes Summary in the rendered hierarchy.
    const headingOrder = await page.evaluate(() => {
      const status = document.querySelector("#status");
      const summary = document.querySelector("#summary");
      if (status === null || summary === null) {
        return "missing";
      }
      return status.compareDocumentPosition(summary) &
        Node.DOCUMENT_POSITION_FOLLOWING
        ? "status-first"
        : "summary-first";
    });
    expect(headingOrder).toBe("status-first");

    // Summary retains every canonical Finding with deterministic numbering.
    await expect(
      page.getByText(/Finding 1: Generated summary for canonical finding 1\./),
    ).toBeVisible();
    await expect(
      page.getByText(/Finding 2: Generated summary for canonical finding 2\./),
    ).toBeVisible();
    expect(await page.getByText(/Assessment 1/).count()).toBe(0);

    // Details retains every canonical Finding with the persisted prose.
    await expect(
      page.getByText(/Finding 1 — Generated finding 1 heading/).first(),
    ).toBeVisible();
    await expect(
      page.getByText(/Generated reader-facing description for canonical finding 1\./),
    ).toBeVisible();
    await expect(
      page.getByText(/Finding 2 — Generated finding 2 heading/).first(),
    ).toBeVisible();
    await expect(
      page.getByText(/Generated reader-facing description for canonical finding 2\./),
    ).toBeVisible();

    // Direct support subsections; no Corroboration wrapper and no
    // relationship-observation report heading.
    await expect(page.getByRole("heading", { name: "Evidence" })).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Graph Analysis" }),
    ).toBeVisible();
    expect(await page.getByText("Corroboration").count()).toBe(0);
    expect(
      await page.getByRole("heading", { name: "Relationship observation" }).count(),
    ).toBe(0);

    // No Back-to-contents inside Details.
    expect(await page.getByText("Back to contents").count()).toBe(0);

    // Contents uses a stable, title-independent anchor and the target exists.
    await page.getByRole("link", { name: /Finding 2 —/ }).first().click();
    await expect(page).toHaveURL(/#finding-2/);
    await expect(page.locator("#finding-2")).toBeVisible();

    // Deep-link + legacy-URL compatibility both retain the persisted Report
    // and the stable fragment without regenerating anything.
    await page.goto(`${base}/overview/report#finding-1`);
    await expect(page).toHaveURL(new RegExp(`${base}/overview#finding-1$`));
    await expect(page.locator("#finding-1")).toBeVisible();
    await expect(
      page.getByText(/Generated reader-facing description for canonical finding 1\./),
    ).toBeVisible();
    await page.reload();
    await expect(page.locator("#finding-1")).toBeVisible();
    await expect(
      page.getByText(/Generated reader-facing description for canonical finding 1\./),
    ).toBeVisible();

    expect(failedResponses).toEqual([]);
    expect(consoleErrors).toEqual([]);
  });
});
