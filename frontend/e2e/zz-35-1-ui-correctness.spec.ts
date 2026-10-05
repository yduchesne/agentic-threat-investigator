// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 35-1 real-stack UI correctness acceptance (Chromium + Firefox).
//
// Fresh-main PR 35-1 fixes several analyst-facing navigation/drill-down
// defects without changing the graph, Pivot, Evidence, or temporal-frame
// architecture. This spec runs the required normal-pointer journeys
// against the authoritative repository harness (scripts/e2e.sh):
//
//   W1 Evidence Subject pivot -> "Evidence for this entity"
//   W2 Relationships history -> row View -> exact observation detail
//   Evidence linked ID -> exact Evidence details
//   Relationship history contextual Back -> exact origin
//   HOPS 1 -> 2 -> 3 depth propagation
//
// Every wedge journey uses a normal locator click, retries=0, a bounded
// page heartbeat, and a clean product console/pageerror assertion. No
// dispatchEvent, forced click, coordinate click, sleep, or reload is used
// to make a journey pass.

import { expect, test, type Locator, type Page } from "@playwright/test";

const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "PR 35-1 UI correctness acceptance journey";

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

/** Prove the page is alive with a bounded heartbeat after a transition. */
async function heartbeat(page: Page, label: string): Promise<void> {
  await page.evaluate("1+1", undefined, { timeout: 3000 });
  console.log(`35-1-OK ${label}`);
}

/** Normal locator click with connected/visible geometry; no workarounds. */
async function click(page: Page, loc: Locator, label: string): Promise<void> {
  await expect(loc).toBeVisible({ timeout: 30_000 });
  await loc.click();
  await heartbeat(page, label);
}

async function login(page: Page): Promise<void> {
  await page.goto(`${process.env.E2E_BASE_URL ?? ""}/login`);
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
  await expect(
    page.getByLabel("Status: Completed").first(),
  ).toBeVisible({ timeout: 240_000 });
  return investigationId ?? "";
}

test.describe("PR 35-1 UI correctness (real stack)", () => {
  test.describe.configure({ timeout: 900_000, retries: 0 });

  test("W1/W2/HOPS/Evidence-link/Back journeys", async ({ page }) => {
    await login(page);
    // Track product errors only after the expected pre-auth /auth/me probe.
    const consoleErrors = trackConsoleErrors(page);
    const investigationId = await completeF02Investigation(page);
    const base = `/investigations/${investigationId}`;

    // ---- W1: Evidence Subject pivot -> Evidence for this entity ----
    await page.goto(`${base}/evidence`);
    const evidenceTable = page.getByRole("table", { name: "Evidence" });
    await expect(evidenceTable).toBeVisible({ timeout: 30_000 });
    const subjectPivot = evidenceTable.getByRole("button", { name: "Subject" }).first();
    await click(page, subjectPivot, "w1-subject-trigger");
    await click(
      page,
      page.getByRole("link", { name: "Evidence for this entity" }).first(),
      "w1-evidence-for-entity",
    );
    await expect(page).toHaveURL(new RegExp("subject_entity_id="));
    await expect(
      page.getByRole("table", { name: "Evidence" }),
    ).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "w1-landed");

    // ---- W2: Relationship history -> row View -> exact detail ----
    await page.goto(`${base}/relationships/observations`);
    const historyTable = page.getByRole("table", { name: "Relationship history" });
    await expect(historyTable).toBeVisible({ timeout: 30_000 });
    const viewButton = historyTable.getByRole("button", { name: /^View / }).first();
    await click(page, viewButton, "w2-view");
    await expect(
      page.getByRole("heading", { name: "Relationship observation detail" }),
    ).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "w2-detail");
    // Close the detail and confirm the table survives (no reload, no wedge).
    await click(
      page,
      page.getByTestId("resource-detail-back"),
      "w2-back-to-list",
    );
    await expect(historyTable).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "w2-closed");

    // ---- Evidence linked ID -> exact Evidence details ----
    const evidenceLink = historyTable.getByRole("link", { name: "Evidence" }).first();
    await expect(evidenceLink).toHaveAttribute("href", /\/evidence\/[0-9a-f-]+$/);
    await click(page, evidenceLink, "evidence-link");
    await expect(
      page.getByRole("heading", { name: "Evidence details" }),
    ).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "evidence-exact");

    // ---- Contextual Back from Relationship history to exact origin ----
    await page.goto(`${base}/relationships`);
    await expect(
      page.getByRole("heading", { name: "Relationships" }),
    ).toBeVisible({ timeout: 30_000 });
    await click(
      page,
      page.getByRole("link", { name: "History" }).first(),
      "history-link",
    );
    await expect(page).toHaveURL(/\/relationships\/observations/);
    const back = page.getByRole("button", { name: "< Back" });
    await expect(back).toBeVisible({ timeout: 30_000 });
    await click(page, back, "history-back");
    await expect(page).toHaveURL(/\/relationships$/);

    // ---- HOPS 1 -> 2 -> 3 depth propagation ----
    await page.goto(`${base}/relationships`);
    const firstEvolution = page
      .getByRole("link", { name: /relationship history/i })
      .first();
    await expect(firstEvolution).toBeVisible({ timeout: 30_000 });
    const href = await firstEvolution.getAttribute("href");
    const entityId = href?.match(/entity_id=([0-9a-f-]+)/i)?.[1] ?? "";
    await page.goto(
      `${base}/relationships/evolution?entity_id=${entityId}&view=graph`,
    );
    await expect(
      page.getByRole("group", { name: "Graph context and filters" }),
    ).toBeVisible({ timeout: 30_000 });
    await expect(page).not.toHaveURL(/graph_depth=/);
    await click(page, page.getByRole("button", { name: "2 hops" }), "hops-2-draft");
    await click(
      page,
      page.getByRole("button", { name: /^Apply$/ }),
      "hops-2-apply",
    );
    await expect(page).toHaveURL(/graph_depth=2/);
    await expect(
      page.getByRole("table", { name: "Relationship list (this page)" }),
    ).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "hops-2");
    await click(page, page.getByRole("button", { name: "3 hops" }), "hops-3-draft");
    await click(
      page,
      page.getByRole("button", { name: /^Apply$/ }),
      "hops-3-apply",
    );
    await expect(page).toHaveURL(/graph_depth=3/);
    await expect(
      page.getByRole("table", { name: "Relationship list (this page)" }),
    ).toBeVisible({ timeout: 30_000 });
    await heartbeat(page, "hops-3");

    expect(consoleErrors).toEqual([]);
  });

  test("W1/W2 stability: five normal-click cycles in one page process", async ({
    page,
  }) => {
    await login(page);
    const consoleErrors = trackConsoleErrors(page);
    const investigationId = await completeF02Investigation(page);
    const base = `/investigations/${investigationId}`;
    for (let cycle = 0; cycle < 5; cycle += 1) {
      const C = `c${cycle}`;
      await page.goto(`${base}/evidence`);
      const evidenceTable = page.getByRole("table", { name: "Evidence" });
      await expect(evidenceTable).toBeVisible({ timeout: 30_000 });
      await click(
        page,
        evidenceTable.getByRole("button", { name: "Subject" }).first(),
        `${C}-w1-trigger`,
      );
      await click(
        page,
        page.getByRole("link", { name: "Evidence for this entity" }).first(),
        `${C}-w1-action`,
      );
      await expect(page).toHaveURL(/subject_entity_id=/);
      await heartbeat(page, `${C}-w1`);
      await page.goto(`${base}/relationships/observations`);
      const historyTable = page.getByRole("table", { name: "Relationship history" });
      await expect(historyTable).toBeVisible({ timeout: 30_000 });
      await click(
        page,
        historyTable.getByRole("button", { name: /^View / }).first(),
        `${C}-w2-view`,
      );
      await expect(
        page.getByRole("heading", { name: "Relationship observation detail" }),
      ).toBeVisible({ timeout: 30_000 });
      await click(
        page,
        page.getByTestId("resource-detail-back"),
        `${C}-w2-close`,
      );
      await heartbeat(page, `${C}-w2`);
    }
    expect(consoleErrors).toEqual([]);
  });

  test("provenance Observation Hide closes the observation and nested Evidence", async ({
    page,
  }) => {
    await login(page);
    const consoleErrors = trackConsoleErrors(page);
    const investigationId = await completeF02Investigation(page);
    const base = `/investigations/${investigationId}`;
    await page.goto(`${base}/relationships`);
    await expect(
      page.getByRole("heading", { name: "Relationships" }),
    ).toBeVisible({ timeout: 30_000 });
    const firstEvolution = page
      .getByRole("link", { name: /relationship history/i })
      .first();
    await expect(firstEvolution).toBeVisible({ timeout: 30_000 });
    const href = await firstEvolution.getAttribute("href");
    const entityId = href?.match(/entity_id=([0-9a-f-]+)/i)?.[1] ?? "";
    await page.goto(
      `${base}/relationships/evolution?entity_id=${entityId}&view=graph`,
    );
    const graphList = page.getByRole("table", {
      name: "Relationship list (this page)",
    });
    await expect(graphList).toBeVisible({ timeout: 30_000 });
    await click(
      page,
      graphList.getByRole("link", { name: "Provenance" }).first(),
      "provenance-open",
    );
    const provenance = page.getByRole("region", {
      name: "Relationship provenance",
    });
    await expect(provenance).toBeVisible({ timeout: 30_000 });
    const observations = provenance.getByRole("table", {
      name: "Supporting observations",
    });
    await expect(observations).toBeVisible({ timeout: 30_000 });
    await click(
      page,
      observations.getByRole("button", { name: "View observation" }).first(),
      "provenance-observation",
    );
    await click(
      page,
      provenance.getByRole("button", { name: "View supporting evidence" }),
      "provenance-evidence",
    );
    await expect(
      provenance.getByRole("heading", { name: "Supporting evidence" }),
    ).toBeVisible({ timeout: 30_000 });
    // Hide the Observation (the first Hide section), clearing nested Evidence.
    const observationHeading = provenance.getByRole("heading", {
      name: "Observation",
      exact: true,
    });
    await click(
      page,
      observationHeading.locator("xpath=..").getByRole("button", { name: "Hide" }),
      "provenance-hide-observation",
    );
    await expect(
      provenance.getByRole("heading", { name: "Observation", exact: true }),
    ).toHaveCount(0);
    await expect(
      provenance.getByRole("heading", { name: "Supporting evidence" }),
    ).toHaveCount(0);
    // Parent provenance and the bounded observation list remain.
    await expect(provenance).toBeVisible();
    await expect(
      provenance.getByRole("table", { name: "Supporting observations" }),
    ).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });
});
