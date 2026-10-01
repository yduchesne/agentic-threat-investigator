// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 31F-8 routed cross-resource provenance
// navigation (replaces the PR 24D/31F-6 Pivot stack journeys, E22/E22-B).
//
// Runs against the production-path stack created by the repository E2E
// harness (scripts/e2e.sh): built/static React + Nginx -> real FastAPI ->
// real PostgreSQL -> real durable Investigation worker with the
// deterministic offline LLM boundary, over the packaged PR 23D fake world.
// No live Internet, no live threat-intelligence provider, and no live
// LLM; `FAKE DATA` remains visible throughout.
//
// Cross-resource exploration is ordinary Investigation-scoped React Router
// navigation: report support opens the exact Evidence route, capabilities
// resolve through the exhaustive typed mapper, and browser Back/Forward
// owns the reverse journey. Every activation is a normal locator click;
// canonical URLs never carry `pivot=` and no `pivot-workbench` exists.

import { expect, test, type Page } from "@playwright/test";

const OBJECTIVE = "PR 31F-8 routed provenance navigation";
const F02_ROOT_DOMAIN = "update-package.test";
const F01_BENIGN_OBJECTIVE = "PR 31F-8 benign dead-end routed path";
const F01_ROOT_DOMAIN = "alice-corp.test";
const SHARED_SESSION_STATE = "test-results/analyst-session.json";

/** Progress markers printed when a journey ends pin the exact stall point. */
const stepTags: Array<{ tag: string; at: number }> = [];
function step(tag: string): void {
  stepTags.push({ tag, at: Date.now() });
  console.log(`E22-STEP ${tag}`);
}

/** Create and complete one deterministic fake-world Investigation. */
async function completeInvestigation(
  page: Page,
  objective: string,
  rootDomain: string,
): Promise<string> {
  await page.getByRole("link", { name: "New Investigation" }).click();
  await expect(
    page.getByRole("heading", { name: "Create Investigation" }),
  ).toBeVisible();
  await page.getByLabel(/^Objective/).fill(objective);
  await page.getByLabel("Indicator value 1").fill(rootDomain);
  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
  const url = page.url();
  const investigationId = url.match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
  expect(investigationId).not.toBeUndefined();
  await expect(
    page.getByRole("heading", { name: objective }),
  ).toBeVisible({ timeout: 20_000 });
  await expect(page.getByLabel("Status: Completed").first()).toBeVisible({ timeout: 240_000 });
  return investigationId ?? "";
}

test.describe("PR 31F-8 routed cross-resource navigation", () => {
  test.describe.configure({ timeout: 240_000 });
  test.use({ storageState: SHARED_SESSION_STATE });

  test("E22 provenance -> routed Evidence -> Relationships -> observations -> Evidence -> Back/Forward/refresh", async ({
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
    const base = `/investigations/${await completeInvestigation(
      page,
      OBJECTIVE,
      F02_ROOT_DOMAIN,
    )}`;
    step("overview ready");

    // The completed Overview shows the persisted Report with finding
    // support references; the semantic support line stays visible.
    await expect(page.getByText("Supports").first()).toBeVisible({ timeout: 30_000 });
    await expect(
      page.getByText(/urn:ati:source:[a-z_]+ · [A-Za-z ]+ · /).first(),
    ).toBeVisible({ timeout: 30_000 });

    // Evidence support -> exact scoped Evidence route (semantic link).
    await expect(
      page.getByRole("link", { name: "Open evidence" }).first(),
    ).toBeVisible({ timeout: 120_000 });
    await page.getByRole("link", { name: "Open evidence" }).first().click();
    await expect(page).toHaveURL(new RegExp(`${base}/evidence/[0-9a-f-]+$`));
    const evidenceHeading = page.getByRole("heading", { name: "Evidence details" });
    await expect(evidenceHeading).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });
    // No dialog/modal in the routed architecture; no shared workbench.
    await expect(page.getByRole("dialog")).toHaveCount(0);
    expect(await page.getByTestId("pivot-workbench").count()).toBe(0);
    expect(page.url()).not.toContain("pivot=");
    step("evidence route open");

    // Evidence subject -> Relationships direction. The fake world's
    // orientation is deterministic: the domain is always a relationship
    // SOURCE and the malware always a TARGET, so the subject's type
    // selects the typed route with data.
    const evidenceDetailText = ((await page.locator("main").textContent()) ?? "").replace(
      /\s+/g,
      " ",
    );
    const subjectIsMalware =
      evidenceDetailText.includes("Subject type malware") ||
      evidenceDetailText.includes("Subject typemalware");
    const pivotDirection = subjectIsMalware ? "Relationships where target" : "Relationships where source";
    const pivotFilterName = subjectIsMalware ? "Target entity ID" : "Source entity ID";
    await page.getByRole("button", { name: /^Pivot actions/ }).click();
    await page.getByRole("group", { name: "Pivot actions" }).getByRole("link", { name: pivotDirection }).click();
    await expect(page).toHaveURL(new RegExp(`${base}/relationships\\?(source|target)_entity_id=`));
    await expect(
      page.getByRole("textbox", { name: pivotFilterName }),
    ).toHaveValue(/^[0-9a-f-]{36}$/, { timeout: 30_000 });
    const relationshipsTable = page.getByRole("table", { name: "Relationships" });
    await expect(relationshipsTable).toBeVisible({ timeout: 60_000 });
    step("relationships route open");

    // Open the Relationship detail (list/detail), then follow the
    // "View all observations" semantic link to the observations route.
    await relationshipsTable
      .getByRole("row")
      .filter({ hasText: F02_ROOT_DOMAIN })
      .first()
      .getByRole("button", { name: /^View / })
      .click();
    await expect(
      page.getByRole("heading", { name: "Relationships details" }),
    ).toBeVisible({ timeout: 30_000 });
    step("relationship detail open");
    await page.getByRole("link", { name: "View all observations" }).click();
    await expect(page).toHaveURL(new RegExp(`${base}/relationships/observations\\?relationship_id=`));
    await expect(
      page.getByRole("textbox", { name: "Relationship ID" }),
    ).toBeVisible({ timeout: 30_000 });
    step("observations route open");

    // Observation row -> exact Evidence route (single-entry semantic
    // action; accessible name is the column aria-label "Evidence").
    const observationsTable = page.getByRole("table", { name: "Relationship observations" });
    await expect(observationsTable).toBeVisible({ timeout: 30_000 });
    await observationsTable
      .getByRole("row")
      .nth(1)
      .getByRole("link", { name: "Evidence", exact: true })
      .first()
      .click();
    await expect(page).toHaveURL(new RegExp(`${base}/evidence/[0-9a-f-]+$`));
    await expect(
      page.getByRole("heading", { name: "Evidence details" }),
    ).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });
    step("nested evidence route open");

    // Browser Back restores the observations route; Forward restores the
    // exact Evidence route again (browser history owns the journey).
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`${base}/relationships/observations`));
    await expect(
      page.getByRole("textbox", { name: "Relationship ID" }),
    ).toBeVisible({ timeout: 30_000 });
    await page.goForward();
    await expect(page).toHaveURL(new RegExp(`${base}/evidence/[0-9a-f-]+$`));
    step("Back/Forward restored");

    // Refresh reconstructs the same routed Evidence surface from URL state.
    await page.reload();
    await expect(
      page.getByRole("heading", { name: "Evidence details" }),
    ).toBeVisible({ timeout: 30_000 });

    // Browser Back walks the entry back to the Overview (browsing back to
    // the previous surface); no "Close workspace" control exists.
    await page.goBack(); // observations
    await page.goBack(); // relationship detail
    await page.goBack(); // relationships route
    await page.goBack(); // evidence exact
    await page.goBack(); // overview
    await expect(page.getByRole("heading", { name: OBJECTIVE })).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("Supports").first()).toBeVisible();
    expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(page.url()).not.toContain("pivot=");
    expect(consoleErrors).toEqual([]);
    for (const { tag, at } of stepTags) {
      console.log(`E22-MARK ${tag} +${(at - stepTags[0].at) / 1000}s`);
    }
  });

  test("E22-B benign/dead-end routed path resolves honestly (F01)", async ({
    page,
  }) => {
    const consoleErrors: string[] = [];
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${String(error)}`));
    page.on("console", (message) => {
      if (message.type === "error") {
        consoleErrors.push(`console: ${message.text}`);
      }
    });

    step("dead: start");
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const base = `/investigations/${await completeInvestigation(
      page,
      F01_BENIGN_OBJECTIVE,
      F01_ROOT_DOMAIN,
    )}`;
    step("dead: F01 completed");

    // Legal typed capability from the benign Investigation's Evidence:
    // "Research for this entity" -> the canonical research route with the
    // exact subject filter (F01 persists no research; an honest dead end).
    await page.getByRole("tab", { name: "Evidence" }).click();
    await expect(
      page.getByText(F01_ROOT_DOMAIN, { exact: true }).first(),
    ).toBeVisible({ timeout: 30_000 });
    await page.getByRole("button", { name: /^View / }).first().click();
    await expect(
      page.getByRole("heading", { name: "Evidence details" }),
    ).toBeVisible({ timeout: 30_000 });
    step("dead: evidence detail open");

    await page.getByRole("button", { name: /^Pivot actions/ }).click();
    await page
      .getByRole("group", { name: "Pivot actions" })
      .getByRole("link", { name: "Research for this entity" })
      .click();
    await expect(page).toHaveURL(new RegExp(`${base}/research\\?subject_entity_id=`));
    step("dead: research route open");

    // The exact bounded server filter is visible in the URL-backed form.
    await expect(
      page.getByRole("textbox", { name: "Subject entity ID" }),
    ).toHaveValue(/^[0-9a-f-]{36}$/);
    // Honest empty/dead-end semantics; no invented fallback target.
    await expect(
      page.getByText("No research results match these filters"),
    ).toBeVisible({ timeout: 30_000 });
    await expect(
      page.getByText("The active filters exclude every loaded research result."),
    ).toBeVisible();
    expect(page.getByText(/inferred|equivalent|related observation/i)).toHaveCount(0);
    expect(page.url()).not.toContain("pivot=");
    step("dead: honest empty state");

    // Browser Back returns to the Evidence detail; then to the list.
    await page.goBack();
    await expect(
      page.getByRole("heading", { name: "Evidence details" }),
    ).toBeVisible({ timeout: 30_000 });
    await page.goBack();
    await expect(page.getByRole("table", { name: "Evidence" })).toBeVisible({ timeout: 30_000 });
    expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(page.url()).not.toContain("pivot=");
    expect(consoleErrors).toEqual([]);
    for (const { tag, at } of stepTags) {
      console.log(`E22B-MARK ${tag} +${(at - stepTags[0].at) / 1000}s`);
    }
  });

  test("E22-ND routed Evidence detail Back closes only the detail; surfaces stay browsable", async ({
    page,
  }) => {
    const consoleErrors: string[] = [];
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${String(error)}`));
    page.on("console", (message) => {
      if (message.type === "error") {
        consoleErrors.push(`console: ${message.text}`);
      }
    });

    step("nd: start");
    await page.goto("/investigations");
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    const base = `/investigations/${await completeInvestigation(
      page,
      OBJECTIVE,
      F02_ROOT_DOMAIN,
    )}`;
    step("nd: F02 completed");

    // Investigation -> Evidence -> Subject Pivot -> Relationships. Select
    // the DOMAIN evidence row whose subject is a relationship source, so
    // the routed slice deterministically has rows.
    await page.getByRole("tab", { name: "Evidence" }).click();
    await expect(page.getByText(F02_ROOT_DOMAIN).first()).toBeVisible({ timeout: 30_000 });
    const rootRow = page
      .getByRole("row")
      .filter({ hasText: F02_ROOT_DOMAIN })
      .first();
    await rootRow.getByRole("button", { name: "Subject" }).click();
    await page
      .getByRole("group", { name: "Pivot actions" })
      .getByRole("link", { name: "Relationships where source" })
      .click();
    await expect(page).toHaveURL(new RegExp(`${base}/relationships\\?source_entity_id=`));
    await expect(
      page.getByRole("textbox", { name: "Source entity ID" }),
    ).toHaveValue(/^[0-9a-f-]{36}$/);
    const relationshipsTable = page.getByRole("table", { name: "Relationships" });
    await expect(relationshipsTable).toBeVisible({ timeout: 60_000 });
    step("nd: relationships route open");

    // Relationship detail -> pivot source -> exact Evidence surface.
    await relationshipsTable
      .getByRole("row")
      .filter({ hasText: F02_ROOT_DOMAIN })
      .first()
      .getByRole("button", { name: /^View / })
      .click();
    await expect(
      page.getByRole("heading", { name: "Relationships details" }),
    ).toBeVisible({ timeout: 30_000 });
    await page.getByRole("button", { name: "Pivot actions Source entity" }).click();
    await page
      .getByRole("group", { name: "Pivot actions" })
      .getByRole("link", { name: "Evidence for this entity" })
      .click();
    await expect(page).toHaveURL(new RegExp(`${base}/evidence\\?subject_entity_id=`));
    await expect(page.getByRole("table", { name: "Evidence" })).toBeVisible({ timeout: 30_000 });
    step("nd: evidence surface open");

    // Evidence list/detail: View -> detail -> Back closes only the detail
    // (no dialog, no overlay); repeated same-page cycles stay clean.
    const evidenceTable = page.getByRole("table", { name: "Evidence" });
    await evidenceTable
      .getByRole("row")
      .filter({ hasText: F02_ROOT_DOMAIN })
      .first()
      .getByRole("button", { name: /^View / })
      .click();
    await expect(
      page.getByRole("heading", { name: "Evidence details" }),
    ).toBeVisible({ timeout: 30_000 });
    await expect(page.getByRole("dialog")).toHaveCount(0);
    expect(await page.getByTestId("pivot-workbench").count()).toBe(0);
    await page.getByRole("button", { name: "Back to Evidence" }).click();
    await expect(evidenceTable).toBeVisible({ timeout: 30_000 });

    // Open another detail, Back again: the surface survives repeated
    // same-page lifecycle.
    await evidenceTable
      .getByRole("row")
      .filter({ hasText: F02_ROOT_DOMAIN })
      .first()
      .getByRole("button", { name: /^View / })
      .click();
    await expect(
      page.getByRole("heading", { name: "Evidence details" }),
    ).toBeVisible({ timeout: 30_000 });
    await page.getByRole("button", { name: "Back to Evidence" }).click();
    await expect(evidenceTable).toBeVisible({ timeout: 30_000 });
    step("nd: Back closed only the detail");

    // Browser Back returns to the previous entry: the closed Evidence
    // detail re-renders from URL state (route-owned detail, N12).
    await page.goBack();
    await expect(
      page.getByRole("heading", { name: "Evidence details" }),
    ).toBeVisible({ timeout: 30_000 });

    // The persistent Investigation shell stays browsable: the
    // Relationships tab reaches the routed Relationships surface with the
    // exact pre-applied source filter.
    await page.getByRole("tab", { name: "Relationships" }).click();
    await expect(page).toHaveURL(new RegExp(`${base}/relationships$`));
    await expect(
      page.getByRole("table", { name: "Relationships" }),
    ).toBeVisible({ timeout: 60_000 });
    expect(page.getByText("FAKE DATA")).toBeVisible();
    expect(page.url()).not.toContain("pivot=");
    expect(consoleErrors).toEqual([]);
  });
});
