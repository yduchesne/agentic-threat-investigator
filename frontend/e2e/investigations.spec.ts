// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: the complete PR 24B analyst workflow (E10-E14).
//
// Runs against the production-path stack created by the repository E2E
// harness (scripts/e2e.sh): built/static React + Nginx -> real FastAPI ->
// real PostgreSQL -> real durable Investigation worker executing the
// production coordinator/runner/persistence with the deterministic offline
// LLM boundary, over the packaged PR 23D fake world. No live Internet, no
// live threat-intelligence provider, and no live LLM; `FAKE DATA` remains
// visible throughout.
//
// Canonical slice:
//   login -> Investigations -> New Investigation -> submit known fake
//   indicator + objective -> POST 202 (Idempotency-Key) -> workspace
//   immediately -> bounded polling -> terminal -> current Assessment ->
//   current Report -> Overview.

import { expect, test, type Page } from "@playwright/test";

const ADMIN_USERNAME = process.env.E2E_ADMIN_USERNAME ?? "";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "";

const F02_ROOT_DOMAIN = "update-package.test";
const OBJECTIVE = "assess the update-package delivery domain";

async function login(page: Page): Promise<void> {
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Username").fill(ADMIN_USERNAME);
  await page.getByLabel("Password").fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test.describe("PR 24B real-stack investigation workflow", () => {
  // The durable worker path (fake-world provider work + analyst rounds +
  // report writing) legitimately takes tens of seconds; the workflow test
  // is bounded by the stack, not by the default 60s test timeout.
  test.describe.configure({ timeout: 300_000 });

  test.beforeAll(() => {
    if (ADMIN_USERNAME.length === 0 || ADMIN_PASSWORD.length === 0) {
      throw new Error("E2E_ADMIN_USERNAME and E2E_ADMIN_PASSWORD are required.");
    }
  });

  test("E10 create -> 202 -> workspace -> poll -> terminal Assessment/Report Overview", async ({
    page,
  }) => {
    const consoleErrors: string[] = [];
    page.on("console", (message) => {
      if (message.type() === "error") {
        consoleErrors.push(message.text());
      }
    });
    // Chrome logs the protected-route auth probe (`/auth/me` before login)
    // as a resource-load 401; it is the documented unauthenticated probe,
    // not an application failure. Every other console error still fails.
    const isAuthProbe401 = (text: string): boolean =>
      text ===
      "Failed to load resource: the server responded with a status of 401 (Unauthorized)";

    await login(page);
    await expect(page.getByText("FAKE DATA")).toBeVisible();

    // New Investigation
    await page.getByRole("link", { name: "New Investigation" }).click();
    await expect(
      page.getByRole("heading", { name: "Create Investigation" }),
    ).toBeVisible();

    // Capture the create POST: CSRF-protected and carrying Idempotency-Key.
    let createHeaders: Record<string, string> | null = null;
    let createBody: unknown = null;
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (
        request.method() === "POST" &&
        url.pathname === "/api/v1/investigations"
      ) {
        createHeaders = request.headers();
        createBody = request.postDataJSON();
      }
    });

    // Submit one logical request: objective + one typed fake indicator.
    await page.getByLabel(/^Objective/).fill(OBJECTIVE);
    await page.getByLabel("Indicator value 1").fill(F02_ROOT_DOMAIN);
    await page.getByRole("button", { name: "Submit" }).click();

    // 202 -> immediate workspace (never waits for the worker inside create).
    await expect(page).toHaveURL(/\/investigations\/[0-9a-f-]+\/overview/);
    await expect(
      page.getByRole("heading", { name: OBJECTIVE }),
    ).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText("FAKE DATA")).toBeVisible();

    // The create request carried exactly one logical submission: a
    // cryptographically strong Idempotency-Key, the CSRF header, and the
    // typed payload.
    expect(createHeaders).not.toBeNull();
    expect(createHeaders?.["idempotency-key"]).toMatch(/^[A-Za-z0-9._~-]{1,128}$/);
    expect(createHeaders?.["x-csrf-token"]).toBeTruthy();
    const indicators = (createBody as { indicators?: unknown[] }).indicators ?? [];
    expect(indicators).toHaveLength(1);
    expect(indicators[0]).toEqual({
      type: "domain",
      value: F02_ROOT_DOMAIN,
    });

    // Workspace shows the analyst workflow immediately (pending/running or
    // already terminal), then the worker + bounded polling converge on a
    // terminal lifecycle state without any live LLM.
    await expect(page.getByLabel("Status: Completed").first()).toBeVisible({ timeout: 240_000 });

    // Current Assessment/Report overview: verdict and confidence.
    await expect(page.getByText(/Verdict: Malicious/)).toBeVisible();
    await expect(page.getByText("High", { exact: false }).first()).toBeVisible();

    // Executive summary statement and at least one finding with visible
    // support references.
    await expect(
      page.getByText(/The investigation concluded .* malicious delivery/i),
    ).toBeVisible();
    await expect(page.getByText("Findings")).toBeVisible();
    await expect(
      page.getByText(/Threat-intelligence and reputation sources/),
    ).toBeVisible();
    await expect(page.getByText("Supports")).toBeVisible();
    await expect(page.getByText("Evidence").first()).toBeVisible();

    // The full persisted Report is reachable as the secondary surface.
    await page.getByRole("link", { name: "View full report" }).click();
    await expect(
      page.getByRole("heading", { name: "Report", exact: true }),
    ).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/Version:/)).toBeVisible();
    await expect(
      page.getByText(/The investigation concluded .* malicious delivery/i),
    ).toBeVisible();
    await expect(page.getByText("FAKE DATA")).toBeVisible();

    expect(consoleErrors.filter((text) => !isAuthProbe401(text))).toEqual([]);
  });

  test("E11 the created Investigation appears once in the real list", async ({
    page,
  }) => {
    await login(page);
    await expect(page.getByText("FAKE DATA")).toBeVisible();

    // The list page renders exactly one Investigation for the objective
    // submitted by E10; no duplicated logical submissions exist.
    await expect(
      page.getByRole("link", { name: OBJECTIVE }),
    ).toBeVisible({ timeout: 30_000 });
    await expect(page.getByRole("link", { name: OBJECTIVE })).toHaveCount(1);
    // Terminal status and artifact availability render from the API.
    await expect(page.getByLabel("Status: Completed")).toBeVisible();
  });
});