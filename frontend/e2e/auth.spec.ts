// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E (PR 24A E01-E04).
//
// Runs against the production-path stack created by the repository E2E
// harness (scripts/e2e.sh): built/static React + Nginx -> real FastAPI ->
// real PostgreSQL, in fake operating mode with a throwaway bootstrap admin.
// No live LLM is involved. Never touches normal developer data.

import { expect, test, type Page } from "@playwright/test";

const ADMIN_USERNAME = process.env.E2E_ADMIN_USERNAME ?? "";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "";

async function login(page: Page): Promise<void> {
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Username").fill(ADMIN_USERNAME);
  await page.getByLabel("Password").fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test.describe("PR 24A real-stack browser flows", () => {
  test.beforeAll(() => {
    if (ADMIN_USERNAME.length === 0 || ADMIN_PASSWORD.length === 0) {
      throw new Error("E2E_ADMIN_USERNAME and E2E_ADMIN_PASSWORD are required.");
    }
  });

  test("E01 login to the authenticated shell", async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on("console", (message) => {
      if (message.type === "error") {
        consoleErrors.push(message.text);
      }
    });

    // Unauthenticated protected navigation -> login.
    await page.goto("/investigations");
    await expect(page).toHaveURL(/\/login/);

    const passwordField = page.getByLabel("Password");
    await expect(passwordField).toHaveAttribute("type", "password");

    await page.getByLabel("Username").fill(ADMIN_USERNAME);
    await passwordField.fill(ADMIN_PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();

    // Authenticated shell + runtime FAKE DATA indicator.
    await expect(page).toHaveURL(/\/investigations/);
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    await expect(page.getByText(ADMIN_USERNAME)).toBeVisible();
    await expect(page.getByRole("heading", { name: "Investigations" })).toBeVisible();
    await expect(page.locator("main")).toBeVisible();
    expect(consoleErrors).toEqual([]);
  });

  test("E02 session restore after reload", async ({ page }) => {
    await login(page);
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    await page.reload();
    await expect(page.getByRole("heading", { name: "Investigator" })).toBeVisible();
    await expect(page.getByText("FAKE DATA")).toBeVisible();
    await expect(page).toHaveURL(/\/investigations/);
  });

  test("E03 CSRF-protected logout returns to login and revokes the session", async ({ page }) => {
    await login(page);
    await expect(page.getByText("FAKE DATA")).toBeVisible();

    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

    // The server session is revoked: protected navigation returns to login.
    await page.goto("/investigations");
    await expect(page).toHaveURL(/\/login/);
  });

  test("E04 direct SPA navigation through Nginx serves the app, not a 404", async ({ page }) => {
    await page.goto("/investigations");
    // Nginx history fallback hands the path to React Router, which renders
    // the login page for the unauthenticated visitor instead of a server
    // 404.
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await expect(page.getByText("Page not found")).not.toBeVisible();
  });
});