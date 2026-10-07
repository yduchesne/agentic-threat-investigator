// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// V07-01 real-stack browser smoke: login -> authenticated shell -> one
// HTMX-enhanced harmless interaction -> refresh/session persistence ->
// CSRF-protected logout -> protected redirect.
//
// The critical acceptance runs with retries=0 and workers=1 (playwright
// config) so a deterministic defect is never hidden by retries.

import { expect, test } from "@playwright/test";

const USERNAME = process.env.WEB_E2E_ADMIN_USERNAME ?? "web-e2e-admin";
const PASSWORD = process.env.WEB_E2E_ADMIN_PASSWORD ?? "";

test.describe("V07-01 server-rendered web smoke", () => {
  test("login, shell, HTMX, refresh, logout", async ({ page }) => {
    const pageErrors: string[] = [];
    const consoleErrors: string[] = [];
    const serverErrors: number[] = [];

    page.on("pageerror", (error) => pageErrors.push(error.message));
    page.on("console", (message) => {
      if (message.type() !== "error") return;
      // Browsers opportunistically request /favicon.ico; a missing favicon
      // is not an ATI presentation regression.
      if (message.location().url.includes("favicon")) return;
      consoleErrors.push(message.text());
    });
    page.on("response", (response) => {
      if (response.status() >= 500) serverErrors.push(response.status());
    });

    // A protected page redirects an unauthenticated browser to the login page.
    await page.goto("/");
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

    // Sign in through the ordinary HTML form (no JavaScript required).
    await page.getByLabel("Username").fill(USERNAME);
    await page.getByLabel("Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();

    // Authenticated shell with a visible public identity.
    await expect(page).toHaveURL(/\/$/);
    await expect(
      page.getByRole("heading", { name: "Authenticated shell" }),
    ).toBeVisible();
    await expect(page.locator(".ati-identity")).toContainText(USERNAME);

    // One HTMX-enhanced harmless interaction: refresh the connection card.
    const renderId = page.locator("[data-ati-render-id]");
    await expect(renderId).toBeVisible();
    const before = await renderId.getAttribute("data-ati-render-id");
    await page.getByRole("link", { name: "Refresh connection" }).click();
    await expect(renderId).not.toHaveAttribute("data-ati-render-id", before ?? "");
    await expect(page.getByRole("heading", { name: "Connection" })).toBeVisible();

    // A full page refresh preserves the server-side session.
    await page.reload();
    await expect(
      page.getByRole("heading", { name: "Authenticated shell" }),
    ).toBeVisible();

    // CSRF-protected logout returns to the login page.
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page).toHaveURL(/\/login/);

    // The protected page redirects to login again after logout.
    await page.goto("/");
    await expect(page).toHaveURL(/\/login/);

    expect(pageErrors).toEqual([]);
    expect(consoleErrors).toEqual([]);
    expect(serverErrors).toEqual([]);
  });
});
