// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Real-stack browser E2E: PR 35-4 mandatory GEOINT enrichment (Chromium +
// Firefox).
//
// This journey proves the *mandatory* enrichment pipeline produces resolved
// GEOINT data visible in the UI, independently of any analyst/pivot
// decision. It does NOT seed GEOLOCATION Evidence or final GEOINT rows
// through the harness seeders: the only input is a browser-created
// Investigation whose root is the deterministic Fake World applicable IP
// `203.0.113.81`. The full production path then runs:
//
//   root IP Entity
//     -> mandatory DB-IP enrichment scheduler (graph)
//     -> FakeWorldEvidenceProvider (exact production SourceId.DBIP_CITY_LITE)
//     -> shared ProviderWorkExecutor execution seam
//     -> ProviderObservationPersistenceService
//     -> GEOLOCATION EvidenceObservation + Entity association + admission
//     -> GeoResolution
//     -> production Geo Resolution worker
//     -> canonical Dallas Location
//     -> GEOINT API
//     -> GEOINT MAP / TABLE
//
// The test fails if the GEOINT view renders but contains no resolved GEOINT
// data (the previously observed `No geolocation context` failure mode).
// External OpenStreetMap raster tiles are never an acceptance dependency;
// only ATI-owned accessible table/map semantics are asserted.

import { expect, test, type Page } from "@playwright/test";

const ROOT_IP = "203.0.113.81";
const EXPECTED_CITY = "Dallas";
const OBJECTIVE = "PR 35-4 mandatory GEOINT acceptance";
const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";

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
  await page.goto(`${BASE_URL}/login`);
  await page.getByLabel("Username").fill(process.env.E2E_ADMIN_USERNAME ?? "admin");
  await page.getByLabel("Password").fill(process.env.E2E_ADMIN_PASSWORD ?? "admin");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByText("FAKE DATA").waitFor();
}

/** Create and complete one Investigation rooted directly at the Fake IP. */
async function completeRootIpInvestigation(page: Page): Promise<string> {
  await page.getByRole("link", { name: "New Investigation" }).click();
  await expect(
    page.getByRole("heading", { name: "Create Investigation" }),
  ).toBeVisible({ timeout: 30_000 });
  await page.getByLabel(/^Objective/).fill(OBJECTIVE);
  await page.getByLabel("Indicator type").click();
  await page.getByRole("option", { name: "IP address" }).click();
  await page.getByLabel("Indicator value 1").fill(ROOT_IP);
  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page).toHaveURL(/\/investigations\/([0-9a-f-]+)\/overview/);
  const investigationId = page.url().match(/\/investigations\/([0-9a-f-]+)\//)?.[1];
  expect(investigationId).not.toBeUndefined();
  await expect(page.getByRole("heading", { name: OBJECTIVE })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByLabel("Status: Completed").first()).toBeVisible({
    timeout: 300_000,
  });
  return investigationId ?? "";
}

test.describe("PR 35-4 mandatory GEOINT enrichment", () => {
  test.describe.configure({ timeout: 600_000, retries: 0 });
  test.use({ storageState: { cookies: [], origins: [] } });

  test("root IP mandatory enrichment yields resolved GEOINT in MAP and TABLE", async ({
    page,
  }) => {
    await login(page);
    // Track errors only after sign-in: the unauthenticated `/auth/me` probe
    // is an expected 401, not a product error.
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

    const investigationId = await completeRootIpInvestigation(page);
    const base = `/investigations/${investigationId}`;

    // Navigate through the user-visible GEOINT primary tab.
    await page.goto(`${base}/geoint/map`);
    await expect(page.getByRole("heading", { name: "GEOINT" })).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByRole("tab", { name: "MAP" })).toHaveAttribute(
      "aria-selected",
      "true",
    );

    // The mandatory pipeline must have produced resolved GEOINT data; the
    // route rendering alone is not sufficient.
    await expect
      .poll(
        async () =>
          page.getByText(/no geolocation context/i).count(),
        { timeout: 60_000 },
      )
      .toBe(0);

    // MAP exposes at least one ATI-owned resolved GEOINT row.
    const mapRows = page
      .getByRole("table", { name: "All returned geolocation items" })
      .locator("tbody tr");
    await expect(mapRows.first()).toBeVisible({ timeout: 60_000 });
    await expect(mapRows.filter({ hasText: ROOT_IP }).first()).toBeVisible({
      timeout: 60_000,
    });

    // TABLE sub-tab via the normal user-visible control.
    await page.getByRole("tab", { name: "TABLE" }).click();
    await expect(page).toHaveURL(`${base}/geoint/table`);
    await expect(page.getByRole("tab", { name: "TABLE" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    const topLocations = page.getByRole("table", {
      name: "Top canonical Locations in this Investigation",
    });
    await expect(topLocations).toBeVisible({ timeout: 60_000 });
    await expect(topLocations.getByText(EXPECTED_CITY).first()).toBeVisible({
      timeout: 60_000,
    });
    const geolocationRows = page
      .getByRole("table", { name: "All returned geolocation items" })
      .locator("tbody tr");
    await expect(geolocationRows.first()).toBeVisible({ timeout: 60_000 });
    await expect(geolocationRows.filter({ hasText: ROOT_IP }).first()).toBeVisible({
      timeout: 60_000,
    });

    // No unexpected ATI API 4xx/5xx and no uncaught browser exceptions.
    expect(failedResponses).toEqual([]);
    expect(consoleErrors).toEqual([]);
  });
});
