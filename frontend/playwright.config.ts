// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Playwright configuration (PR 24A; PR 31F-6).
//
// The E2E suite targets the real production-path stack built and served by
// the E2E harness: built/static React frontend behind Nginx -> real
// FastAPI -> real PostgreSQL. Credentials and URL come from the harness
// environment so tests never touch normal developer data.

import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  // The real-stack stack legitimately cold-starts slower (bootstrap
  // ingestion, API + durable worker containers); 30s keeps single-step
  // waits deterministic without masking failures.
  expect: { timeout: 30_000 },
  // PR 31F-6 A5: the Pivot workbench is ordinary in-flow content; the
  // former overlay freeze is gone and critical raw-pointer acceptance runs
  // with --retries=0 (zz-pointer-acceptance, zz-pivot-acceptance,
  // zz-list-detail). The suite-wide retry remains for environmental
  // stability only (a loaded development machine can produce transient
  // fake-world/data-timing or headless-drag misses on the broader specs);
  // it never masks an unconditional failure of the critical gates.
  retries: 1,
  // Resource control (PR 31F-4): real-stack browser tests are
  // resource-intensive and concurrent workers can saturate a development
  // machine, producing misleading slowdowns. The repository default is one
  // worker; controlled local runs use `npx playwright test --workers=1`.
  // See docs/TESTING.md "Playwright resource control".
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:8080",
    headless: true,
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
    // PR 31F-6: the list/detail lifecycle and the raw-pointer acceptance
    // journey must ALSO run in Firefox, which reproduces the motivating
    // freeze class in both engines. The Firefox project is deliberately
    // scoped to those specs: unrelated suite-wide Firefox gaps never block
    // the rest of the suite.
    {
      name: "inspector-firefox",
      use: { browserName: "firefox" },
      // PR 31F-8: the routed native-pointer stress journey runs in Firefox
      // as well (both engines reproduced the detached-DOM/pointer class).
      // PR 31G: the graph-context lifecycle stress also runs in both engines.
      testMatch:
        /(zz-list-detail|zz-pointer-acceptance|zz-pivot-acceptance|zz-pr31f7-critical|zz-31f8-stress|zz-31g-graph-context)\.spec\.ts/,
    },
  ],
});
