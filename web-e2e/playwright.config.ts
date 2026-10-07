// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// V07-01 server-rendered web acceptance configuration.
//
// Owned by the web presentation adapter (not by frontend/) so the suite
// survives eventual React/frontend removal. The real-stack topology is built
// by scripts/e2e-web.sh; the base URL and generated bootstrap credentials
// come from the harness environment.

import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 30_000 },
  // Critical acceptance is deliberately deterministic: no retries.
  retries: 0,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env.WEB_E2E_BASE_URL ?? "http://localhost:8000",
    headless: true,
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
    { name: "firefox", use: { browserName: "firefox" } },
  ],
});
