// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Playwright configuration (PR 24A).
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
  retries: 0,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:8080",
    headless: true,
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});